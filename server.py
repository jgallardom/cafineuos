#!/usr/bin/env python3
"""Local sync target for Cafineuos.

Each device keeps its own copy and pushes dirty records with the revision
they were based on. The server accepts the write only when that revision is
still current. Otherwise it returns the server copy so the device can merge
or ask the user to resolve the conflict.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import shutil
import sqlite3
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "static"
DATA = Path(os.environ.get("DATA_DIR", ROOT))
DB_PATH = DATA / "cloud.sqlite"
BLOB_DIR = DATA / "blobs"
BACKUP_DIR = DATA / "backups"
MAX_BLOB = 12 * 1024 * 1024
DEFAULT_ACCESS = {
    "create": {"mode": "all", "users": []},
    "edit": {"mode": "all", "users": []},
    "erase": {"mode": "all", "users": []},
}
HOST = os.environ.get("HOST", "0.0.0.0" if os.environ.get("PORT") else "127.0.0.1")
PORT = int(os.environ.get("PORT", "8765"))
LOCK = threading.Lock()
LEVELS = {"none": 0, "own": 1, "all": 2}
PASSWORD_ROUNDS = 200_000

MIME = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".webmanifest": "application/manifest+json",
    ".svg": "image/svg+xml",
}


def connect(path: Path | None = None) -> sqlite3.Connection:
    con = sqlite3.connect(path or DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def init_db(path: Path | None = None) -> sqlite3.Connection:
    con = connect(path)
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS counters (
            name TEXT PRIMARY KEY,
            n INTEGER NOT NULL
        );
        INSERT OR IGNORE INTO counters(name, n) VALUES ('change', 0);

        CREATE TABLE IF NOT EXISTS libraries (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            fields_json TEXT NOT NULL,
            rev INTEGER NOT NULL,
            updated_at TEXT NOT NULL,
            deleted INTEGER NOT NULL,
            change_seq INTEGER NOT NULL,
            updated_by TEXT,
            updated_by_name TEXT,
            created_by TEXT
        );

        CREATE TABLE IF NOT EXISTS entries (
            id TEXT PRIMARY KEY,
            library_id TEXT NOT NULL,
            values_json TEXT NOT NULL,
            rev INTEGER NOT NULL,
            updated_at TEXT NOT NULL,
            deleted INTEGER NOT NULL,
            change_seq INTEGER NOT NULL,
            updated_by TEXT,
            updated_by_name TEXT,
            created_by TEXT
        );

        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            password_salt TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS groups (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE COLLATE NOCASE
        );

        CREATE TABLE IF NOT EXISTS group_members (
            group_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            PRIMARY KEY (group_id, user_id)
        );

        CREATE TABLE IF NOT EXISTS grants (
            id TEXT PRIMARY KEY,
            subject_type TEXT NOT NULL,
            subject_id TEXT NOT NULL,
            library_id TEXT NOT NULL,
            target TEXT NOT NULL,
            field_id TEXT NOT NULL DEFAULT '',
            see_level TEXT NOT NULL DEFAULT 'none',
            edit_level TEXT NOT NULL DEFAULT 'none',
            create_level TEXT NOT NULL DEFAULT 'none',
            erase_level TEXT NOT NULL DEFAULT 'none',
            UNIQUE (subject_type, subject_id, library_id, target, field_id)
        );

        CREATE TABLE IF NOT EXISTS blobs (
            id TEXT PRIMARY KEY,
            entry_id TEXT,
            field_id TEXT,
            name TEXT NOT NULL,
            mime TEXT NOT NULL,
            size INTEGER NOT NULL,
            created_by TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_libraries_seq ON libraries(change_seq);
        CREATE INDEX IF NOT EXISTS idx_entries_seq ON entries(change_seq);
        """
    )
    _ensure_column(con, "libraries", "created_by", "TEXT")
    _ensure_column(con, "entries", "created_by", "TEXT")
    _ensure_column(con, "libraries", "access_json", "TEXT")
    con.commit()
    return con


def _ensure_column(con: sqlite3.Connection, table: str, column: str, typedef: str) -> None:
    names = {row["name"] for row in con.execute(f"PRAGMA table_info({table})")}
    if column not in names:
        con.execute(f"ALTER TABLE {table} ADD COLUMN {column} {typedef}")


class AuthzError(Exception):
    pass


def _now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), PASSWORD_ROUNDS)
    return salt, digest.hex()


def _check_password(password: str, salt: str, expected: str) -> bool:
    _, digest = hash_password(password, salt)
    return hmac.compare_digest(digest, expected)


def _level(value: str, action: str) -> str:
    value = value if value in LEVELS else "none"
    if action == "create" and value == "own":
        return "all"
    return value


def _wider(left: str, right: str) -> str:
    return left if LEVELS[left] >= LEVELS[right] else right


def create_user(con: sqlite3.Connection, name: str, password: str, is_admin: bool = False) -> str:
    name = (name or "").strip()
    if not name:
        raise ValueError("Name is required")
    if len(password or "") < 4:
        raise ValueError("Password must be at least 4 characters")
    user_id = str(uuid.uuid4())
    salt, digest = hash_password(password)
    try:
        con.execute(
            """
            INSERT INTO users (id, name, password_hash, password_salt, is_admin, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (user_id, name, digest, salt, 1 if is_admin else 0, _now()),
        )
    except sqlite3.IntegrityError as exc:
        raise ValueError("That name is already used") from exc
    return user_id


def update_user(con: sqlite3.Connection, actor: dict, body: dict) -> dict:
    if not actor or not actor.get("is_admin"):
        raise AuthzError("Only an admin can do that")
    row = con.execute("SELECT * FROM users WHERE id = ?", (body.get("id"),)).fetchone()
    if row is None:
        raise ValueError("User not found")
    name = (body.get("name") if body.get("name") is not None else row["name"]).strip()
    if not name:
        raise ValueError("Name is required")
    is_admin = bool(body.get("is_admin"))
    if row["is_admin"] and not is_admin:
        others = con.execute("SELECT COUNT(*) AS n FROM users WHERE is_admin = 1 AND id != ?", (row["id"],)).fetchone()["n"]
        if others == 0:
            raise ValueError("Keep at least one admin")
    password = body.get("password") or ""
    try:
        if password:
            if len(password) < 4:
                raise ValueError("Password must be at least 4 characters")
            salt, digest = hash_password(password)
            con.execute(
                "UPDATE users SET name = ?, is_admin = ?, password_hash = ?, password_salt = ? WHERE id = ?",
                (name, 1 if is_admin else 0, digest, salt, row["id"]),
            )
        else:
            con.execute(
                "UPDATE users SET name = ?, is_admin = ? WHERE id = ?",
                (name, 1 if is_admin else 0, row["id"]),
            )
    except sqlite3.IntegrityError as exc:
        raise ValueError("That name is already used") from exc
    if isinstance(body.get("group_ids"), list):
        con.execute("DELETE FROM group_members WHERE user_id = ?", (row["id"],))
        for group_id in body["group_ids"]:
            if con.execute("SELECT 1 FROM groups WHERE id = ?", (group_id,)).fetchone() is None:
                raise ValueError("Group not found")
            con.execute("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)", (group_id, row["id"]))
    return {"ok": True, "name": name}


def remove_user(con: sqlite3.Connection, actor: dict, user_id: str) -> dict:
    if not actor or not actor.get("is_admin"):
        raise AuthzError("Only an admin can do that")
    if user_id == actor["id"]:
        raise ValueError("You cannot remove the account you are using")
    row = con.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if row is None:
        raise ValueError("User not found")
    if row["is_admin"]:
        others = con.execute("SELECT COUNT(*) AS n FROM users WHERE is_admin = 1 AND id != ?", (user_id,)).fetchone()["n"]
        if others == 0:
            raise ValueError("Keep at least one admin")
    con.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
    con.execute("DELETE FROM group_members WHERE user_id = ?", (user_id,))
    con.execute("DELETE FROM grants WHERE subject_type = 'user' AND subject_id = ?", (user_id,))
    con.execute("DELETE FROM users WHERE id = ?", (user_id,))
    return {"ok": True}


def update_account(con: sqlite3.Connection, actor: dict, body: dict) -> dict:
    if not actor:
        raise PermissionError("Sign in first")
    name = (body.get("name") or "").strip()
    if not name:
        raise ValueError("Name is required")
    password = body.get("password") or ""
    try:
        if password:
            if len(password) < 4:
                raise ValueError("Password must be at least 4 characters")
            salt, digest = hash_password(password)
            con.execute(
                "UPDATE users SET name = ?, password_hash = ?, password_salt = ? WHERE id = ?",
                (name, digest, salt, actor["id"]),
            )
        else:
            con.execute("UPDATE users SET name = ? WHERE id = ?", (name, actor["id"]))
    except sqlite3.IntegrityError as exc:
        raise ValueError("That name is already used") from exc
    return {"id": actor["id"], "name": name, "is_admin": bool(actor.get("is_admin"))}


def update_group(con: sqlite3.Connection, actor: dict, body: dict) -> dict:
    if not actor or not actor.get("is_admin"):
        raise AuthzError("Only an admin can do that")
    group_id = body.get("group_id")
    row = con.execute("SELECT * FROM groups WHERE id = ?", (group_id,)).fetchone()
    if row is None:
        raise ValueError("Group not found")
    name = (body.get("name") if body.get("name") is not None else row["name"]).strip()
    if not name:
        raise ValueError("Name is required")
    try:
        con.execute("UPDATE groups SET name = ? WHERE id = ?", (name, group_id))
    except sqlite3.IntegrityError as exc:
        raise ValueError("That name is already used") from exc
    con.execute("DELETE FROM group_members WHERE group_id = ?", (group_id,))
    for user_id in body.get("user_ids") or []:
        if con.execute("SELECT 1 FROM users WHERE id = ?", (user_id,)).fetchone() is None:
            raise ValueError("User not found")
        con.execute("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)", (group_id, user_id))
    return {"ok": True}


def remove_group(con: sqlite3.Connection, actor: dict, group_id: str) -> dict:
    if not actor or not actor.get("is_admin"):
        raise AuthzError("Only an admin can do that")
    if con.execute("SELECT 1 FROM groups WHERE id = ?", (group_id,)).fetchone() is None:
        raise ValueError("Group not found")
    con.execute("DELETE FROM group_members WHERE group_id = ?", (group_id,))
    con.execute("DELETE FROM grants WHERE subject_type = 'group' AND subject_id = ?", (group_id,))
    con.execute("DELETE FROM groups WHERE id = ?", (group_id,))
    return {"ok": True}


def _groups_for(con: sqlite3.Connection, user_id: str) -> list[str]:
    return [
        row["group_id"]
        for row in con.execute("SELECT group_id FROM group_members WHERE user_id = ?", (user_id,))
    ]


def _actor_from_row(con: sqlite3.Connection, row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "name": row["name"],
        "is_admin": bool(row["is_admin"]),
        "groups": _groups_for(con, row["id"]),
    }


def actor_from_token(con: sqlite3.Connection, token: str) -> dict | None:
    if not token:
        return None
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    row = con.execute(
        """
        SELECT users.* FROM sessions
        JOIN users ON users.id = sessions.user_id
        WHERE sessions.token_hash = ?
        """,
        (token_hash,),
    ).fetchone()
    if row is None:
        return None
    return _actor_from_row(con, row)


def open_session(con: sqlite3.Connection, name: str, password: str) -> tuple[str, dict]:
    row = con.execute("SELECT * FROM users WHERE name = ? COLLATE NOCASE", ((name or "").strip(),)).fetchone()
    if row is None or not _check_password(password or "", row["password_salt"], row["password_hash"]):
        raise PermissionError("Wrong name or password")
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    con.execute(
        "INSERT INTO sessions (token_hash, user_id, created_at) VALUES (?, ?, ?)",
        (token_hash, row["id"], _now()),
    )
    return token, _actor_from_row(con, row)


def _subjects(actor: dict) -> set[tuple[str, str]]:
    pairs = {("user", actor["id"])}
    for group_id in actor.get("groups") or []:
        pairs.add(("group", group_id))
    return pairs


def _grant_out(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "subject_type": row["subject_type"],
        "subject_id": row["subject_id"],
        "library_id": row["library_id"],
        "target": row["target"],
        "field_id": row["field_id"] or "",
        "see": row["see_level"],
        "edit": row["edit_level"],
        "create": row["create_level"],
        "erase": row["erase_level"],
    }


def load_grants(con: sqlite3.Connection) -> list[dict]:
    return [_grant_out(row) for row in con.execute("SELECT * FROM grants")]


def access_for(con: sqlite3.Connection, actor: dict) -> dict:
    subjects = _subjects(actor)
    grants = [grant for grant in load_grants(con) if (grant["subject_type"], grant["subject_id"]) in subjects]
    people = [{"id": row["id"], "name": row["name"]} for row in con.execute("SELECT id, name FROM users ORDER BY name")]
    return {"user_id": actor["id"], "is_admin": bool(actor["is_admin"]), "grants": grants, "people": people}


def _best_level(actor: dict, grants: list[dict], library_id: str, target: str, action: str, field_id: str = "") -> str:
    if actor.get("is_admin"):
        return "all"
    best = "none"
    subjects = _subjects(actor)
    for grant in grants:
        if (grant["subject_type"], grant["subject_id"]) not in subjects:
            continue
        if grant["library_id"] not in (library_id, "*"):
            continue
        if grant["target"] != target:
            continue
        if target == "field" and (grant["field_id"] or "") != field_id:
            continue
        best = _wider(best, _level(grant.get(action) or "none", action))
    return best


def _field_level(actor, grants, library_id, field_id, action, entry_level: str) -> str:
    specific = [
        grant
        for grant in grants
        if (grant["subject_type"], grant["subject_id"]) in _subjects(actor)
        and grant["library_id"] in (library_id, "*")
        and grant["target"] == "field"
        and (grant["field_id"] or "") == field_id
    ]
    if actor.get("is_admin"):
        return "all"
    if not specific:
        return entry_level
    best = "none"
    for grant in specific:
        best = _wider(best, _level(grant.get(action) or "none", action))
    return best


def _allows(level: str, created_by: str | None, user_id: str, action: str) -> bool:
    if action == "create":
        return level in ("all", "own")
    if level == "all":
        return True
    if level == "own":
        return bool(created_by) and created_by == user_id
    return False


def _can(actor, grants, library_id, target, action, created_by=None, field_id: str = "") -> bool:
    if target == "field":
        entry_level = _best_level(actor, grants, library_id, "entry", action)
        level = _field_level(actor, grants, library_id, field_id, action, entry_level)
    else:
        level = _best_level(actor, grants, library_id, target, action, field_id)
    return _allows(level, created_by, actor["id"], action)


def _can_see_library(actor, grants, row) -> bool:
    if _can(actor, grants, row["id"], "library", "see", row["created_by"]):
        return True
    entry_level = _best_level(actor, grants, row["id"], "entry", "see")
    if entry_level in ("own", "all"):
        return True
    access = row.get("access") or DEFAULT_ACCESS
    user_id = actor["id"]
    for key in ("create", "edit", "erase"):
        if _rule_ok(access.get(key), user_id, row.get("created_by")):
            return True
    return False


def _clean_access(raw) -> dict:
    cleaned = {
        "create": {"mode": "none", "users": []},
        "edit": {"mode": "none", "users": []},
        "erase": {"mode": "none", "users": []},
    }
    if not isinstance(raw, dict):
        return cleaned
    for key in cleaned:
        rule = raw.get(key) if isinstance(raw.get(key), dict) else {}
        mode = rule.get("mode") if rule.get("mode") in {"none", "all", "own", "list"} else "none"
        if key == "create" and mode == "own":
            mode = "none"
        users = [str(item) for item in (rule.get("users") or []) if item]
        cleaned[key] = {"mode": mode, "users": users}
    return cleaned


def _parse_access(raw) -> dict:
    if not raw:
        return _clean_access(None)
    if isinstance(raw, dict):
        return _clean_access(raw)
    try:
        return _clean_access(json.loads(raw))
    except (TypeError, json.JSONDecodeError):
        return _clean_access(None)


def _rule_ok(rule, user_id: str, created_by) -> bool:
    if not rule:
        return False
    mode = rule.get("mode") or "none"
    if mode == "all":
        return True
    if mode == "own":
        return bool(created_by) and created_by == user_id
    if mode == "list":
        return user_id in (rule.get("users") or [])
    return False


def _ids_in_value(values, field_id: str) -> set[str]:
    if not values or not field_id:
        return set()
    raw = values.get(field_id)
    value = raw.get("v") if isinstance(raw, dict) else raw
    if isinstance(value, list):
        return {str(item) for item in value if item}
    if isinstance(value, str) and value:
        return {value}
    return set()


def _fields_for_role(library, role: str) -> list[dict]:
    fields = (library or {}).get("fields") or []
    matched = [field for field in fields if field.get("role") == role]
    if matched or role != "viewers":
        return matched
    return [field for field in fields if field.get("type") == "users" and not field.get("role")]


def _role_ids(library, values, role: str) -> set[str]:
    found: set[str] = set()
    for field in _fields_for_role(library, role):
        found |= _ids_in_value(values, field.get("id") or "")
    return found


def _field_by_id(library, field_id: str):
    for field in (library or {}).get("fields") or []:
        if field.get("id") == field_id:
            return field
    return None


def _entry_allowed(actor, grants, library, action: str, created_by, values, field=None) -> bool:
    if actor is None or actor.get("is_admin"):
        return True
    user_id = actor["id"]
    library_id = (library or {}).get("id") or ""
    access = (library or {}).get("access") or DEFAULT_ACCESS
    if action == "see":
        if _can(actor, grants, library_id, "entry", "see", created_by):
            return True
        if created_by == user_id:
            return True
        return user_id in _role_ids(library, values, "viewers")
    if action == "create":
        return _can(actor, grants, library_id, "entry", "create") or _rule_ok(access.get("create"), user_id, created_by)
    if action == "erase":
        return _can(actor, grants, library_id, "entry", "erase", created_by) or _rule_ok(access.get("erase"), user_id, created_by)
    if field:
        specific = [
            grant
            for grant in grants
            if (grant["subject_type"], grant["subject_id"]) in _subjects(actor)
            and grant["library_id"] in (library_id, "*")
            and grant["target"] == "field"
            and (grant["field_id"] or "") == (field.get("id") or "")
        ]
        if specific:
            return any(
                _allows(_level(grant.get("edit") or "none", "edit"), created_by, user_id, "edit")
                for grant in specific
            )
    if _can(actor, grants, library_id, "entry", "edit", created_by):
        return True
    if user_id in _role_ids(library, values, "editors"):
        return True
    if _rule_ok(access.get("edit"), user_id, created_by):
        return True
    if field and field.get("viewer_edit") and field.get("role") not in ("viewers", "editors"):
        return _entry_allowed(actor, grants, library, "see", created_by, values)
    return False


def _cell_value(cell) -> object:
    if not isinstance(cell, dict):
        return cell
    value = cell.get("v")
    return None if value == "" else value


def _same_cell(left, right) -> bool:
    return json.dumps(_cell_value(left), sort_keys=True) == json.dumps(_cell_value(right), sort_keys=True)


def _creator_grants(con: sqlite3.Connection, user_id: str, library_id: str) -> None:
    rows = [
        ("library", "", "all", "all", "none", "all"),
        ("entry", "", "all", "all", "all", "all"),
    ]
    for target, field_id, see, edit, create, erase in rows:
        con.execute(
            """
            INSERT OR REPLACE INTO grants
                (id, subject_type, subject_id, library_id, target, field_id, see_level, edit_level, create_level, erase_level)
            VALUES (?, 'user', ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (str(uuid.uuid4()), user_id, library_id, target, field_id, see, edit, create, erase),
        )


def replace_library_grants(con: sqlite3.Connection, library_id: str, grants: list[dict]) -> None:
    con.execute("DELETE FROM grants WHERE library_id = ?", (library_id,))
    for grant in grants:
        target = grant.get("target")
        if target not in ("library", "entry", "field"):
            raise ValueError("Unknown permission target")
        field_id = grant.get("field_id") or ""
        if target != "field":
            field_id = ""
        subject_type = grant.get("subject_type")
        if subject_type not in ("user", "group"):
            raise ValueError("Permission must name a user or a group")
        if not grant.get("subject_id"):
            raise ValueError("Permission is missing a subject")
        see = _level(grant.get("see") or "none", "see")
        edit = _level(grant.get("edit") or "none", "edit")
        create = _level(grant.get("create") or "none", "create")
        erase = _level(grant.get("erase") or "none", "erase")
        if target != "field" and see == edit == create == erase == "none":
            continue
        con.execute(
            """
            INSERT INTO grants
                (id, subject_type, subject_id, library_id, target, field_id, see_level, edit_level, create_level, erase_level)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (str(uuid.uuid4()), subject_type, grant["subject_id"], library_id, target, field_id, see, edit, create, erase),
        )
    _touch_library(con, library_id)


def set_library_creators(con: sqlite3.Connection, subjects: list[dict]) -> None:
    con.execute("DELETE FROM grants WHERE library_id = '*' AND target = 'library'")
    for subject in subjects:
        if subject.get("subject_type") not in ("user", "group") or not subject.get("subject_id"):
            raise ValueError("Choose a user or a group")
        con.execute(
            """
            INSERT INTO grants
                (id, subject_type, subject_id, library_id, target, field_id, see_level, edit_level, create_level, erase_level)
            VALUES (?, ?, ?, '*', 'library', '', 'none', 'none', 'all', 'none')
            """,
            (str(uuid.uuid4()), subject["subject_type"], subject["subject_id"]),
        )


def _touch_library(con: sqlite3.Connection, library_id: str) -> None:
    if library_id in ("", "*"):
        return
    seq = bump(con)
    con.execute("UPDATE libraries SET change_seq = ? WHERE id = ?", (seq, library_id))
    for row in con.execute("SELECT id FROM entries WHERE library_id = ?", (library_id,)):
        seq = bump(con)
        con.execute("UPDATE entries SET change_seq = ? WHERE id = ?", (seq, row["id"]))


def bump(con: sqlite3.Connection) -> int:
    con.execute("UPDATE counters SET n = n + 1 WHERE name = 'change'")
    row = con.execute("SELECT n FROM counters WHERE name = 'change'").fetchone()
    return int(row["n"])


def library_out(row: sqlite3.Row) -> dict:
    return {
        "kind": "library",
        "id": row["id"],
        "name": row["name"],
        "fields": json.loads(row["fields_json"]),
        "rev": row["rev"],
        "updated_at": row["updated_at"],
        "deleted": bool(row["deleted"]),
        "change_seq": row["change_seq"],
        "updated_by": row["updated_by"],
        "updated_by_name": row["updated_by_name"],
        "created_by": row["created_by"],
        "access": _parse_access(row["access_json"] if "access_json" in row.keys() else None),
    }


def entry_out(row: sqlite3.Row) -> dict:
    return {
        "kind": "entry",
        "id": row["id"],
        "library_id": row["library_id"],
        "values": json.loads(row["values_json"]),
        "rev": row["rev"],
        "updated_at": row["updated_at"],
        "deleted": bool(row["deleted"]),
        "change_seq": row["change_seq"],
        "updated_by": row["updated_by"],
        "updated_by_name": row["updated_by_name"],
        "created_by": row["created_by"],
    }


def _require(item: dict, *keys: str) -> None:
    missing = [key for key in keys if key not in item]
    if missing:
        raise ValueError(f"missing {', '.join(missing)}")


def apply_sync(con: sqlite3.Connection, body: dict, actor: dict | None = None) -> dict:
    device_id = str(body.get("device_id") or "")
    device_name = str(body.get("device_name") or "Unknown device")
    if actor:
        device_id = actor["id"]
        device_name = actor["name"]
    cursor = int(body.get("cursor") or 0)
    grants = load_grants(con) if actor else []
    accepted = []
    conflicts = []
    forbidden = []

    for item in body.get("libraries") or []:
        _require(item, "id", "name", "fields", "base_rev", "updated_at")
        outcome, payload = _upsert_library(con, item, device_id, device_name, actor, grants)
        if outcome == "accepted":
            accepted.append({"kind": "library", "id": item["id"], "rev": payload})
        elif outcome == "forbidden":
            forbidden.append({"kind": "library", "id": item["id"], "error": payload})
        else:
            conflicts.append({"kind": "library", "id": item["id"], "server": payload})

    for item in body.get("entries") or []:
        _require(item, "id", "library_id", "values", "base_rev", "updated_at")
        outcome, payload = _upsert_entry(con, item, device_id, device_name, actor, grants)
        if outcome == "accepted":
            accepted.append({"kind": "entry", "id": item["id"], "rev": payload})
        elif outcome == "forbidden":
            forbidden.append({"kind": "entry", "id": item["id"], "error": payload})
        else:
            conflicts.append({"kind": "entry", "id": item["id"], "server": payload})

    if actor:
        grants = load_grants(con)
    changes, hidden = _changes_since(con, cursor, actor, grants)
    new_cursor = cursor
    for change in changes:
        new_cursor = max(new_cursor, int(change["change_seq"]))
    for item in hidden:
        new_cursor = max(new_cursor, int(item.get("change_seq") or 0))
    result = {
        "cursor": new_cursor,
        "accepted": accepted,
        "conflicts": conflicts,
        "forbidden": forbidden,
        "changes": changes,
        "hidden": [{"kind": item["kind"], "id": item["id"]} for item in hidden],
    }
    if actor:
        result["access"] = access_for(con, actor)
        _note_access(con)
    return result


def _upsert_library(con, item, device_id, device_name, actor=None, grants=None):
    row = con.execute("SELECT * FROM libraries WHERE id = ?", (item["id"],)).fetchone()
    base_rev = int(item["base_rev"])
    grants = grants or []
    if actor and not actor.get("is_admin"):
        return "forbidden", "Only an admin can change libraries"
    if row is not None and int(row["rev"]) != base_rev:
        projected = _project_library(library_out(row), actor, grants, con)
        return "conflict", projected or {"kind": "library", "id": row["id"], "rev": int(row["rev"])}
    seq = bump(con)
    rev = 1 if row is None else int(row["rev"]) + 1
    fields = json.dumps(item["fields"])
    deleted = 1 if item.get("deleted") else 0
    access_json = json.dumps(_clean_access(item.get("access") if "access" in item else _parse_access(row["access_json"] if row is not None and "access_json" in row.keys() else None)))
    if row is None:
        created_by = actor["id"] if actor else (item.get("created_by") or device_id)
        con.execute(
            """
            INSERT INTO libraries
                (id, name, fields_json, rev, updated_at, deleted, change_seq, updated_by, updated_by_name, created_by, access_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (item["id"], item["name"], fields, rev, item["updated_at"], deleted, seq, device_id, device_name, created_by, access_json),
        )
        if actor and not actor.get("is_admin"):
            _creator_grants(con, actor["id"], item["id"])
    else:
        con.execute(
            """
            UPDATE libraries
               SET name = ?, fields_json = ?, rev = ?, updated_at = ?, deleted = ?,
                   change_seq = ?, updated_by = ?, updated_by_name = ?, access_json = ?
             WHERE id = ?
            """,
            (item["name"], fields, rev, item["updated_at"], deleted, seq, device_id, device_name, access_json, item["id"]),
        )
    _touch_library(con, item["id"])
    return "accepted", rev


def _file_items(value):
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict) and item.get("id")]
    if isinstance(value, dict) and value.get("id"):
        return [value]
    return []


def _merge_saved_files(library, current, incoming):
    if not isinstance(incoming, dict):
        return incoming
    fields = {field.get("id"): field for field in (library or {}).get("fields") or []}
    current = current or {}
    merged = dict(incoming)
    for field_id, cell in incoming.items():
        field = fields.get(field_id)
        if not field or field.get("type") not in ("file", "image"):
            continue
        raw = _cell_value(cell)
        if isinstance(raw, list):
            continue
        previous_items = _file_items(_cell_value(current.get(field_id)))
        new_items = _file_items(raw)
        if not previous_items or not new_items:
            continue
        seen = {item.get("id") for item in previous_items}
        extra = [item for item in new_items if item.get("id") not in seen]
        stamp = cell.get("t") if isinstance(cell, dict) else None
        merged[field_id] = {"v": previous_items + extra, "t": stamp}
    return merged


def _merge_entry_values(row, item, actor, grants, library=None):
    current = json.loads(row["values_json"]) if row is not None else {}
    incoming = item.get("values") or {}
    if actor is None or actor.get("is_admin") or row is None:
        return _merge_saved_files(library, current, incoming), None
    merged = dict(current)
    created_by = row["created_by"]
    blocked = False
    changed = False
    for field_id, cell in incoming.items():
        previous = current.get(field_id)
        if _same_cell(previous, cell):
            merged[field_id] = previous if previous is not None else cell
            continue
        field = _field_by_id(library, field_id)
        if not _entry_allowed(actor, grants, library, "edit", created_by, current, field):
            blocked = True
            if previous is not None:
                merged[field_id] = previous
            else:
                merged.pop(field_id, None)
            continue
        merged[field_id] = cell
        changed = True
    for field_id in list(merged):
        if field_id in incoming:
            continue
        field = _field_by_id(library, field_id)
        if _entry_allowed(actor, grants, library, "edit", created_by, current, field):
            del merged[field_id]
            changed = True
    if blocked and not changed:
        return None, "You cannot edit that field"
    return _merge_saved_files(library, current, merged), None


def _upsert_entry(con, item, device_id, device_name, actor=None, grants=None):
    row = con.execute("SELECT * FROM entries WHERE id = ?", (item["id"],)).fetchone()
    base_rev = int(item["base_rev"])
    grants = grants or []
    library = _library_by_id(con, row["library_id"] if row is not None else item["library_id"])
    if actor and not actor.get("is_admin"):
        if row is None:
            if not _entry_allowed(actor, grants, library, "create", None, item.get("values") or {}):
                return "forbidden", "You cannot create entries here"
        elif item.get("deleted") and not row["deleted"]:
            current = json.loads(row["values_json"])
            if not _entry_allowed(actor, grants, library, "erase", row["created_by"], current):
                return "forbidden", "You cannot erase this entry"
        elif not item.get("deleted"):
            current = json.loads(row["values_json"])
            if not _entry_allowed(actor, grants, library, "see", row["created_by"], current):
                return "forbidden", "You cannot see this entry"
            _, field_error = _merge_entry_values(row, item, actor, grants, library)
            if field_error:
                return "forbidden", field_error
    if row is not None and int(row["rev"]) != base_rev:
        projected = _project_entry(entry_out(row), actor, grants, library)
        return "conflict", projected or {"kind": "entry", "id": row["id"], "rev": int(row["rev"])}
    values, _ = _merge_entry_values(row, item, actor, grants, library)
    if values is None:
        values = item["values"]
    seq = bump(con)
    rev = 1 if row is None else int(row["rev"]) + 1
    deleted = 1 if item.get("deleted") else 0
    if row is None:
        created_by = actor["id"] if actor else (item.get("created_by") or device_id)
        con.execute(
            """
            INSERT INTO entries
                (id, library_id, values_json, rev, updated_at, deleted, change_seq, updated_by, updated_by_name, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                item["id"],
                item["library_id"],
                json.dumps(values),
                rev,
                item["updated_at"],
                deleted,
                seq,
                device_id,
                device_name,
                created_by,
            ),
        )
    else:
        con.execute(
            """
            UPDATE entries
               SET library_id = ?, values_json = ?, rev = ?, updated_at = ?, deleted = ?,
                   change_seq = ?, updated_by = ?, updated_by_name = ?
             WHERE id = ?
            """,
            (
                item["library_id"],
                json.dumps(values),
                rev,
                item["updated_at"],
                deleted,
                seq,
                device_id,
                device_name,
                item["id"],
            ),
        )
    return "accepted", rev


def _values_differ(row, item) -> bool:
    current = json.loads(row["values_json"])
    incoming = item.get("values") or {}
    keys = set(current) | set(incoming)
    return any(not _same_cell(current.get(key), incoming.get(key)) for key in keys)


def _library_by_id(con, library_id: str):
    row = con.execute("SELECT * FROM libraries WHERE id = ?", (library_id,)).fetchone()
    return library_out(row) if row else None


def _field_hidden(actor, grants, library_id: str, field_id: str) -> bool:
    specific = [
        grant
        for grant in grants
        if (grant["subject_type"], grant["subject_id"]) in _subjects(actor)
        and grant["library_id"] in (library_id, "*")
        and grant["target"] == "field"
        and (grant["field_id"] or "") == field_id
    ]
    if not specific:
        return False
    return all(_level(grant.get("see") or "none", "see") == "none" for grant in specific)


def _project_library(data: dict, actor, grants, con=None) -> dict | None:
    if actor is None:
        return data
    fake = {"id": data["id"], "created_by": data.get("created_by"), "access": data.get("access")}
    visible = _can_see_library(actor, grants, fake)
    if not visible and con is not None and not actor.get("is_admin"):
        for row in con.execute("SELECT * FROM entries WHERE library_id = ? AND deleted = 0", (data["id"],)):
            entry = entry_out(row)
            if _entry_allowed(actor, grants, data, "see", entry.get("created_by"), entry.get("values")):
                visible = True
                break
    if not visible:
        return None
    if not actor.get("is_admin"):
        data["fields"] = [
            field
            for field in data.get("fields") or []
            if not _field_hidden(actor, grants, data["id"], field.get("id") or "")
        ]
    return data


def _project_entry(data: dict, actor, grants, library=None) -> dict | None:
    if actor is None:
        return data
    values_in = data.get("values") or {}
    if not _entry_allowed(actor, grants, library, "see", data.get("created_by"), values_in):
        return None
    values = {}
    for field_id, cell in values_in.items():
        if actor.get("is_admin") or not _field_hidden(actor, grants, data["library_id"], field_id):
            values[field_id] = cell
    data["values"] = values
    return data


def _changes_since(con: sqlite3.Connection, cursor: int, actor=None, grants=None) -> tuple[list[dict], list[dict]]:
    grants = grants or []
    libs = [
        library_out(row)
        for row in con.execute("SELECT * FROM libraries WHERE change_seq > ? ORDER BY change_seq", (cursor,))
    ]
    entries = [
        entry_out(row)
        for row in con.execute("SELECT * FROM entries WHERE change_seq > ? ORDER BY change_seq", (cursor,))
    ]
    changes = libs + entries
    changes.sort(key=lambda item: item["change_seq"])
    if actor is None:
        return changes, []
    visible = []
    hidden = []
    seen_libraries = set()
    for change in changes:
        if change["kind"] == "library":
            projected = _project_library(dict(change), actor, grants, con)
        else:
            projected = _project_entry(dict(change), actor, grants, _library_by_id(con, change["library_id"]))
        if projected is None:
            hidden.append(change)
        else:
            visible.append(projected)
            if projected["kind"] == "library":
                seen_libraries.add(projected["id"])
    # A person added to "who can see" must receive the library even when that
    # library changed before their cursor. Otherwise the entry arrives alone
    # and the library list stays empty.
    extras = []
    for item in visible:
        if item.get("kind") != "entry" or item.get("library_id") in seen_libraries:
            continue
        library = _library_by_id(con, item["library_id"])
        if not library or library.get("deleted"):
            continue
        projected = _project_library(dict(library), actor, grants, con)
        if projected is None:
            continue
        extras.append(projected)
        seen_libraries.add(projected["id"])
    # Tasks already behind this phone's cursor stay invisible if they were
    # hidden on an earlier sync. Send the ones this person can see now.
    if actor is not None:
        seen_entries = {item["id"] for item in visible if item.get("kind") == "entry"}
        for row in con.execute(
            "SELECT * FROM entries WHERE deleted = 0 AND change_seq <= ? ORDER BY change_seq",
            (cursor,),
        ):
            entry = entry_out(row)
            if entry["id"] in seen_entries:
                continue
            library = _library_by_id(con, entry["library_id"])
            projected = _project_entry(dict(entry), actor, grants, library)
            if projected is None:
                continue
            visible.append(projected)
            seen_entries.add(projected["id"])
            if projected.get("library_id") in seen_libraries:
                continue
            if not library or library.get("deleted"):
                continue
            library_view = _project_library(dict(library), actor, grants, con)
            if library_view is None:
                continue
            extras.append(library_view)
            seen_libraries.add(library_view["id"])
    if extras:
        visible = extras + visible
    return visible, hidden


def _setting(con, key: str, default: str = "") -> str:
    row = con.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def _put_setting(con, key: str, value: str) -> None:
    con.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )


def backup_settings(con) -> dict:
    mode = _setting(con, "backup_mode", "off")
    if mode not in {"off", "hours", "accesses"}:
        mode = "off"
    try:
        every = max(1, int(_setting(con, "backup_every", "24")))
    except ValueError:
        every = 24
    return {"mode": mode, "every": every, "last_at": _setting(con, "backup_last", ""), "accesses": int(_setting(con, "backup_accesses", "0") or 0)}


def save_backup_settings(con, mode: str, every: int) -> dict:
    if mode not in {"off", "hours", "accesses"}:
        raise ValueError("Choose off, hours, or accesses")
    if every < 1:
        raise ValueError("Use a number of at least 1")
    _put_setting(con, "backup_mode", mode)
    _put_setting(con, "backup_every", str(int(every)))
    return backup_settings(con)


def _note_access(con) -> None:
    settings = backup_settings(con)
    count = settings["accesses"] + 1
    _put_setting(con, "backup_accesses", str(count))
    if settings["mode"] == "accesses" and count % settings["every"] == 0:
        _write_backup(con)


def maybe_backup_by_time(con) -> None:
    settings = backup_settings(con)
    if settings["mode"] != "hours":
        return
    last = settings["last_at"]
    if last:
        try:
            previous = time.strptime(last, "%Y-%m-%dT%H:%M:%SZ")
            elapsed = time.time() - time.mktime(previous)
        except ValueError:
            elapsed = settings["every"] * 3600
    else:
        elapsed = settings["every"] * 3600
    if elapsed >= settings["every"] * 3600:
        _write_backup(con)


def _write_backup(con) -> None:
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    folder = BACKUP_DIR / stamp
    folder.mkdir(parents=True, exist_ok=True)
    dest = sqlite3.connect(folder / "cloud.sqlite")
    try:
        con.backup(dest)
    finally:
        dest.close()
    if BLOB_DIR.exists():
        shutil.copytree(BLOB_DIR, folder / "blobs", dirs_exist_ok=True)
    _put_setting(con, "backup_last", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    _put_setting(con, "backup_accesses", "0")
    folders = sorted(path for path in BACKUP_DIR.iterdir() if path.is_dir())
    for old in folders[:-5]:
        shutil.rmtree(old, ignore_errors=True)


def _backup_loop() -> None:
    while True:
        time.sleep(60)
        try:
            with LOCK:
                con = connect()
                try:
                    maybe_backup_by_time(con)
                    con.commit()
                finally:
                    con.close()
        except Exception:
            continue


def _save_blob(con, actor, blob_id: str, name: str, mime: str, payload: bytes, entry_id: str, field_id: str) -> None:
    if not blob_id or not payload:
        raise ValueError("Missing file")
    if len(payload) > MAX_BLOB:
        raise ValueError("File is larger than 12 MB")
    BLOB_DIR.mkdir(parents=True, exist_ok=True)
    target = (BLOB_DIR / blob_id).resolve()
    if target.parent != BLOB_DIR.resolve():
        raise ValueError("Bad file id")
    target.write_bytes(payload)
    con.execute(
        """
        INSERT INTO blobs (id, entry_id, field_id, name, mime, size, created_by, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            entry_id = excluded.entry_id,
            field_id = excluded.field_id,
            name = excluded.name,
            mime = excluded.mime,
            size = excluded.size
        """,
        (blob_id, entry_id, field_id, name or "file", mime or "application/octet-stream", len(payload), actor["id"] if actor else "", _now()),
    )


def _blob_visible(con, actor, row) -> bool:
    if actor is None:
        return False
    if actor.get("is_admin") or row["created_by"] == actor["id"]:
        return True
    if not row["entry_id"]:
        return False
    entry = con.execute("SELECT * FROM entries WHERE id = ?", (row["entry_id"],)).fetchone()
    if entry is None:
        return False
    library = _library_by_id(con, entry["library_id"])
    grants = load_grants(con)
    values = json.loads(entry["values_json"])
    if not _entry_allowed(actor, grants, library, "see", entry["created_by"], values):
        return False
    return not _field_hidden(actor, grants, entry["library_id"], row["field_id"] or "")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:
        print("%s - %s" % (self.address_string(), fmt % args))

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/api/health":
            con = connect()
            try:
                needs_setup = con.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"] == 0
            finally:
                con.close()
            self._json(200, {"ok": True, "needs_setup": needs_setup})
            return
        if path == "/api/me":
            self._authed(self._me)
            return
        if path == "/api/directory":
            self._authed(self._directory, admin=True)
            return
        if path == "/api/grants":
            library_id = (parse_qs(parsed.query).get("library_id") or [""])[0]
            self._authed(lambda con, actor: self._grants(con, actor, library_id), admin=True)
            return
        if path == "/api/backup":
            self._authed(lambda con, actor: backup_settings(con), admin=True)
            return
        if path.startswith("/api/blobs/"):
            self._send_blob(path.removeprefix("/api/blobs/"))
            return
        if path in ("/", "/index.html"):
            self._file(ROOT / "static" / "index.html", "text/html; charset=utf-8")
            return
        if path == "/sw.js":
            self._file(STATIC / "sw.js", MIME[".js"])
            return
        if path.startswith("/static/"):
            target = (STATIC / path.removeprefix("/static/")).resolve()
            if not target.is_relative_to(STATIC.resolve()) or not target.is_file():
                self._json(404, {"error": "not found"})
                return
            self._file(target, MIME.get(target.suffix, "application/octet-stream"))
            return
        self._json(404, {"error": "not found"})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/blobs":
            self._post_blob()
            return
        body = self._read_json()
        if body is None:
            return
        routes = {
            "/api/setup": self._setup,
            "/api/login": self._login,
            "/api/logout": self._logout,
            "/api/users": self._add_user,
            "/api/users/update": self._update_user,
            "/api/users/remove": self._remove_user,
            "/api/account": self._account,
            "/api/groups": self._add_group,
            "/api/groups/members": self._set_members,
            "/api/groups/remove": self._remove_group,
            "/api/grants": self._save_grants,
            "/api/creators": self._save_creators,
            "/api/sync": self._sync,
            "/api/backup": self._save_backup,
        }
        handler = routes.get(path)
        if handler is None:
            self._json(404, {"error": "not found"})
            return
        self._authed_post(handler, body)

    def _me(self, con, actor):
        return {"user": {"id": actor["id"], "name": actor["name"], "is_admin": actor["is_admin"]}, "access": access_for(con, actor)}

    def _directory(self, con, actor):
        users = []
        for row in con.execute("SELECT * FROM users ORDER BY name"):
            users.append({
                "id": row["id"],
                "name": row["name"],
                "is_admin": bool(row["is_admin"]),
                "group_ids": _groups_for(con, row["id"]),
            })
        groups = []
        for row in con.execute("SELECT * FROM groups ORDER BY name"):
            members = [
                item["user_id"]
                for item in con.execute("SELECT user_id FROM group_members WHERE group_id = ?", (row["id"],))
            ]
            groups.append({"id": row["id"], "name": row["name"], "user_ids": members})
        creators = [
            {"subject_type": grant["subject_type"], "subject_id": grant["subject_id"]}
            for grant in load_grants(con)
            if grant["library_id"] == "*" and grant["target"] == "library" and grant["create"] == "all"
        ]
        return {"users": users, "groups": groups, "creators": creators}

    def _grants(self, con, actor, library_id):
        grants = [grant for grant in load_grants(con) if grant["library_id"] == library_id]
        return {"grants": grants}

    def _setup(self, con, actor, body):
        count = con.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
        if count:
            raise AuthzError("An admin already exists")
        user_id = create_user(con, body.get("name") or "", body.get("password") or "", True)
        row = con.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        token, person = open_session(con, row["name"], body.get("password") or "")
        return {"token": token, "user": {"id": person["id"], "name": person["name"], "is_admin": True}, "access": access_for(con, person)}

    def _login(self, con, actor, body):
        token, person = open_session(con, body.get("name") or "", body.get("password") or "")
        return {
            "token": token,
            "user": {"id": person["id"], "name": person["name"], "is_admin": person["is_admin"]},
            "access": access_for(con, person),
        }

    def _logout(self, con, actor, body):
        token = self._bearer()
        if token:
            token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
            con.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
        return {"ok": True}

    def _add_user(self, con, actor, body):
        self._admin(actor)
        user_id = create_user(con, body.get("name") or "", body.get("password") or "", bool(body.get("is_admin")))
        return {"id": user_id}

    def _update_user(self, con, actor, body):
        return update_user(con, actor, body)

    def _remove_user(self, con, actor, body):
        return remove_user(con, actor, body.get("id") or "")

    def _account(self, con, actor, body):
        user = update_account(con, actor, body)
        return {"user": user}

    def _add_group(self, con, actor, body):
        self._admin(actor)
        name = (body.get("name") or "").strip()
        if not name:
            raise ValueError("Name is required")
        group_id = str(uuid.uuid4())
        try:
            con.execute("INSERT INTO groups (id, name) VALUES (?, ?)", (group_id, name))
        except sqlite3.IntegrityError as exc:
            raise ValueError("That name is already used") from exc
        return {"id": group_id}

    def _set_members(self, con, actor, body):
        return update_group(con, actor, body)

    def _remove_group(self, con, actor, body):
        return remove_group(con, actor, body.get("group_id") or "")

    def _save_grants(self, con, actor, body):
        self._admin(actor)
        library_id = body.get("library_id") or ""
        if not library_id or library_id == "*":
            raise ValueError("Choose a library")
        replace_library_grants(con, library_id, body.get("grants") or [])
        return {"ok": True}

    def _save_creators(self, con, actor, body):
        self._admin(actor)
        set_library_creators(con, body.get("subjects") or [])
        return {"ok": True}

    def _save_backup(self, con, actor, body):
        self._admin(actor)
        return save_backup_settings(con, body.get("mode") or "off", int(body.get("every") or 1))

    def _post_blob(self) -> None:
        form = self._read_form()
        if not form or "file" not in form:
            self._json(400, {"error": "Missing file"})
            return
        with LOCK:
            con = connect()
            try:
                actor = actor_from_token(con, self._bearer())
                if actor is None:
                    raise PermissionError("Sign in first")
                def text(name):
                    return (form.get(name, {}).get("data") or b"").decode("utf-8", "replace")
                uploaded = form["file"]
                _save_blob(
                    con,
                    actor,
                    text("id"),
                    uploaded.get("filename") or text("name") or "file",
                    uploaded.get("type") or "application/octet-stream",
                    uploaded.get("data") or b"",
                    text("entry_id"),
                    text("field_id"),
                )
                con.commit()
            except PermissionError as exc:
                con.rollback()
                self._json(401, {"error": str(exc)})
                return
            except ValueError as exc:
                con.rollback()
                self._json(400, {"error": str(exc)})
                return
            finally:
                con.close()
        self._json(200, {"ok": True})

    def _send_blob(self, blob_id: str) -> None:
        with LOCK:
            con = connect()
            try:
                actor = actor_from_token(con, self._bearer())
                if actor is None:
                    self._json(401, {"error": "Sign in first"})
                    return
                row = con.execute("SELECT * FROM blobs WHERE id = ?", (blob_id,)).fetchone()
                if row is None or not _blob_visible(con, actor, row):
                    self._json(404, {"error": "not found"})
                    return
                target = (BLOB_DIR / blob_id).resolve()
                if target.parent != BLOB_DIR.resolve() or not target.is_file():
                    self._json(404, {"error": "not found"})
                    return
                data = target.read_bytes()
                mime = row["mime"] or "application/octet-stream"
                name = (row["name"] or "file").replace('"', "")
            finally:
                con.close()
        self.send_response(200)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Disposition", f'inline; filename="{name}"')
        self.send_header("Cache-Control", "private")
        self.end_headers()
        self.wfile.write(data)

    def _read_form(self):
        from email.parser import BytesParser
        from email.policy import default
        ctype = self.headers.get("Content-Type") or ""
        if "multipart/form-data" not in ctype.lower():
            return None
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        message = BytesParser(policy=default).parsebytes(
            f"Content-Type: {ctype}\r\nMIME-Version: 1.0\r\n\r\n".encode() + body
        )
        fields = {}
        for part in message.iter_parts():
            name = part.get_param("name", header="content-disposition")
            if not name:
                continue
            fields[name] = {
                "filename": part.get_filename(),
                "type": part.get_content_type(),
                "data": part.get_payload(decode=True) or b"",
            }
        return fields

    def _sync(self, con, actor, body):
        if actor is None:
            raise PermissionError("Sign in first")
        return apply_sync(con, body, actor)

    def _admin(self, actor):
        if not actor or not actor.get("is_admin"):
            raise AuthzError("Only an admin can do that")

    def _authed(self, fn, admin=False):
        with LOCK:
            con = connect()
            try:
                actor = actor_from_token(con, self._bearer())
                if actor is None:
                    raise PermissionError("Sign in first")
                if admin:
                    self._admin(actor)
                payload = fn(con, actor)
                con.commit()
            except PermissionError as exc:
                con.rollback()
                self._json(401, {"error": str(exc)})
                return
            except AuthzError as exc:
                con.rollback()
                self._json(403, {"error": str(exc)})
                return
            except ValueError as exc:
                con.rollback()
                self._json(400, {"error": str(exc)})
                return
            finally:
                con.close()
        self._json(200, payload)

    def _authed_post(self, fn, body):
        with LOCK:
            con = connect()
            try:
                actor = actor_from_token(con, self._bearer())
                if fn not in (self._setup, self._login) and actor is None and fn is not self._logout:
                    raise PermissionError("Sign in first")
                payload = fn(con, actor, body)
                con.commit()
            except PermissionError as exc:
                con.rollback()
                self._json(401, {"error": str(exc)})
                return
            except AuthzError as exc:
                con.rollback()
                self._json(403, {"error": str(exc)})
                return
            except (ValueError, TypeError) as exc:
                con.rollback()
                self._json(400, {"error": str(exc)})
                return
            finally:
                con.close()
        self._json(200, payload)

    def _bearer(self) -> str:
        header = self.headers.get("Authorization") or ""
        if header.lower().startswith("bearer "):
            return header[7:].strip()
        return ""

    def _read_json(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            return json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            self._json(400, {"error": "invalid json"})
            return None

    def _json(self, status: int, payload: dict) -> None:
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _file(self, path: Path, content_type: str) -> None:
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(data)


def main() -> None:
    init_db(DB_PATH)
    threading.Thread(target=_backup_loop, daemon=True).start()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"Cafineuos is running at http://{HOST}:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
