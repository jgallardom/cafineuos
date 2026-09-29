#!/usr/bin/env python3
"""Local sync target for Cafinewo.

Each device keeps its own copy and pushes dirty records with the revision
they were based on. The server accepts the write only when that revision is
still current. Otherwise it returns the server copy so the device can merge
or ask the user to resolve the conflict.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "static"
DB_PATH = ROOT / "cloud.sqlite"
HOST = "127.0.0.1"
PORT = 8765
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

        CREATE INDEX IF NOT EXISTS idx_libraries_seq ON libraries(change_seq);
        CREATE INDEX IF NOT EXISTS idx_entries_seq ON entries(change_seq);
        """
    )
    _ensure_column(con, "libraries", "created_by", "TEXT")
    _ensure_column(con, "entries", "created_by", "TEXT")
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
    return {"user_id": actor["id"], "is_admin": bool(actor["is_admin"]), "grants": grants}


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
    return entry_level in ("own", "all")


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
    return result


def _upsert_library(con, item, device_id, device_name, actor=None, grants=None):
    row = con.execute("SELECT * FROM libraries WHERE id = ?", (item["id"],)).fetchone()
    base_rev = int(item["base_rev"])
    grants = grants or []
    if actor and not actor.get("is_admin"):
        if row is None:
            if not _can(actor, grants, "*", "library", "create"):
                return "forbidden", "You cannot create libraries"
        elif item.get("deleted"):
            if not _can(actor, grants, row["id"], "library", "erase", row["created_by"]):
                return "forbidden", "You cannot erase this library"
        elif not _can(actor, grants, row["id"], "library", "edit", row["created_by"]):
            return "forbidden", "You cannot edit this library"
    if row is not None and int(row["rev"]) != base_rev:
        projected = _project_library(library_out(row), actor, grants)
        return "conflict", projected or {"kind": "library", "id": row["id"], "rev": int(row["rev"])}
    seq = bump(con)
    rev = 1 if row is None else int(row["rev"]) + 1
    fields = json.dumps(item["fields"])
    deleted = 1 if item.get("deleted") else 0
    if row is None:
        created_by = actor["id"] if actor else (item.get("created_by") or device_id)
        con.execute(
            """
            INSERT INTO libraries
                (id, name, fields_json, rev, updated_at, deleted, change_seq, updated_by, updated_by_name, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (item["id"], item["name"], fields, rev, item["updated_at"], deleted, seq, device_id, device_name, created_by),
        )
        if actor and not actor.get("is_admin"):
            _creator_grants(con, actor["id"], item["id"])
    else:
        con.execute(
            """
            UPDATE libraries
               SET name = ?, fields_json = ?, rev = ?, updated_at = ?, deleted = ?,
                   change_seq = ?, updated_by = ?, updated_by_name = ?
             WHERE id = ?
            """,
            (item["name"], fields, rev, item["updated_at"], deleted, seq, device_id, device_name, item["id"]),
        )
    return "accepted", rev


def _merge_entry_values(row, item, actor, grants):
    current = json.loads(row["values_json"]) if row is not None else {}
    incoming = item.get("values") or {}
    if actor is None or actor.get("is_admin") or row is None:
        return incoming, None
    merged = dict(current)
    created_by = row["created_by"]
    library_id = row["library_id"]
    for field_id, cell in incoming.items():
        previous = current.get(field_id)
        if _same_cell(previous, cell):
            merged[field_id] = previous if previous is not None else cell
            continue
        if not _can(actor, grants, library_id, "field", "edit", created_by, field_id):
            return None, "You cannot edit that field"
        merged[field_id] = cell
    for field_id in list(merged):
        if field_id in incoming:
            continue
        if _can(actor, grants, library_id, "field", "edit", created_by, field_id):
            del merged[field_id]
    return merged, None


def _upsert_entry(con, item, device_id, device_name, actor=None, grants=None):
    row = con.execute("SELECT * FROM entries WHERE id = ?", (item["id"],)).fetchone()
    base_rev = int(item["base_rev"])
    grants = grants or []
    if actor and not actor.get("is_admin"):
        if row is None:
            if not _can(actor, grants, item["library_id"], "entry", "create"):
                return "forbidden", "You cannot create entries here"
        elif item.get("deleted") and not row["deleted"]:
            if not _can(actor, grants, row["library_id"], "entry", "erase", row["created_by"]):
                return "forbidden", "You cannot erase this entry"
        elif not item.get("deleted"):
            if not _can(actor, grants, row["library_id"], "entry", "see", row["created_by"]):
                return "forbidden", "You cannot see this entry"
            _, field_error = _merge_entry_values(row, item, actor, grants)
            if field_error:
                return "forbidden", field_error
    if row is not None and int(row["rev"]) != base_rev:
        projected = _project_entry(entry_out(row), actor, grants)
        return "conflict", projected or {"kind": "entry", "id": row["id"], "rev": int(row["rev"])}
    values, _ = _merge_entry_values(row, item, actor, grants)
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


def _project_library(data: dict, actor, grants) -> dict | None:
    if actor is None:
        return data
    fake = {"id": data["id"], "created_by": data.get("created_by")}
    if not _can_see_library(actor, grants, fake):
        return None
    if not _can(actor, grants, data["id"], "library", "edit", data.get("created_by")):
        data["fields"] = [
            field
            for field in data.get("fields") or []
            if _field_level(actor, grants, data["id"], field["id"], "see", _best_level(actor, grants, data["id"], "entry", "see")) != "none"
        ]
    return data


def _project_entry(data: dict, actor, grants) -> dict | None:
    if actor is None:
        return data
    if not _can(actor, grants, data["library_id"], "entry", "see", data.get("created_by")):
        return None
    entry_see = _best_level(actor, grants, data["library_id"], "entry", "see")
    values = {}
    for field_id, cell in (data.get("values") or {}).items():
        if _allows(_field_level(actor, grants, data["library_id"], field_id, "see", entry_see), data.get("created_by"), actor["id"], "see"):
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
    for change in changes:
        projected = _project_library(dict(change), actor, grants) if change["kind"] == "library" else _project_entry(dict(change), actor, grants)
        if projected is None:
            hidden.append(change)
        else:
            visible.append(projected)
    return visible, hidden


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
        body = self._read_json()
        if body is None:
            return
        routes = {
            "/api/setup": self._setup,
            "/api/login": self._login,
            "/api/logout": self._logout,
            "/api/users": self._add_user,
            "/api/users/update": self._update_user,
            "/api/groups": self._add_group,
            "/api/groups/members": self._set_members,
            "/api/grants": self._save_grants,
            "/api/creators": self._save_creators,
            "/api/sync": self._sync,
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
        self._admin(actor)
        row = con.execute("SELECT * FROM users WHERE id = ?", (body.get("id"),)).fetchone()
        if row is None:
            raise ValueError("User not found")
        is_admin = bool(body.get("is_admin"))
        if row["is_admin"] and not is_admin:
            others = con.execute("SELECT COUNT(*) AS n FROM users WHERE is_admin = 1 AND id != ?", (row["id"],)).fetchone()["n"]
            if others == 0:
                raise ValueError("Keep at least one admin")
        if body.get("password"):
            if len(body["password"]) < 4:
                raise ValueError("Password must be at least 4 characters")
            salt, digest = hash_password(body["password"])
            con.execute(
                "UPDATE users SET is_admin = ?, password_hash = ?, password_salt = ? WHERE id = ?",
                (1 if is_admin else 0, digest, salt, row["id"]),
            )
        else:
            con.execute("UPDATE users SET is_admin = ? WHERE id = ?", (1 if is_admin else 0, row["id"]))
        return {"ok": True}

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
        self._admin(actor)
        group_id = body.get("group_id")
        if con.execute("SELECT 1 FROM groups WHERE id = ?", (group_id,)).fetchone() is None:
            raise ValueError("Group not found")
        con.execute("DELETE FROM group_members WHERE group_id = ?", (group_id,))
        for user_id in body.get("user_ids") or []:
            if con.execute("SELECT 1 FROM users WHERE id = ?", (user_id,)).fetchone() is None:
                raise ValueError("User not found")
            con.execute("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)", (group_id, user_id))
        return {"ok": True}

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
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"Cafinewo is running at http://{HOST}:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
