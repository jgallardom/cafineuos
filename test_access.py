"""Users, groups, and library permissions."""

import json
import tempfile
import unittest
from pathlib import Path

import server


def cell(value, stamp="t0"):
    return {"v": value, "t": stamp}


class AccessTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.con = server.init_db(Path(self.tmp.name) / "cloud.sqlite")
        self.admin = self.person("Ada", "admin-pass", True)
        self.ana = self.person("Ana", "ana-pass", False)
        self.bo = self.person("Bo", "bo-pass", False)

    def tearDown(self):
        self.con.close()
        self.tmp.cleanup()

    def person(self, name, password, is_admin):
        user_id = server.create_user(self.con, name, password, is_admin)
        row = self.con.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return server._actor_from_row(self.con, row)

    def sync(self, actor, body):
        result = server.apply_sync(self.con, body, actor)
        self.con.commit()
        return result

    def grant(self, library_id, grants):
        server.replace_library_grants(self.con, library_id, grants)
        self.con.commit()

    def entry_grant(self, user, see, edit="none", create="none", erase="none"):
        return {
            "subject_type": "user",
            "subject_id": user["id"],
            "target": "entry",
            "see": see,
            "edit": edit,
            "create": create,
            "erase": erase,
        }

    def test_user_sees_only_entries_they_created(self):
        self.sync(self.admin, {
            "cursor": 0,
            "libraries": [{
                "id": "lib1",
                "name": "Visits",
                "fields": [{"id": "f1", "name": "Site", "type": "text"}, {"id": "notes", "name": "Notes", "type": "text"}],
                "base_rev": 0,
                "updated_at": "2026-09-28T00:00:00Z",
            }],
            "entries": [],
        })
        self.grant("lib1", [
            self.entry_grant(self.ana, "own", "own", "all", "own"),
            {"subject_type": "user", "subject_id": self.ana["id"], "target": "library", "see": "all"},
        ])
        self.sync(self.admin, {
            "cursor": 0,
            "entries": [{
                "id": "admin-entry",
                "library_id": "lib1",
                "values": {"f1": cell("Office")},
                "base_rev": 0,
                "updated_at": "2026-09-28T00:01:00Z",
            }],
        })
        ana = self.sync(self.ana, {
            "cursor": 0,
            "entries": [{
                "id": "ana-entry",
                "library_id": "lib1",
                "values": {"f1": cell("Pier")},
                "base_rev": 0,
                "updated_at": "2026-09-28T00:02:00Z",
            }],
        })
        visible = {item["id"] for item in ana["changes"] if item["kind"] == "entry"}
        hidden = {item["id"] for item in ana["hidden"] if item["kind"] == "entry"}
        self.assertIn("ana-entry", visible)
        self.assertNotIn("admin-entry", visible)
        self.assertIn("admin-entry", hidden)
        blocked = self.sync(self.ana, {
            "cursor": ana["cursor"],
            "entries": [{
                "id": "admin-entry",
                "library_id": "lib1",
                "values": {"f1": cell("Stolen")},
                "base_rev": 1,
                "updated_at": "2026-09-28T00:03:00Z",
            }],
        })
        self.assertEqual(blocked["accepted"], [])
        self.assertEqual(blocked["forbidden"][0]["error"], "You cannot see this entry")

    def test_group_grant_lets_members_see_every_entry(self):
        self.con.execute("INSERT INTO groups (id, name) VALUES ('g1', 'Field')")
        self.con.execute("INSERT INTO group_members (group_id, user_id) VALUES ('g1', ?)", (self.bo["id"],))
        self.con.commit()
        self.bo = self.person_existing(self.bo["id"])
        self.sync(self.admin, {
            "cursor": 0,
            "libraries": [{
                "id": "lib1",
                "name": "Visits",
                "fields": [{"id": "f1", "name": "Site", "type": "text"}],
                "base_rev": 0,
                "updated_at": "2026-09-28T00:00:00Z",
            }],
            "entries": [{
                "id": "e1",
                "library_id": "lib1",
                "values": {"f1": cell("Pier")},
                "base_rev": 0,
                "updated_at": "2026-09-28T00:00:01Z",
            }],
        })
        self.grant("lib1", [{
            "subject_type": "group",
            "subject_id": "g1",
            "target": "library",
            "see": "all",
        }, {
            "subject_type": "group",
            "subject_id": "g1",
            "target": "entry",
            "see": "all",
            "edit": "own",
            "create": "all",
            "erase": "own",
        }])
        pulled = self.sync(self.bo, {"cursor": 0, "libraries": [], "entries": []})
        ids = {item["id"] for item in pulled["changes"] if item["kind"] == "entry"}
        self.assertIn("e1", ids)

    def test_field_grant_blocks_one_field_and_erase_is_own(self):
        self.sync(self.admin, {
            "cursor": 0,
            "libraries": [{
                "id": "lib1",
                "name": "Visits",
                "fields": [{"id": "f1", "name": "Site", "type": "text"}, {"id": "notes", "name": "Notes", "type": "text"}],
                "base_rev": 0,
                "updated_at": "2026-09-28T00:00:00Z",
            }],
            "entries": [],
        })
        self.grant("lib1", [
            self.entry_grant(self.ana, "all", "all", "all", "own"),
            {"subject_type": "user", "subject_id": self.ana["id"], "target": "library", "see": "all"},
            {
                "subject_type": "user",
                "subject_id": self.ana["id"],
                "target": "field",
                "field_id": "notes",
                "see": "none",
                "edit": "none",
            },
        ])
        created = self.sync(self.admin, {
            "cursor": 0,
            "entries": [{
                "id": "e1",
                "library_id": "lib1",
                "values": {"f1": cell("Pier"), "notes": cell("secret")},
                "base_rev": 0,
                "updated_at": "2026-09-28T00:01:00Z",
            }],
        })
        pulled = self.sync(self.ana, {"cursor": 0, "entries": []})
        entry = next(item for item in pulled["changes"] if item["id"] == "e1")
        self.assertNotIn("notes", entry["values"])
        self.assertEqual(entry["values"]["f1"]["v"], "Pier")
        edited = self.sync(self.ana, {
            "cursor": pulled["cursor"],
            "entries": [{
                "id": "e1",
                "library_id": "lib1",
                "values": {"f1": cell("Pier north"), "notes": cell("nope")},
                "base_rev": 1,
                "updated_at": "2026-09-28T00:02:00Z",
            }],
        })
        self.assertTrue(edited["accepted"])
        self.assertEqual(edited["forbidden"], [])
        stored = self.con.execute("SELECT values_json FROM entries WHERE id = 'e1'").fetchone()[0]
        self.assertIn("secret", stored)
        self.assertIn("Pier north", stored)
        erased = self.sync(self.ana, {
            "cursor": edited["cursor"],
            "entries": [{
                "id": "e1",
                "library_id": "lib1",
                "values": {"f1": cell("Pier north")},
                "base_rev": edited["accepted"][0]["rev"],
                "deleted": True,
                "updated_at": "2026-09-28T00:04:00Z",
            }],
        })
        self.assertEqual(erased["forbidden"][0]["error"], "You cannot erase this entry")

    def test_non_admin_cannot_create_a_library_until_allowed(self):
        blocked = self.sync(self.ana, {
            "cursor": 0,
            "libraries": [{
                "id": "lib2",
                "name": "Mine",
                "fields": [{"id": "f1", "name": "Site", "type": "text"}],
                "base_rev": 0,
                "updated_at": "2026-09-28T00:00:00Z",
            }],
        })
        self.assertEqual(blocked["forbidden"][0]["error"], "Only an admin can change libraries")
        server.set_library_creators(self.con, [{"subject_type": "user", "subject_id": self.ana["id"]}])
        self.con.commit()
        created = self.sync(self.ana, {
            "cursor": 0,
            "libraries": [{
                "id": "lib2",
                "name": "Mine",
                "fields": [{"id": "f1", "name": "Site", "type": "text"}],
                "base_rev": 0,
                "updated_at": "2026-09-28T00:00:00Z",
            }],
        })
        self.assertEqual(created["forbidden"][0]["error"], "Only an admin can change libraries")

    def test_viewers_and_library_lists(self):
        self.sync(self.admin, {
            "cursor": 0,
            "libraries": [{
                "id": "tasks",
                "name": "Tasks",
                "fields": [
                    {"id": "title", "name": "Title", "type": "text", "viewer_edit": True},
                    {"id": "see", "name": "Who can see", "type": "users", "role": "viewers"},
                    {"id": "edit", "name": "Who can modify", "type": "users", "role": "editors"},
                ],
                "access": {
                    "create": {"mode": "list", "users": [self.ana["id"]]},
                    "edit": {"mode": "none", "users": []},
                    "erase": {"mode": "list", "users": [self.bo["id"]]},
                },
                "base_rev": 0,
                "updated_at": "2026-09-28T00:00:00Z",
            }],
        })
        blocked = self.sync(self.bo, {
            "cursor": 0,
            "entries": [{
                "id": "task1",
                "library_id": "tasks",
                "values": {"title": cell("Gate"), "see": cell([self.bo["id"]])},
                "base_rev": 0,
                "updated_at": "2026-09-28T00:01:00Z",
            }],
        })
        self.assertEqual(blocked["forbidden"][0]["error"], "You cannot create entries here")
        made = self.sync(self.ana, {
            "cursor": 0,
            "entries": [{
                "id": "task1",
                "library_id": "tasks",
                "values": {
                    "title": cell("Gate"),
                    "see": cell([self.bo["id"]]),
                    "edit": cell([self.bo["id"]]),
                },
                "base_rev": 0,
                "updated_at": "2026-09-28T00:02:00Z",
            }],
        })
        self.assertTrue(made["accepted"])
        rev = made["accepted"][0]["rev"]
        hidden = self.sync(self.bo, {"cursor": 0, "entries": []})
        visible = next(item for item in hidden["changes"] if item["id"] == "task1")
        self.assertEqual(visible["values"]["title"]["v"], "Gate")
        outsider = self.sync(self.person("Cia", "cia-pass", False), {"cursor": 0, "entries": []})
        self.assertNotIn("task1", {item["id"] for item in outsider["changes"] if item["kind"] == "entry"})
        edited = self.sync(self.bo, {
            "cursor": hidden["cursor"],
            "entries": [{
                "id": "task1",
                "library_id": "tasks",
                "values": {"title": cell("Gate today"), "see": cell([self.bo["id"]]), "edit": cell([self.bo["id"]])},
                "base_rev": rev,
                "updated_at": "2026-09-28T00:03:00Z",
            }],
        })
        self.assertTrue(edited["accepted"])

    def test_viewer_can_save_an_open_field_when_another_field_is_locked(self):
        self.sync(self.admin, {
            "cursor": 0,
            "libraries": [{
                "id": "tasks",
                "name": "Tasks",
                "fields": [
                    {"id": "title", "name": "Title", "type": "text"},
                    {"id": "see", "name": "Who can see", "type": "users", "role": "viewers"},
                    {"id": "done", "name": "Done", "type": "boolean", "viewer_edit": True},
                    {"id": "notes", "name": "Notes", "type": "text"},
                ],
                "access": {
                    "create": {"mode": "none", "users": []},
                    "edit": {"mode": "none", "users": []},
                    "erase": {"mode": "none", "users": []},
                },
                "base_rev": 0,
                "updated_at": "2026-09-28T00:00:00Z",
            }],
            "entries": [{
                "id": "task1",
                "library_id": "tasks",
                "values": {
                    "title": cell("Gate"),
                    "see": cell([self.bo["id"]]),
                    "done": cell(False),
                    "notes": cell("Keep"),
                },
                "base_rev": 0,
                "updated_at": "2026-09-28T00:02:00Z",
            }],
        })
        seen = self.sync(self.bo, {"cursor": 0})
        rev = next(item["rev"] for item in seen["changes"] if item["id"] == "task1")
        saved = self.sync(self.bo, {
            "cursor": seen["cursor"],
            "entries": [{
                "id": "task1",
                "library_id": "tasks",
                "values": {
                    "title": cell("Changed title"),
                    "see": cell([self.bo["id"]]),
                    "done": cell(True),
                    "notes": cell("Changed notes"),
                },
                "base_rev": rev,
                "updated_at": "2026-09-28T00:03:00Z",
            }],
        })
        self.assertTrue(saved["accepted"])
        self.assertEqual(saved["forbidden"], [])
        row = self.con.execute("SELECT values_json FROM entries WHERE id = 'task1'").fetchone()
        values = json.loads(row["values_json"])
        self.assertTrue(values["done"]["v"])
        self.assertEqual(values["notes"]["v"], "Keep")
        self.assertEqual(values["title"]["v"], "Gate")

    def test_creator_keeps_people_fields_when_a_later_save_clears_them(self):
        self.sync(self.admin, {
            "cursor": 0,
            "libraries": [{
                "id": "tasks",
                "name": "Tasks",
                "fields": [
                    {"id": "title", "name": "Title", "type": "text"},
                    {"id": "encargado", "name": "Encargado", "type": "users", "role": "viewers"},
                    {"id": "creado", "name": "Creado por", "type": "users"},
                    {"id": "done", "name": "Done", "type": "boolean", "viewer_edit": True},
                ],
                "access": {
                    "create": {"mode": "list", "users": [self.ana["id"]]},
                    "edit": {"mode": "none", "users": []},
                    "erase": {"mode": "none", "users": []},
                },
                "base_rev": 0,
                "updated_at": "2026-09-28T00:00:00Z",
            }],
        })
        made = self.sync(self.ana, {
            "cursor": 0,
            "entries": [{
                "id": "task1",
                "library_id": "tasks",
                "values": {
                    "title": cell("Gate"),
                    "encargado": cell([self.bo["id"]]),
                    "creado": cell([self.ana["id"]]),
                    "done": cell(False),
                },
                "base_rev": 0,
                "updated_at": "2026-09-28T00:02:00Z",
            }],
        })
        self.assertTrue(made["accepted"])
        cleared = self.sync(self.ana, {
            "cursor": made["cursor"],
            "entries": [{
                "id": "task1",
                "library_id": "tasks",
                "values": {
                    "title": cell("Gate"),
                    "encargado": cell([]),
                    "creado": cell([]),
                    "done": cell(True),
                },
                "base_rev": made["accepted"][0]["rev"],
                "updated_at": "2026-09-28T00:03:00Z",
            }],
        })
        self.assertTrue(cleared["accepted"])
        values = json.loads(self.con.execute("SELECT values_json FROM entries WHERE id = 'task1'").fetchone()["values_json"])
        self.assertEqual(values["encargado"]["v"], [self.bo["id"]])
        self.assertEqual(values["creado"]["v"], [self.ana["id"]])
        self.assertTrue(values["done"]["v"])

    def test_viewer_added_later_still_receives_the_library(self):
        self.sync(self.admin, {
            "cursor": 0,
            "libraries": [{
                "id": "tasks",
                "name": "Tasks",
                "fields": [
                    {"id": "title", "name": "Title", "type": "text"},
                    {"id": "see", "name": "Who can see", "type": "users", "role": "viewers"},
                ],
                "access": {
                    "create": {"mode": "none", "users": []},
                    "edit": {"mode": "none", "users": []},
                    "erase": {"mode": "none", "users": []},
                },
                "base_rev": 0,
                "updated_at": "2026-09-28T00:00:00Z",
            }],
        })
        first = self.sync(self.bo, {"cursor": 0})
        self.assertNotIn("tasks", {item["id"] for item in first["changes"]})
        self.assertIn("tasks", {item["id"] for item in first["hidden"]})
        made = self.sync(self.admin, {
            "cursor": first["cursor"],
            "entries": [{
                "id": "task1",
                "library_id": "tasks",
                "values": {"title": cell("Gate"), "see": cell([self.bo["id"]])},
                "base_rev": 0,
                "updated_at": "2026-09-28T00:02:00Z",
            }],
        })
        self.assertTrue(made["accepted"])
        second = self.sync(self.bo, {"cursor": first["cursor"]})
        ids = {item["id"] for item in second["changes"]}
        self.assertIn("task1", ids)
        self.assertIn("tasks", ids)

    def test_encargado_sees_tasks_already_behind_the_cursor(self):
        self.sync(self.admin, {
            "cursor": 0,
            "libraries": [{
                "id": "tasks",
                "name": "Tasks",
                "fields": [
                    {"id": "title", "name": "Title", "type": "text"},
                    {"id": "encargado", "name": "Encargado", "type": "users", "role": "editors"},
                ],
                "access": {
                    "create": {"mode": "list", "users": [self.bo["id"]]},
                    "edit": {"mode": "none", "users": []},
                    "erase": {"mode": "none", "users": []},
                },
                "base_rev": 0,
                "updated_at": "2026-09-28T00:00:00Z",
            }],
        })
        made = self.sync(self.admin, {
            "cursor": 0,
            "entries": [{
                "id": "task1",
                "library_id": "tasks",
                "values": {"title": cell("Gate"), "encargado": cell([self.bo["id"]])},
                "base_rev": 0,
                "updated_at": "2026-09-28T00:02:00Z",
            }],
        })
        self.assertTrue(made["accepted"])
        first = self.sync(self.bo, {"cursor": 0})
        self.assertNotIn("task1", {item["id"] for item in first["changes"] if item["kind"] == "entry" and not item.get("deleted")})
        self.con.execute(
            "UPDATE libraries SET fields_json = ? WHERE id = 'tasks'",
            (json.dumps([
                {"id": "title", "name": "Title", "type": "text"},
                {"id": "encargado", "name": "Encargado", "type": "users", "role": "viewers"},
            ]),),
        )
        self.con.commit()
        second = self.sync(self.bo, {"cursor": first["cursor"]})
        ids = {item["id"] for item in second["changes"]}
        self.assertIn("task1", ids)
        self.assertIn("tasks", ids)
        task = next(item for item in second["changes"] if item["id"] == "task1")
        self.assertEqual(task["values"]["title"]["v"], "Gate")

    def test_people_field_shares_the_entry_when_no_viewers_role_is_set(self):
        self.sync(self.admin, {
            "cursor": 0,
            "libraries": [{
                "id": "tasks",
                "name": "Tasks",
                "fields": [
                    {"id": "title", "name": "Title", "type": "text"},
                    {"id": "encargado", "name": "Encargado", "type": "users"},
                ],
                "access": {
                    "create": {"mode": "all", "users": []},
                    "edit": {"mode": "none", "users": []},
                    "erase": {"mode": "none", "users": []},
                },
                "base_rev": 0,
                "updated_at": "2026-09-28T00:00:00Z",
            }],
            "entries": [{
                "id": "task1",
                "library_id": "tasks",
                "values": {"title": cell("Gate"), "encargado": cell([self.bo["id"]])},
                "base_rev": 0,
                "updated_at": "2026-09-28T00:02:00Z",
            }],
        })
        seen = self.sync(self.bo, {"cursor": 0})
        self.assertIn("task1", {item["id"] for item in seen["changes"] if item["kind"] == "entry"})
        outsider = self.sync(self.person("Cia", "cia-pass", False), {"cursor": 0})
        self.assertNotIn("task1", {item["id"] for item in outsider["changes"] if item["kind"] == "entry"})

    def person_existing(self, user_id):
        row = self.con.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return server._actor_from_row(self.con, row)


    def test_admin_can_rename_and_remove_people_and_groups(self):
        self.con.execute("INSERT INTO groups (id, name) VALUES ('g-bo', 'Crew')")
        self.con.commit()
        renamed = server.update_user(self.con, self.admin, {"id": self.bo["id"], "name": "Pocho", "is_admin": False, "group_ids": ["g-bo"]})
        self.con.commit()
        self.assertEqual(renamed["name"], "Pocho")
        self.assertEqual(self.con.execute("SELECT name FROM users WHERE id = ?", (self.bo["id"],)).fetchone()["name"], "Pocho")
        self.assertEqual(self.con.execute("SELECT group_id FROM group_members WHERE user_id = ?", (self.bo["id"],)).fetchone()["group_id"], "g-bo")
        account = server.update_account(self.con, self.ana, {"name": "Ana Maria", "password": "ana-new"})
        self.con.commit()
        self.assertEqual(account["name"], "Ana Maria")
        server.open_session(self.con, "Ana Maria", "ana-new")
        with self.assertRaises(ValueError):
            server.remove_user(self.con, self.admin, self.admin["id"])
        server.remove_user(self.con, self.admin, self.bo["id"])
        self.con.commit()
        self.assertIsNone(self.con.execute("SELECT 1 FROM users WHERE id = ?", (self.bo["id"],)).fetchone())
        server.update_group(self.con, self.admin, {"group_id": "g-bo", "name": "Field crew", "user_ids": [self.ana["id"]]})
        self.con.commit()
        self.assertEqual(self.con.execute("SELECT name FROM groups WHERE id = 'g-bo'").fetchone()["name"], "Field crew")
        self.assertEqual(self.con.execute("SELECT user_id FROM group_members WHERE group_id = 'g-bo'").fetchone()["user_id"], self.ana["id"])
        server.remove_group(self.con, self.admin, "g-bo")
        self.con.commit()
        self.assertIsNone(self.con.execute("SELECT 1 FROM groups WHERE id = 'g-bo'").fetchone())


    def test_a_new_file_is_added_beside_the_file_already_there(self):
        made = self.sync(self.admin, {
            "cursor": 0,
            "libraries": [{
                "id": "tasks",
                "name": "Tasks",
                "fields": [
                    {"id": "title", "name": "Title", "type": "text"},
                    {"id": "archivo", "name": "Archivo", "type": "file"},
                ],
                "base_rev": 0,
                "updated_at": "2026-09-28T00:00:00Z",
            }],
            "entries": [{
                "id": "task1",
                "library_id": "tasks",
                "values": {
                    "title": cell("Gate"),
                    "archivo": cell({"id": "file-a", "name": "one.pdf"}),
                },
                "base_rev": 0,
                "updated_at": "2026-09-28T00:02:00Z",
            }],
        })
        rev = next(item["rev"] for item in made["accepted"] if item["id"] == "task1")
        self.sync(self.admin, {
            "cursor": made["cursor"],
            "entries": [{
                "id": "task1",
                "library_id": "tasks",
                "values": {
                    "title": cell("Gate"),
                    "archivo": cell({"id": "file-b", "name": "two.pdf"}),
                },
                "base_rev": rev,
                "updated_at": "2026-09-28T00:03:00Z",
            }],
        })
        values = json.loads(self.con.execute("SELECT values_json FROM entries WHERE id = 'task1'").fetchone()["values_json"])
        self.assertEqual([item["id"] for item in values["archivo"]["v"]], ["file-a", "file-b"])

    def test_viewer_can_download_a_file_on_an_entry_they_can_see(self):
        self.sync(self.admin, {
            "cursor": 0,
            "libraries": [{
                "id": "tasks",
                "name": "Tasks",
                "fields": [
                    {"id": "title", "name": "Title", "type": "text"},
                    {"id": "see", "name": "Encargado", "type": "users", "role": "viewers"},
                    {"id": "photo", "name": "Photo", "type": "image"},
                ],
                "access": {
                    "create": {"mode": "none", "users": []},
                    "edit": {"mode": "none", "users": []},
                    "erase": {"mode": "none", "users": []},
                },
                "base_rev": 0,
                "updated_at": "2026-09-28T00:00:00Z",
            }],
            "entries": [{
                "id": "task1",
                "library_id": "tasks",
                "values": {
                    "title": cell("Gate"),
                    "see": cell([self.ana["id"]]),
                    "photo": cell({"id": "blob1", "name": "gate.jpg"}),
                },
                "base_rev": 0,
                "updated_at": "2026-09-28T00:02:00Z",
            }],
        })
        self.con.execute(
            "INSERT INTO blobs (id, entry_id, field_id, name, mime, size, created_by, created_at) VALUES ('blob1', 'task1', 'photo', 'gate.jpg', 'image/jpeg', 4, ?, 't')",
            (self.admin["id"],),
        )
        self.con.commit()
        row = self.con.execute("SELECT * FROM blobs WHERE id = 'blob1'").fetchone()
        self.assertTrue(server._blob_visible(self.con, self.ana, row))
        outsider = self.person("Cia", "cia-pass", False)
        self.assertFalse(server._blob_visible(self.con, outsider, row))


if __name__ == "__main__":
    unittest.main()
