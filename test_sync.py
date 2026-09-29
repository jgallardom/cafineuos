"""Sync rules: a write lands only when it is based on the current revision."""

import tempfile
import unittest
from pathlib import Path

import server


def cell(value, stamp="t0"):
    return {"v": value, "t": stamp}


class SyncTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "cloud.sqlite"
        self.con = server.init_db(self.db)

    def tearDown(self):
        self.con.close()
        self.tmp.cleanup()

    def sync(self, body):
        result = server.apply_sync(self.con, body)
        self.con.commit()
        return result

    def test_create_then_stale_update_conflicts(self):
        created = self.sync(
            {
                "device_id": "phone",
                "device_name": "Field phone",
                "cursor": 0,
                "libraries": [
                    {
                        "id": "lib1",
                        "name": "Site visits",
                        "fields": [{"id": "f1", "name": "Site", "type": "text"}],
                        "base_rev": 0,
                        "updated_at": "2026-09-28T00:00:00Z",
                    }
                ],
                "entries": [
                    {
                        "id": "e1",
                        "library_id": "lib1",
                        "values": {"f1": cell("Pier")},
                        "base_rev": 0,
                        "updated_at": "2026-09-28T00:00:01Z",
                    }
                ],
            }
        )
        self.assertEqual(created["accepted"], [
            {"kind": "library", "id": "lib1", "rev": 1},
            {"kind": "entry", "id": "e1", "rev": 1},
        ])
        self.assertEqual(created["conflicts"], [])

        office = self.sync(
            {
                "device_id": "office",
                "device_name": "Office",
                "cursor": 0,
                "libraries": [],
                "entries": [
                    {
                        "id": "e1",
                        "library_id": "lib1",
                        "values": {"f1": cell("Pier north", "t1")},
                        "base_rev": 1,
                        "updated_at": "2026-09-28T00:01:00Z",
                    }
                ],
            }
        )
        self.assertEqual(office["accepted"][0]["rev"], 2)

        stale = self.sync(
            {
                "device_id": "phone",
                "device_name": "Field phone",
                "cursor": created["cursor"],
                "libraries": [],
                "entries": [
                    {
                        "id": "e1",
                        "library_id": "lib1",
                        "values": {"f1": cell("Pier south", "t2")},
                        "base_rev": 1,
                        "updated_at": "2026-09-28T00:02:00Z",
                    }
                ],
            }
        )
        self.assertEqual(stale["accepted"], [])
        self.assertEqual(stale["conflicts"][0]["server"]["rev"], 2)
        self.assertEqual(stale["conflicts"][0]["server"]["values"]["f1"]["v"], "Pier north")
        self.assertEqual(stale["conflicts"][0]["server"]["updated_by_name"], "Office")

    def test_pull_returns_only_newer_changes(self):
        first = self.sync(
            {
                "device_id": "phone",
                "device_name": "Field phone",
                "cursor": 0,
                "libraries": [
                    {
                        "id": "lib1",
                        "name": "Notes",
                        "fields": [],
                        "base_rev": 0,
                        "updated_at": "2026-09-28T00:00:00Z",
                    }
                ],
                "entries": [],
            }
        )
        second = self.sync(
            {
                "device_id": "phone",
                "device_name": "Field phone",
                "cursor": first["cursor"],
                "libraries": [],
                "entries": [
                    {
                        "id": "e1",
                        "library_id": "lib1",
                        "values": {},
                        "base_rev": 0,
                        "updated_at": "2026-09-28T00:03:00Z",
                    }
                ],
            }
        )
        kinds = [change["kind"] for change in second["changes"]]
        self.assertEqual(kinds, ["entry"])
        self.assertGreater(second["cursor"], first["cursor"])

    def test_delete_is_a_tombstone_other_devices_can_pull(self):
        self.sync(
            {
                "device_id": "phone",
                "device_name": "Field phone",
                "cursor": 0,
                "libraries": [],
                "entries": [
                    {
                        "id": "e1",
                        "library_id": "lib1",
                        "values": {"f1": cell("Pier")},
                        "base_rev": 0,
                        "updated_at": "2026-09-28T00:00:00Z",
                    }
                ],
            }
        )
        deleted = self.sync(
            {
                "device_id": "phone",
                "device_name": "Field phone",
                "cursor": 0,
                "libraries": [],
                "entries": [
                    {
                        "id": "e1",
                        "library_id": "lib1",
                        "values": {"f1": cell("Pier")},
                        "base_rev": 1,
                        "updated_at": "2026-09-28T00:04:00Z",
                        "deleted": True,
                    }
                ],
            }
        )
        self.assertTrue(deleted["changes"][-1]["deleted"])
        self.assertEqual(deleted["accepted"][0]["rev"], 2)


if __name__ == "__main__":
    unittest.main()
