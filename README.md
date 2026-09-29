# Cafinewo

Offline-first database, in the spirit of Memento: libraries, typed fields, and entries. Changes are saved on the device immediately. When a connection is available they sync, and edits that touch the same field are resolved by you.

This MVP runs in the browser. A JDK and Android SDK are not installed on this machine, so there is no native Android build yet. After the app has loaded once, the screen still opens with no connection; entries stay in this browser until sync works again.

## Run

```bash
python3 server.py
```

Open http://127.0.0.1:8765

The first visit asks for an admin name and password. That account can add users and groups, choose who may create libraries, and set access on each library.

Access is per library, for a user or a group:

- See, edit, create, and erase can be turned on separately for the library and for its entries.
- Each field can follow the entry rule, or be hidden or locked on its own.
- Own means only records that person created. A group member with Own sees the entries they created, not the rest of the group.
- If a person also belongs to a group, the wider permission applies. A group set to All lets every member see every entry.

## Try a conflict

1. Add the sample library and sync (you should be online).
2. Open Devices and add a second device, for example `Office`.
3. On Office, sync so it receives the library, then change a field.
4. Switch back to Field phone, turn Offline on, and change that same field.
5. Turn Offline off. The conflict screen asks which value to keep.

Edits to different fields merge on their own.
