# Cafineuos

Offline-first database, in the spirit of Memento: libraries, typed fields, and entries. Changes are saved on the device immediately. When a connection is available they sync, and edits that touch the same field are resolved by you.

This MVP runs in the browser. A JDK and Android SDK are not installed on this machine, so there is no native Android build yet. After the app has loaded once, the screen still opens with no connection; entries stay in this browser until sync works again.

## Run

```bash
python3 server.py
```

Open http://127.0.0.1:8765

The first visit asks for an admin name and password. Admins create, edit, and delete libraries, and they manage users. On each library they choose who can create, edit, or delete entries: None, All, Own, or a list of users.

Each entry has people fields for who can see it and who can modify it. The person who created the entry can still see it. A field can be marked so that anyone who can see the entry may edit that field.

Field types include text, date, time, single choice, multiple choice, image, and file. Files stay on the phone and upload with the next sync.

People, on an admin account, sets backups every N hours or every N syncs. The server keeps the last five copies.

## Hosting

Render can run this server. Push the repo, then New > Blueprint and pick `render.yaml`.

The Blueprint uses a Starter instance (about $7 a month) and a 1 GB disk (about $0.25 a month). The disk keeps accounts, libraries, uploaded files, and backups. A free instance has no disk, so that data disappears whenever Render restarts the service.

After the first deploy, open the URL and create the admin account. Phones load the same URL, work offline after that, and sync when they are online.

When files grow, keep the app on Render and put `blobs/` in Cloudflare R2 or Backblaze B2.

## Try a conflict

1. Add the sample library and sync (you should be online).
2. Open Devices and add a second device, for example `Office`.
3. On Office, sync so it receives the library, then change a field.
4. Switch back to Field phone, turn Offline on, and change that same field.
5. Turn Offline off. The conflict screen asks which value to keep.

Edits to different fields merge on their own.
