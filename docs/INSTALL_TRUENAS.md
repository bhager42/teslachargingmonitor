<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Brad Hager and contributors -->

# Install on TrueNAS SCALE 25.10+

This guide installs Tesla Charger Monitoring (`tcmon`) as a custom app.
It takes about ten minutes. You need:

- TrueNAS SCALE 25.10 or newer, with **Apps** set up (Apps → Configuration →
  Choose Pool, done once).
- The IP address of your Wall Connector (your router's DHCP list or the Tesla
  One app). Reserve it in the router so it does not change.

The app stores everything (database, encryption key, HTTPS certificate) in
one dataset, so snapshots of that dataset are complete backups.

## 1. Create the dataset

1. **Datasets** → select your pool (or an existing `apps` dataset) → **Add
   Dataset**.
2. **Name:** `tcmon`. **Dataset Preset:** *Apps*. **Save**.
3. Select the new dataset → **Permissions** → **Edit**.
4. Set **Owner → User** to `apps` and **Owner → Group** to `apps`, tick
   **Apply User** and **Apply Group**, and **Save Access Control List**.

`apps` is UID/GID 568, which the container runs as. Note the dataset path,
for example `/mnt/tank/apps/tcmon`.

## 2. Install via YAML

1. **Apps** → **Discover Apps** → **⋮** (top right) → **Install via YAML**.
2. **Name:** `tcmon`.
3. Paste [`deploy/truenas/custom-app.yaml`](../deploy/truenas/custom-app.yaml)
   and change the two lines marked `EDIT`:
   - `TZ:` your time zone, for example `America/Chicago` (used for days,
     quiet hours and costs).
   - the volume path before `:/data`: your dataset path from step 1.
4. **Save**. TrueNAS pulls the image and starts the app; it shows
   **Running** within a minute.

If port 8443 is already used on your TrueNAS, change the first number in
`ports: ["8443:8443"]`, for example `"9443:8443"`, and use that port below.

## 3. First sign-in

1. **Apps** → **Installed** → **tcmon** → **Workloads** → the `tcmon`
   container → **View Logs**. Find the line `FIRST-RUN SETUP` and copy the
   `setup_token` value. It is valid for 30 minutes; restarting the app
   prints a new one.
2. Open `https://<truenas-ip>:8443/` in your browser. It warns once that the
   certificate is self-signed: this is expected on a LAN (the app makes its
   own certificate). Choose *Advanced → Continue*. To remove the warning
   permanently, download the certificate from **About** in the app and trust
   it on your devices.
3. Enter the setup token and choose a password (at least 12 characters; a
   few random words work well).
4. **Settings → Wall Connectors → Add Wall Connector**: enter the Wall Connector's IP
   address and **Test connection**.
5. **Notifications → Add email (Gmail)**: set up Gmail with an app password, then **Send
   test email**.

## Using a host name

IP addresses always work. To use a name such as `truenas.lan`, add it to
the `environment:` section and redeploy (Apps → tcmon → **Edit**):

```yaml
      TCMON_PUBLIC_HOSTNAMES: truenas.lan
```

The app makes a new self-signed certificate that includes the name when it
restarts, so the browser warns once more.

To use your own certificate instead, copy `cert.pem` and `key.pem` into the
dataset (owned by `apps`, mode 600) and add:

```yaml
      TCMON_TLS: file
      TCMON_TLS_CERT_FILE: /data/cert.pem
      TCMON_TLS_KEY_FILE: /data/key.pem
```

## Updating

Releases are listed at
<https://github.com/bhager42/teslachargingmonitor/releases>.

1. Optional but recommended: take a snapshot of the `tcmon` dataset
   (**Datasets** → `tcmon` → **Create Snapshot**).
2. **Apps** → **tcmon** → **Edit**, change the image tag (for example
   `:latest` to `:0.8.0`) and **Save**. TrueNAS pulls the image and restarts
   the app. The database is upgraded automatically on start.

Pinning a version tag such as `:0.7.0` instead of `:latest` makes updates
explicit. To pull a newer `:latest`, use **Edit** → **Save** as well.

## Backups

- **Snapshots (recommended):** **Data Protection** → **Periodic Snapshot
  Tasks** → **Add**, dataset `tcmon`, daily, keep for 2 weeks. A snapshot
  contains everything the app needs.
- **From the app:** **Settings → Backup** downloads a copy of the database.
  Also keep `secret.key` (it encrypts the saved Gmail password) and the
  `tls` folder from the dataset.

### Restore

1. **Apps** → **tcmon** → **Stop**.
2. Roll back the snapshot (**Datasets** → `tcmon` → **Snapshots** →
   **Rollback**), or replace `tcmon.db` in the dataset with a downloaded
   backup and delete `tcmon.db-wal` and `tcmon.db-shm` next to it. Keep the
   original `secret.key`; without it the Gmail password must be entered
   again.
3. **Start** the app.

## Forgotten password

**System → Shell**, then:

```bash
sudo docker exec -it tcmon /tcmon reset-password
```

Type the new password and press Enter. Every browser is signed out. (The
app's own **Shell** button does not work: the image has no shell, which is
deliberate.)

## Troubleshooting

| Symptom | Fix |
|---|---|
| App stops at once; log says `permission denied` and `chown` | The dataset is not owned by `apps` (568). Repeat step 1.4. |
| Browser shows *Misdirected request* | You used a host name: add it to `TCMON_PUBLIC_HOSTNAMES`, or use the IP address. |
| Browser shows *403* from another network | The app answers only private (LAN) addresses by design. Use a VPN into your LAN for remote access. |
| *No Wall Connector answered* | Check the IP, that the Wall Connector is on Wi-Fi, and that TrueNAS can reach that network. |
| Setup token expired | **Apps** → **tcmon** → **Restart**, then read the new token in the log. |
