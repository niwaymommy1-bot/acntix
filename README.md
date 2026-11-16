# acntix — CLD custom scripts for Acunetix

Custom **target scripts** for Acunetix (Linux, on-premises) that look for exposed secrets,
backups and API documentation. They are only used against targets you are authorized to test.

Each script runs **once per target**, sends at most ~100 requests to the scanned host only,
and reports an alert only when the response contains real proof (not just HTTP 200).

## Scripts

| Script | Looks for | Proof required | Requests |
|---|---|---|---|
| `CLD-env-disclosure.js` | `.env` files (`/.env`, `/.env.bak`, `/.env.production`, `/api/.env` …) | ≥ 3 `KEY=VALUE` lines **and** a known config key (`APP_KEY`, `DB_PASSWORD`, `AWS_*` …). A random `/.env.<random>` is checked first, so catch-all servers are skipped. Says whether real secrets or only template values were found. | ≤ 100, up to 5 alerts |
| `CLD-accessible-wpconfig.js` | WordPress `wp-config` copies (`.bak`, `.old`, `.swp`, `~`, `/backup/` …) | HTTP 200 **and** `DB_NAME` / `DB_USER` / `DB_PASSWORD` / `AUTH_KEY` / `WPENGINE_ACCOUNT` | ≤ 100, stops at first hit |
| `CLD-hostname-backups-archives.js` | Site backup archives (`/backup.zip`, `/www.example.com.zip`, `.tar.gz`, `.rar`, `.7z` …) | Non-HTML response **and** a real archive signature (ZIP, gzip, RAR, 7z, bzip2, tar) | ≤ 100, stops at first hit |
| `CLD-hostname-backups-sql.js` | SQL dumps and database files (`/dump.sql`, `/example.com.sql`, `.sql.gz`, `.sqlite` …) | Dump header (mysqldump, pg_dump, phpMyAdmin, Adminer), `CREATE TABLE` / `INSERT INTO` lines, or a binary signature (gzip, ZIP, PGDMP, SQLite) | ≤ 100, stops at first hit |
| `CLD-api-discovery.js` | OpenAPI / Swagger specs, Swagger UI / ReDoc pages, GraphQL endpoints | Valid spec with a `paths` object, a docs UI bundle, or a GraphQL introspection answer | 25, one alert per finding type |

Archive and SQL scripts also try names built from the target host:
`www.example.com` → `www.example.com`, `example.com`, `example`.

## Quick install (recommended)

Run on the Acunetix machine:

```bash
curl -fsSL https://raw.githubusercontent.com/niwaymommy1-bot/acntix/main/install-cld-scripts.sh -o install-cld-scripts.sh
sudo bash install-cld-scripts.sh        # scanner threads = 8
sudo bash install-cld-scripts.sh 40     # or choose the thread count
```

`install-cld-scripts.sh`:

1. Re-runs itself as root if needed.
2. Downloads every `*.js` script from this repo (`main` branch).
3. Applies the [alert patch](#patch-one-alert-per-finding) to each script.
4. Finds **every** Acunetix install (`*/.acunetix` under `/home`, `/root`, `/opt`) and for each one:
   - copies the scripts to `data/custom-scripts/target/` (prints `new` / `updated` / `same`),
   - sets `<Threads>` in `data/general/settings.xml` (the first run saves `settings.xml.orig`).
5. Restarts Acunetix (`systemctl restart acunetix`, or restarts the supervisor directly
   when there is no systemd service, e.g. Google Cloud Shell; log in `/tmp/acunetix.log`).
6. Waits for the UI on port 3443, starts a **Cloudflare quick tunnel** and prints the result:

```
=================== RESULT ===================
 Custom scripts : 5 installed from niwaymommy1-bot/acntix
 Threads        : 8
 Acunetix       : running
 Public URL     : https://xxxx-xxxx.trycloudflare.com
 API base       : https://xxxx-xxxx.trycloudflare.com/api/v1
==============================================
```

Re-run it whenever scripts are added or changed in this repo: new scripts get installed
and changed ones get updated.

> **Warning:** the tunnel URL is public. Anyone with the link reaches the Acunetix login page
> and API. Use a strong password, keep the API key private, and stop the tunnel when you are done
> (`sudo pkill -f "cloudflared tunnel"`). Tunnel log: `/tmp/cloudflared.log`.

**Requirements:** Linux, `bash`, `curl`, `tar`, `sudo`, `setpriv` (util-linux), internet access to
GitHub and Cloudflare.

## Manual install

```bash
sudo cp CLD-*.js /home/acunetix/.acunetix/data/custom-scripts/target/
sudo chown acunetix:acunetix /home/acunetix/.acunetix/data/custom-scripts/target/CLD-*.js
```

Then apply the patch below. New scans pick the scripts up automatically. They run in
**Full Scan** and in any custom scan profile that does not exclude custom scripts.

## Patch: one alert per finding

**Problem:** every script reports through the shared `custom.xml` alert type. When the
reported path is not part of the crawled site, Acunetix places the alert at the site root
(`/`). Several alerts with the same type and the same location are **merged into one**.
In testing, all 5 scripts found their planted file, but only one alert was saved.

**Fix:** give every alert a unique `parameter`. The install script does this automatically:

```js
scanState.addVuln({
    typeId: 'custom.xml',
    path: CLD_PATHS[i],
    parameter: 'CLD ' + CLD_PATHS[i],   // added (api-discovery uses: 'CLD ' + title)
    http: job,
    ...
});
```

Equivalent `sed` commands, for a manual install:

```bash
cd /home/acunetix/.acunetix/data/custom-scripts/target
sudo sed -i -E "/typeId: 'custom.xml',/{n;/parameter:/!s/^(\s*)path: (.*),$/&\n\1parameter: 'CLD ' + \2,/}" CLD-*.js
sudo sed -i "s/parameter: 'CLD ' + hits\[0\].path,/parameter: 'CLD ' + title,/" CLD-api-discovery.js
```

After the patch, a test scan against a site with all five files planted showed 5 separate
custom alerts.

**Known limit:** every alert shows the severity of the built-in `custom.xml` type
(High in the tested build). The `Severity:` line in each script header is documentation only;
Acunetix does not read it.

## Choosing the thread count

`<Threads>` applies to **each** scan, so concurrent scans multiply the load. Each scan also
starts its own Chromium (roughly 0.5–1 GB of memory).

Measured on a 2-CPU / 7 GB machine (one scan, Fast speed, local test site):

| Threads | Requests/sec | CPU | Memory used |
|---|---|---|---|
| 5 (default) | 18 | 38% | 3.7 GB |
| 10 | 52 | 77% | 4.3 GB |
| 40 | 58 | 88% | 5.1 GB |
| 60 | 120 | 94% | 6.5 GB |

Rough guide: total threads across all running scans ≈ 20 per CPU, and about 1 GB of memory
per 10 threads.

| Machine | 1 scan at a time | 5 scans at once |
|---|---|---|
| 2 CPU / 7 GB | 40 | 8 |

Set the target's **Scan Speed** to *Fast* as well. It controls a separate per-host limit on
concurrent requests.

## Uninstall

```bash
sudo rm /home/acunetix/.acunetix/data/custom-scripts/target/CLD-*.js
sudo cp -p /home/acunetix/.acunetix/data/general/settings.xml.orig \
           /home/acunetix/.acunetix/data/general/settings.xml   # restore threads
```
