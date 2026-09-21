# Watch-U

Watch-U is a local security-operations dashboard for Laragon. A Python worker ingests Suricata or Wazuh JSON, scores and deduplicates alerts, and writes incidents to SQLite. A separate live process can read new Wazuh alerts over SSH/SFTP after the VM credentials are configured.

It uses **PHP 8 + SQLite/PDO + Python + vanilla JavaScript/CSS**. It does not require or use XAMPP, MySQL, Node.js, Composer or a JavaScript framework.

## What is included

- Database-backed Register, Login and Logout flows
- `password_hash()` / `password_verify()` password storage
- Server-side validation, generic login errors, secure session cookies and CSRF protection
- Public registration that can create **Analyst accounts only**
- Analyst access to the dashboard, incidents, vulnerabilities, assets and reports
- Incident filtering, status updates and CSV exports
- Security Department-only role management, system/Telegram settings and authorised Nmap scans
- RFC1918-only, allowlist-enforced Nmap targets with fixed safe profiles and no shell interpolation
- Low, Medium, High and Critical scoring
- Python-side fingerprint deduplication with configurable time windows
- SSH/SFTP live Wazuh reader with a durable SQLite byte cursor and file-rotation detection
- AI-ready summary calls with a deterministic local template fallback
- Telegram alerting for newly created incidents at a configured severity threshold
- Empty-by-default workspace: no demonstration users, assets, incidents or findings are inserted
- Spreadsheet-formula-safe CSV exports

## Architecture

```text
Wazuh VM alerts.json -- SSH/SFTP --> python/wazuh_live.py
                                         |
                                         v
Suricata JSON -----------------> python/watchu_worker.py
                                  score -> dedupe -> SQLite
                                         |
                                         v
                              PHP dashboard + CSV reports
```

The application is intentionally small and modular:

```text
app/                    PHP configuration, auth, CSRF and repository code
app/Services/           Telegram, Wazuh API check and guarded Nmap integrations
app/Views/              Individual beginner-friendly page templates
assets/                 Vanilla CSS and JavaScript charts/interactions
database/               SQLite schema, HeidiSQL launcher and initializer
data/                   Runtime SQLite/session files (Apache-protected)
python/                 Suricata/Wazuh worker, live SFTP reader and sample fixture
scripts/                Windows start/stop/status command for live reader
tests/                  PHP and Python smoke tests
index.php               Front controller and route/permission handling
```

## Laragon setup on Windows

### 1. Requirements

- Laragon with Apache and PHP 8.0 or newer (PHP 8.3 is a good choice)
- PHP extensions: `pdo_sqlite`, `sqlite3`, `mbstring` and `openssl`
- Python 3.10 or newer; install `python/requirements.txt` for live SSH/SFTP
- Nmap only if authorised private-lab scanning will be used

In Laragon, choose **Menu → PHP → Extensions** and enable `pdo_sqlite`, `sqlite3` and `mbstring` if they are not already active. Restart Apache after changing extensions.

### 2. Place and configure the project

The current project location is:

```text
C:\laragon\www\WATCHU!
```

An untracked local `.env` has already been created with safe defaults. For another installation, copy `.env.example` to `.env`:

```powershell
Copy-Item .env.example .env
```

When using Laragon's automatic virtual hosts, rename the folder to `watch-u`, restart Laragon and set:

```dotenv
APP_URL=http://watch-u.test
```

When keeping the current folder name and opening the app through localhost, leave `APP_URL` empty and use:

```text
http://localhost/WATCHU!/
```

### 3. Create the empty SQLite database

Open Laragon Terminal in the project and run:

```powershell
php database\init.php
```

The first web request also creates a missing database automatically. The explicit command is recommended because it confirms the PHP SQLite extension and the writable data directory before login. It creates tables only; it does not add demonstration records.

The database is stored at the obvious path `database/watchu.sqlite`. Both the `database` and `data` directories are denied by the included Apache rules, directory indexing is disabled, and runtime database/session files are ignored by Git.

### Open the database in HeidiSQL

HeidiSQL does not automatically discover SQLite files because SQLite is a file, not a running database server. The quickest option is to double-click:

```text
database\Open in HeidiSQL.bat
```

Watch-U passes the SQLite network type and exact database filename to HeidiSQL. To configure it manually, create a new HeidiSQL session, select **SQLite** as the network type, and browse to:

```text
C:\laragon\www\WATCHU!\database\watchu.sqlite
```

Security Department users can also copy the current absolute database path from the **Settings** page.

### 4. Start the site

Start Apache from Laragon and open the chosen URL. The login page is empty by design; create the first Analyst account only when access is approved.

## First account

This draft does not create accounts automatically. Use the registration page to add the first Analyst account when the project is approved for use. Before signing in as Security Department for the first time, assign that account's `role` to `security_department` in HeidiSQL; after that, the normal access-management screen can manage roles.

Public registration always writes `role = analyst`; a submitted role value is never accepted. A signed-in Security Department user can assign elevated access on **Users**. Watch-U prevents self-demotion and prevents removal of the last Security Department account.

## Python ingestion worker

Initialize the database first, then ingest the supplied mixed fixture:

```powershell
python python\watchu_worker.py python\fixtures\sample-events.jsonl
```

Expected behaviour: three lines are read, two new incidents are created, and the repeated Suricata alert is merged into the first incident with `event_count = 2`.

Read a live JSONL stream from standard input:

```powershell
Get-Content C:\security-feed\eve.json -Wait | python python\watchu_worker.py
```

Watch a directory for appended `.json` and `.jsonl` files:

```powershell
python python\watchu_worker.py --watch C:\security-feed --interval 3
```

Preview parsing and scoring without database writes:

```powershell
python python\watchu_worker.py --dry-run python\fixtures\sample-events.jsonl
```

### Scoring and deduplication

- Critical: 85–100
- High: 70–84
- Medium: 40–69
- Low: 0–39

Suricata priority and Wazuh rule level establish the base score. High-risk categories and signatures add bounded modifiers. A SHA-256 fingerprint is built from the source, detection title, category and network endpoints. A matching fingerprint inside the configured window increments `event_count` and `last_seen`; a later recurrence becomes a new incident occurrence.

## AI-ready summaries

No AI service is required. The worker always has a deterministic analyst-summary template. To connect a compatible internal summary endpoint, configure only `.env`:

```dotenv
WATCHU_AI_SUMMARY_URL=https://your-approved-internal-service.example/summarise
WATCHU_AI_API_KEY=replace-with-a-secret
```

The worker sends a compact normalised event object and expects JSON such as:

```json
{"summary":"Two concise, evidence-grounded analyst sentences."}
```

Timeouts, malformed responses and service failures automatically use the local template. Secrets are never stored in SQLite or rendered in the dashboard.

## Telegram alerts

1. Put the bot token in `.env` only:

   ```dotenv
   TELEGRAM_BOT_TOKEN=replace-with-your-bot-token
   ```

2. Sign in as Security Department and open **Settings**.
3. Enter the destination chat ID, choose the minimum severity and enable alerts.
4. Use **Send test alert**.

The Python worker alerts only on a newly created incident, not every deduplicated repetition. Delivery attempts are recorded in `notification_log`. Do not commit `.env` or paste the token into a database setting.

## Authorised private-lab Nmap scans

Nmap execution is disabled by default. The scan feature rejects hostnames, public addresses, shell characters and user-supplied Nmap flags. It accepts only literal RFC1918 IPv4 addresses/CIDRs inside the Security Department-managed allowlist. Profiles are fixed in PHP, execution bypasses the command shell, and jobs retain an audit record.

After obtaining written authorisation for the specific lab ranges:

1. Install Nmap and confirm `nmap` is available in Laragon Terminal.
2. Add the exact private CIDRs on **Settings**.
3. Enable execution in `.env`:

   ```dotenv
   ENABLE_NMAP_SCANS=true
   NMAP_BINARY=nmap
   ```

4. Restart Apache so PHP receives the new environment settings.

The worker and scan page are not intended for public internet scanning.

## CSV reports

Analysts and Security Department users can download incident and vulnerability CSV reports. CSV downloads are UTF-8 with a byte-order mark for Excel compatibility. Values starting with formula characters are prefixed before export to reduce spreadsheet injection risk.

## Tests

Run the PHP checks from Laragon Terminal:

```powershell
php tests\smoke.php
```

Run Python worker tests:

```powershell
python -m unittest tests.test_worker -v
```

Run live-reader tests (fake SFTP data, no VM connection):

```powershell
python -m unittest tests.test_wazuh_live -v
```

Run the backend-only Wazuh connection checks (no live manager is contacted):

```powershell
php tests\wazuh_service.php
```

The PHP suite verifies accounts, filters, status changes, roles and scan boundaries. The Python suite verifies scoring, summaries, deduplication, saved offsets, restarts, incomplete lines and file rotation.

## Wazuh Manager API connection test

In the server-side `.env` file, set `WAZUH_URL=https://192.168.1.10:55000`, `WAZUH_USERNAME`, and `WAZUH_PASSWORD`. Leave real credentials out of `.env.example` and never put them in the browser. Restart Apache after editing `.env`, then sign in as Security Department, open **Settings → Wazuh Integration**, and click **Test Connection**. The page shows only **Connected**, **Authentication Failed**, **Unreachable**, or a configuration/not-tested state. The API authentication response and JWT stay on the PHP server and are not stored in SQLite or sent to the browser.

The test verifies the manager's HTTPS certificate. If your lab uses a private CA, set `WAZUH_CA_BUNDLE` to the absolute path of a readable PEM CA certificate on the Watch-U host. The certificate must also match the configured hostname or IP address. Watch-U does not disable TLS verification.

This button checks API authentication. The live SSH/SFTP process below brings alerts into SQLite.

## Wazuh live: panduan ringkas VM ke Windows

Aliran: `alerts.json` dalam VM → SSH/SFTP → `python/wazuh_live.py` di Windows → fungsi scoring/dedup `watchu_worker.py` → SQLite → dashboard. Akaun API Wazuh untuk butang **Test Connection** berasingan daripada akaun Linux SSH untuk baca fail log.

### 1. Sediakan VM Wazuh

1. Pastikan Wazuh menulis JSON ke `/var/ossec/logs/alerts/alerts.json`. Semak `jsonout_output` bernilai `yes` dalam `/var/ossec/etc/ossec.conf` dan pastikan fail itu ada alert. [Dokumentasi Wazuh](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/global.html) menerangkan tetapan ini.
2. Hidupkan servis SSH pada VM. Guna akaun Linux khas yang hanya boleh baca `alerts.json` dan masuk ke direktori induknya. Beri izin melalui group atau ACL yang sesuai pada VM; jangan jadikan fail log boleh ditulis oleh semua orang.
3. Semak sebagai akaun tersebut pada VM: `test -r /var/ossec/logs/alerts/alerts.json`. Jika arahan gagal, selesaikan izin fail dahulu.
4. Semak fingerprint kunci SSH VM dari konsol VM sebelum menerima sambungan pertama pada Windows.

### 2. Sediakan Windows dan `.env`

Dari folder projek dalam Laragon Terminal:

```powershell
python -m pip install -r python\requirements.txt
php database\init.php
```

Isi `WAZUH_SSH_HOST`, `WAZUH_SSH_USERNAME`, dan salah satu daripada `WAZUH_SSH_PRIVATE_KEY` atau `WAZUH_SSH_PASSWORD` dalam `.env`. Laluan `WAZUH_ALERTS_PATH` sudah diisi dengan fail alert Wazuh. `WAZUH_SSH_PORT` biasanya `22`. `WAZUH_SSH_KNOWN_HOSTS` boleh dibiarkan kosong untuk guna `C:\Users\<nama>\.ssh\known_hosts`; jika guna fail lain, isi path penuh. Jika kunci SSH disulitkan, isi `WAZUH_SSH_KEY_PASSPHRASE` juga. Isi nilai sebenar hanya dalam `.env`, bukan `.env.example`.

Dari Windows, sambung sekali dengan OpenSSH SFTP menggunakan akaun Linux tadi untuk semak fingerprint dan menyimpan kunci host dalam `known_hosts`. Contoh bentuk arahan: `sftp -P 22 <akaun-linux>@192.168.1.10`. Jika guna key, tambah pilihan `-i <path-key>`. Kemudian taip `bye`. Pembaca live akan menolak kunci host yang belum dikenali atau berubah.

Jika `python` tidak dijumpai oleh skrip Windows, isi `PYTHON_BINARY` dalam `.env` dengan path penuh `python.exe` yang digunakan semasa memasang pakej.

Yang perlu kau isi sendiri dalam `.env`: `WAZUH_USERNAME` dan `WAZUH_PASSWORD` untuk butang API (jika mahu guna butang itu); `WAZUH_SSH_USERNAME` serta **salah satu** `WAZUH_SSH_PRIVATE_KEY` atau `WAZUH_SSH_PASSWORD` untuk alert live. `WAZUH_CA_BUNDLE` perlu jika sijil API VM belum dipercayai oleh PHP. `WAZUH_SSH_KEY_PASSPHRASE` hanya untuk key yang disulitkan. IP VM, port SSH, dan lokasi `alerts.json` sudah disediakan dalam `.env`; semak jika VM kau berbeza. Simpan private key di luar folder web Laragon.

### 3. Uji sample dahulu

Arahan ini hanya memaparkan tafsiran sample; ia tidak mengubah database utama:

```powershell
python python\watchu_worker.py --dry-run python\fixtures\sample-events.jsonl
python -m unittest tests.test_worker tests.test_wazuh_live -v
```

### 4. Jalankan alert sebenar

Skrip Windows menjalankan satu pembaca di latar belakang. Jalankan dari folder projek:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\wazuh-live.ps1 start
powershell -ExecutionPolicy Bypass -File .\scripts\wazuh-live.ps1 status
powershell -ExecutionPolicy Bypass -File .\scripts\wazuh-live.ps1 stop
```

Selepas menukar tetapan SSH dalam `.env`, jalankan `stop` kemudian `start` supaya proses membaca nilai baharu.

Pada sambungan pertama, pembaca melangkau alert lama dan menunggu alert baharu. Selepas `start`, hasilkan satu alert ujian dalam VM, semak log `data\wazuh-live-*.log`, kemudian refresh halaman **Incidents**. Untuk semakan satu kali di depan mata, jalankan `python python\wazuh_live.py --once`. Untuk baca log lama pada database ujian yang belum ada cursor, guna `--from-start` sekali sahaja.

Kedudukan bacaan disimpan dalam jadual SQLite `wazuh_ingest_cursor` bersama perubahan incident. Jadual ini dicipta automatik dalam database lama pada mula pertama. Restart proses tidak mengulang semua alert lama. Bila Wazuh mengganti atau mengosongkan fail, pembaca mengesan perubahan fail dan membaca fail baharu dari awal. Hanya satu pembaca live boleh berjalan pada satu masa.

Jangan jalankan `watchu_worker.py --watch` pada salinan alert Wazuh yang sama serentak dengan `wazuh_live.py`, kerana itu akan memasukkan alert yang sama dua kali.

### Jika ada masalah

- **API Connected tetapi dashboard kosong:** API hanya menguji login. Semak proses `status`, log proses, izin baca `alerts.json`, dan hasilkan alert baharu selepas proses mula.
- **SSH login gagal:** semak akaun Linux, key/password SSH dan port `22`. Ini berbeza daripada `WAZUH_USERNAME` untuk API.
- **Kunci host tidak dikenali/berubah:** semak fingerprint di konsol VM sebelum mengubah `known_hosts`.
- **Fail alert tidak boleh dibaca:** akaun SSH perlukan izin baca pada fail dan izin masuk ke semua direktori induk.
- **Python/Paramiko tidak dijumpai:** pasang Python, jalankan `python -m pip install -r python\requirements.txt`, dan semak `PYTHON_BINARY`.
- **Proses berhenti sebaik mula:** baca fail `data\wazuh-live-*.err.log` yang dinamakan dalam mesej `start`.

Jika proses terhenti sepanjang satu putaran fail Wazuh, alert dalam fail lama yang sudah dipindah mungkin perlu diimport semula secara manual. Simpan backup SQLite dan pantau log proses untuk penggunaan berterusan.

## Safe database reset

To restore the original demonstration data, stop Apache and the Python worker, move the existing database to a backup name, then initialize a new one:

```powershell
Move-Item database\watchu.sqlite database\watchu-backup.sqlite
php database\init.php
```

Do not reset the database when it contains evidence that must be retained.

## Troubleshooting

- **Could not find driver**: enable `pdo_sqlite` and `sqlite3`, then restart Apache.
- **Database is not writable**: grant the Windows account running Apache modify access to `data` and `data\sessions`.
- **Login form reports an expired token**: clear the Watch-U session cookie and confirm `data\sessions` is writable.
- **Nmap remains disabled**: restart Apache after editing `.env`; verify `ENABLE_NMAP_SCANS=true` and the binary path.
- **Telegram test fails**: verify the bot token, chat ID, bot membership and outbound HTTPS access.
- **Python says the database is missing**: run `php database\init.php` from the project root or pass `--db` with the correct SQLite path.
