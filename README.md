# Router Manager

Standalone manager for Cudy, Tenda, and TP-Link consumer routers. Encrypted credential storage,
a local-only web dashboard, guarded scheduled reboots, and opt-in network discovery.

This is a self-contained project. It shares no code, dependencies, configuration, or
virtual environment with any other project.

## Security model

- Passwords are never written to the device config. Each device stores a
  `password_ref` that points into a Fernet-encrypted vault.
- The vault key is generated on first run at `data/master.key` with mode `0600`, inside
  a `0700` directory. Back this file up; without it the vault cannot be decrypted.
- The device config is written with mode `0600`.
- API responses never contain a password or a secret reference, only
  `password_configured: true|false`.
- The web UI binds to `127.0.0.1` by default. Do not expose router admin ports to the
  public internet; reach them over a VPN or an authenticating reverse proxy.
- Sessions are held server-side in memory, so a restart signs everyone out. Cookies are
  `HttpOnly` and `SameSite=strict`, and every mutating request needs a CSRF token.
  Login attempts are rate limited.
- If no web password is configured the server still starts, but fails closed: `/healthz`
  stays public and every other endpoint, including the API and login, returns `503`
  without touching a device.

## Install

Requires Python 3.12 or newer.

```bash
python3.12 -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

`.[dev]` adds the test and lint tooling. For runtime only, install
`requirements.txt`. Then set a config location, because the built-in default sits
inside the installed package directory:

```bash
export ROUTER_MANAGER_CONFIG=~/router-devices.yaml
```

## Run the web dashboard

```bash
export ROUTER_MANAGER_PASSWORD='use-a-long-random-password'
.venv/bin/router-manager serve
```

Open <http://127.0.0.1:8091> and sign in with the passkey, the value of
`ROUTER_MANAGER_PASSWORD`. There is no username.

`--host` and `--port` override the bind address. Only move off loopback behind a VPN
or an authenticating reverse proxy. The session cookie carries no `Secure` flag over
plain HTTP, so set `ROUTER_MANAGER_SECURE_COOKIE=1` when you terminate TLS in front.

## Command line

```bash
router-manager add <id> <host> --vendor cudy|tenda|tplink [--username admin] [--model X] [--no-verify]
router-manager set-password <id> [--no-verify]
router-manager diagnose <id>
router-manager list
router-manager status <id>
router-manager reboot <id>
router-manager wifi-password <id> [--radio 2.4G|5G]
router-manager discover [--subnet 192.168.1.0/24]
router-manager serve [--host 127.0.0.1] [--port 8091]
router-manager acs status|devices|dump|bootstrap|wifi|job|firmware ...
router-manager activity [--router ID] [--who NAME] [--kind KIND] [--before ID|TIME] [--limit N] [--csv]
router-manager firmware status|check <id>
router-manager firmware auto-update <id> --on|--off [--window HH]
router-manager maintenance list|show <plan>|run <plan>
```

The `acs` commands manage TR-069 routers through GenieACS; see
[TR-069 through GenieACS](#tr-069-through-genieacs-optional). `activity`, `firmware`
and `maintenance` are described under [Maintenance](#maintenance).

`add` prompts for the password with `getpass` so it never appears in shell history or
in `ps` output. When stdin is not a terminal, `getpass` falls back to reading a line,
so you can pipe the password instead:

```bash
printf '%s' "$ROUTER_PASSWORD" | router-manager add cudy1 192.168.1.1 --vendor cudy
```

`add` then attempts a real login so a wrong password is reported immediately. The
device is still saved when the login fails, because a router that is temporarily busy
should not cost you the configuration. The command exits `1` on a failed login, so
`set -e` scripts notice. Pass `--no-verify` to skip the login entirely.

`wifi-password` changes the Wi-Fi passphrase of a directly managed router, on every
band or only the one given with `--radio`. It asks twice with `getpass` and refuses
anything but 8 to 63 printable ASCII characters. For unattended use set
`ROUTER_MANAGER_WIFI_PASSPHRASE` together with `ROUTER_MANAGER_ASSUME_YES=1`. It is
deliberately a different variable from `ROUTER_MANAGER_DEVICE_PASSWORD`, so a router
admin password exported for `set-password` never becomes a Wi-Fi passphrase.

`discover` is bounded to one subnet and never runs automatically.

Exit codes are meant for scripting: `status` exits `1` when the device is offline,
`reboot` exits `1` when the router does not confirm, and `add` exits `1` when the
password was rejected. Failures print a single `error:` line, never a traceback.

## Diagnosing a router that will not log in

`diagnose` replays the login by hand and prints every step, so you can see whether the
problem is the port, the firmware, or the password:

```bash
router-manager diagnose cudy1
```

Each step reports the HTTP status, the fields found on the page, and any cookie names.
Values are never printed: form fields appear as `<24 chars>` and the login body is
redacted. A verdict at the end names the most likely cause, for example:

| Verdict | Meaning |
| --- | --- |
| `the router did not answer on this address` | Wrong port, wrong scheme, or the device is offline. |
| `no LuCI login page at ...` | Something is answering, but it is not a Cudy login page. Check the port and `https`. |
| `login page has no salt` | The firmware does not use the expected challenge/response handshake. Not a password problem. |
| `credentials rejected; the login form came back` | The password is wrong. The port, path, and handshake are all correct. |
| `login accepted; the router issued a session cookie` | The password is good. |

`diagnose` performs only reads and one login attempt, so it is safe to run against
production hardware.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `ROUTER_MANAGER_PASSWORD` | none | The dashboard passkey, the only thing the sign-in page asks for. Without it every endpoint returns `503`. |
| `AUTH_PASSWORD` | none | Fallback read when the above is unset. |
| `ROUTER_MANAGER_USERNAME` | unused | No longer checked: the passkey alone signs in. A `username` sent to `POST /login` is ignored. |
| `AUTH_USERNAME` | unused | As above. |
| `ROUTER_MANAGER_CONFIG` | `<package>/cudy_devices.yaml` | Device inventory path. |
| `ROUTER_MANAGER_DATA_DIR` | `~/.local/state/skybre-router-manager` | Key, vault, scheduler state. |
| `ROUTER_MANAGER_SCHEDULER_INTERVAL` | `30` | Scheduler tick in seconds, minimum `15`. |
| `ROUTER_MANAGER_SECURE_COOKIE` | `0` | Set to `1` when served over HTTPS. |
| `ROUTER_MANAGER_DEVICE_PASSWORD` | none | Password used by `set-password` with `ROUTER_MANAGER_ASSUME_YES=1`. |
| `ROUTER_MANAGER_WIFI_PASSPHRASE` | none | Passphrase used by `wifi-password` and `acs wifi` with `ROUTER_MANAGER_ASSUME_YES=1`. |
| `ROUTER_MANAGER_TRUST_PROXY` | unset | Honour `X-Forwarded-For` for login throttling. Only enable behind a proxy that overwrites the header. |
| `ROUTER_MANAGER_ASSUME_YES` | unset | Set to `1` to skip the interactive confirmation. Unattended use only. |

The `ROUTER_MANAGER_ACS_*` variables are described under
[TR-069 through GenieACS](#tr-069-through-genieacs-optional).

## Resetting a password

If a router password is wrong, mistyped, or changed on the device itself, replace the
stored copy. From the dashboard, open the router, choose **More**, then **Router admin
password**: enter it twice, then save. The result tells you whether the router accepted it.

From the command line:

```bash
router-manager set-password cudy1
```

It asks twice and refuses to change anything if the entries differ, so a typo cannot
leave you locked out. The password is never accepted as a command-line argument, which
would put it in your shell history and in `ps` output.

By default it then tests the new password by authenticating against the router, which
is worth keeping. It reports which of three outcomes occurred:

- **Saved and verified** means the router accepted it. Exit status `0`.
- **Saved but rejected** means the password was stored but the router answered and
  refused it, so the value is still wrong. Exit status `1` so a script or a test run
  notices.
- **Saved but unverifiable** means the router could not be reached at all, so nothing
  was actually tested. Exit status `1` as well. This is deliberately not reported as a
  rejection: if the device is asleep or on another subnet, chasing the password is the
  wrong response, so the message names the connectivity problem instead.

A rejected password is deliberately still saved, so a transient failure such as the
router being mid-reboot does not throw away what you just typed. Fix the cause and run
the command again. Use `--no-verify` to skip the round trip when you are certain, or
when the router is offline.

For unattended use, set both variables. This skips the confirmation prompt, so use it
only where the value is already held in a secret store:

```bash
ROUTER_MANAGER_DEVICE_PASSWORD="$NEW" ROUTER_MANAGER_ASSUME_YES=1 \
  router-manager set-password cudy1
```

`ROUTER_MANAGER_DEVICE_PASSWORD` is deliberately separate from
`ROUTER_MANAGER_PASSWORD`, which is the dashboard login. Mixing them up would store
your dashboard password as a router password, so the two are never interchangeable.

Rotating a password preserves the device's existing reference; no orphaned secret is
left behind. Resetting also works on a device that was added without one.

### The dashboard login password

`ROUTER_MANAGER_PASSWORD` is read from the environment at startup, so rotate it by
changing the variable and restarting. It is never written to disk. Sessions live in
memory, so a restart signs everyone out.

### If the vault key is lost

`master.key` cannot be recovered. Every stored password becomes unreadable, and each
device then fails to load until its reference is repaired. Reset each one with
`set-password`, or re-add the device, and the config loads again. Back the key up
before the test day:

```bash
systemctl stop router-manager 2>/dev/null || pkill -f 'router-manager serve'
cp ~/.local/state/skybre-router-manager/master.key ~/master.key.bak
chmod 600 ~/master.key.bak
```

## Device config

Devices are created with `router-manager add` or from the dashboard, never by writing
secrets by hand. `add` stores the password in the encrypted vault and leaves only a
reference behind:

```yaml
devices:
  cudy1:
    vendor: cudy
    host: 192.168.1.1
    username: root
    password_ref: device-cudy1-password
    http_port: 80
    transport: web
    enabled: true
    reboot:
      enabled: false
      at: "04:00"
      timezone: UTC
      window_minutes: 15
      min_uptime_seconds: 3600
      cooldown_seconds: 21600
    metadata: {}
```

Hand-editing is for settings like `reboot` and `metadata`, which you can change freely
on a device that already has a valid `password_ref`.

**Do not hand-write a `password_ref`.** If one points at a key that is not in the
vault, the entire config fails to load, not just that device, and no device becomes
reachable until the reference is repaired. The only ways to populate the vault are
`router-manager add` and the dashboard.

Other fields the writer emits and preserves: `https`, `verify_tls`, `ssh_port`,
`snmp_port`, `snmp_community_ref`, `rpc_path`, `allow_legacy_login`, and
`accept_unknown_host_key`. `allow_legacy_login` permits Cudy routers with no HTTPS
certificate; leave it off unless the device forces it.

## Scheduled reboots

A reboot happens only when every guard passes, in this order:

1. The policy is enabled, the device is enabled, and the current local time in the
   device's timezone falls inside the window starting at `at`.
2. No reboot has already been scheduled for that local calendar day.
3. The device reports as online.
4. Uptime is readable and at least `min_uptime_seconds`. **If uptime cannot be
   determined the reboot is skipped**, because an unknown uptime means a
   reboot-on-boot loop cannot be ruled out.
5. `cooldown_seconds` have passed since the last reboot.
6. The adapter confirms the reboot was accepted.

State is persisted, so restarting the service does not trigger a catch-up reboot
storm. Disabled by default. A policy that is off in config, or a device that never
satisfies a guard, never reboots:

```yaml
    reboot:
      enabled: true
      at: "04:00"
      timezone: "America/Chicago"
      window_minutes: 15
      min_uptime_seconds: 86400
      cooldown_seconds: 172800
```

The window is `window_minutes` long starting at `at`, so a 15-minute window plus the
30-second scheduler tick gives a reboot roughly every other day when a guard such as
uptime is what blocks it. The scheduler runs at `ROUTER_MANAGER_SCHEDULER_INTERVAL`
seconds and re-checks every device each tick.

## TR-069 through GenieACS (optional)

Routers that speak TR-069 (CWMP) can be managed through GenieACS 1.2.16, which runs
unmodified as separate services on the same host. SkyRouter talks only to GenieACS's
northbound API (the NBI), and the browser talks only to SkyRouter. TR-069 routers
appear when they first check in and live in GenieACS's database, never in the device
config. Routers added by hand keep working exactly as before.

**The feature is off unless `ROUTER_MANAGER_ACS_URL` is set.** Without it the server
behaves exactly as it did before: the dashboard lists direct routers only, without
the **Managed** filter or the Setup page's TR-069 choice, and every `/api/acs` route
returns `503`.

Installing GenieACS, MongoDB and the firewall rules is covered by the operator
runbook in [deploy/genieacs/README.md](deploy/genieacs/README.md).

| Variable | Default | Purpose |
| --- | --- | --- |
| `ROUTER_MANAGER_ACS_URL` | unset | NBI address, for example `http://127.0.0.1:7557`. `http` or `https` only, with no credentials or path. Unset switches the feature off. |
| `ROUTER_MANAGER_ACS_ALLOW_REMOTE` | `0` | Set to `1` to accept an NBI address that is not loopback. The NBI has no authentication, so do this only when something else protects it. |
| `ROUTER_MANAGER_ACS_INFORM_INTERVAL` | `300` | Seconds between router check-ins, `60` to `86400`. The bootstrap pushes it to every router. |
| `ROUTER_MANAGER_ACS_SCRUB_SECRETS` | `1` | After a Wi-Fi passphrase change is acknowledged, read the passphrase back so the plaintext copy GenieACS keeps in MongoDB becomes empty. |
| `ROUTER_MANAGER_ACS_CWMP_URL` | unset | The ACS address the Setup page tells technicians to type into each router, for example `http://10.10.0.2:7547/`: GenieACS's CWMP service as the routers reach it. SkyRouter never connects to it. `http` or `https` only, with no credentials, query or fragment. |

An invalid `ROUTER_MANAGER_ACS_*` value stops the server from starting, with an error
naming the variable, instead of falling back to a default. The interval is pushed to
every router, and a mistyped remote URL would expose the unauthenticated NBI. While
`ROUTER_MANAGER_ACS_URL` is unset the others are ignored.

From the command line:

```bash
router-manager acs status
router-manager acs devices [--q TEXT] [--tag TAG] [--skip N] [--limit N]
router-manager acs dump <acs_id>
router-manager acs bootstrap [--remove-seeded]
router-manager acs wifi <acs_id> --band 2.4GHz|5GHz|6GHz|all [--ssid NAME] [--keep-passphrase] [--wait SECONDS]
router-manager acs job <job_id> [--wait SECONDS]
router-manager acs firmware list|add|remove|upgrade ...
```

- `status` checks that GenieACS answers, its version, and SkyRouter's bootstrap. It
  exits `1` until the bootstrap is installed and the presets GenieACS's own UI seeds
  are removed.
- `bootstrap` installs SkyRouter's provisions and presets, and a second run writes
  nothing. It refuses while the UI-seeded presets exist; `--remove-seeded` deletes them.
- `dump` prints a router's cached parameter tree with every secret redacted.
- `wifi` asks for the passphrase twice, or reads `ROUTER_MANAGER_WIFI_PASSPHRASE` with
  `ROUTER_MANAGER_ASSUME_YES=1`, then starts a job. TR-069 passphrases are write-only,
  so a successful change is reported as *acknowledged*: the router accepted it, but it
  cannot be read back to compare. A band SkyRouter had to infer needs
  `--confirm-guessed-band`.
- `--wait SECONDS` follows the job until it has a result or the time runs out. It moves
  the job along itself while waiting, so the change finishes even when the server is
  not running.
- `firmware` keeps the firmware library and installs from it; see
  [TR-069 firmware upgrades](#tr-069-firmware-upgrades).

A router that checks in for the first time is tagged `skybre_new` and listed on the
dashboard as a new router to adopt. Adopting it (`POST /api/acs/devices/{id}/adopt`
with an optional `{"customer": "#1080 Customer A"}`, 1 to 120 characters) removes the
tag and links it to that Vexar customer, which the router list shows and searches.
GenieACS has nowhere to keep the customer, so SkyRouter keeps it in
`acs_adoptions.json` in its data directory. Adoptions and firmware library changes are
in the activity log.

Run the `acs` commands with the server's environment: the same `ROUTER_MANAGER_ACS_*`
values, and as the service user with the same `ROUTER_MANAGER_DATA_DIR`, so the CLI and
the server share the job file (`acs_jobs.json`) and the vault. For the unit in
`deploy/skyrouter/`:

```bash
sudo -u skyrouter env ROUTER_MANAGER_DATA_DIR=/var/lib/skyrouter HOME=/var/lib/skyrouter \
  ROUTER_MANAGER_ACS_URL=http://127.0.0.1:7557 /opt/skyrouter/venv/bin/router-manager acs status
```

## Maintenance

Routine work on many routers: an activity log of every change, firmware checks and
upgrades, and maintenance plans that run them in a chosen window.

### The activity log

Every change to a router is recorded in `activity.jsonl` in the data directory
(mode `0600`, rotated at 5 MB, three old files kept): when, who, which router, the
kind of change, the result and one sentence saying what happened. A router is its
device id, or `acs:<GenieACS ID>` for a TR-069 router.

| Kind | Recorded for |
| --- | --- |
| `setup` | adding, editing and removing a router |
| `credentials` | a new router login password or SNMP community |
| `wifi` | network name and Wi-Fi password changes |
| `reboot` | reboots, by hand, by a device's reboot policy or by a plan |
| `firmware` | update checks, automatic-update settings and firmware upgrades |
| `maintenance` | a plan holding a router back, or stopping on an error |

The result is `applied`, `queued` (a TR-069 job or plan step sent and not yet
settled), `refused` (SkyRouter declined: a guard, bad input, an unsupported
operation, a latched credential), `failed` (the router or the ACS did not do it)
or `info` (a check, which changes nothing).

Who made the change:

| Actor | Meaning |
| --- | --- |
| `Skybre staff` | the dashboard. Everyone signs in with the one password, so there is no individual to name yet. |
| `cli (<login name>)` | the command line, as the user who ran it |
| `scheduler` | a device's own reboot policy |
| `Maintenance: <plan>` | a maintenance plan in its window |
| `Maintenance: <plan> (run by <actor>)` | a plan someone ran by hand |
| `system` | anything else |

**Entries never hold a secret.** Detail keys that look like one (`pass`, `key`,
`secret`, `token`, `psk`) are refused rather than stored, a Wi-Fi password change
records only the bands it reached, and a router error that quotes the new password
is withheld. A TR-069 router's own fault text is left out of every entry for a
Wi-Fi password change, keeping only the fault codes, because it can quote the value
the router refused. The actor always comes from the session or the login name, never from
a request.

```bash
router-manager activity --router cudy1 --limit 20
router-manager activity --kind firmware --csv > firmware.csv
```

The dashboard reads the same log through `GET /api/activity` (filters `router`,
`who`, `kind`, `limit` up to 1000 and `before`, an entry id for the next page or an
ISO 8601 time) and exports it with `GET /api/activity.csv`. The CSV holds every
entry still kept unless `limit` is given, and a cell that starts like a formula is
prefixed with `'` so a spreadsheet shows it rather than runs it.

### Firmware on each kind of router

| Router | Version | Automatic update | Update check | Install |
| --- | --- | --- | --- | --- |
| Cudy (web) | Auto Update page | on or off, with its 2-hour window | the router's own check | not supported |
| TP-Link (11N web UI) | status page | not supported | not supported | not supported |
| Tenda | status | not supported | not supported | not supported |
| OpenWrt (SSH) | `/etc/openwrt_release`, board model | none exists | not supported | not supported |
| TR-069 | reported to GenieACS | not over TR-069 | not over TR-069 | from the firmware library |

```bash
router-manager firmware status cudy1
router-manager firmware check cudy1
router-manager firmware auto-update cudy1 --on --window 3
router-manager firmware auto-update cudy1 --off
```

- `check` asks the router whether newer firmware exists, the way its own Auto Update
  page does. **A check installs nothing.** It takes up to about a minute, during
  which other requests to that router wait. When the router's answer cannot be read
  with certainty the result is `available: null` and the note starts with
  `result not recognised`; SkyRouter never reports an update it has no evidence for.
  `check` exits `1` when it could not tell.
- `auto-update --window HH` picks the router's 2-hour window starting at that hour,
  on the router's own clock. Without `--window` the router keeps the window it has;
  one with no window set is refused, since the router would otherwise take its first
  slot, which nobody chose. SkyRouter reads the page back and fails if the router
  did not keep the change.
- A TP-Link is never logged in to for these: an unsupported call would still count
  towards its ten-failure lockout.

The dashboard routes are `GET /api/devices/{id}/firmware`,
`PUT /api/devices/{id}/firmware/auto-update` with `{"enabled": true,
"window_start_hour": 3}`, and `POST /api/devices/{id}/firmware/check`.

#### TR-069 firmware upgrades

A TR-069 router installs firmware from SkyRouter's library, which lives on the ACS.
GenieACS's file server has to be running first; see "Firmware pushes" in
[deploy/genieacs/README.md](deploy/genieacs/README.md).

```bash
router-manager acs firmware add AP1300-2.5.26.bin --version 2.5.26-20261001-101010 \
  --oui 80AFCA --product-class AP1300 --model-hint "Cudy AP1300"
router-manager acs firmware list
router-manager acs firmware upgrade <acs_id> <name> [--wait SECONDS]
router-manager acs firmware remove <name>
```

- `--version` must be exactly what the router will report as its software version
  once it runs the image, because that is how the upgrade is verified. `--oui` and
  `--product-class` are those of the routers it is for.
- Each file is stored under a random name (`skybre-fw-…`): the file server hands any
  stored file, without authentication, to whoever knows its name.
- An upgrade asks first (`ROUTER_MANAGER_ASSUME_YES=1` for unattended use). It is
  refused while the router is not checking in, when it already runs that version,
  and when it reports another OUI or product class than the file was stored for,
  unless `--confirm-model-mismatch` is given.
- The job is *verified* only when the router reports the file's version after a boot
  later than the request. The router accepting the download proves nothing yet;
  it then has an hour to install and come back. A transfer fault rejects the job.

The dashboard routes are `GET /api/acs/firmware`, `POST /api/acs/firmware` (the image
as the raw `application/octet-stream` body, at most 64 MiB, with `version`, `oui`,
`product_class`, and optionally `filename` and `model_hint`, as query fields or as
`X-Firmware-*` headers), `DELETE /api/acs/firmware/{name}` and
`POST /api/acs/devices/{acs_id}/firmware` with `{"firmware": "<name>", "confirm":
true}`. A model mismatch answers `409` with both sides, to be sent again with
`"confirm_model_mismatch": true`.

### Maintenance plans

A plan names its routers, a weekly or monthly window, the actions to take and the
guards that hold them back. The server runs plans on every scheduler tick, and acts
on each router at most once per window.

```json
{
  "name": "Sunday night",
  "targets": {"devices": ["cudy1", "cudy2"], "acs_devices": ["80AFCA-AP1300-000001"], "all": false},
  "schedule": {"days": ["sun"], "start": "02:00", "duration_minutes": 120, "timezone": "Africa/Johannesburg"},
  "actions": ["firmware_check", "auto_update_on", "firmware_update", "reboot"],
  "firmware": {"AP1300": "skybre-fw-0123456789abcdef0123456789abcdef"},
  "guards": {"min_uptime_seconds": 3600, "skip_if_clients_over": 10, "cooldown_hours": 20}
}
```

- **Targets**: direct routers by device id, TR-069 routers by GenieACS ID, or
  `"all": true` for every enabled direct router and every adopted TR-069 router.
  `"groups"` names whole groups instead, worked out each time the plan runs:
  `direct` (every enabled direct router), `managed` (every adopted TR-069 router)
  and `cudy` (both kinds, Cudy only). A router named twice is visited once.
  Keep each router in one inventory. SkyRouter has no link between a direct device
  and a TR-069 one, so a router in both would be restarted once for each. The one
  case it recognises is a TR-069 router reporting, as its WAN address, the address
  a direct device the plan also names is managed at: that router is held back over
  TR-069 and maintained directly only.
- **Schedule**: `days` (weekly) or `monthly_day` (1 to 28, so every month has it),
  never both; `start` in `HH:MM`, `duration_minutes` from 15 to 480 (default 60),
  and an IANA timezone.
- **Actions** always run in this order, whatever order they are listed in:
  `firmware_check` and `auto_update_on` (directly managed routers that support them,
  which today means Cudy),
  `firmware_update` (TR-069 routers, using the file chosen for their product class)
  and `reboot`. A reboot is skipped after a firmware upgrade was queued, or refused
  because another upgrade is under way, because the upgrade restarts the router
  itself.
- `auto_update_on` turns the router's automatic update on in the 2-hour slot that
  starts at the plan's start hour (`03:30` gives `03:00-05:00`). The router keeps
  that slot on its own clock, which may not be in the plan's timezone, and from then
  on installs updates by itself every day, outside SkyRouter's windows and guards. A
  router whose automatic update is already on is left as it is; when its slot is not
  the plan's start hour, the result says so.
- **TR-069 steps** are queued to expire when the window closes. A router that misses
  the connection request takes the task at its next periodic inform, and one that
  does not inform before the window ends never takes it. Nothing is queued in the
  window's last minute. A router that took a firmware download may still be
  installing it, and restart, up to an hour after the window.
- **Guards**, checked for every router every time, by hand as well:
  `min_uptime_seconds` (default 3600; an unreadable uptime holds the router back),
  `skip_if_clients_over` (off by default) and `cooldown_hours` (default 20). The
  cooldown counts restarts sent by a maintenance plan and by a device's own reboot
  policy. It does not count a reboot or firmware upgrade started from the dashboard
  or the command line; the uptime guard is what holds a router back after one of
  those. Over TR-069 the client limit uses GenieACS's cached host and station
  tables, and holds the router back when they are missing or more than two hours
  old, since an unknown count is not zero. A router that is offline, disabled, not
  checking in, whose credential was rejected, or that has a TR-069 firmware upgrade
  under way is held back too. A held-back router is tried again on later ticks while
  the window lasts, and each reason is logged once per window. A device's own reboot
  policy likewise waits out its cooldown after a plan restarted the router.
- **The window and the plan are checked again** before each router is claimed and
  before each restart, because a pass over a large fleet can outlast its window. A
  router reached after the window closed, or after the plan was turned off, deleted
  or changed to leave it out, is held back. Edits to a plan's guards apply to the
  routers visited after the edit.
- **Once per window**: a router is marked as reached before anything is sent to it,
  so a restart of the server, or a request that timed out, never repeats the work.

```bash
router-manager maintenance list
router-manager maintenance show <plan>
router-manager maintenance run <plan>
```

`run` acts at once, window or not, with the guards still applying. It asks first;
set `ROUTER_MANAGER_ASSUME_YES=1` for unattended use. It exits `1` when an action on
any router failed. A router whose only restart was queued over TR-069 is reported as
`queued` with its job, never as `done`: the job may still fail. It is followed by the
running server, or by `router-manager acs job <job_id> --wait SECONDS` when no server
is running, and its outcome is in the activity log.

Plans live in `maintenance.json` and what each window reached in
`maintenance_state.json`, both in the data directory. A damaged file stops the plans
with an error naming it rather than being treated as empty, which could run a window
twice. The dashboard uses `GET` and `POST /api/maintenance/plans`, `GET`, `PUT` and
`DELETE /api/maintenance/plans/{id}`, `POST /api/maintenance/plans/{id}/run` with
`{"confirm": true}`, and `GET /api/maintenance/runs` for the latest windows. Changes
to plans are written to the server log, not the activity log, which is about
routers; each router a plan acts on is in the activity log under the plan's name.

### What has not been verified on hardware

- **Cudy Auto Update page.** Rebuilt from the field list of a real AP1300 (firmware
  2.5.25, hardware V1.1), not captured whole. Other Cudy models and firmware may
  differ; SkyRouter refuses a page without the switch or the chosen hour rather than
  guess.
- **Cudy update check result.** The page the router shows after a check has never
  been seen, so expect `result not recognised` until one is captured. The check
  itself follows the real page's own script.
- **TR-069 firmware installs.** GenieACS's side follows its 1.2.16 source and is
  tested against a fake NBI only. No router has been upgraded through SkyRouter
  yet, and whether a given router accepts its vendor's image over TR-069 is untested.
- **OpenWrt firmware information** is tested with recorded command output only.
- **A router in both inventories.** Recognising one relies on the WAN address it
  reports over TR-069 being the address SkyRouter manages it at directly, which is
  expected of an AP1300 on a LAN but has not been seen on a real one.
- Direct firmware installs are not supported on any router, and TP-Link firmware
  settings stay excluded.

## Supported hardware

| Vendor | Transport | Notes |
| --- | --- | --- |
| Cudy | Web, LuCI | Login, status, reboot, SSID and Wi-Fi password changes, firmware version, automatic update and update checks. |
| Tenda | Web, `/goform/modules` | Login, status, reboot, SSID changes, firmware version. |
| Any | SSH via Paramiko | Selected by `transport: ssh`. Firmware version from OpenWrt's release file. |
| Any with TR-069 | CWMP through GenieACS | Optional; see [TR-069 through GenieACS](#tr-069-through-genieacs-optional). Firmware upgrades from the library. |

Not supported: the Tenda ME3 Pro BE3600, which uses a separate encrypted API.
Changing a Wi-Fi SSID over SSH needs `metadata.uci_section`; the CLI can only create
web-transport Cudy and Tenda devices, so SSH devices are added by editing the config
by hand.

### TP-Link

The older TP-Link web UI (WR840N and similar) authenticates with HTTP Basic, but
only through a cookie rather than an `Authorization` header. The login page
builds the credential in JavaScript and stores it:

```js
auth = "Basic " + base64(username + ":" + password)
document.cookie = "Authorization=" + auth
```

**This firmware locks the web UI for two hours after ten failed logins.** The
adapter therefore authenticates once per session and never retries, and it
reports the router's own `authTimes` counter so a wrong password is
distinguishable from an existing lockout. If a password is rejected, fix it in
the dashboard rather than re-running the command in a loop.

Supported: status (model, firmware, uptime), connected clients, and reboot.
Changing the SSID is deliberately not supported on this family, because a bad
write can drop you off the router mid-change.

The adapters are written against the vendors' documented request shapes and every
test runs against mocked transports. **This has not been verified against real Cudy or
Tenda hardware.** Confirm status and reboot behaviour on a device you can reach before
enabling scheduled reboots on anything you depend on.

SSH rejects unknown host keys by default. Verify a device's key before enabling SSH
transport, and prefer pre-seeding known hosts over turning on auto-add.

## Tests

```bash
.venv/bin/pytest
.venv/bin/ruff check .
.venv/bin/mypy cudy_manager
```

## Project layout

```
cudy_manager/
  models.py         device and reboot policy, validation
  secrets.py        Fernet key and encrypted vault
  http_client.py    cookie-aware HTTP, charset and URL scheme handling
  adapters.py       Cudy, Tenda, and TP-Link adapters
  openwrt.py        SSH/UCI adapter
  manager.py        inventory, secrets, adapters, status
  activity.py       the activity log: who changed what on which router
  scheduler.py      guarded scheduled reboots, and the tick that runs maintenance plans
  maintenance.py    maintenance plans, their windows, guards and runner
  discovery.py      bounded opt-in discovery
  web.py            FastAPI service, sessions, CSRF
  cli.py            command line entry point
  dashboard.html    dashboard
  acs/              GenieACS: NBI client, parameter map, jobs, bootstrap
    provisions/     SkyRouter's provisions, installed into GenieACS by the bootstrap
deploy/
  genieacs/         GenieACS runbook, units, env template, extension, MongoDB scripts
  skyrouter/        optional systemd unit for SkyRouter
tests/              TEST_COUNT tests, all mocked
```

## Licence

Private project. No licence granted.
