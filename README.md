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

Open <http://127.0.0.1:8091> and log in as `admin`, or set `ROUTER_MANAGER_USERNAME`.

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
router-manager discover [--subnet 192.168.1.0/24]
router-manager serve [--host 127.0.0.1] [--port 8091]
```

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
| `ROUTER_MANAGER_PASSWORD` | none | Web login password. Without it every endpoint returns `503`. |
| `AUTH_PASSWORD` | none | Fallback read when the above is unset. |
| `ROUTER_MANAGER_USERNAME` | `admin` | Web login username. |
| `AUTH_USERNAME` | `admin` | Fallback read when the above is unset. |
| `ROUTER_MANAGER_CONFIG` | `<package>/cudy_devices.yaml` | Device inventory path. |
| `ROUTER_MANAGER_DATA_DIR` | `~/.local/state/skybre-router-manager` | Key, vault, scheduler state. |
| `ROUTER_MANAGER_SCHEDULER_INTERVAL` | `30` | Scheduler tick in seconds, minimum `15`. |
| `ROUTER_MANAGER_SECURE_COOKIE` | `0` | Set to `1` when served over HTTPS. |
| `ROUTER_MANAGER_DEVICE_PASSWORD` | none | Password used by `set-password` with `ROUTER_MANAGER_ASSUME_YES=1`. |
| `ROUTER_MANAGER_TRUST_PROXY` | unset | Honour `X-Forwarded-For` for login throttling. Only enable behind a proxy that overwrites the header. |
| `ROUTER_MANAGER_ASSUME_YES` | unset | Set to `1` to skip the interactive confirmation. Unattended use only. |

## Resetting a password

If a router password is wrong, mistyped, or changed on the device itself, replace the
stored copy. From the dashboard, use the **Password** button on the device card: enter
it twice, then save. The result tells you whether the router accepted it.

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

## Supported hardware

| Vendor | Transport | Notes |
| --- | --- | --- |
| Cudy | Web, LuCI | Login, status, reboot, SSID changes. |
| Tenda | Web, `/goform/modules` | Login, status, reboot, SSID changes. |
| Any | SSH via Paramiko | Selected by `transport: ssh`. |

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
  scheduler.py      guarded scheduled reboots
  discovery.py      bounded opt-in discovery
  web.py            FastAPI service, sessions, CSRF
  cli.py            command line entry point
  dashboard.html    dashboard
tests/              285 tests, all mocked
```

## Licence

Private project. No licence granted.
