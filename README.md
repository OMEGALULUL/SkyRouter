# Router Manager

Standalone manager for Cudy and Tenda consumer routers. Encrypted credential storage,
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
router-manager add <id> <host> --vendor cudy|tenda [--username admin] [--model X]
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

`discover` is bounded to one subnet and never runs automatically.

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
  adapters.py       Cudy and Tenda adapters
  openwrt.py        SSH/UCI adapter
  manager.py        inventory, secrets, adapters, status
  scheduler.py      guarded scheduled reboots
  discovery.py      bounded opt-in discovery
  web.py            FastAPI service, sessions, CSRF
  cli.py            command line entry point
  dashboard.html    dashboard
tests/              118 tests, all mocked
```

## Licence

Private project. No licence granted.
