# GenieACS for SkyRouter: operator runbook

SkyRouter manages TR-069 routers through [GenieACS](https://genieacs.com) 1.2.16.
GenieACS runs unmodified as separate services on this host, and SkyRouter talks to
it only through its REST API (the NBI) on `127.0.0.1:7557`. Nothing in this
directory is run by SkyRouter; an operator runs it once per host, with `sudo`
where shown.

Run every command from the repository root. Commands that need no root run
without `sudo`, so the environment variables they read reach them.

## What runs, and who can reach it

| Service | Port | Listens on | Reached by | Authentication |
|---|---|---|---|---|
| `genieacs-cwmp` | 7547 | every address (`::`) | routers, through the firewall | `cwmp.auth` (step 6) |
| `genieacs-nbi` | 7557 | `127.0.0.1` only | SkyRouter only | **none** |
| `mongod` | 27017 | `127.0.0.1` only | cwmp and nbi | on (step 1) |
| `genieacs-fs` | 7567 | every address | routers, from phase 3 | none; unit installed, not enabled |
| `genieacs-ui` | 3000 | | nobody | never installed or run |

Rules that hold on every host:

- **Never open 7557, 3000 or 27017 in the firewall, and never proxy the NBI.** It
  has no authentication and hands out `cwmp.auth`, users and every device to
  anyone who reaches it (CVE-2025-56015). The NBI unit pins `--nbi-interface
  127.0.0.1` on its command line, which overrides the env file.
- **Never run `genieacs-ui`.** On an empty database its setup wizard is open to
  anyone and creates `admin`/`admin`. SkyRouter replaces it.
- **Never set `GENIEACS_DEBUG_FILE` outside a lab.** It dumps SOAP traffic,
  including Wi-Fi passphrases.
- **Never edit the `skybre-*` presets by hand.** One malformed preset can stop
  GenieACS loading presets at all. `router-manager acs bootstrap` validates them.
- **Secrets are read from the environment** by the scripts here, never passed as
  arguments, so they do not show in the process list or shell history.

## Files

| File | Installed as | Purpose |
|---|---|---|
| `VERSION` | | the pinned release, its npm integrity and how to check it |
| `genieacs.env.example` | `/etc/genieacs/genieacs.env` | settings for the three services; no secrets |
| `render-env.sh` | | fills the env template's secrets from the environment |
| `systemd/genieacs-{cwmp,nbi,fs}.service` | `/etc/systemd/system/` | units with `Restart=on-failure` and hardening |
| `ext/skyrouter.js` | `/opt/genieacs/ext/skyrouter.js` | extension that derives each router's connection-request password |
| `mongo/create-users.js` | | mongosh: the `genieacs` database account and device indexes |
| `mongo/set-cwmp-auth.js` | | mongosh: the username and secret every router must present |
| `logrotate/genieacs` | `/etc/logrotate.d/genieacs` | daily rotation of `/var/log/genieacs` |
| `smoke-test.sh` | | read-only health checks (step 8) |
| `../skyrouter/router-manager.service`, `.env.example` | `/etc/systemd/system/`, `/etc/skyrouter/` | optional: SkyRouter as a service |

## Parameters

This laptop moves between networks (for example `192.168.3.0/24` and
`10.247.89.0/24`), and has the stable VPN address `10.10.0.2` on `wg0`. Only three
things depend on the network: which subnet the firewall lets in, the ACS URL a
router is given, and the address the smoke test checks. Set these at the start of
each shell session:

```bash
# Lab: the LAN this laptop is on right now.
LAN_IF=wlo1
ACS_ADDR=$(ip -4 -o addr show dev "$LAN_IF" | awk '{ split($4, a, "/"); print a[1]; exit }')
LAN_SUBNET=$(ip -4 route show dev "$LAN_IF" proto kernel scope link | awk '{ print $1; exit }')
echo "ACS address $ACS_ADDR, LAN $LAN_SUBNET"

# Production: routers reach the ACS over the VPN.
VPN_IF=wg0
VPN_ADDR=10.10.0.2
```

The GenieACS configuration itself does not depend on the network. File-server
URLs follow whichever address a router used to reach CWMP, so nothing has to be
re-rendered when the laptop moves.

---

## Install (once per host, the same for lab and production)

### Step 1: MongoDB 8.0

Mint's `lsb_release -cs` prints `zena`, so the Ubuntu base `noble` is written out.
MongoDB 7.0 has no noble packages; 8.0 does.

```bash
curl -fsSL https://www.mongodb.org/static/pgp/server-8.0.asc | sudo gpg --dearmor -o /usr/share/keyrings/mongodb-server-8.0.gpg
echo "deb [ arch=amd64 signed-by=/usr/share/keyrings/mongodb-server-8.0.gpg ] https://repo.mongodb.org/apt/ubuntu noble/mongodb-org/8.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-8.0.list
sudo apt-get update && sudo apt-get install -y mongodb-org && sudo apt-mark hold mongodb-org mongodb-org-server
sudo systemctl enable --now mongod
grep -n 'bindIp' /etc/mongod.conf        # must show 127.0.0.1 and nothing else
mongosh --nodb --quiet --eval 'disableTelemetry()'
```

Create the administrator while authorization is still off (mongod only listens on
loopback, so the window is local), then turn authorization on:

```bash
mongosh --quiet "mongodb://127.0.0.1:27017/admin" --eval '
  db.createUser({user: "admin", pwd: passwordPrompt(),
    roles: [{role: "userAdminAnyDatabase", db: "admin"}, {role: "readWriteAnyDatabase", db: "admin"}]})'
grep -q '^security:' /etc/mongod.conf || printf '\nsecurity:\n  authorization: enabled\n' | sudo tee -a /etc/mongod.conf
grep -n -A1 '^security:' /etc/mongod.conf   # must show authorization: enabled
sudo systemctl restart mongod
mongosh --quiet "mongodb://127.0.0.1:27017/admin" --username admin \
  --eval 'db.runCommand({connectionStatus: 1}).authInfo.authenticatedUsers' --password
```

Keep the admin password in the vault. The later steps log in with it, and it
never goes into any file here.

### Step 2: a system copy of Node

Node 22.23.2 is already installed in `/home/linux/node`, but `/home/linux` is mode
750, so the service user cannot run it. Copy it; nothing is downloaded.

```bash
sudo cp -a /home/linux/node /opt/node-v22.23.2 && sudo chown -R root:root /opt/node-v22.23.2
/opt/node-v22.23.2/bin/node --version    # v22.23.2
```

The units put `/opt/node-v22.23.2/bin` on `PATH`, because GenieACS's binaries and
its extension runner start with `#!/usr/bin/env node`. For a different Node
version, name the directory after it and change `Environment=PATH=` in the three
units to match.

### Step 3: the GenieACS package, service user and directories

Check the registry still reports the integrity recorded in `VERSION` before
installing anything:

```bash
npm view genieacs@1.2.16 dist.integrity
grep integrity deploy/genieacs/VERSION     # the two values must be identical
```

Everything under `/opt/genieacs` belongs to root and is read-only to the service:

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin --user-group genieacs
sudo install -d -m 0755 /opt/genieacs
sudo env PATH=/opt/node-v22.23.2/bin:/usr/bin:/bin npm install --prefix /opt/genieacs --omit=dev --ignore-scripts --save-exact genieacs@1.2.16
sudo install -d -o root -g genieacs -m 0750 /opt/genieacs/ext
sudo install -m 0644 deploy/genieacs/ext/skyrouter.js /opt/genieacs/ext/
sudo -u genieacs /opt/node-v22.23.2/bin/node --check /opt/genieacs/ext/skyrouter.js
sudo install -d -o genieacs -g genieacs -m 0750 /var/log/genieacs
sudo install -d -o root -g genieacs -m 0750 /etc/genieacs
```

Then confirm what npm installed is what `VERSION` records:

```bash
/opt/node-v22.23.2/bin/node -p 'require("/opt/genieacs/package-lock.json").packages["node_modules/genieacs"].integrity'
```

The package's own `npm-shrinkwrap.json` pins every transitive dependency by
integrity too. On any mismatch, stop and find out why before going further.
[Verify the GenieACS package](#verify-the-genieacs-package) has an independent check.

### Step 4: secrets, the database account and the env file

Two secrets are generated here. Neither needs writing down: both end up only in
`/etc/genieacs/genieacs.env` (mode 0640, root:genieacs).

| Secret | Used by |
|---|---|
| `ACS_DB_PASSWORD` | GenieACS's MongoDB login (`genieacs`, readWrite on the `genieacs` database) |
| `SKYROUTER_CR_SECRET` | `ext/skyrouter.js`: each router's connection-request password is HMAC-SHA256(secret, device ID), cut to 32 hex characters |

```bash
umask 077
export ACS_DB_PASSWORD="$(openssl rand -hex 24)"
export SKYROUTER_CR_SECRET="$(openssl rand -hex 32)"
mongosh "mongodb://127.0.0.1:27017/admin" --username admin \
  --file deploy/genieacs/mongo/create-users.js --password
out=$(deploy/genieacs/render-env.sh) &&
  printf '%s\n' "$out" | sudo install -o root -g genieacs -m 0640 /dev/stdin /etc/genieacs/genieacs.env
unset out ACS_DB_PASSWORD SKYROUTER_CR_SECRET
sudo grep -c '{{' /etc/genieacs/genieacs.env   # must print 0
```

`create-users.js` is safe to run again; for an existing account it only sets the
new password. `render-env.sh` prints nothing unless every placeholder was filled,
so a mistake leaves no half-written env file to install. For later changes that
are not secrets, `sudoedit /etc/genieacs/genieacs.env`.

To rotate either secret, repeat this step and restart the services. A new
`SKYROUTER_CR_SECRET` changes every router's connection-request password at its
next check-in, and connection requests to a router fail until then.

### Step 5: units and log rotation

```bash
sudo install -m 0644 deploy/genieacs/systemd/genieacs-{cwmp,nbi,fs}.service /etc/systemd/system/
sudo install -m 0644 deploy/genieacs/logrotate/genieacs /etc/logrotate.d/genieacs
sudo systemctl daemon-reload && sudo systemctl enable --now genieacs-cwmp genieacs-nbi
systemctl status --no-pager genieacs-cwmp genieacs-nbi
```

`genieacs-fs` is installed but stays disabled until firmware pushes (phase 3).
GenieACS's own guide ships units with no `Restart=`; these restart on failure,
because the primary process exits after repeated worker crashes.

### Step 6: router authentication

Without `cwmp.auth` GenieACS accepts any client that reaches port 7547, so this
comes before any router is pointed at the ACS. Every router logs in with one
shared username and secret.

Create the secret in the vault first (48 hex characters, or `openssl rand -hex 24`
in a terminal nobody else can see) and store it there: routers need it, and it
cannot be read back from anywhere but MongoDB.

```bash
export CPE_USER=skybre-cpe
read -rs -p 'CPE secret (hex, from the vault): ' CPE_SECRET; echo; export CPE_SECRET
mongosh "mongodb://127.0.0.1:27017/admin" --username admin \
  --file deploy/genieacs/mongo/set-cwmp-auth.js --password
unset CPE_SECRET
```

This stores `AUTH("skybre-cpe", "<secret>")` as `cwmp.auth` and makes GenieACS
reload it within about 5 seconds. The NBI cannot write config, which is why this
is a database script.

---

## Lab quick start (on the LAN IP)

For trying routers on the bench. After steps 1-6, with the
[parameters](#parameters) set for the LAN the laptop is on:

### Step 7 (lab): let the LAN in

```bash
sudo ufw status verbose | grep -i '^default'   # incoming must be deny
sudo ufw allow from "$LAN_SUBNET" to any port 7547 proto tcp comment 'genieacs-cwmp lab'
```

Only CWMP is opened. Remove the rule when leaving that network, so the next
network with the same numbering gets nothing:

```bash
sudo ufw delete allow from "$LAN_SUBNET" to any port 7547 proto tcp
sudo ufw status numbered      # or find the 'genieacs-cwmp lab' rule here and: sudo ufw delete <number>
```

On another lab network, set the [parameters](#parameters) again, add the rule for
that subnet and re-point the routers there: their ACS URL holds the old address.

### Step 8 (lab): smoke test

```bash
deploy/genieacs/smoke-test.sh "$ACS_ADDR"
```

It sends only GET and HEAD requests and prints no secret. It expects:

- `GET http://127.0.0.1:7557/` answers 404 with `GenieACS-Version: 1.2.16+…`;
- `HEAD /presets` answers 200 with a `total` header, which proves the MongoDB login works;
- the NBI and MongoDB listen on loopback only, and the NBI does not answer on `$ACS_ADDR`;
- `cwmp.auth` exists (checked with a HEAD, which returns a count, never the value);
- CWMP answers `405` to a GET on `http://$ACS_ADDR:7547/`;
- both units are active and systemd has not had to restart them.

Watch the logs for a crash loop for a minute or two as well. The bundled MongoDB
driver is officially untested against MongoDB 8.0, and this is where that shows:

```bash
journalctl -u genieacs-cwmp -u genieacs-nbi --since -10min --no-pager
sudo tail -n 50 /var/log/genieacs/cwmp.log /var/log/genieacs/nbi.log
```

### Step 9 (lab): point one router at the ACS

| Router setting | Value |
|---|---|
| ACS URL | `http://$ACS_ADDR:7547/` (print it with `echo "http://$ACS_ADDR:7547/"`) |
| ACS username | `skybre-cpe` |
| ACS password | the CPE secret from the vault |
| Periodic inform | enabled; the interval is set by SkyRouter's `skybre-inform` preset |
| Connection-request username and password | leave as they are; `skybre-inform` sets them |

On Cudy this is System > TR069, with Data Model set to TR-181.

A router that is also a direct device in SkyRouter is then in both inventories. A
maintenance plan with `"all": true`, or naming it both ways, would restart it once
for each, so keep each router in one inventory (see Maintenance plans in the main
README).

A DHCP reservation for the laptop keeps `$ACS_ADDR` from changing under the
router. Confirm the router checked in (the projection keeps the output to IDs
and times):

```bash
curl -s -G http://127.0.0.1:7557/devices --data-urlencode 'projection=_id,_lastInform' --data-urlencode 'limit=20'
sudo grep -c 'Authentication failure' /var/log/genieacs/cwmp-access.log   # wrong secret on the router if this grows
```

### Step 10 (lab): connect SkyRouter

```bash
export ROUTER_MANAGER_ACS_URL=http://127.0.0.1:7557
router-manager acs status
router-manager acs bootstrap
```

`router-manager acs status` exits non-zero until the bootstrap is installed and
the presets GenieACS's UI seeds are gone; `router-manager acs bootstrap
--remove-seeded` deletes those. Run the `acs` commands with the server's
environment: for the service in [Run SkyRouter as a service](#run-skyrouter-as-a-service)
that means as the `skyrouter` user with `ROUTER_MANAGER_DATA_DIR=/var/lib/skyrouter`
and the same `ROUTER_MANAGER_ACS_*` values, so the CLI and the server share
`acs_jobs.json` and the vault.

Without the bootstrap routers get no inform interval and no connection-request
credentials: GenieACS ships no default provisioning unless its UI creates it.
Connection requests to a router only work after its first session that ran
`skybre-inform`; until then changes wait for the router's next periodic check-in.

Leave `ROUTER_MANAGER_ACS_URL` unset and SkyRouter behaves exactly as it did
without GenieACS.

---

## Production (routers over the VPN)

Routers reach the ACS at the stable VPN address, so moving the laptop between
networks changes nothing for them. Do steps 1-6, then:

### Step 7 (production): only the VPN gets in

```bash
sudo ufw allow in on "$VPN_IF" to any port 7547 proto tcp comment 'genieacs-cwmp vpn'
sudo ufw status numbered      # delete any 'genieacs-cwmp lab' rules: sudo ufw delete <number>
```

### Step 8 (production): smoke test

```bash
deploy/genieacs/smoke-test.sh "$VPN_ADDR"
```

The same checks as in the lab, against `10.10.0.2`.

### Step 9 (production): routers

As in the lab, with the ACS URL `http://10.10.0.2:7547/`. Each router must be able
to reach `10.10.0.2` over the VPN.

### Step 10 (production): SkyRouter

As in the lab. To run SkyRouter as a service, see
[Run SkyRouter as a service](#run-skyrouter-as-a-service).

### Running it long term

- **Plain HTTP.** CWMP here is unencrypted; Digest protects only the login.
  Wi-Fi passphrases SkyRouter sets cross the network in clear text, which is
  why routers belong on the VPN. GenieACS also keeps the last passphrase it sent
  in MongoDB until SkyRouter re-reads it (`ROUTER_MANAGER_ACS_SCRUB_SECRETS=1`).
- **VPN-only CWMP (optional).** To stop CWMP listening on the LAN at all, set
  `GENIEACS_CWMP_INTERFACE=10.10.0.2` in the env file. The address must exist
  before the unit starts; if `wg-quick` brings the tunnel up, order the unit after
  it with `sudo systemctl edit genieacs-cwmp`:

  ```ini
  [Unit]
  After=wg-quick@wg0.service
  Requires=wg-quick@wg0.service
  ```

  The lab quick start then no longer works on this host.
- **Backups.** The database holds `cwmp.auth` and, briefly, passphrases, so keep
  dumps encrypted and private:

  ```bash
  (umask 077; mongodump --host 127.0.0.1 --port 27017 --db genieacs --username admin \
    --authenticationDatabase admin --gzip --archive="genieacs-$(date +%F).archive.gz")
  ```

  `mongodump` prompts for the password when `--password` is left out.
- **Logs.** `/var/log/genieacs/*.log`, rotated daily and kept 30 days. Start, stop
  and restart events are in `journalctl -u genieacs-cwmp -u genieacs-nbi`.
- **Monitoring.** Run `deploy/genieacs/smoke-test.sh "$VPN_ADDR"` after every
  change and from a daily timer; it exits non-zero on any failure.
- **Upgrades.** SkyRouter is pinned to the release in `VERSION` and refuses 1.3.x.
  Upgrade GenieACS only after SkyRouter has been tested against the new release,
  and update `VERSION` in the same change. MongoDB is held with `apt-mark hold`;
  unhold it deliberately. For a new Node, copy it to its own `/opt/node-v…`
  directory, change `Environment=PATH=` in the three units, then
  `sudo systemctl daemon-reload` and restart.
- **Firmware pushes (phase 3).** See [Firmware pushes](#firmware-pushes).

## Firmware pushes

SkyRouter's TR-069 firmware upgrades (`router-manager acs firmware`, described in
the top-level README) store each image in GenieACS through the NBI, and the router
then fetches it from `genieacs-fs` on port 7567. Uploading works without the file
server; an upgrade does not, so enable it before the first one:

```bash
sudo systemctl enable --now genieacs-fs
systemctl status --no-pager genieacs-fs
```

**`genieacs-fs` has no authentication.** It hands any stored file to anyone who
can reach 7567 and knows the file's name. So:

- **Routers reach it over the VPN only.** Open 7567 on the VPN interface alone, the
  way [step 7 (production)](#step-7-production-only-the-vpn-gets-in) opens 7547,
  and never on a LAN or public interface. Push firmware to production routers
  only, not to lab routers on the LAN.
- **Names are unguessable.** SkyRouter stores every image as `skybre-fw-` followed
  by 32 random hex characters, and only ever points a router at such a name. Do
  not upload files to GenieACS by hand, where a readable name such as
  `AP1300.bin` would be served to anyone who guessed it.
- **Nothing secret goes in.** Never store a configuration backup or anything else
  holding a password; the file store is only for firmware images.
- **Remove what is no longer needed** with `router-manager acs firmware remove
  <name>`, which deletes it from GenieACS too. SkyRouter refuses while an upgrade is
  still using the file.

The address in each Download request is `GENIEACS_FS_URL_PREFIX` followed by the
file name. Leave the prefix unset, as `genieacs.env.example` has it, and the address
follows the one the router used to reach CWMP. Set it, with the trailing `/`, only
when routers must fetch files from somewhere else, such as behind a proxy or with
`genieacs-fs` on another host:

```bash
sudoedit /etc/genieacs/genieacs.env      # GENIEACS_FS_URL_PREFIX=http://10.10.0.2:7567/
sudo systemctl restart genieacs-cwmp genieacs-fs
```

`genieacs-cwmp` writes the Download requests, so it needs the restart as well as
the file server. Each fetch is logged in `/var/log/genieacs/fs-access.log`, which
is the first place to look when a router accepted an upgrade but never installed
it:

```bash
sudo tail -n 20 /var/log/genieacs/fs-access.log
```

---

## Run SkyRouter as a service

Optional. Running `router-manager serve` by hand from a checkout keeps working.
The unit runs it as its own user with its state in `/var/lib/skyrouter`.

```bash
sudo useradd --system --no-create-home --home-dir /var/lib/skyrouter --shell /usr/sbin/nologin --user-group skyrouter
.venv/bin/pip wheel --no-deps -w dist/ .          # built as you, so no root-owned files land in the checkout
sudo python3.12 -m venv /opt/skyrouter/venv
sudo /opt/skyrouter/venv/bin/pip install dist/skybre_router_manager-*.whl
sudo install -d -o root -g skyrouter -m 0750 /etc/skyrouter
sudo install -o root -g skyrouter -m 0640 deploy/skyrouter/router-manager.env.example /etc/skyrouter/router-manager.env
sudoedit /etc/skyrouter/router-manager.env      # set ROUTER_MANAGER_PASSWORD
sudo install -m 0644 deploy/skyrouter/router-manager.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now router-manager
```

The dashboard is then on `http://127.0.0.1:8091`. To move an existing vault,
stop the old server and copy everything in its data directory
(`ROUTER_MANAGER_DATA_DIR`, by default `~/.local/state/skybre-router-manager`)
into `/var/lib/skyrouter`, owned by `skyrouter` and keeping the 0600 modes.
Without `master.key` the vault cannot be decrypted.

## Verify the GenieACS package

`VERSION` records the npm integrity of `genieacs-1.2.16.tgz` as it was checked on
2026-09-28, and lists four checks. Step 3 runs two of them (the registry before
installing, the lockfile after). The independent one hashes the tarball
without trusting npm's own verification:

```bash
d=$(mktemp -d) && npm pack genieacs@1.2.16 --pack-destination "$d" >/dev/null &&
  printf 'sha512-%s\n' "$(openssl dgst -sha512 -binary "$d/genieacs-1.2.16.tgz" | openssl base64 -A)"
grep integrity deploy/genieacs/VERSION
```

## Troubleshooting

| Symptom | Likely cause and fix |
|---|---|
| A unit keeps restarting | `journalctl -u <unit> -n 50` and `/var/log/genieacs/<svc>.log`. `Authentication failed`: the password in the env file does not match the database account; repeat step 4. `MongoServerSelectionError`: mongod is down. `Too many crashes, exiting`: workers died repeatedly, often for one of those two reasons. |
| A unit fails at once with "Operation not permitted" | Possibly the syscall filter. Confirm with `sudo systemctl edit <unit>`, adding `[Service]` and an empty `SystemCallFilter=`, then restart; report it so the unit can be fixed. |
| Router never appears | Firewall rule for its network (step 7), the ACS URL on the router, and `Authentication failure` lines in `/var/log/genieacs/cwmp-access.log` (wrong CPE secret). |
| `ext.Error` fault on `skybre-inform` | `SKYROUTER_CR_SECRET` is missing or shorter than 32 hex characters in the env file. Fix it, then `sudo systemctl restart genieacs-cwmp`: the extension process only reads its environment when it starts. |
| Connection request reports `Device is offline` | The router is behind NAT or blocks its connection-request port, or this host has no route to it. Queued changes still apply at the router's next periodic check-in (300 s by default). |
| `router-manager acs bootstrap` refuses seeded presets | `genieacs-ui` was run at some point and created `bootstrap`, `default` and `inform`. Re-run with `--remove-seeded`, and check nothing else from the UI (such as `users`) is left. |
| Smoke test: NBI version is not 1.2.16 | Another GenieACS is installed or `/opt/genieacs` was upgraded. SkyRouter refuses 1.3.x. |

## Licensing

GenieACS is AGPL-3.0 and runs here unmodified, as separate processes. None of its
code is in this repository: every file in this directory is SkyRouter's own,
written against GenieACS's documented behaviour. `ext/skyrouter.js` runs inside
GenieACS's extension process and the provisions run inside genieacs-cwmp, so
consider putting those under a permissive licence such as MIT (an owner decision,
not legal advice).
