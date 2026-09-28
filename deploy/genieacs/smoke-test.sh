#!/usr/bin/env bash
# Read-only checks that GenieACS is installed the way SkyRouter needs it
# (README step 8). It sends only GET and HEAD requests, changes nothing and
# prints no secret: the one check on config is a HEAD, which returns a count
# and no document.
#
# Usage: deploy/genieacs/smoke-test.sh [ACS_ADDR]
#   ACS_ADDR     the address routers use to reach this host (the LAN IP in the
#                lab, 10.10.0.2 in production). With it, CWMP must answer there
#                and the NBI must not.
# Environment (all optional):
#   NBI_URL      default http://127.0.0.1:7557
#   CWMP_PORT    default 7547
#   MONGO_PORT   default 27017; 0 skips the MongoDB bind check
#   SKIP_SYSTEMD 1 skips the unit checks (for hosts without these units)
#
# Exit status: 0 when nothing failed (warnings allowed), 1 otherwise.
set -uo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
acs_addr=${1:-${ACS_ADDR:-}}
nbi_url=${NBI_URL:-http://127.0.0.1:7557}
nbi_url=${nbi_url%/}
cwmp_port=${CWMP_PORT:-7547}
mongo_port=${MONGO_PORT:-27017}
skip_systemd=${SKIP_SYSTEMD:-0}
timeout=5
expected=$(head -n1 "$here/VERSION")

failures=0
warnings=0
pass() { printf 'PASS  %s\n' "$*"; }
info() { printf 'INFO  %s\n' "$*"; }
warn() { printf 'WARN  %s\n' "$*"; warnings=$((warnings + 1)); }
fail() { printf 'FAIL  %s\n' "$*"; failures=$((failures + 1)); }

# request METHOD URL [QUERY_JSON]: sets STATUS (000 when nothing answered) and
# HEADERS. Bodies are always discarded, so no document is ever printed.
STATUS=000
HEADERS=""
request() {
    local method=$1 url=$2 query=${3:-} out
    local args=(-sS --max-time "$timeout" --noproxy '*' -o /dev/null -D - -w '%{http_code}')
    [[ $method == HEAD ]] && args+=(-I)
    # URLSearchParams on the NBI side: form-encode, never send a raw query.
    [[ -n $query ]] && args+=(-G --data-urlencode "query=$query")
    if out=$(curl "${args[@]}" "$url" 2>/dev/null); then
        STATUS=${out: -3}
        HEADERS=${out%???}
    else
        STATUS=000
        HEADERS=""
    fi
}

header() {
    printf '%s' "$HEADERS" | tr -d '\r' | awk -v name="$1" '
        tolower(substr($0, 1, length(name) + 1)) == tolower(name) ":" {
            sub(/^[^:]*:[ \t]*/, ""); print; exit
        }'
}

# count COLLECTION [QUERY_JSON]: sets COUNT to the NBI's total header, or to
# "" when the NBI did not answer 200 (STATUS says what it did answer).
COUNT=""
count() {
    request HEAD "$nbi_url/$1" "${2:-}"
    COUNT=""
    if [[ $STATUS == 200 ]]; then
        COUNT=$(header total)
    fi
}

# listening_addresses PORT: the local addresses with a TCP listener on PORT.
listening_addresses() {
    ss -Hltn "sport = :$1" 2>/dev/null | awk '{ print $4 }' | sed 's/:[0-9]*$//'
}

only_loopback() {
    local port=$1 what=$2 addrs addr bad=""
    if ! command -v ss >/dev/null 2>&1; then
        warn "ss is not installed; cannot check which addresses $what listens on"
        return
    fi
    addrs=$(listening_addresses "$port")
    if [[ -z $addrs ]]; then
        warn "nothing is listening on port $port ($what)"
        return
    fi
    # A wildcard bind shows up as "*", so read line by line rather than let the
    # shell glob it into file names.
    while IFS= read -r addr; do
        case $addr in
            127.* | "[::1]" | "[::ffff:127."*) ;;
            *) bad+=" $addr" ;;
        esac
    done <<<"$addrs"
    if [[ -n $bad ]]; then
        fail "$what listens on non-loopback address(es):$bad (port $port must stay on 127.0.0.1)"
    else
        pass "$what listens on loopback only (port $port)"
    fi
}

echo "GenieACS smoke test: NBI $nbi_url, expecting $expected"

# 1. The NBI answers GET / from memory with 404 and its version.
request GET "$nbi_url/"
version=$(header GenieACS-Version)
if [[ $STATUS == 000 ]]; then
    fail "the NBI at $nbi_url does not answer (is genieacs-nbi running?)"
elif [[ $STATUS != 404 || -z $version ]]; then
    fail "GET $nbi_url/ returned $STATUS without a GenieACS-Version header; is this the NBI?"
elif [[ $version == "$expected" || $version == "$expected+"* ]]; then
    pass "NBI version $version"
else
    fail "NBI version is $version, SkyRouter is pinned to $expected (never 1.3.x)"
fi

# 2. HEAD /presets goes through MongoDB, so a 200 with a total proves the
#    database login works.
count presets
if [[ -n $COUNT ]]; then
    pass "MongoDB reachable through the NBI ($COUNT preset(s))"
else
    fail "HEAD /presets returned $STATUS; check GENIEACS_MONGODB_CONNECTION_URL and mongod"
fi

nbi_port=${nbi_url##*:}
nbi_port=${nbi_port%%/*}
only_loopback "$nbi_port" "the NBI"
if [[ $mongo_port != 0 ]]; then
    only_loopback "$mongo_port" "MongoDB"
fi

# 3. Router authentication. Without cwmp.auth every client is accepted.
count config '{"_id":"cwmp.auth"}'
if [[ $COUNT == 1 ]]; then
    pass "cwmp.auth is configured"
elif [[ -n $COUNT ]]; then
    fail "cwmp.auth is not configured, so GenieACS accepts any router; run mongo/set-cwmp-auth.js"
else
    fail "could not check cwmp.auth (HEAD /config returned $STATUS)"
fi

# 4. Leftovers from genieacs-ui's setup wizard, which SkyRouter never runs.
count presets '{"_id":{"$in":["bootstrap","default","inform"]}}'
if [[ -n $COUNT && $COUNT != 0 ]]; then
    warn "$COUNT UI-seeded preset(s) exist; router-manager acs bootstrap refuses until they are removed"
fi
count users
if [[ -n $COUNT && $COUNT != 0 ]]; then
    warn "$COUNT genieacs-ui user(s) exist; the wizard's admin/admin account may be among them"
fi

# 5. SkyRouter's own presets and their faults (after router-manager acs bootstrap).
count presets '{"_id":{"$in":["skybre-bootstrap","skybre-registered","skybre-inform","skybre-refresh"]}}'
if [[ ${COUNT:-0} == 4 ]]; then
    pass "SkyRouter's four presets are installed"
else
    info "${COUNT:-0} of SkyRouter's 4 presets installed; run router-manager acs bootstrap once SkyRouter is connected"
fi
count faults '{"channel":{"$in":["skybre-bootstrap","skybre-inform","skybre-refresh"]}}'
if [[ -n $COUNT && $COUNT != 0 ]]; then
    warn "$COUNT fault(s) on SkyRouter's channels; an ext.Error on skybre-inform means SKYROUTER_CR_SECRET is missing"
fi

# 6. What routers see at ACS_ADDR.
if [[ -n $acs_addr ]]; then
    request GET "http://$acs_addr:$cwmp_port/"
    if [[ $STATUS == 405 ]]; then
        pass "CWMP answers at http://$acs_addr:$cwmp_port/ (405 to a GET is expected)"
    else
        fail "CWMP at http://$acs_addr:$cwmp_port/ returned $STATUS instead of 405"
    fi
    nbi_host=${nbi_url#*://}
    nbi_host=${nbi_host%%[:/]*}
    if [[ $acs_addr != "$nbi_host" ]]; then
        request GET "http://$acs_addr:$nbi_port/"
        if [[ $STATUS == 000 ]]; then
            pass "the NBI is not reachable at $acs_addr:$nbi_port"
        else
            fail "the NBI answers at $acs_addr:$nbi_port; it must only listen on 127.0.0.1"
        fi
    fi
else
    info "no ACS_ADDR given; skipped the checks of what routers can reach"
fi

# 7. Units: running, not crash-looping (the MongoDB 8.0 driver risk), UI absent.
if [[ $skip_systemd != 1 ]] && command -v systemctl >/dev/null 2>&1; then
    for unit in genieacs-cwmp genieacs-nbi; do
        if systemctl is-active --quiet "$unit"; then
            restarts=$(systemctl show -p NRestarts --value "$unit" 2>/dev/null)
            if [[ ${restarts:-0} != 0 ]]; then
                warn "$unit is active but systemd restarted it $restarts time(s); check journalctl -u $unit and /var/log/genieacs"
            else
                pass "$unit is active with no restarts"
            fi
        else
            fail "$unit is not active"
        fi
    done
    if systemctl is-active --quiet genieacs-ui; then
        fail "genieacs-ui is running; SkyRouter replaces it and its setup wizard is unauthenticated"
    fi
    if [[ -r /opt/genieacs/ext/skyrouter.js ]]; then
        if cmp -s "$here/ext/skyrouter.js" /opt/genieacs/ext/skyrouter.js; then
            pass "the installed extension matches ext/skyrouter.js"
        else
            warn "/opt/genieacs/ext/skyrouter.js differs from ext/skyrouter.js; reinstall it (README step 3)"
        fi
    else
        info "cannot read /opt/genieacs/ext/skyrouter.js as $(id -un); run with sudo to compare it"
    fi
else
    info "skipped the systemd unit checks"
fi

echo "$failures failure(s), $warnings warning(s)"
[[ $failures == 0 ]]
