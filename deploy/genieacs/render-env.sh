#!/usr/bin/env bash
# Print /etc/genieacs/genieacs.env: genieacs.env.example with every {{NAME}}
# placeholder filled from the environment (README step 4).
#
#   ACS_DB_PASSWORD      the password create-users.js gave the genieacs MongoDB user
#   SKYROUTER_CR_SECRET  the key ext/skyrouter.js derives connection-request passwords from
#
# Both must be hex, at least 32 characters (openssl rand -hex N). Secrets come from
# the environment, not arguments, so they never show in the process list.
#
# The result is printed only once it is complete. It is meant to be captured and
# installed in one go, so a failure here must leave nothing behind to install:
#   out=$(deploy/genieacs/render-env.sh) &&
#     printf '%s\n' "$out" | sudo install -o root -g genieacs -m 0640 /dev/stdin /etc/genieacs/genieacs.env
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
template=${GENIEACS_ENV_TEMPLATE:-$here/genieacs.env.example}

die() {
    printf 'render-env.sh: %s\n' "$*" >&2
    exit 2
}

# Every placeholder the template may use, and nothing else: an unknown one is a
# template this script was not updated for.
placeholders=(ACS_DB_PASSWORD SKYROUTER_CR_SECRET)

for name in "${placeholders[@]}"; do
    value=${!name:-}
    [[ -n $value ]] || die "$name is not set (generate it with: openssl rand -hex 32)"
    [[ $value =~ ^[0-9A-Fa-f]{32,128}$ ]] || die "$name must be 32-128 hex characters (openssl rand -hex 32)"
done

[[ -r $template ]] || die "cannot read the template $template"

rendered=""
while IFS= read -r line || [[ -n $line ]]; do
    for name in "${placeholders[@]}"; do
        line=${line//"{{$name}}"/${!name}}
    done
    rendered+="$line"$'\n'
done <"$template"

if [[ $rendered =~ \{\{[A-Za-z0-9_]*\}\} ]]; then
    die "the template uses a placeholder this script does not fill: ${BASH_REMATCH[0]}"
fi

printf '%s' "$rendered"
