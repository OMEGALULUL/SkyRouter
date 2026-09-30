"""Checks on the GenieACS deployment files in deploy/.

Nothing here starts GenieACS, MongoDB or a systemd unit. The JavaScript runs
under node against stand-ins (skipped when node is not on PATH), the shell
scripts run against a fake NBI on 127.0.0.1, and everything else is parsed.
"""

import base64
import hashlib
import hmac
import json
import os
import re
import shutil
import subprocess
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

PROJECT = Path(__file__).resolve().parent.parent
GENIEACS = PROJECT / "deploy" / "genieacs"
SKYROUTER = PROJECT / "deploy" / "skyrouter"
ENV_EXAMPLE = GENIEACS / "genieacs.env.example"
EXTENSION = GENIEACS / "ext" / "skyrouter.js"
CREATE_USERS = GENIEACS / "mongo" / "create-users.js"
SET_CWMP_AUTH = GENIEACS / "mongo" / "set-cwmp-auth.js"
RENDER_ENV = GENIEACS / "render-env.sh"
SMOKE_TEST = GENIEACS / "smoke-test.sh"
README = GENIEACS / "README.md"
VERSION = GENIEACS / "VERSION"
SERVICES = ("cwmp", "nbi", "fs")

NODE = shutil.which("node")
needs_node = pytest.mark.skipif(NODE is None, reason="node is not on PATH")
needs_bash = pytest.mark.skipif(shutil.which("bash") is None, reason="bash is not on PATH")
needs_curl = pytest.mark.skipif(shutil.which("curl") is None, reason="curl is not on PATH")

PLACEHOLDER = re.compile(r"\{\{[A-Z0-9_]+\}\}")
DB_PASSWORD = "3f" * 24
CR_SECRET = "a1" * 32
CPE_SECRET = "5c" * 24


def _clean_env(**extra: str) -> dict[str, str]:
    """Only PATH from the developer's shell, so a real secret exported there cannot leak in."""
    return {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C", **extra}


def _env_file(text: str) -> dict[str, str]:
    """Parse systemd EnvironmentFile syntax as this repo writes it: KEY=value, no quoting."""
    values: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith(("#", ";")):
            continue
        key, sep, value = line.partition("=")
        assert sep, f"not KEY=value: {line!r}"
        assert re.fullmatch(r"[A-Z_][A-Z0-9_]*", key), f"bad key {key!r}"
        # systemd keeps the last assignment, so a duplicate silently overrides the first.
        assert key not in values, f"{key} is assigned twice"
        values[key] = value
    return values


def _unit(path: Path) -> dict[str, dict[str, list[str]]]:
    sections: dict[str, dict[str, list[str]]] = {}
    current: dict[str, list[str]] | None = None
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        assert not line.endswith("\\"), "continuation lines are not parsed here"
        if line.startswith("[") and line.endswith("]"):
            current = sections.setdefault(line[1:-1], {})
            continue
        assert current is not None, f"{path.name}: setting outside a section"
        key, _, value = line.partition("=")
        current.setdefault(key.strip(), []).append(value.strip())
    return sections


def _one(unit: dict[str, dict[str, list[str]]], section: str, key: str) -> str:
    values = unit[section].get(key, [])
    assert len(values) == 1, f"[{section}] {key} should be set exactly once, got {values}"
    return values[0]


def _words(unit: dict[str, dict[str, list[str]]], section: str, key: str) -> list[str]:
    return " ".join(unit[section].get(key, [])).split()


# --- genieacs.env.example ----------------------------------------------------


def test_env_example_holds_no_secret_values():
    text = ENV_EXAMPLE.read_text()
    values = _env_file(text)
    for key, value in values.items():
        if re.search(r"SECRET|PASSWORD|TOKEN|JWT", key):
            assert PLACEHOLDER.fullmatch(value), f"{key} carries a value instead of a placeholder"
    url = urlsplit(values["GENIEACS_MONGODB_CONNECTION_URL"])
    assert url.password is not None
    assert PLACEHOLDER.fullmatch(url.password), "the MongoDB URL carries a password"
    # A pasted secret is almost always a long hex run.
    assert not re.search(r"[0-9A-Fa-f]{24,}", text)


def test_env_example_keeps_the_nbi_ui_and_database_on_loopback():
    values = _env_file(ENV_EXAMPLE.read_text())
    assert values["GENIEACS_NBI_INTERFACE"] == "127.0.0.1"
    assert values["GENIEACS_UI_INTERFACE"] == "127.0.0.1"
    assert urlsplit(values["GENIEACS_MONGODB_CONNECTION_URL"]).hostname == "127.0.0.1"


def test_env_example_never_enables_the_debug_dump_or_the_ui():
    values = _env_file(ENV_EXAMPLE.read_text())
    # The debug file records SOAP bodies, Wi-Fi passphrases included.
    assert "GENIEACS_DEBUG_FILE" not in values
    assert values.get("GENIEACS_DEBUG", "false") == "false"
    assert "GENIEACS_UI_JWT_SECRET" not in values


def test_env_example_uses_only_names_genieacs_or_the_extension_reads():
    # GenieACS ignores anything without its prefix, so a typo is a silently dropped setting.
    for key in _env_file(ENV_EXAMPLE.read_text()):
        assert key.startswith("GENIEACS_") or key in {"NODE_OPTIONS", "SKYROUTER_CR_SECRET"}, key


def test_env_example_ext_dir_is_where_the_runbook_installs_the_extension():
    ext_dir = _env_file(ENV_EXAMPLE.read_text())["GENIEACS_EXT_DIR"]
    assert f"deploy/genieacs/ext/skyrouter.js {ext_dir}/" in README.read_text()


def test_render_env_fills_exactly_the_placeholders_the_template_uses():
    used = set(PLACEHOLDER.findall(ENV_EXAMPLE.read_text()))
    match = re.search(r"^placeholders=\(([^)]*)\)", RENDER_ENV.read_text(), re.MULTILINE)
    assert match is not None
    assert used == {f"{{{{{name}}}}}" for name in match.group(1).split()}


# --- render-env.sh -----------------------------------------------------------


def _render(env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["bash", str(RENDER_ENV)], env=env, capture_output=True, text=True, timeout=30)


@needs_bash
def test_render_env_fills_the_secrets_and_changes_nothing_else():
    done = _render(_clean_env(ACS_DB_PASSWORD=DB_PASSWORD, SKYROUTER_CR_SECRET=CR_SECRET))
    assert done.returncode == 0, done.stderr
    assert done.stderr == ""
    rendered = _env_file(done.stdout)
    assert urlsplit(rendered["GENIEACS_MONGODB_CONNECTION_URL"]).password == DB_PASSWORD
    assert rendered["SKYROUTER_CR_SECRET"] == CR_SECRET
    assert "{{" not in done.stdout
    template = ENV_EXAMPLE.read_text().splitlines()
    output = done.stdout.splitlines()
    assert len(output) == len(template)
    changed = [line for line, original in zip(output, template, strict=True) if line != original]
    assert len(changed) == 2


@needs_bash
@pytest.mark.parametrize("missing", ["ACS_DB_PASSWORD", "SKYROUTER_CR_SECRET"])
def test_render_env_prints_nothing_when_a_secret_is_missing(missing: str):
    env = _clean_env(ACS_DB_PASSWORD=DB_PASSWORD, SKYROUTER_CR_SECRET=CR_SECRET)
    del env[missing]
    done = _render(env)
    assert done.returncode == 2
    # Piped into install, any output at all would become the env file.
    assert done.stdout == ""
    assert missing in done.stderr


@needs_bash
@pytest.mark.parametrize(
    "bad", ["not-hex-but-long-enough-to-pass-length", "abc123", "{{SKYROUTER_CR_SECRET}}", "ab" * 65]
)
def test_render_env_refuses_a_secret_that_is_not_long_hex(bad: str):
    done = _render(_clean_env(ACS_DB_PASSWORD=DB_PASSWORD, SKYROUTER_CR_SECRET=bad))
    assert done.returncode == 2
    assert done.stdout == ""
    # A mistyped secret is still a secret.
    assert bad not in done.stderr


@needs_bash
def test_render_env_refuses_a_template_with_an_unknown_placeholder(tmp_path: Path):
    template = tmp_path / "genieacs.env.example"
    template.write_text(ENV_EXAMPLE.read_text() + "GENIEACS_XMPP_PASSWORD={{XMPP_PASSWORD}}\n")
    env = _clean_env(ACS_DB_PASSWORD=DB_PASSWORD, SKYROUTER_CR_SECRET=CR_SECRET, GENIEACS_ENV_TEMPLATE=str(template))
    done = _render(env)
    assert done.returncode == 2
    assert done.stdout == ""
    assert "{{XMPP_PASSWORD}}" in done.stderr


# --- systemd units -----------------------------------------------------------


@pytest.mark.parametrize("service", SERVICES)
def test_units_restart_on_failure(service: str):
    unit = _unit(GENIEACS / "systemd" / f"genieacs-{service}.service")
    # The primary exits after repeated worker crashes; without this the service stays down.
    assert _one(unit, "Service", "Restart") == "on-failure"
    assert int(_one(unit, "Service", "RestartSec")) > 0


@pytest.mark.parametrize("service", SERVICES)
def test_units_run_the_pinned_install_as_the_service_user(service: str):
    unit = _unit(GENIEACS / "systemd" / f"genieacs-{service}.service")
    assert _one(unit, "Service", "User") == "genieacs"
    assert _one(unit, "Service", "Group") == "genieacs"
    assert _words(unit, "Service", "ExecStart")[0] == f"/opt/genieacs/node_modules/genieacs/bin/genieacs-{service}"
    # No "-" prefix: a missing env file must stop the unit, not start it on bind-everything defaults.
    assert _one(unit, "Service", "EnvironmentFile") == "/etc/genieacs/genieacs.env"
    assert "mongod.service" in _words(unit, "Unit", "After")
    assert _one(unit, "Install", "WantedBy") == "multi-user.target"


@pytest.mark.parametrize("service", SERVICES)
def test_units_put_the_system_node_on_path(service: str):
    unit = _unit(GENIEACS / "systemd" / f"genieacs-{service}.service")
    assignments = dict(word.split("=", 1) for word in _words(unit, "Service", "Environment"))
    node_bin = assignments["PATH"].split(":")[0]
    assert re.fullmatch(r"/opt/node-v\d+\.\d+\.\d+/bin", node_bin)
    # The runbook's copy step must create exactly the directory the units expect.
    assert f"/opt/{node_bin.split('/')[2]} " in README.read_text()


@pytest.mark.parametrize("service", SERVICES)
def test_units_are_hardened(service: str):
    unit = _unit(GENIEACS / "systemd" / f"genieacs-{service}.service")
    expected = {
        "NoNewPrivileges": "yes",
        "ProtectSystem": "strict",
        "ProtectHome": "yes",
        "PrivateTmp": "yes",
        "PrivateDevices": "yes",
        "ReadWritePaths": "/var/log/genieacs",
        "CapabilityBoundingSet": "",
    }
    for key, value in expected.items():
        assert _one(unit, "Service", key) == value, key
    # V8's JIT needs writable-then-executable memory: this would crash-loop the service.
    assert unit["Service"].get("MemoryDenyWriteExecute", ["no"]) == ["no"]


def test_the_nbi_unit_pins_loopback_over_the_env_file():
    unit = _unit(GENIEACS / "systemd" / "genieacs-nbi.service")
    words = _words(unit, "Service", "ExecStart")
    assert words[words.index("--nbi-interface") + 1] == "127.0.0.1"


@pytest.mark.skipif(shutil.which("systemd-analyze") is None, reason="systemd-analyze is not installed")
def test_units_have_no_unknown_or_invalid_settings(tmp_path: Path):
    copies = []
    for path in [*(GENIEACS / "systemd").glob("*.service"), SKYROUTER / "router-manager.service"]:
        # verify also checks that ExecStart exists, which it cannot on a test host.
        text = re.sub(r"^ExecStart=\S+", "ExecStart=/bin/true", path.read_text(), flags=re.MULTILINE)
        copy = tmp_path / path.name
        copy.write_text(text)
        copies.append(str(copy))
    done = subprocess.run(
        ["systemd-analyze", "verify", "--man=no", *copies], capture_output=True, text=True, timeout=60
    )
    report = done.stdout + done.stderr
    assert not re.search(r"Unknown (key|section)|Failed to parse|[Ii]nvalid|not a valid", report), report


def test_router_manager_unit_is_optional_and_stays_on_loopback():
    unit = _unit(SKYROUTER / "router-manager.service")
    assert _one(unit, "Service", "Restart") == "on-failure"
    words = _words(unit, "Service", "ExecStart")
    assert words[words.index("--host") + 1] == "127.0.0.1"
    assert "genieacs-nbi.service" in _words(unit, "Unit", "After")
    # SkyRouter runs without GenieACS, so it must neither pull the NBI in nor stop with it.
    for key in ("Wants", "Requires", "BindsTo", "Requisite"):
        assert "genieacs-nbi.service" not in _words(unit, "Unit", key)
    assert _one(unit, "Service", "User") == "skyrouter"
    assert _one(unit, "Service", "StateDirectoryMode") == "0700"


def test_router_manager_env_example_holds_no_password_and_a_loopback_acs():
    values = _env_file((SKYROUTER / "router-manager.env.example").read_text())
    assert values["ROUTER_MANAGER_PASSWORD"] == ""
    assert urlsplit(values["ROUTER_MANAGER_ACS_URL"]).hostname == "127.0.0.1"
    assert "ROUTER_MANAGER_ACS_ALLOW_REMOTE" not in values


def test_logrotate_rotates_without_truncating_as_the_service_user():
    text = (GENIEACS / "logrotate" / "genieacs").read_text()
    directives = [line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    assert directives[0] == "/var/log/genieacs/*.log {"
    assert "su genieacs genieacs" in directives
    assert "create 0640 genieacs genieacs" in directives
    # GenieACS reopens a renamed log by itself; copytruncate would lose lines instead.
    assert "copytruncate" not in directives


# --- ext/skyrouter.js --------------------------------------------------------

# Loads the extension by name without ".js", from inside its directory, the way
# GenieACS's extension runner does, and prints exactly one JSON line.
EXT_HARNESS = r"""
"use strict";
const [extDir, argsJson] = process.argv.slice(2);
process.chdir(extDir);
const ext = require(`${extDir}/skyrouter`);
ext.crPassword(JSON.parse(argsJson), (err, result) => {
  const out = err ? { error: { name: err.name, message: err.message } } : { result };
  process.stdout.write(JSON.stringify(out));
});
"""


def _cr_password(tmp_path: Path, args: list[str], secret: str | None) -> tuple[dict, subprocess.CompletedProcess[str]]:
    harness = tmp_path / "ext-harness.js"
    harness.write_text(EXT_HARNESS)
    env = _clean_env() if secret is None else _clean_env(SKYROUTER_CR_SECRET=secret)
    assert NODE is not None
    done = subprocess.run(
        [NODE, str(harness), str(EXTENSION.parent), json.dumps(args)],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert done.returncode == 0, done.stderr
    # The extension itself must print nothing: GenieACS logs its stdout and stderr.
    assert done.stderr == ""
    return json.loads(done.stdout), done


def _expected_password(secret: str, device_id: str) -> str:
    return hmac.new(secret.encode(), device_id.encode(), hashlib.sha256).hexdigest()[:32]


@needs_node
def test_extension_passes_node_check():
    assert NODE is not None
    done = subprocess.run([NODE, "--check", str(EXTENSION)], capture_output=True, text=True, timeout=30)
    assert done.returncode == 0, done.stderr


def test_extension_needs_nothing_beyond_nodes_crypto():
    assert re.findall(r"require\(\s*[\"']([^\"']+)[\"']\s*\)", EXTENSION.read_text()) == ["crypto"]


@needs_node
def test_extension_refuses_to_answer_without_the_secret(tmp_path: Path):
    out, _ = _cr_password(tmp_path, ["202BC1-BM632w-000000"], secret=None)
    assert "result" not in out
    # A plain Error, so GenieACS records the fault as ext.Error for SkyRouter's health check.
    assert out["error"]["name"] == "Error"
    assert "SKYROUTER_CR_SECRET" in out["error"]["message"]


@needs_node
@pytest.mark.parametrize("secret", ["", "abc", "a" * 31, "g" * 64, "{{SKYROUTER_CR_SECRET}}", " " + "a" * 40])
def test_extension_refuses_a_weak_or_unfilled_secret(tmp_path: Path, secret: str):
    out, _ = _cr_password(tmp_path, ["202BC1-BM632w-000000"], secret=secret)
    assert "result" not in out
    assert out["error"]["name"] == "Error"


@needs_node
@pytest.mark.parametrize(
    "device_id",
    ["202BC1-BM632w-000000", "00259E-HG8245H-4857544300%2D1", "001122-SERIAL_1", "E4C32A-%20-X"],
)
def test_extension_derives_the_documented_hmac(tmp_path: Path, device_id: str):
    out, done = _cr_password(tmp_path, [device_id], secret=CR_SECRET)
    assert out == {"result": _expected_password(CR_SECRET, device_id)}
    assert re.fullmatch(r"[0-9a-f]{32}", out["result"])
    assert CR_SECRET not in done.stdout


@needs_node
def test_extension_passwords_differ_per_device_and_per_secret(tmp_path: Path):
    first, _ = _cr_password(tmp_path, ["202BC1-BM632w-000000"], secret=CR_SECRET)
    other_device, _ = _cr_password(tmp_path, ["202BC1-BM632w-000001"], secret=CR_SECRET)
    other_secret, _ = _cr_password(tmp_path, ["202BC1-BM632w-000000"], secret="b2" * 32)
    assert len({first["result"], other_device["result"], other_secret["result"]}) == 3


@needs_node
@pytest.mark.parametrize(
    "args",
    [
        [],
        [""],
        ["undefined"],
        ["202BC1 BM632w-000000"],
        ["202BC1-BM632w-000000-extra"],
        ["202bc1-%2d-000000"],
        ["A-" + "x" * 300],
        ["202BC1-BM632w-000000", "second"],
    ],
)
def test_extension_refuses_anything_but_one_genieacs_device_id(tmp_path: Path, args: list[str]):
    out, _ = _cr_password(tmp_path, args, secret=CR_SECRET)
    assert "result" not in out
    assert out["error"]["name"] == "Error"


# --- mongo/*.js --------------------------------------------------------------

# A stand-in for the mongosh globals the scripts use: db, print, quit and
# process.env. Every database call is recorded and printed as one JSON object.
MONGOSH_HARNESS = r"""
"use strict";
const fs = require("fs");
const vm = require("vm");
const script = process.argv[2];
const existingUsers = JSON.parse(process.env.HARNESS_EXISTING_USERS || "[]");
const calls = [];
const printed = [];
class Quit extends Error {
  constructor(code) { super("quit"); this.code = code; }
}
function collection(dbName, name) {
  return new Proxy({}, {
    get: (_, method) => (...args) => {
      calls.push({ db: dbName, collection: name, method: String(method), args });
      return { acknowledged: true };
    },
  });
}
function database(name) {
  return {
    getSiblingDB: (other) => database(other),
    getCollection: (other) => collection(name, other),
    getUser: (user) => (existingUsers.includes(user) ? { user } : null),
    createUser: (spec) => { calls.push({ db: name, method: "createUser", args: [spec] }); },
    updateUser: (user, spec) => { calls.push({ db: name, method: "updateUser", args: [user, spec] }); },
  };
}
const env = Object.assign({}, process.env);
delete env.HARNESS_EXISTING_USERS;
const sandbox = {
  db: database("admin"),
  print: (...parts) => { printed.push(parts.join(" ")); },
  quit: (code) => { throw new Quit(code === undefined ? 0 : code); },
  process: { env },
};
let code = 0;
try {
  vm.runInNewContext(fs.readFileSync(script, "utf8"), sandbox, { filename: script });
} catch (err) {
  if (err instanceof Quit) code = err.code;
  else { printed.push("uncaught: " + err.message); code = 99; }
}
process.stdout.write(JSON.stringify({ code, calls, printed }));
"""


def _mongosh(tmp_path: Path, script: Path, env: dict[str, str], existing_users: list[str] | None = None) -> dict:
    harness = tmp_path / "mongosh-harness.js"
    harness.write_text(MONGOSH_HARNESS)
    assert NODE is not None
    done = subprocess.run(
        [NODE, str(harness), str(script)],
        env=_clean_env(HARNESS_EXISTING_USERS=json.dumps(existing_users or []), **env),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert done.returncode == 0, done.stderr
    assert done.stderr == ""
    return json.loads(done.stdout)


def _writes(result: dict) -> list[dict]:
    return [call for call in result["calls"] if call["method"] not in {"getUser"}]


@needs_node
@pytest.mark.parametrize("script", [CREATE_USERS, SET_CWMP_AUTH])
def test_mongo_scripts_pass_node_check(script: Path):
    assert NODE is not None
    done = subprocess.run([NODE, "--check", str(script)], capture_output=True, text=True, timeout=30)
    assert done.returncode == 0, done.stderr


@needs_node
@pytest.mark.parametrize(
    "env",
    [
        {},
        {"ACS_DB_PASSWORD": "short"},
        {"ACS_DB_PASSWORD": "z" * 48},
        {"ACS_DB_PASSWORD": DB_PASSWORD, "ACS_DB_NAME": "genieacs.devices"},
        {"ACS_DB_PASSWORD": DB_PASSWORD, "ACS_DB_USER": "Admin$"},
    ],
)
def test_create_users_refuses_bad_input_before_touching_the_database(tmp_path: Path, env: dict[str, str]):
    result = _mongosh(tmp_path, CREATE_USERS, env)
    assert result["code"] == 2
    assert _writes(result) == []


@needs_node
def test_create_users_creates_the_genieacs_account_and_indexes(tmp_path: Path):
    result = _mongosh(tmp_path, CREATE_USERS, {"ACS_DB_PASSWORD": DB_PASSWORD})
    assert result["code"] == 0
    users = [call for call in result["calls"] if call["method"] in {"createUser", "updateUser"}]
    assert users == [
        {
            "db": "genieacs",
            "method": "createUser",
            "args": [
                {
                    "user": "genieacs",
                    "pwd": DB_PASSWORD,
                    "roles": [{"role": "readWrite", "db": "genieacs"}],
                    "mechanisms": ["SCRAM-SHA-256"],
                }
            ],
        }
    ]
    indexes = [call["args"][0] for call in result["calls"] if call["method"] == "createIndex"]
    assert all(call["collection"] == "devices" for call in result["calls"] if call["method"] == "createIndex")
    assert indexes == [{"_lastInform": -1}, {"_tags": 1}, {"_deviceId._SerialNumber": 1}]
    assert DB_PASSWORD not in "\n".join(result["printed"])


@needs_node
def test_create_users_rekeys_an_existing_account_instead_of_failing(tmp_path: Path):
    result = _mongosh(tmp_path, CREATE_USERS, {"ACS_DB_PASSWORD": DB_PASSWORD}, existing_users=["genieacs"])
    assert result["code"] == 0
    methods = [call["method"] for call in result["calls"] if call["method"] in {"createUser", "updateUser"}]
    assert methods == ["updateUser"]
    update = next(call for call in result["calls"] if call["method"] == "updateUser")
    assert update["args"][0] == "genieacs"
    assert update["args"][1]["pwd"] == DB_PASSWORD


@needs_node
def test_create_users_targets_another_database_when_asked(tmp_path: Path):
    result = _mongosh(tmp_path, CREATE_USERS, {"ACS_DB_PASSWORD": DB_PASSWORD, "ACS_DB_NAME": "genieacs_e2e"})
    assert result["code"] == 0
    assert {call["db"] for call in _writes(result)} == {"genieacs_e2e"}


@needs_node
@pytest.mark.parametrize(
    "env",
    [
        {},
        {"CPE_USER": "skybre-cpe"},
        {"CPE_SECRET": CPE_SECRET},
        {"CPE_USER": "skybre-cpe", "CPE_SECRET": "tooshort"},
        {"CPE_USER": 'x", "y") OR TRUE OR AUTH("z', "CPE_SECRET": CPE_SECRET},
        {"CPE_USER": "back\\slash", "CPE_SECRET": CPE_SECRET},
        {"CPE_USER": "skybre-cpe", "CPE_SECRET": CPE_SECRET + '")'},
    ],
)
def test_set_cwmp_auth_refuses_bad_input_before_touching_the_database(tmp_path: Path, env: dict[str, str]):
    result = _mongosh(tmp_path, SET_CWMP_AUTH, env)
    assert result["code"] == 2
    assert _writes(result) == []


@needs_node
def test_set_cwmp_auth_writes_the_expression_and_busts_the_config_cache(tmp_path: Path):
    result = _mongosh(tmp_path, SET_CWMP_AUTH, {"CPE_USER": "skybre-cpe", "CPE_SECRET": CPE_SECRET})
    assert result["code"] == 0
    assert _writes(result) == [
        {
            "db": "genieacs",
            "collection": "config",
            "method": "updateOne",
            "args": [
                {"_id": "cwmp.auth"},
                {"$set": {"value": f'AUTH("skybre-cpe", "{CPE_SECRET}")'}},
                {"upsert": True},
            ],
        },
        {"db": "genieacs", "collection": "cache", "method": "deleteOne", "args": [{"_id": "cwmp-local-cache-hash"}]},
    ]
    printed = "\n".join(result["printed"])
    assert CPE_SECRET not in printed
    assert "skybre-cpe" in printed


# --- smoke-test.sh -----------------------------------------------------------


class FakeNbi:
    """Answers the few requests the smoke test makes, the way GenieACS 1.2.16's NBI does."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0, version: str = "1.2.16+26032938e9"):
        self.version = version
        self.requests: list[tuple[str, str, str | None]] = []
        self.totals: dict[tuple[str, str | None], int] = {
            ("presets", None): 4,
            ("config", '{"_id":"cwmp.auth"}'): 1,
            (
                "presets",
                '{"_id":{"$in":["skybre-bootstrap","skybre-registered","skybre-inform","skybre-refresh"]}}',
            ): 4,
        }
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: object) -> None:
                return

            def _record(self) -> tuple[str, str | None]:
                parts = urlsplit(self.path)
                query = parse_qs(parts.query).get("query", [None])[0]
                fake.requests.append((self.command, parts.path, query))
                return parts.path.strip("/"), query

            def _reply(self, code: int, headers: dict[str, str], body: bytes = b"") -> None:
                self.send_response(code)
                self.send_header("GenieACS-Version", fake.version)
                for name, value in headers.items():
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)

            def do_GET(self) -> None:
                path, _ = self._record()
                if path == "":
                    self._reply(404, {}, b"404 Not Found")
                else:
                    self._reply(405, {"Allow": "HEAD"})

            def do_HEAD(self) -> None:
                collection, query = self._record()
                self._reply(200, {"total": str(fake.totals.get((collection, query), 0))})

            def do_POST(self) -> None:
                self._record()
                self._reply(405, {})

            do_PUT = do_DELETE = do_POST

        self.server = ThreadingHTTPServer((host, port), Handler)
        self.port = self.server.server_address[1]
        self.url = f"http://{host}:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> "FakeNbi":
        self.thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.server.shutdown()
        self.server.server_close()


class FakeCwmp:
    """genieacs-cwmp answers anything but POST with 405, before any authentication."""

    def __init__(self, host: str):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: object) -> None:
                return

            def do_GET(self) -> None:
                self.send_response(405)
                self.send_header("Allow", "POST")
                self.send_header("Content-Length", "0")
                self.end_headers()

        self.server = ThreadingHTTPServer((host, 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> "FakeCwmp":
        self.thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.server.shutdown()
        self.server.server_close()


@contextmanager
def _second_loopback(port: int = 0) -> Iterator[FakeNbi]:
    """A fake NBI on 127.0.0.2, standing in for a routable address of this host."""
    try:
        fake = FakeNbi(host="127.0.0.2", port=port)
    except OSError as exc:
        pytest.skip(f"cannot bind 127.0.0.2: {exc}")
    with fake:
        yield fake


def _smoke(nbi_url: str, *args: str, **env: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(SMOKE_TEST), *args],
        env=_clean_env(NBI_URL=nbi_url, SKIP_SYSTEMD="1", MONGO_PORT="0", **env),
        capture_output=True,
        text=True,
        timeout=60,
    )


@needs_bash
@needs_curl
def test_smoke_test_passes_on_a_healthy_nbi_and_only_reads():
    with FakeNbi() as nbi:
        done = _smoke(nbi.url)
    assert done.returncode == 0, done.stdout
    assert "FAIL" not in done.stdout
    assert "PASS  NBI version 1.2.16+26032938e9" in done.stdout
    assert "PASS  cwmp.auth is configured" in done.stdout
    assert {method for method, _, _ in nbi.requests} <= {"GET", "HEAD"}
    # A GET on config would return the cwmp.auth secret in its body.
    assert [method for method, path, _ in nbi.requests if path.startswith("/config")] == ["HEAD"]


@needs_bash
@needs_curl
def test_smoke_test_fails_on_a_1_3_nbi():
    with FakeNbi(version="1.3.0-dev+4aa5cbfa33") as nbi:
        done = _smoke(nbi.url)
    assert done.returncode == 1
    assert "FAIL  NBI version is 1.3.0-dev+4aa5cbfa33" in done.stdout


@needs_bash
@needs_curl
def test_smoke_test_fails_when_routers_need_no_authentication():
    with FakeNbi() as nbi:
        nbi.totals[("config", '{"_id":"cwmp.auth"}')] = 0
        done = _smoke(nbi.url)
    assert done.returncode == 1
    assert "FAIL  cwmp.auth is not configured" in done.stdout


@needs_bash
@needs_curl
def test_smoke_test_fails_when_the_nbi_is_down():
    with FakeNbi() as nbi:
        url = nbi.url
    done = _smoke(url)
    assert done.returncode == 1
    assert "does not answer" in done.stdout


@needs_bash
@needs_curl
def test_smoke_test_warns_about_ui_leftovers_without_failing():
    with FakeNbi() as nbi:
        nbi.totals[("presets", '{"_id":{"$in":["bootstrap","default","inform"]}}')] = 3
        nbi.totals[("users", None)] = 1
        done = _smoke(nbi.url)
    assert done.returncode == 0, done.stdout
    assert "WARN  3 UI-seeded preset(s) exist" in done.stdout
    assert "WARN  1 genieacs-ui user(s) exist" in done.stdout


@needs_bash
@needs_curl
def test_smoke_test_checks_what_routers_can_reach():
    try:
        cwmp = FakeCwmp("127.0.0.2")
    except OSError as exc:
        pytest.skip(f"cannot bind 127.0.0.2: {exc}")
    with FakeNbi() as nbi, cwmp:
        done = _smoke(nbi.url, "127.0.0.2", CWMP_PORT=str(cwmp.port))
    assert done.returncode == 0, done.stdout
    assert "PASS  CWMP answers at http://127.0.0.2:" in done.stdout
    assert f"PASS  the NBI is not reachable at 127.0.0.2:{nbi.port}" in done.stdout


@needs_bash
@needs_curl
def test_smoke_test_fails_when_the_nbi_answers_on_the_router_facing_address():
    try:
        cwmp = FakeCwmp("127.0.0.2")
    except OSError as exc:
        pytest.skip(f"cannot bind 127.0.0.2: {exc}")
    with FakeNbi() as nbi, cwmp, _second_loopback(port=nbi.port):
        done = _smoke(nbi.url, "127.0.0.2", CWMP_PORT=str(cwmp.port))
    assert done.returncode == 1
    assert f"FAIL  the NBI answers at 127.0.0.2:{nbi.port}" in done.stdout


# --- scripts, VERSION and README ----------------------------------------------


@pytest.mark.parametrize("script", [RENDER_ENV, SMOKE_TEST])
def test_shell_scripts_are_executable_and_parse(script: Path):
    assert os.access(script, os.X_OK), f"{script.name} is not executable"
    if shutil.which("bash") is not None:
        done = subprocess.run(["bash", "-n", str(script)], capture_output=True, text=True, timeout=30)
        assert done.returncode == 0, done.stderr


def test_version_pins_1_2_16_with_a_well_formed_integrity():
    lines = VERSION.read_text().splitlines()
    assert lines[0] == "1.2.16"
    fields = dict(re.findall(r"^#\s+(version|build|integrity|shasum)\s+(\S+)", VERSION.read_text(), re.MULTILINE))
    assert fields["version"] == lines[0]
    assert fields["build"].startswith(lines[0] + "+")
    algorithm, _, digest = fields["integrity"].partition("-")
    assert algorithm == "sha512"
    assert len(base64.b64decode(digest, validate=True)) == 64
    assert re.fullmatch(r"[0-9a-f]{40}", fields["shasum"])


def test_every_pinned_genieacs_version_matches_version():
    pinned = VERSION.read_text().splitlines()[0]
    for path in (README, VERSION):
        versions = set(re.findall(r"genieacs@(\d+\.\d+\.\d+)", path.read_text()))
        assert versions == {pinned}, f"{path.name} pins {versions}"


def test_readme_never_opens_the_unauthenticated_ports():
    for line in README.read_text().splitlines():
        if "ufw allow" in line:
            ports = set(re.findall(r"port (\d+)", line))
            assert ports == {"7547"}, line


def test_readme_never_puts_a_secret_on_a_command_line():
    for line in README.read_text().splitlines():
        # sudo's arguments, a URL's userinfo and --password <value> are all visible in ps.
        assert not ("sudo" in line and "$(openssl rand" in line), line
        assert not re.search(r"mongodb://[^/@\s:]+:[^/@\s]+@", line), line
        assert not re.search(r"--password\s+\S", line), line


def test_readme_refers_only_to_files_that_exist():
    text = README.read_text()
    referenced = set(re.findall(r"deploy/[A-Za-z0-9_./{},*-]+", text))
    assert referenced
    for reference in referenced:
        reference = reference.rstrip(".,")
        match = re.search(r"\{([^}]*)\}", reference)
        options = match.group(1).split(",") if match else [""]
        for option in options:
            path = reference.replace(match.group(0), option) if match else reference
            if "*" in path:
                assert list(PROJECT.glob(path)), path
            else:
                assert (PROJECT / path).exists(), path


# --- deploy/skyrouter/update.sh ---------------------------------------------

UPDATE = SKYROUTER / "update.sh"
ROUTER_MANAGER_UNIT = SKYROUTER / "router-manager.service"
HEALTHY = '{"status":"ok","authentication_configured":true}'


def _fake_command(directory: Path, name: str, body: str = "") -> None:
    command = directory / name
    command.write_text(f'#!/usr/bin/env bash\necho "{name} $*" >> "$CALLS"\n{body}')
    command.chmod(0o755)


def _update(
    tmp_path: Path, *, uid: int = 0, pull_status: int = 0, healthy: bool = True, installed_unit: str | None = None
) -> tuple[subprocess.CompletedProcess[str], list[str], Path]:
    """Run update.sh with git, pip, systemctl and curl replaced by recorders."""
    fakes = tmp_path / "bin"
    venv = tmp_path / "venv"
    fakes.mkdir()
    (venv / "bin").mkdir(parents=True)
    calls = tmp_path / "calls"
    calls.touch()
    unit_file = tmp_path / "router-manager.service"
    unit_file.write_text(ROUTER_MANAGER_UNIT.read_text() if installed_unit is None else installed_unit)
    _fake_command(fakes, "id", f"echo {uid}\n")
    # HEAD moves once the pull has run, so the report can name both commits.
    _fake_command(
        fakes,
        "git",
        'if [[ $1 == pull ]]; then touch "$CALLS.pulled"; exit "$PULL_STATUS"; fi\n'
        '[[ -e "$CALLS.pulled" ]] && echo bbb2222 || echo aaa1111\n',
    )
    _fake_command(venv / "bin", "pip")
    _fake_command(fakes, "systemctl")
    _fake_command(fakes, "curl", f"[[ $HEALTHY == 1 ]] && echo '{HEALTHY}' && exit 0\nexit 7\n")
    _fake_command(fakes, "sleep")
    done = subprocess.run(
        ["bash", str(UPDATE)],
        env=_clean_env(
            PATH=f"{fakes}:{os.environ.get('PATH', '/usr/bin:/bin')}",
            CALLS=str(calls),
            PULL_STATUS=str(pull_status),
            HEALTHY="1" if healthy else "0",
            SKYROUTER_SRC=str(PROJECT),
            SKYROUTER_VENV=str(venv),
            SKYROUTER_UNIT_FILE=str(unit_file),
        ),
        capture_output=True,
        text=True,
        timeout=60,
    )
    recorded = [line for line in calls.read_text().splitlines() if not line.startswith(("id ", "sleep "))]
    return done, recorded, unit_file


@needs_bash
def test_update_script_parses():
    assert subprocess.run(["bash", "-n", str(UPDATE)], capture_output=True).returncode == 0


@needs_bash
def test_update_refuses_to_run_without_root(tmp_path: Path):
    done, recorded, _ = _update(tmp_path, uid=1000)
    assert done.returncode == 1
    assert "Run this with sudo." in done.stderr
    assert recorded == []


@needs_bash
def test_update_pulls_reinstalls_restarts_and_waits_for_the_dashboard(tmp_path: Path):
    done, recorded, _ = _update(tmp_path)
    assert done.returncode == 0, done.stderr
    assert recorded == [
        "git rev-parse --short HEAD",
        "git pull --ff-only",
        "git rev-parse --short HEAD",
        f"pip install --quiet --disable-pip-version-check {PROJECT}",
        "systemctl restart router-manager",
        "curl -fsS --max-time 2 http://127.0.0.1:8091/healthz",
    ]
    assert f"SkyRouter aaa1111 -> bbb2222 is running: {HEALTHY}" in done.stdout


@needs_bash
def test_update_installs_a_changed_unit_before_restarting(tmp_path: Path):
    done, recorded, unit_file = _update(tmp_path, installed_unit="[Service]\nExecStart=/bin/false\n")
    assert done.returncode == 0, done.stderr
    assert unit_file.read_text() == ROUTER_MANAGER_UNIT.read_text()
    assert recorded.index("systemctl daemon-reload") < recorded.index("systemctl restart router-manager")
    assert "Service unit updated." in done.stdout


@needs_bash
def test_update_stops_before_installing_when_the_pull_cannot_fast_forward(tmp_path: Path):
    done, recorded, _ = _update(tmp_path, pull_status=128)
    assert done.returncode != 0
    assert not [call for call in recorded if call.startswith(("pip ", "systemctl ", "curl "))]


@needs_bash
def test_update_reports_a_dashboard_that_does_not_come_back(tmp_path: Path):
    done, recorded, _ = _update(tmp_path, healthy=False)
    assert done.returncode == 1
    assert len([call for call in recorded if call.startswith("curl ")]) == 30
    assert "sudo journalctl -u router-manager" in done.stderr


def test_the_router_manager_unit_serves_where_update_checks():
    port = re.search(r"--port (\d+)", ROUTER_MANAGER_UNIT.read_text())
    assert port is not None
    assert f"http://127.0.0.1:{port.group(1)}/healthz" in UPDATE.read_text()
