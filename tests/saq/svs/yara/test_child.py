"""The sandboxed compile and scan (saq/svs/yara/child.py), held to what the yara service does with
the same rules (yara_scanner.YaraScanner, as saq/yara_scanning/server.py runs it)."""

import json
import os

import pytest
import yara_scanner

from saq.configuration.schema import SandboxConfig
from saq.environment import get_base_dir
from saq.sandbox.runner import landlock_available
from saq.svs.yara import child
from saq.svs.yara.corpus import Corpus, Unit
from saq.svs.yara.layout import TreeLayout, TreeNamespace
from saq.svs.yara.replay import _run_child

PATH_RULES = """
rule by_file_ext { meta: uuid = "u-ext" file_ext = "txt" strings: $a = "evil" condition: $a }
rule by_file_name { meta: uuid = "u-name" file_name = "re:^inv" strings: $a = "evil" condition: $a }
rule by_extension { meta: uuid = "u-extension" strings: $a = "evil" condition: $a and extension == "txt" }
rule by_filename { meta: uuid = "u-filename" strings: $a = "evil" condition: $a and filename == "invoice.txt" }
rule by_filepath { meta: uuid = "u-filepath" strings: $a = "evil" condition: $a and filepath contains "/files/" }
rule by_meta_tags { meta: uuid = "u-tags" meta_tags = "kind=email" strings: $a = "evil" condition: $a }
rule not_meta_tags { meta: uuid = "u-not-tags" meta_tags = "!kind=email" strings: $a = "evil" condition: $a }
rule by_mime_type { meta: uuid = "u-mime" mime_type = "text/plain" strings: $a = "evil" condition: $a }
rule plain { meta: uuid = "u-plain" strings: $a = "evil" condition: $a }
"""


def _write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb" if isinstance(content, bytes) else "w") as fp:
        fp.write(content)


def _signature_dir(root, namespaces: dict[str, dict[str, str]]) -> str:
    signature_dir = os.path.join(root, "tree", "yara")
    for namespace, files in namespaces.items():
        os.makedirs(os.path.join(signature_dir, namespace), exist_ok=True)
        for name, content in files.items():
            _write(os.path.join(signature_dir, namespace, name), content)
    return signature_dir


def _namespaces(signature_dir) -> list[dict]:
    result = []
    for name in sorted(os.listdir(signature_dir)):
        directory = os.path.join(signature_dir, name)
        # the rule files directly inside it, as saq.svs.yara.layout lists them
        result.append({"name": name, "directory": directory, "files": [
            os.path.join(directory, file_name) for file_name in sorted(os.listdir(directory))
            if file_name.endswith((".yar", ".yara")) and os.path.isfile(os.path.join(directory, file_name))]})
    return result


def _run(root, signature_dir, units: list[dict]) -> dict:
    """child.run() in this process, without the sandbox."""
    with open(os.path.join(root, child.JOB_FILE), "w") as fp:
        json.dump({"version": child.PROTOCOL_VERSION, "tree_root": os.path.dirname(signature_dir), "file_timeout": 10,
                   "namespaces": _namespaces(signature_dir), "units": units}, fp)
    return child.run(str(root))


def _production(signature_dir) -> yara_scanner.YaraScanner:
    scanner = yara_scanner.YaraScanner(signature_dir=signature_dir, default_timeout=10)
    scanner.load_rules()
    return scanner


def _sample(root, unit_id: int, file_path: str, content: bytes = b"some evil text\n") -> str:
    path = os.path.join(root, "u", str(unit_id), "files", file_path)
    _write(path, content)
    return path


@pytest.mark.unit
@pytest.mark.parametrize("file_path, meta_tags", [
    ("invoice.txt", ["kind=email"]),
    ("invoice.txt", []),
    ("attachments/notes", ["kind=other"]),
    ("report.pdf.txt", []),
])
def test_matches_agree_with_the_yara_service(tmp_path, file_path, meta_tags):
    signature_dir = _signature_dir(str(tmp_path), {"acme": {"paths.yar": PATH_RULES}})
    path = _sample(str(tmp_path), 0, file_path)

    result = _run(tmp_path, signature_dir, [{"id": 0, "path": path, "meta_tags": meta_tags}])
    production = _production(signature_dir)
    production.scan(path, meta_tags=meta_tags or None)

    assert {match["rule"] for match in result["units"]["0"]["matches"]} == {match["rule"] for match in production.scan_results}
    assert {match["namespace"] for match in result["units"]["0"]["matches"]} <= {"acme"}


@pytest.mark.unit
def test_a_file_that_does_not_compile_drops_only_its_rules(tmp_path):
    signature_dir = _signature_dir(str(tmp_path), {"acme": {
        "good.yar": 'rule good { meta: uuid = "u-good" strings: $a = "evil" condition: $a }\n',
        "broken.yar": 'rule broken { meta: uuid = "u-broken" condition: nope }\n',
    }})
    path = _sample(str(tmp_path), 0, "x.bin")

    result = _run(tmp_path, signature_dir, [{"id": 0, "path": path, "meta_tags": []}])
    files = {os.path.basename(entry["path"]): entry for entry in result["files"]}
    assert "undefined identifier" in files["broken.yar"]["error"]
    assert [rule["name"] for rule in files["good.yar"]["rules"]] == ["good"]
    assert result["ruleset_error"] is None
    assert [match["rule"] for match in result["units"]["0"]["matches"]] == ["good"]

    production = _production(signature_dir)
    assert production.rules is not None
    production.scan(path)
    assert [match["rule"] for match in production.scan_results] == ["good"]


@pytest.mark.unit
def test_a_ruleset_that_does_not_compile_together_would_not_load(tmp_path):
    signature_dir = _signature_dir(str(tmp_path), {"acme": {
        "one.yar": 'rule same { strings: $a = "evil" condition: $a }\n',
        "two.yar": 'rule same { strings: $a = "good" condition: $a }\n',
    }})
    path = _sample(str(tmp_path), 0, "x.bin")

    result = _run(tmp_path, signature_dir, [{"id": 0, "path": path, "meta_tags": []}])
    assert "duplicated identifier" in result["ruleset_error"]
    assert result["units"] == {}
    assert _production(signature_dir).rules is None

    # the same rule name in two namespaces is fine
    signature_dir = _signature_dir(str(tmp_path / "ok"), {
        "one": {"one.yar": 'rule same { strings: $a = "evil" condition: $a }\n'},
        "two": {"two.yar": 'rule same { strings: $a = "evil" condition: $a }\n'},
    })
    result = _run(tmp_path, signature_dir, [{"id": 0, "path": path, "meta_tags": []}])
    assert result["ruleset_error"] is None
    assert sorted(match["namespace"] for match in result["units"]["0"]["matches"]) == ["one", "two"]


@pytest.mark.unit
def test_a_ruleset_that_does_not_load_still_lists_each_files_rules(tmp_path):
    # the report's "no uuid" and full_path diagnostics are read from them
    signature_dir = _signature_dir(str(tmp_path), {"acme": {
        "one.yar": 'include "common.inc"\nrule same { meta: uuid = "u-one" condition: helper }\n',
        "common.inc": 'private rule helper { condition: true }\n',
        "two.yar": 'rule same { meta: full_path = "x" condition: true }\n',
    }})

    result = _run(tmp_path, signature_dir, [])
    assert "duplicated identifier" in result["ruleset_error"]
    files = {os.path.basename(entry["path"]): entry for entry in result["files"]}
    assert {rule["name"]: (rule["private"], rule["meta"]) for rule in files["one.yar"]["rules"]} == {
        "same": (False, {"uuid": "u-one"}), "helper": (True, {})}
    assert [(rule["name"], rule["meta"]) for rule in files["two.yar"]["rules"]] == [("same", {"full_path": "x"})]


@pytest.mark.unit
def test_a_namespace_without_rule_files_is_left_out(tmp_path):
    # tree_layout makes a namespace of every directory, so one can hold only includes
    signature_dir = _signature_dir(str(tmp_path), {
        "acme": {"rules.yar": 'rule good { strings: $a = "evil" condition: $a }\n'},
        "shared": {"common.inc": 'rule unused { condition: true }\n'},
    })
    path = _sample(str(tmp_path), 0, "x.bin")

    result = _run(tmp_path, signature_dir, [{"id": 0, "path": path, "meta_tags": []}])
    assert result["ruleset_error"] is None
    assert list(result["namespaces"]) == ["acme"]
    assert [(match["namespace"], match["rule"]) for match in result["units"]["0"]["matches"]] == [("acme", "good")]


@pytest.mark.unit
def test_an_include_outside_the_repository_is_reported(tmp_path):
    outside = os.path.join(str(tmp_path), "outside", "strings.inc")
    _write(outside, "rule shared { condition: false }\n")
    signature_dir = _signature_dir(str(tmp_path), {"acme": {
        "rules.yar": f'include "{outside}"\nrule uses {{ condition: true }}\n',
    }})

    result = _run(tmp_path, signature_dir, [])
    assert result["ruleset_error"] is None
    assert [(os.path.basename(w["file"]), w["include"], w["error"]) for w in result["include_warnings"]] == [
        ("rules.yar", outside, "the include is outside the repository: it resolves differently in production")]


@pytest.mark.unit
def test_a_unit_that_cannot_be_scanned_is_reported_and_the_rest_are_scanned(tmp_path):
    signature_dir = _signature_dir(str(tmp_path), {"acme": {
        "rules.yar": 'rule good { strings: $a = "evil" condition: $a }\n',
    }})
    path = _sample(str(tmp_path), 0, "x.bin")
    missing = os.path.join(str(tmp_path), "u", "1", "files", "gone.bin")

    # a scan that raises leaves the scanner's results of the unit before it, which must not be
    # credited to the unit that failed
    result = _run(tmp_path, signature_dir, [{"id": 0, "path": path, "meta_tags": []},
                                            {"id": 1, "path": missing, "meta_tags": []}])
    assert [match["rule"] for match in result["units"]["0"]["matches"]] == ["good"]
    (error,) = result["units"]["1"]["errors"]
    assert (error["namespace"], error["type"]) == ("acme", "error")
    assert result["units"]["1"]["matches"] == []


@pytest.mark.unit
def test_a_file_that_is_not_utf8_drops_only_its_rules(tmp_path):
    signature_dir = _signature_dir(str(tmp_path), {"acme": {
        "good.yar": 'rule good { strings: $a = "evil" condition: $a }\n',
        "latin1.yar": 'rule caf\xe9 { condition: false }\n'.encode("latin-1"),
    }})
    path = _sample(str(tmp_path), 0, "x.bin")

    result = _run(tmp_path, signature_dir, [{"id": 0, "path": path, "meta_tags": []}])
    files = {os.path.basename(entry["path"]): entry for entry in result["files"]}
    assert "can't decode" in files["latin1.yar"]["error"]
    assert result["ruleset_error"] is None
    assert [match["rule"] for match in result["units"]["0"]["matches"]] == ["good"]

    production = _production(signature_dir)
    production.scan(path)
    assert [match["rule"] for match in production.scan_results] == ["good"]


@pytest.mark.unit
def test_a_nested_include_resolves_as_the_yara_service_resolves_it(tmp_path):
    signature_dir = _signature_dir(str(tmp_path), {"acme": {
        "main.yar": 'include "inc/outer.inc"\nrule main_rule { condition: outer_rule }\n',
        "inc/outer.inc": 'include "inner.inc"\nrule outer_rule { condition: inner_rule }\n',
        "inc/inner.inc": 'rule inner_rule { strings: $a = "evil" condition: $a }\n',
    }})
    path = _sample(str(tmp_path), 0, "x.bin")

    result = _run(tmp_path, signature_dir, [{"id": 0, "path": path, "meta_tags": []}])
    assert result["include_warnings"] == []
    (entry,) = result["files"]
    assert entry["error"] is None
    assert sorted(rule["name"] for rule in entry["rules"]) == ["inner_rule", "main_rule", "outer_rule"]

    production = _production(signature_dir)
    production.scan(path)
    assert sorted(match["rule"] for match in result["units"]["0"]["matches"]) == \
        sorted(match["rule"] for match in production.scan_results) == ["inner_rule", "main_rule", "outer_rule"]


@pytest.mark.unit
def test_a_missing_include_compiles_and_is_reported(tmp_path):
    signature_dir = _signature_dir(str(tmp_path), {"acme": {
        "inc.yar": 'include "common.yar"\nrule uses { strings: $a = "evil" condition: $a }\n',
        "local.yar": 'include "../../shared/strings.yar"\nrule shared { condition: false }\n',
    }})
    _write(os.path.join(signature_dir, "..", "shared", "strings.yar"), "")

    result = _run(tmp_path, signature_dir, [])
    assert result["ruleset_error"] is None
    assert [(os.path.basename(w["file"]), w["include"]) for w in result["include_warnings"]] == [("inc.yar", "common.yar")]
    assert _production(signature_dir).rules is not None


@pytest.mark.unit
def test_compiler_warnings_and_rules_are_reported(tmp_path):
    signature_dir = _signature_dir(str(tmp_path), {"acme": {
        "slow.yar": 'rule slow { meta: uuid = "u-slow" enabled = false strings: $a = /a.*b/ condition: $a }\n'
                    'private rule helper { condition: true }\n',
    }})
    result = _run(tmp_path, signature_dir, [])
    assert result["warnings"]
    assert result["namespaces"]["acme"]["rules"] == 2
    (entry,) = result["files"]
    assert {rule["name"]: (rule["private"], rule["meta"]) for rule in entry["rules"]} == {
        "slow": (False, {"uuid": "u-slow", "enabled": False}), "helper": (True, {})}


@pytest.mark.unit
@pytest.mark.skipif(not landlock_available(), reason="landlock is unavailable")
def test_the_sandboxed_scan_cannot_read_saq_home(tmp_path):
    workdir = tmp_path / "work"
    tree = workdir / "base" / "tree"
    secret = os.path.join(get_base_dir(), "etc", "saq.default.yaml")
    namespace_dir = str(tree / "yara" / "acme")
    _write(os.path.join(namespace_dir, "steal.yar"), f'include "{secret}"\nrule x {{ strings: $a = "evil" condition: $a }}\n')
    corpus = Corpus(units=[Unit(0, "0" * 64, "x.bin", (), path=_sample(str(workdir), 0, "x.bin"))])
    with open(os.path.join(workdir, "child.py"), "w") as fp, open(child.__file__) as source:
        fp.write(source.read())

    layout = TreeLayout(namespaces=[TreeNamespace("acme", namespace_dir, [os.path.join(namespace_dir, "steal.yar")])])
    # TCP is left unrestricted so this runs without TCP port rules (Landlock ABI 4, Linux 6.7)
    result = _run_child(str(workdir), str(workdir / "base"), str(tree), layout, corpus,
                        SandboxConfig(allowed_tcp_ports=None))

    errors = [warning["error"] for warning in result["include_warnings"]]
    assert any("Permission denied" in error for error in errors), errors
    assert [match["rule"] for match in result["units"]["0"]["matches"]] == ["x"]


@pytest.mark.unit
def test_two_namespaces_of_one_directory_stay_apart(tmp_path):
    # in the linked layout, two signature_dir entries can link to the same directory
    signature_dir = _signature_dir(str(tmp_path), {"acme": {
        "rules.yar": 'include "common.yar"\nrule same { strings: $a = "evil" condition: $a }\n',
        "common.yar": "",
    }})
    path = _sample(str(tmp_path), 0, "x.bin")
    namespace = _namespaces(signature_dir)[0]
    namespace["files"] = [file for file in namespace["files"] if file.endswith("rules.yar")]
    with open(os.path.join(tmp_path, child.JOB_FILE), "w") as fp:
        json.dump({"version": child.PROTOCOL_VERSION, "tree_root": os.path.dirname(signature_dir), "file_timeout": 10,
                   "namespaces": [namespace, {**namespace, "name": "alias"}],
                   "units": [{"id": 0, "path": path, "meta_tags": []}]}, fp)

    result = child.run(str(tmp_path))
    assert result["ruleset_error"] is None
    assert result["include_warnings"] == []
    assert sorted(match["namespace"] for match in result["units"]["0"]["matches"]) == ["acme", "alias"]
