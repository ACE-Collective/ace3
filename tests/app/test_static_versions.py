"""Static URLs carry a hash of the file, so a release that changes a file changes its URL and
the browser never runs a stale copy (add_static_version in app/application.py)."""

import hashlib
import os
import pathlib
import re

import pytest
from flask import Blueprint, url_for

from app.application import static_file_version

pytestmark = pytest.mark.integration

ROOT = pathlib.Path(__file__).resolve().parents[2]


def _version_of(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()[:12]


def test_static_url_carries_the_file_hash(app):
    url = url_for("static", filename="css/saq.css")
    assert url.endswith(f"/static/css/saq.css?v={_version_of(ROOT / 'app/static/css/saq.css')}")


def test_missing_file_gets_no_version(app):
    assert url_for("static", filename="js/does-not-exist.js").endswith("/static/js/does-not-exist.js")


def test_path_outside_the_static_folder_gets_no_version(app):
    assert "v=" not in url_for("static", filename="../application.py")


def test_explicit_version_is_kept(app):
    assert url_for("static", filename="css/saq.css", v="pinned").endswith("?v=pinned")


def test_hash_is_computed_once_per_process(app, tmp_path):
    app.static_folder = str(tmp_path)
    app.debug = False  # the unit test config runs with DEBUG on
    (tmp_path / "a.js").write_text("one")
    first = url_for("static", filename="a.js")

    (tmp_path / "a.js").write_text("two")
    assert url_for("static", filename="a.js") == first


def test_debug_rehashes_a_changed_file(app, tmp_path):
    app.static_folder = str(tmp_path)
    app.debug = True
    path = tmp_path / "a.js"
    path.write_text("one")
    first = url_for("static", filename="a.js")

    path.write_text("two, longer")
    stat = path.stat()
    # make sure the mtime moves even on a filesystem with coarse timestamps
    os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000_000))

    second = url_for("static", filename="a.js")
    assert second != first
    assert second.endswith(f"?v={_version_of(path)}")


def test_debug_missing_file_gets_no_version(app, tmp_path):
    app.static_folder = str(tmp_path)
    app.debug = True
    assert "v=" not in url_for("static", filename="missing.js")


def test_blueprint_static_url_carries_the_file_hash(app, tmp_path):
    (tmp_path / "x.js").write_text("integration")
    app.register_blueprint(Blueprint("versioned_bp", __name__, static_folder=str(tmp_path),
                                     static_url_path="/versioned_bp/static"))
    assert url_for("versioned_bp.static", filename="x.js").endswith(f"?v={_version_of(tmp_path / 'x.js')}")


def test_every_static_reference_on_a_page_is_versioned(web_client):
    html = web_client.get(url_for("analysis.manage")).data.decode()
    html = re.sub(r"<!--.*?-->", "", html, flags=re.S)  # base.html keeps a few disabled includes
    references = re.findall(r'(?:src|href)="([^"]*/static/[^"]*)"', html)
    assert references
    assert [r for r in references if not re.search(r"\?v=[0-9a-f]{12}$", r)] == []


def test_static_file_version_of_unreadable_file_is_none(tmp_path):
    assert static_file_version(str(tmp_path / "missing")) is None
    assert static_file_version(str(tmp_path)) is None  # a directory


def test_no_template_appends_its_own_version():
    """url_for() adds ?v= itself; a second query string appended by hand would end up inside v."""
    offenders = [str(p) for p in (ROOT / "app/templates").rglob("*.html") if "?version=" in p.read_text()]
    assert offenders == []


@pytest.mark.parametrize("conf", ["etc/nginx/conf.d/default.conf", "etc/nginx/conf.d.external/default.conf"])
def test_nginx_sets_cache_control_on_static_files(conf):
    """Without Cache-Control the browser guesses a lifetime from Last-Modified and keeps
    running the old file after a release."""
    text = (ROOT / conf).read_text()
    location = re.search(r"location /ace/static \{(.*?)\}", text, re.S).group(1)
    assert "add_header Cache-Control $ace_static_cache_control;" in location
    assert re.search(r'map \$arg_v \$ace_static_cache_control \{\s*""\s+"no-cache";', text)
