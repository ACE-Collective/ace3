"""Every guide in the registry exists, and every link and image in it resolves.

Guides are refreshed piecemeal (a screenshot retaken, a section renamed), so this is what keeps a
guide from pointing at an image, a guide or a section that is no longer there, and keeps images/
free of screenshots nothing uses.
"""

from html.parser import HTMLParser
from urllib.parse import urlsplit

import pytest
from werkzeug.exceptions import MethodNotAllowed, NotFound

from app.help.guides import GUIDE_SETS
from app.help.rendering import render_guide

pytestmark = pytest.mark.unit

# where the GUI is mounted (saq/cli/commands/gui_api.py); the test app itself is served from /
GUI_ROOT = "/ace"


class _References(HTMLParser):
    def __init__(self):
        super().__init__()
        self.hrefs: list[str] = []
        self.images: list[str] = []
        self.ids: set[str] = set()

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if "id" in attrs:
            self.ids.add(attrs["id"])
        if tag == "a" and "href" in attrs:
            self.hrefs.append(attrs["href"])
        if tag == "img":
            self.images.append(attrs["src"])


def _references(guide_set, guide) -> _References:
    refs = _References()
    refs.feed(render_guide(guide_set.path(guide)).html)
    return refs


ALL_GUIDES = [(s, g) for s in GUIDE_SETS for g in s.guides]


def _guide_id(param):
    return f"{param[0].slug}/{param[1].slug}"


@pytest.mark.parametrize("guide_set, guide", ALL_GUIDES, ids=[_guide_id(p) for p in ALL_GUIDES])
def test_guide_file_exists(guide_set, guide):
    assert guide_set.path(guide).is_file()


@pytest.mark.parametrize("guide_set, guide", ALL_GUIDES, ids=[_guide_id(p) for p in ALL_GUIDES])
def test_images_exist(guide_set, guide):
    for src in _references(guide_set, guide).images:
        assert src.startswith("images/"), f"{src}: images live in the set's images/ directory"
        assert (guide_set.directory / src).is_file(), src


@pytest.mark.parametrize("guide_set, guide", ALL_GUIDES, ids=[_guide_id(p) for p in ALL_GUIDES])
def test_links_resolve(app, guide_set, guide):
    refs = _references(guide_set, guide)
    adapter = app.url_map.bind("localhost")
    problems = []
    for href in refs.hrefs:
        parts = urlsplit(href)
        if parts.scheme in ("http", "https", "mailto"):
            continue
        if href.startswith("images/"):
            if not (guide_set.directory / parts.path).is_file():
                problems.append(f"{href}: no such image")
            continue
        if parts.path.startswith("/"):
            # a page of the GUI, e.g. /ace/svs/runs
            if not parts.path.startswith(f"{GUI_ROOT}/"):
                problems.append(f"{href}: a GUI link starts with {GUI_ROOT}/")
                continue
            try:
                adapter.match(parts.path.removeprefix(GUI_ROOT), method="GET")
            except (NotFound, MethodNotAllowed):
                problems.append(f"{href}: no such GUI page")
            continue
        target = guide_set.get_guide(parts.path) if parts.path else guide
        if target is None:
            problems.append(f"{href}: no such guide in {guide_set.slug}")
            continue
        if parts.fragment:
            ids = refs.ids if target is guide else _references(guide_set, target).ids
            if parts.fragment not in ids:
                problems.append(f"{href}: no section #{parts.fragment} in {target.slug}")
    assert problems == []


@pytest.mark.parametrize("guide_set", GUIDE_SETS, ids=[s.slug for s in GUIDE_SETS])
def test_no_orphan_images(guide_set):
    used = {src for g in guide_set.guides for src in _references(guide_set, g).images}
    used |= {h for g in guide_set.guides for h in _references(guide_set, g).hrefs if h.startswith("images/")}
    on_disk = {f"images/{p.relative_to(guide_set.images_dir).as_posix()}"
               for p in guide_set.images_dir.rglob("*") if p.is_file()}
    assert sorted(on_disk - used) == []


def test_guide_slugs_are_unique():
    for guide_set in GUIDE_SETS:
        slugs = [g.slug for g in guide_set.guides]
        assert len(slugs) == len(set(slugs)), guide_set.slug
        # a guide named "images" would be shadowed by the image route
        assert "images" not in slugs
    set_slugs = [s.slug for s in GUIDE_SETS]
    assert len(set_slugs) == len(set(set_slugs))
