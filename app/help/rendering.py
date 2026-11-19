"""Rendering a guide's Markdown into the HTML the guide page shows, with its table of contents.

The guides are trusted repository content, so raw HTML in them passes through. Beyond Python-
Markdown's `extra` and `toc`, three things make a guide read the same in the GUI and in the
repository:
- a link to another guide is written `users.md#section` and served as `users#section`;
- GitHub's alert syntax (`> [!TIP]`) becomes a callout block;
- an image links to itself, so a screenshot shrunk to the page width opens at full size in a new
  tab.
Only absolute http(s) links open in a new tab.

Playbooks (render_playbook) share the callouts, the image links and the new-tab rule; see below for
what they do differently.
"""

import re
import xml.etree.ElementTree as etree
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import markdown
import yaml
from markdown.preprocessors import Preprocessor
from markdown.treeprocessors import Treeprocessor
from markupsafe import Markup

from saq.configuration.config import get_config
from saq.constants import PLAYBOOK_NAME_PATTERN
from saq.environment import get_base_dir

# a link to a sibling guide: `users.md` or `users.md#reviewing-a-run`
_GUIDE_LINK = re.compile(r"^([A-Za-z0-9_-]+)\.md(#.*)?$")
# the marker GitHub uses for an alert blockquote, at the start of its first paragraph
_CALLOUT = re.compile(r"^\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\][ \t]*\n?")
_CALLOUT_TITLES = {"NOTE": "Note", "TIP": "Tip", "IMPORTANT": "Important", "WARNING": "Warning",
                   "CAUTION": "Caution"}


def _open_external_links(root) -> None:
    for a in root.iter("a"):
        if a.get("href", "").startswith(("http://", "https://")):
            a.set("target", "_blank")
            a.set("rel", "noopener noreferrer")


def _convert_callouts(root) -> None:
    for blockquote in root.iter("blockquote"):
        first = blockquote[0] if len(blockquote) else None
        if first is None or first.tag != "p" or not (m := _CALLOUT.match(first.text or "")):
            continue
        kind = m.group(1)
        first.text = first.text[m.end():]
        blockquote.tag = "div"
        blockquote.set("class", f"help-callout help-callout-{kind.lower()}")
        title = etree.Element("p", {"class": "help-callout-title"})
        title.text = _CALLOUT_TITLES[kind]
        blockquote.insert(0, title)


def _link_images(root) -> None:
    for parent in list(root.iter()):
        if parent.tag == "a":
            continue
        for index, child in enumerate(list(parent)):
            if child.tag != "img":
                continue
            link = etree.Element("a", {"href": child.get("src", ""), "class": "help-image",
                                       "title": "Open the full-size image", "target": "_blank"})
            link.tail, child.tail = child.tail, None
            parent.remove(child)
            link.append(child)
            parent.insert(index, link)


class _GuideTreeprocessor(Treeprocessor):
    def run(self, root):
        _open_external_links(root)
        for a in root.iter("a"):
            if (m := _GUIDE_LINK.match(a.get("href", ""))):
                a.set("href", m.group(1) + (m.group(2) or ""))
        _convert_callouts(root)
        _link_images(root)


class _GuideExtension(markdown.Extension):
    def extendMarkdown(self, md):
        # after inline processing (priority 20), so links and images exist as elements
        md.treeprocessors.register(_GuideTreeprocessor(md), "help_guide", 15)


@dataclass(frozen=True)
class TocEntry:
    id: str
    name: str
    children: tuple["TocEntry", ...]


@dataclass(frozen=True)
class RenderedGuide:
    html: Markup
    # the guide's sections (h2) and their subsections (h3), for the page's sidebar
    toc: tuple[TocEntry, ...]


def _toc_entries(tokens: list[dict]) -> tuple[TocEntry, ...]:
    return tuple(TocEntry(t["id"], t["name"], _toc_entries(t["children"])) for t in tokens)


def render_markdown_guide(text: str) -> RenderedGuide:
    md = markdown.Markdown(
        extensions=["extra", "toc", "sane_lists", _GuideExtension()],
        extension_configs={"toc": {"toc_depth": "2-3", "permalink": "#", "permalink_class": "help-anchor",
                                   "permalink_title": "Link to this section"}},
    )
    html = md.convert(text)
    return RenderedGuide(Markup(html), _toc_entries(md.toc_tokens))


@lru_cache(maxsize=32)
def _render_file(path: str, mtime_ns: int) -> RenderedGuide:
    # mtime_ns is part of the cache key only: an edited guide renders again on its next view
    return render_markdown_guide(Path(path).read_text(encoding="utf-8"))


def render_guide(path: Path) -> RenderedGuide:
    return _render_file(str(path), path.stat().st_mtime_ns)


# ---------------------------------------------------------------------------------------- playbooks
# A playbook (global.playbooks_dir) is an analyst's triage guide that a hunt names in rule.playbook.
# Unlike a guide it is not ACE's own content, so raw HTML in it is shown as text rather than passed
# through, and a link or image whose URL has a scheme other than http(s) or mailto loses the URL.

_FRONTMATTER = re.compile(r"\A---\r?\n(.*?)\r?\n---[ \t]*\r?\n", re.S)
# a link to another playbook: `oauth-phishing.md` or `oauth-phishing.md#triage`
_PLAYBOOK_LINK = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*\.md)(#.*)?$")
_URL_SCHEME = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*):")
# browsers ignore ASCII whitespace and control characters inside a scheme (`java\tscript:`)
_URL_IGNORED = re.compile(r"[\x00-\x20]")
_SAFE_SCHEMES = {"http", "https", "mailto"}
_PLAYBOOK_ASSETS = "assets/"
_LIST_ITEM = re.compile(r"^( *)([-*+]|\d+[.)])( +)")
_FENCE_OPEN = re.compile(r"^ *(`{3,}|~{3,})")


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def normalize_playbook_lists(lines: list[str]) -> list[str]:
    """GitHub-style list nesting rewritten into what Python-Markdown parses.

    A playbook nests a list under its parent's marker width (2 spaces under `-`, 3 under `1.`), as
    GitHub renders it; Python-Markdown nests only at 4, and flattens anything less into the parent.
    And it cannot parse a fenced code block inside a list item at all, which is where a triage step
    puts its query. So nested list lines move to 4 spaces per level, and a fence inside a list item
    becomes an indented code block in that item. Top-level fences pass through untouched."""
    out: list[str] = []
    stack: list[int] = []  # the source content column of each open list item
    i = 0
    while i < len(lines):
        line = lines[i]
        if not line.strip():
            out.append(line)
            i += 1
            continue
        indent = _indent(line)
        depth = len(stack)
        while stack and indent < stack[-1]:
            stack.pop()
        # Python-Markdown hands a nested list every line of its block, so a shallower item right
        # after one would be swallowed into it without a blank line between them
        if stack and len(stack) < depth and out and out[-1].strip():
            out.append("")
        elif not stack and depth and _LIST_ITEM.match(line) and out and out[-1].strip():
            out.append("")
        if (fence := _FENCE_OPEN.match(line)):
            marker = fence.group(1)
            closing = re.compile(r"^ *" + re.escape(marker[0]) + "{" + str(len(marker)) + r",}\s*$")
            j = i + 1
            # a fence in a list item ends with the item: a line less indented than the fence closes
            # the item, so an unclosed fence cannot swallow the steps after it
            while j < len(lines) and not closing.match(lines[j]) and not (
                    stack and lines[j].strip() and _indent(lines[j]) < indent):
                j += 1
            closed = j < len(lines) and closing.match(lines[j]) is not None
            body = lines[i + 1:j]
            if stack and closed:
                code_indent = " " * (4 * len(stack) + 4)
                if out and out[-1].strip():
                    out.append("")
                out.extend(code_indent + b[min(indent, _indent(b)):] for b in body)
                out.append("")
                i = j + 1
                continue
            if not stack and closed:
                # Python-Markdown closes a fence only with exactly its opening marker; CommonMark and
                # GitHub accept any longer run of the same character
                out.append(line)
                out.extend(body)
                out.append(" " * _indent(line) + marker)
                i = j + 1
                continue
            # an unclosed fence is ordinary text, as Python-Markdown would read it
        if (item := _LIST_ITEM.match(line)):
            out.append(" " * (4 * len(stack)) + line.lstrip(" "))
            stack.append(indent + len(item.group(2)) + len(item.group(3)))
        elif stack:
            # a continuation of the item; anything indented past its content column (an indented
            # code block) keeps that extra indentation
            out.append(" " * (4 * len(stack) + indent - stack[-1]) + line.lstrip(" "))
        else:
            out.append(line)
        i += 1
    return out


class _PlaybookListPreprocessor(Preprocessor):
    def run(self, lines):
        return normalize_playbook_lists(lines)


def _is_safe_url(url: str) -> bool:
    m = _URL_SCHEME.match(_URL_IGNORED.sub("", url))
    return m is None or m.group(1).lower() in _SAFE_SCHEMES


class _PlaybookTreeprocessor(Treeprocessor):
    def __init__(self, md, page_prefix: str, asset_prefix: str):
        super().__init__(md)
        self.page_prefix = page_prefix
        self.asset_prefix = asset_prefix

    def run(self, root):
        for element in root.iter():
            for attribute in ("href", "src"):
                url = element.get(attribute)
                if url is None:
                    continue
                if not _is_safe_url(url):
                    del element.attrib[attribute]
                elif url.startswith(_PLAYBOOK_ASSETS):
                    element.set(attribute, self.asset_prefix + url[len(_PLAYBOOK_ASSETS):])
                elif attribute == "href" and (m := _PLAYBOOK_LINK.match(url)):
                    element.set(attribute, self.page_prefix + m.group(1) + (m.group(2) or ""))
        _open_external_links(root)
        _convert_callouts(root)
        _link_images(root)


# the attributes the playbook extensions produce; anything else (an event handler, a style) is
# dropped after every other tree step has run
_ALLOWED_ATTRIBUTES = {"href", "src", "alt", "title", "class", "id", "colspan", "rowspan", "align",
                       "start", "target", "rel", "role"}
_TABLE_ALIGN = re.compile(r"^text-align: (left|right|center);?$")


class _PlaybookAttributeFilter(Treeprocessor):
    def run(self, root):
        for element in root.iter():
            for attribute in list(element.attrib):
                value = element.attrib[attribute]
                if attribute == "style" and _TABLE_ALIGN.match(value):
                    continue
                if attribute not in _ALLOWED_ATTRIBUTES or (attribute in ("href", "src") and not _is_safe_url(value)):
                    del element.attrib[attribute]


class _PlaybookExtension(markdown.Extension):
    def __init__(self, page_prefix: str, asset_prefix: str):
        super().__init__()
        self.page_prefix = page_prefix
        self.asset_prefix = asset_prefix

    def extendMarkdown(self, md):
        # without these two, raw HTML becomes text: `<script>` shows as typed, and so does a
        # placeholder like `<hostname>` that would otherwise vanish as an unknown tag
        md.preprocessors.deregister("html_block")
        md.inlinePatterns.deregister("html")
        # after normalize_whitespace (30), before fenced_code_block (25)
        md.preprocessors.register(_PlaybookListPreprocessor(md), "playbook_lists", 27)
        md.treeprocessors.register(_PlaybookTreeprocessor(md, self.page_prefix, self.asset_prefix), "playbook", 15)
        # after inline (20), prettify (10) and every extension's tree step
        md.treeprocessors.register(_PlaybookAttributeFilter(md), "playbook_attributes", 1)


@dataclass(frozen=True)
class RenderedPlaybook:
    name: str
    title: str
    html: Markup
    # the frontmatter's source_url, when it has one
    source_url: str | None


def split_frontmatter(text: str) -> tuple[dict, str]:
    """The YAML frontmatter of a Markdown file as a dict (empty when it has none) and the body after it."""
    m = _FRONTMATTER.match(text)
    if not m:
        return {}, text
    try:
        meta = yaml.safe_load(m.group(1))
    except yaml.YAMLError:
        # broken frontmatter is an authoring mistake in the playbook, not an ACE failure: the body
        # still renders, under the file name
        meta = None
    return (meta if isinstance(meta, dict) else {}), text[m.end():]


def render_markdown_playbook(name: str, text: str, page_prefix: str, asset_prefix: str) -> RenderedPlaybook:
    meta, body = split_frontmatter(text)
    # `extra` without attr_list, which would let `{onclick=...}` put any attribute on an element, and
    # without md_in_html, which has nothing to do with raw HTML turned off
    html = markdown.markdown(body, extensions=["abbr", "def_list", "fenced_code", "footnotes", "tables", "sane_lists",
                                               _PlaybookExtension(page_prefix, asset_prefix)])
    title = meta.get("title")
    source_url = meta.get("source_url")
    return RenderedPlaybook(
        name=name,
        title=str(title) if title else name,
        html=Markup(html),
        source_url=str(source_url) if source_url and _is_safe_url(str(source_url)) else None,
    )


@lru_cache(maxsize=256)
def _render_playbook_file(path: str, mtime_ns: int, page_prefix: str, asset_prefix: str) -> RenderedPlaybook:
    # mtime_ns is part of the cache key only: an edited playbook renders again on its next view
    return render_markdown_playbook(Path(path).name, Path(path).read_text(encoding="utf-8"), page_prefix, asset_prefix)


def get_playbooks_dir() -> Path:
    return Path(get_base_dir()) / get_config().global_settings.playbooks_dir


def contained_path(directory: Path, relative: str) -> Path | None:
    """directory/relative resolved, or None when it resolves outside directory (a symlink out of it)."""
    root = directory.resolve()
    path = (directory / relative).resolve()
    return path if path.is_relative_to(root) and path != root else None


def get_playbook_path(name: str) -> Path | None:
    """The path of the playbook a hunt named, or None when the name is not a bare .md file name or
    resolves outside the playbooks directory."""
    if not re.match(PLAYBOOK_NAME_PATTERN, name or ""):
        return None
    return contained_path(get_playbooks_dir(), name)


def render_playbook(name: str, page_prefix: str, asset_prefix: str) -> RenderedPlaybook | None:
    """The named playbook rendered to HTML, or None when there is no such file. A file that cannot be
    read or rendered raises.

    page_prefix and asset_prefix are the URLs a link to another playbook and an image under assets/
    are rewritten onto (the name or the path under assets/ is appended)."""
    path = get_playbook_path(name)
    if path is None:
        return None
    if not path.is_file():
        # a hunt naming a playbook that is not in the directory: the alert page says so
        return None
    return _render_playbook_file(str(path), path.stat().st_mtime_ns, page_prefix, asset_prefix)
