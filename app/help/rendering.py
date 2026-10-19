"""Rendering a guide's Markdown into the HTML the guide page shows, with its table of contents.

The guides are trusted repository content, so raw HTML in them passes through. Beyond Python-
Markdown's `extra` and `toc`, three things make a guide read the same in the GUI and in the
repository:
- a link to another guide is written `users.md#section` and served as `users#section`;
- GitHub's alert syntax (`> [!TIP]`) becomes a callout block;
- an image links to itself, so a screenshot shrunk to the page width opens at full size in a new
  tab.
Only absolute http(s) links open in a new tab.
"""

import re
import xml.etree.ElementTree as etree
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import markdown
from markdown.treeprocessors import Treeprocessor
from markupsafe import Markup

# a link to a sibling guide: `users.md` or `users.md#reviewing-a-run`
_GUIDE_LINK = re.compile(r"^([A-Za-z0-9_-]+)\.md(#.*)?$")
# the marker GitHub uses for an alert blockquote, at the start of its first paragraph
_CALLOUT = re.compile(r"^\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\][ \t]*\n?")
_CALLOUT_TITLES = {"NOTE": "Note", "TIP": "Tip", "IMPORTANT": "Important", "WARNING": "Warning",
                   "CAUTION": "Caution"}


class _GuideTreeprocessor(Treeprocessor):
    def run(self, root):
        for a in root.iter("a"):
            href = a.get("href", "")
            if href.startswith(("http://", "https://")):
                a.set("target", "_blank")
                a.set("rel", "noopener noreferrer")
            elif (m := _GUIDE_LINK.match(href)):
                a.set("href", m.group(1) + (m.group(2) or ""))

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
