"""The guide registry: which guide sets exist, which guides each holds, and in what order.

A guide set is a directory under app/help/content/ named by its slug, holding `<guide slug>.md` per
guide and the images those guides use under images/. Adding a guide is a Markdown file and an entry
here; tests/app/help/test_help_content.py checks that every entry has its file and that every link
and image in a guide resolves.
"""

from dataclasses import dataclass
from pathlib import Path

CONTENT_DIR = Path(__file__).parent / "content"


@dataclass(frozen=True)
class Guide:
    slug: str
    title: str
    # who the guide is for, shown on the Documentation index
    audience: str


@dataclass(frozen=True)
class GuideSet:
    slug: str
    title: str
    description: str
    guides: tuple[Guide, ...]

    @property
    def directory(self) -> Path:
        return CONTENT_DIR / self.slug

    @property
    def images_dir(self) -> Path:
        return self.directory / "images"

    def get_guide(self, slug: str) -> Guide | None:
        return next((g for g in self.guides if g.slug == slug), None)

    def path(self, guide: Guide) -> Path:
        return self.directory / f"{guide.slug}.md"


GUIDE_SETS: tuple[GuideSet, ...] = (
    GuideSet(
        slug="svs",
        title="Signature Validation System (SVS)",
        description="Testing ACE's detection signatures: YARA regression testing against graded samples, "
                    "and Atomic Red Team runs that measure which ATT&CK techniques ACE detects.",
        guides=(
            Guide("beginners", "Beginner's guide",
                  "New to ACE, or to signature validation and regression testing? Start here."),
            Guide("users", "User's guide",
                  "For analysts who run atomics, review their results and write or fix signatures from them."),
            Guide("administrators", "Administrator's guide",
                  "For ACE administrators who set SVS up and keep it running."),
            Guide("developers", "Developer's guide",
                  "For developers who want to understand how SVS works, to improve it, build on it or fix it."),
        ),
    ),
)


def get_guide_set(slug: str) -> GuideSet | None:
    return next((s for s in GUIDE_SETS if s.slug == slug), None)
