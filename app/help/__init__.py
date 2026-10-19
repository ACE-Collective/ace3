"""The /help GUI area: training guides, written in Markdown and rendered by the GUI.

Guides are grouped in sets, one per subsystem (app/help/guides.py). Each set is a directory under
app/help/content/ holding one Markdown file per guide and an images/ directory, so the guides also
read correctly where the repository is browsed. Any logged-in user may read every guide.
"""

# Imported first so its before_request guard is registered on the blueprint.
from app.help.views import access  # noqa: F401
from app.help.views.guides import guide, guide_image, guide_set, help_index

__all__ = [
    'guide',
    'guide_image',
    'guide_set',
    'help_index',
]
