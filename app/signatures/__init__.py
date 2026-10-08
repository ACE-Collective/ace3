"""The /signatures GUI area: detection signatures and how they are doing.

Laid out like /admin: a hub of cards, one per module, each a page of its own. Only page views live
here. Every page gets its data from aceapi_v2, called directly from the browser; Flask renders the
page shell and nothing else.
"""

# Imported first so its before_request guard is registered on the blueprint: `signature:read` gates
# the whole area, and a page can layer its own permission on top.
from app.signatures.views import access  # noqa: F401
from app.signatures.views.hub import signatures_hub
from app.signatures.views.samples import sample_detail, samples
from app.signatures.views.yara_qa import yara_qa

__all__ = [
    'sample_detail',
    'samples',
    'signatures_hub',
    'yara_qa',
]
