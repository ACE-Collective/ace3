"""The yara rule inventory as the QA listing sees it. Kept apart from inventory.py, which loads it:
the signature loaders import the hunter and, through it, the engine, which the API must not pull
in at import time."""

import time
from dataclasses import dataclass, field
from typing import Optional

from saq.signatures.model import Signature
from saq.signatures.yara_meta import MODIFIER_QA


# yara_qa_signatures.signature_uuid / yara_qa_matches.signature_uuid column width
SIGNATURE_UUID_MAX_LENGTH = 36


def is_qa_signature(signature: Signature) -> bool:
    return MODIFIER_QA in signature.modifiers


@dataclass(frozen=True)
class YaraInventory:
    # every yara rule with a uuid, by uuid
    by_uuid: dict[str, Signature] = field(default_factory=dict)
    # monotonic time it was built
    built_at: float = field(default_factory=time.monotonic)
    # why the inventory is empty or partial, for the API to pass on; None when it loaded cleanly
    error: Optional[str] = None

    @property
    def qa_signatures(self) -> list[Signature]:
        return [signature for signature in self.by_uuid.values() if is_qa_signature(signature)]
