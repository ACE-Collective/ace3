import json

from saq.signatures.builtin import (
    BUILTIN_SIGNATURE_UUID,
    LEGACY_SIGNATURE_UUID,
    LEGACY_SIGNATURE_VERSION,
    get_builtin_signature_version,
)
from saq.util import sha256_str

KEY_DESCRIPTION = 'description'
KEY_DETAILS = 'details'
KEY_QUEUE = 'queue'
KEY_SIGNATURE_UUID = 'signature_uuid'
KEY_SIGNATURE_VERSION = 'signature_version'

class DetectionPoint:
    """Represents an observation that would result in a detection."""

    def __init__(self, description=None, details=None, queue=None, signature_uuid=None, signature_version=None):
        self.description = description
        self.details = details
        # an optional queue this detection requests the resulting alert be routed to
        # (see saq.engine.analysis_orchestrator._apply_detection_queue)
        self.queue = queue
        # signature attribution: which signature produced this detection and at what version.
        # both are required (never null) - default in the constructor so this is the single
        # choke point guaranteeing the invariant for fresh creation and from_json alike.
        # the generic built-in covers detections added without explicit attribution; the
        # built-in version is resolved from ACE_VERSION at creation time.
        self.signature_uuid = signature_uuid or BUILTIN_SIGNATURE_UUID
        self.signature_version = signature_version or get_builtin_signature_version()

    @property
    def json(self):
        return {
            KEY_DESCRIPTION: self.description,
            KEY_DETAILS: self.details,
            KEY_QUEUE: self.queue,
            KEY_SIGNATURE_UUID: self.signature_uuid,
            KEY_SIGNATURE_VERSION: self.signature_version }

    @json.setter
    def json(self, value):
        assert isinstance(value, dict)
        if KEY_DESCRIPTION in value:
            self.description = value[KEY_DESCRIPTION]
        if KEY_DETAILS in value:
            self.details = value[KEY_DETAILS]
        if KEY_QUEUE in value:
            self.queue = value[KEY_QUEUE]
        # backfill the LEGACY identity for OLD serialized detection points that
        # predate signature attribution (or carry an explicit null) so the
        # never-null invariant holds on load and legacy detections stay distinguishable
        # from freshly-created un-attributed ones (which get the generic built-in).
        self.signature_uuid = value.get(KEY_SIGNATURE_UUID) or LEGACY_SIGNATURE_UUID
        self.signature_version = value.get(KEY_SIGNATURE_VERSION) or LEGACY_SIGNATURE_VERSION

    @staticmethod
    def from_json(dp_json):
        """Loads a DetectionPoint from a JSON dict. Used by _materalize."""
        dp = DetectionPoint()
        dp.json = dp_json
        return dp

    @property
    def display_description(self):
        if isinstance(self.description, str):
            return self.description.encode('unicode_escape').decode()
        else:
            return self.description

    @property
    def id(self):
        return sha256_str(str(self))

    @property
    def content_hash(self):
        """Stable data identity for idempotent DB upsert. Distinct from `id`
        (the UI/DOM display identity): folds in the signature attribution and a
        canonical rendering of details so the upsert key is content-addressed.
        Both the analysis and database layers compute this the same way."""
        details = json.dumps(self.details, sort_keys=True, default=str) if self.details else ""
        return sha256_str(self.signature_uuid + "\n" + str(self.description) + "\n" + details)

    def __str__(self):
        return "DetectionPoint({})".format(self.description)

    def __eq__(self, other):
        if not isinstance(other, DetectionPoint):
            return False

        return self.description == other.description and self.details == other.details \
            and self.queue == other.queue and self.signature_uuid == other.signature_uuid \
            and self.signature_version == other.signature_version
