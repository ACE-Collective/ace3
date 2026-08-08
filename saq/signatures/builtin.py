"""built-in detection signature registry

this module holds the *built-in* detection signatures: stable identities for
ACE's own (native) detection logic, where there is no external rule/uuid. it is
distinct from the external-rule "signatures" config domain
(etc/saq.signatures.default.yaml, signature_repos) which manages cloned rule
repositories.

kept intentionally lightweight (only stdlib imports) so that
saq.analysis.detection_point can import from it without creating import cycles.
"""

import os
from dataclasses import dataclass

# version sentinel used when a version cannot be determined: a real signature
# whose rule directory is not a git repo, OR a built-in signature when
# ACE_VERSION is not set in the environment (local/non-container runs, tests).
SIGNATURE_VERSION_UNKNOWN = "unknown"

# version sentinel stamped on detection points that predate signature attribution
# (serialized before this feature existed). distinct from SIGNATURE_VERSION_UNKNOWN
# ("version couldn't be determined for a known signature") - "legacy" means the
# detection has no attribution because it predates the feature entirely.
LEGACY_SIGNATURE_VERSION = "legacy"


def get_builtin_signature_version() -> str:
    """returns the version stamp for built-in (ACE-native) detection logic:
    the running ACE version from the ACE_VERSION environment variable
    (set as ENV in the Dockerfile, e.g. "3.0.60"), or SIGNATURE_VERSION_UNKNOWN
    when it is unset/empty. resolved at call time so detections reflect the
    version running when they were created and so tests can monkeypatch
    ACE_VERSION."""
    return os.environ.get("ACE_VERSION") or SIGNATURE_VERSION_UNKNOWN


@dataclass(frozen=True)
class BuiltinSignature:
    name: str           # stable snake_case identifier
    uuid: str           # generated via `python3 -m uuid`
    description: str     # human-readable purpose


# generic/default built-in: constructor default + safety net for any detection
# point added without an explicit signature (e.g. the test module). detections
# attributed to this should be monitored as "un-attributed".
GENERIC                       = BuiltinSignature("generic", "87fe1a4a-0e60-4e3b-b712-da9d3db12fa7", "ACE detection with no specific signature")
ALERTABLE_TAG                 = BuiltinSignature("alertable_tag", "14564014-a223-440a-914f-03a1f322e1bf", "tag configured as alertable")
CORRELATED_TAG_MATCH          = BuiltinSignature("correlated_tag_match", "6bf55f83-9ec0-4b64-88b4-63b237e010c4", "correlated tag match")
OBSERVABLE_FLAGGED            = BuiltinSignature("observable_flagged_for_detection", "97a0bcb8-1bde-4cf0-8fa2-72d6343c6458", "observable flagged for detection")
ARCHIVE_SINGLE_DANGEROUS_FILE = BuiltinSignature("archive_single_dangerous_file", "de4bfc85-d827-4e60-a7e3-211b60ad61c8", "archive holds a single exe/script/shortcut/JNLP/OneNote")
RTF_EXTRACTED_SUSPECT_FILE    = BuiltinSignature("rtf_extracted_suspect_file", "cb9764d5-049b-4b7e-bf40-cf7e9c618058", "RTF-extracted file suspect ext/mime/type")
OLE_EXTRACTED_SUSPECT_FILE    = BuiltinSignature("ole_extracted_suspect_file", "827c5aab-9fa2-45d9-8c5e-a13cd1be9812", "OLE attachment suspect type/ext/javascript")
VBS_HEX_ENCODED_CONTENT       = BuiltinSignature("vbs_hex_encoded_content", "e46a6485-7ccd-4cba-8196-7540c5e7a1b9", "VBS large hex strings / high hex %")
OFFICE_EXTERNAL_OLEOBJECT     = BuiltinSignature("office_external_oleobject", "6ee4fb89-87d9-4cf0-85ec-52f7760b9a1d", "Office links external OLE object")
XLM_MACRO_URL                 = BuiltinSignature("xlm_macro_url", "3e719b5d-8063-4cd7-a72b-3d1cc8ead39c", "URL inside an Excel 4.0 macro")
EMAIL_ENCRYPTED_DECRYPTED     = BuiltinSignature("email_encrypted_attachment_decrypted", "ef715326-081e-4ece-97ba-02817b5a28cd", "decrypted email attachment (office/rar/zip)")
EMAIL_MACRO_NEW_SENDER        = BuiltinSignature("email_macro_new_sender", "26fb96a4-6e20-48df-b826-a9c4a25b1965", "macro from a new sender")
EMAIL_SUSPECT_URL_NEW_SENDER  = BuiltinSignature("email_suspect_url_new_sender", "11b42a94-e21a-4cd0-bdb6-8f278d20611d", "suspect URL from a new sender")
CVE_2021_30657_DMG_SCRIPT     = BuiltinSignature("cve_2021_30657_dmg_script", "3ba358a3-b7ab-4475-a10a-f2a8070b455d", "CVE-2021-30657 DMG script")
URL_GOOGLE_SAFE_BROWSING      = BuiltinSignature("url_google_safe_browsing_match", "c49cb4bf-12f2-4a46-9943-4c432481fe74", "Google Safe Browsing match")
URL_CLICKER                   = BuiltinSignature("url_clicker", "a764126b-443d-4991-a554-72d86125382d", "user clicked a URL / visited a flagged domain (clicker detection)")
DHASH_IMAGE_MATCH             = BuiltinSignature("dhash_image_match", "10d1e320-3b07-45f1-9bcf-078044643b7e", "image dhash match")
# fallback for YARA rules that matched but carry no uuid meta (warn-but-detect)
YARA_RULE_MATCH               = BuiltinSignature("yara_rule_match", "3557435e-da7f-4b1b-a5dd-655107839530", "YARA rule match with no uuid meta")
# special built-in for detection points that predate signature attribution: applied
# on load when a serialized detection point is missing the signature fields. distinct
# from GENERIC so legacy detections are not conflated with freshly-created un-attributed ones.
LEGACY                        = BuiltinSignature("legacy", "3c649355-160e-405c-ad91-6916ab539849", "detection point predating signature attribution")

# constructor default for DetectionPoint
BUILTIN_SIGNATURE_UUID = GENERIC.uuid

# applied on load to detection points serialized before signature attribution existed
LEGACY_SIGNATURE_UUID = LEGACY.uuid

# uuid -> BuiltinSignature lookup
BUILTIN_SIGNATURES = {
    s.uuid: s
    for s in (
        GENERIC,
        ALERTABLE_TAG,
        CORRELATED_TAG_MATCH,
        OBSERVABLE_FLAGGED,
        ARCHIVE_SINGLE_DANGEROUS_FILE,
        RTF_EXTRACTED_SUSPECT_FILE,
        OLE_EXTRACTED_SUSPECT_FILE,
        VBS_HEX_ENCODED_CONTENT,
        OFFICE_EXTERNAL_OLEOBJECT,
        XLM_MACRO_URL,
        EMAIL_ENCRYPTED_DECRYPTED,
        EMAIL_MACRO_NEW_SENDER,
        EMAIL_SUSPECT_URL_NEW_SENDER,
        CVE_2021_30657_DMG_SCRIPT,
        URL_GOOGLE_SAFE_BROWSING,
        URL_CLICKER,
        DHASH_IMAGE_MATCH,
        YARA_RULE_MATCH,
        LEGACY,
    )
}
