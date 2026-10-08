from flask import current_app, render_template

from app.blueprints import signatures

# Candidate modules shown on the Signatures hub. A tile renders only when its endpoint is registered
# AND the current user holds the required permission (enforced in the template via has_permission).
SIGNATURE_MODULES = [
    {
        "endpoint": "signatures.yara_qa",
        "title": "Yara QA Results",
        "description": "Browse YARA rules running in QA mode, how often they match, and download the files they matched.",
        "major": "signature",
        "minor": "read",
    },
    {
        "endpoint": "signatures.samples",
        "title": "Samples",
        "description": "Files YARA rules matched on alerts graded TP or FP, with their labels. These are what rule changes are tested against.",
        "major": "signature",
        "minor": "read",
    },
]


@signatures.route("/")
def signatures_hub():
    # Auth and the signature:read umbrella gate are enforced by the blueprint before_request (see
    # app/signatures/views/access.py), so no per-view decorator is needed here.
    modules = [m for m in SIGNATURE_MODULES if m["endpoint"] in current_app.view_functions]
    return render_template("signatures/hub.html", signature_modules=modules)
