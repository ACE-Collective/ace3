from flask import render_template

from app.blueprints import signatures


@signatures.route("/yara-qa", methods=["GET"])
def yara_qa():
    # the page is a shell: its script loads everything from /api/v2/signatures/yara-qa. The
    # signature:read gate is the blueprint's; whether the download controls show is decided in the
    # template with has_permission('signature', 'download'), and the API enforces it regardless.
    return render_template("signatures/yara_qa.html")
