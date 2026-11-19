import logging

from flask import abort, render_template, send_file, url_for
from markupsafe import Markup

from app.blueprints import help_pages
from app.help.rendering import RenderedPlaybook, contained_path, get_playbooks_dir, render_playbook
from app.help.views.guides import IMAGE_MAX_AGE_SECONDS

# a placeholder url_for fills in and the prefix helpers cut off again, so the renderer is handed
# the URL a playbook name or asset path is appended to
_PLACEHOLDER = "__placeholder__"

# only raster images are served, and inline: an SVG (or HTML) under assets/ would run as a page on
# the GUI's origin when its full-size link is opened
_ASSET_TYPES = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif",
                ".webp": "image/webp"}


def _prefix(endpoint: str, **values) -> str:
    url = url_for(endpoint, **values)
    return url[:url.rindex(_PLACEHOLDER)]


@help_pages.app_template_global()
def load_playbook(name: str) -> RenderedPlaybook | None:
    """The named playbook rendered for the current request, or None when there is no such file. A
    playbook that cannot be read or rendered is logged and shown as such, so it never takes the
    alert page down with it."""
    try:
        return render_playbook(
            name,
            page_prefix=_prefix("help.playbook", name=_PLACEHOLDER),
            asset_prefix=_prefix("help.playbook_asset", filename=_PLACEHOLDER),
        )
    except Exception:
        logging.exception("unable to render playbook", extra={"playbook": name})
        return RenderedPlaybook(
            name=name,
            title=name,
            html=Markup('<p class="text-danger">This playbook could not be rendered; the GUI log has the error.</p>'),
            source_url=None,
        )


@help_pages.route("/playbooks/<name>", methods=["GET"])
def playbook(name: str):
    # like the guides, a playbook is for anyone who uses ACE: the help area's gate asks only for a login
    rendered = load_playbook(name)
    if rendered is None:
        abort(404)
    return render_template("help/playbook.html", playbook=rendered)


@help_pages.route("/playbooks/assets/<path:filename>", methods=["GET"])
def playbook_asset(filename: str):
    mimetype = _ASSET_TYPES.get("." + filename.rsplit(".", 1)[-1].lower()) if "." in filename else None
    path = contained_path(get_playbooks_dir() / "assets", filename) if mimetype else None
    if path is None or not path.is_file():
        abort(404)
    response = send_file(path, mimetype=mimetype, max_age=IMAGE_MAX_AGE_SECONDS)
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response
