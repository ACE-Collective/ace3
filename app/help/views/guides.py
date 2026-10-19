from flask import abort, redirect, render_template, send_from_directory, url_for

from app.blueprints import help_pages
from app.help.guides import GUIDE_SETS, get_guide_set
from app.help.rendering import render_guide

# screenshots change only when a guide is refreshed, and then the guide is reloaded too
IMAGE_MAX_AGE_SECONDS = 3600


@help_pages.route("/", methods=["GET"])
def help_index():
    return render_template("help/index.html", guide_sets=GUIDE_SETS)


@help_pages.route("/<set_slug>/", methods=["GET"])
def guide_set(set_slug: str):
    guides = get_guide_set(set_slug)
    if guides is None:
        abort(404)
    return redirect(url_for("help.guide", set_slug=guides.slug, guide_slug=guides.guides[0].slug))


@help_pages.route("/<set_slug>/<guide_slug>", methods=["GET"])
def guide(set_slug: str, guide_slug: str):
    guides = get_guide_set(set_slug)
    current = guides.get_guide(guide_slug) if guides else None
    if current is None:
        abort(404)
    index = guides.guides.index(current)
    return render_template(
        "help/guide.html",
        guide_set=guides,
        guide=current,
        rendered=render_guide(guides.path(current)),
        previous_guide=guides.guides[index - 1] if index > 0 else None,
        next_guide=guides.guides[index + 1] if index + 1 < len(guides.guides) else None,
    )


@help_pages.route("/<set_slug>/images/<path:filename>", methods=["GET"])
def guide_image(set_slug: str, filename: str):
    guides = get_guide_set(set_slug)
    if guides is None:
        abort(404)
    # send_from_directory refuses any path that leaves the directory (a 404)
    return send_from_directory(guides.images_dir, filename, max_age=IMAGE_MAX_AGE_SECONDS)
