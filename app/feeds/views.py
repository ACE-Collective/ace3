from flask import render_template

from app.auth.permissions import require_permission
from app.blueprints import feeds
from saq.configuration.config import get_config


@feeds.route("/", methods=["GET"])
@require_permission("feed", "read")
def feeds_page():
    return render_template("feeds/feeds.html", config_feeds=get_config().feeds)


@feeds.route("/watches", methods=["GET"])
@require_permission("feed_watch", "read")
def watches_page():
    return render_template("feeds/watches.html")


@feeds.route("/replay", methods=["GET"])
@require_permission("feed_watch", "read")
def replay_page():
    return render_template("feeds/replay.html", config_feeds=get_config().feeds)


@feeds.route("/watches/<int:watch_id>/evaluation", methods=["GET"])
@require_permission("feed_watch", "read")
def evaluation(watch_id: int):
    return render_template("feeds/evaluation.html", watch_id=watch_id)
