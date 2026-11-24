"""The /feeds GUI area: RSS and Atom feeds, the watches over them, replay and evaluation
(docs/FEED_WATCHES.md). Every page is a shell: its script gets everything from /api/v2/feeds and
/api/v2/feed-watches, which enforce the permissions again."""

from app.feeds.views import evaluation, feeds_page, replay_page, watches_page

__all__ = ["evaluation", "feeds_page", "replay_page", "watches_page"]
