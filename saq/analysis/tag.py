import logging

from saq.configuration.config import get_config
from saq.constants import TAG_LEVEL_ALERT, TAG_LEVEL_CRITICAL, TAG_LEVEL_FALSE_POSITIVE, TAG_LEVEL_INFO, TAG_LEVEL_WARNING

class Tag_DEPRECATED:
    """Gives a bit of metadata to an observable or analysis.  Tags defined in the configuration file are also signals for detection."""

    def __init__(self, name=None, json=None):
        if json is not None:
            self.name = json
        elif name is not None:
            self.name = name

        # all tags default to these values
        self.level = 'info'
        self.score = 0
        self.css_class = 'default' # white

        if self.name is None:
            logging.error("tag has no name")
            return

        # note that a tag can have the form of tag_name:random_stuff
        tag_name_lookup = self.name
        if ':' in tag_name_lookup:
            tag_name_lookup = tag_name_lookup.split(':', 1)[0]

        # does this tag exist in the configuration file?
        self.level = get_config().tags.get(tag_name_lookup)
        if not self.level:
            self.level = TAG_LEVEL_INFO

        if self.level == TAG_LEVEL_FALSE_POSITIVE:
            self.score = 0
        elif self.level == TAG_LEVEL_INFO:
            self.score = 0
        elif self.level == TAG_LEVEL_WARNING:
            self.score = 1
        elif self.level == TAG_LEVEL_ALERT:
            self.score = 3
        elif self.level == TAG_LEVEL_CRITICAL:
            self.score = 10

        try:
            self.css_class = get_config().tag_css_class.get(self.level)
        except KeyError:
            logging.error("invalid tag level {}".format(self.level))
    
    @property
    def json(self):
        return self.name

    @json.setter
    def json(self, value):
        self.name = value

    def __str__(self):
        return self.name

    def __hash__(self):
        return self.name.__hash__()

    def __eq__(self, other):
        if not isinstance(other, Tag):
            return False

        return self.name == other.name