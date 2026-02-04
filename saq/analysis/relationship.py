from saq.constants import VALID_RELATIONSHIP_TYPES


KEY_RELATIONSHIP_TYPE = 'type'
KEY_RELATIONSHIP_TARGET = 'target'

class Relationship:
    """Represents a relationship to another object."""

    def __init__(self, r_type=None, target=None, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._r_type = r_type
        self._target = target

    def __str__(self):
        return "Relationship({} -> {})".format(self.r_type, self.target)

    def __repr__(self):
        return str(self)

    @property
    def r_type(self):
        return self._r_type
    
    @r_type.setter
    def r_type(self, value):
        assert value in VALID_RELATIONSHIP_TYPES
        self._r_type = value

    @property
    def target(self):
        return self._target

    @target.setter
    def target(self, value):
        from saq.analysis.observable import Observable
        assert isinstance(value, str) or isinstance(value, Observable)
        self._target = value

    @property
    def json(self):
        from saq.analysis.observable import Observable
        # it's possible that the target is a string (in the event the observable could not be found when deserializing)
        # handle both Observable objects and string UUIDs
        target_uuid = self.target.uuid if isinstance(self.target, Observable) else self.target
        return {
            KEY_RELATIONSHIP_TYPE: self.r_type,
            KEY_RELATIONSHIP_TARGET: target_uuid
        }

    @json.setter
    def json(self, value):
        assert isinstance(value, dict)
        if KEY_RELATIONSHIP_TYPE in value:
            self.r_type = value[KEY_RELATIONSHIP_TYPE]
        if KEY_RELATIONSHIP_TARGET in value:
            self.target = value[KEY_RELATIONSHIP_TARGET]