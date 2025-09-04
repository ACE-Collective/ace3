from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from saq.analysis.observable import Observable

# dictionary keys used by the ObservableSerializer
KEY_ID = 'id'
KEY_TYPE = 'type'
KEY_VALUE = 'value'
KEY_TIME = 'time'
KEY_ANALYSIS = 'analysis'
KEY_DIRECTIVES = 'directives'
KEY_REDIRECTION = 'redirection'
KEY_LINKS = 'links'
KEY_LIMITED_ANALYSIS = 'limited_analysis'
KEY_EXCLUDED_ANALYSIS = 'excluded_analysis'
KEY_RELATIONSHIPS = 'relationships'
KEY_GROUPING_TARGET = 'grouping_target'
KEY_VOLATILE = 'volatile'
KEY_LLM_CONTEXT_DOCUMENTS = 'llm_context_documents'


class ObservableSerializer:
    """Handles JSON serialization and deserialization for Observable objects."""

    @staticmethod
    def serialize(observable: "Observable") -> dict:
        """Serialize an Observable object to a dictionary for JSON storage."""
        result = {}
        
        # Include data from component managers
        result.update(observable._tag_manager.get_json_data())
        result.update(observable._detection_manager.get_json_data())
        result.update(observable._sort_manager.get_json_data())
        
        # Include observable-specific data
        result.update({
            KEY_ID: observable.id,
            KEY_TYPE: observable.type,
            KEY_TIME: observable.time,
            KEY_VALUE: observable._value,
            KEY_ANALYSIS: observable.analysis,
            KEY_DIRECTIVES: observable.directives,
            KEY_REDIRECTION: observable._redirection,
            KEY_LINKS: observable._links,
            KEY_LIMITED_ANALYSIS: observable._limited_analysis,
            KEY_EXCLUDED_ANALYSIS: observable._excluded_analysis,
            KEY_RELATIONSHIPS: observable._relationships,
            KEY_GROUPING_TARGET: observable._grouping_target,
            KEY_VOLATILE: observable._volatile,
            KEY_LLM_CONTEXT_DOCUMENTS: observable.llm_context_documents,
        })
        
        return result

    @staticmethod
    def deserialize(observable: "Observable", data: dict):
        """Deserialize a dictionary into an Observable object."""
        assert isinstance(data, dict)
        
        # Set component manager data
        observable._tag_manager.set_json_data(data)
        observable._detection_manager.set_json_data(data)
        observable._sort_manager.set_json_data(data)

        # Set observable properties
        if KEY_ID in data:
            observable.id = data[KEY_ID]
        if KEY_TYPE in data:
            observable.type = data[KEY_TYPE]
        if KEY_TIME in data:
            observable.time = data[KEY_TIME]
        if KEY_VALUE in data:
            observable._value = data[KEY_VALUE]
        if KEY_ANALYSIS in data:
            observable.analysis = data[KEY_ANALYSIS]
        if KEY_DIRECTIVES in data:
            observable.directives = data[KEY_DIRECTIVES]
        if KEY_REDIRECTION in data:
            observable._redirection = data[KEY_REDIRECTION]
        if KEY_LINKS in data:
            observable._links = data[KEY_LINKS]
        if KEY_LIMITED_ANALYSIS in data:
            observable._limited_analysis = data[KEY_LIMITED_ANALYSIS]
        if KEY_EXCLUDED_ANALYSIS in data:
            observable._excluded_analysis = data[KEY_EXCLUDED_ANALYSIS]
        if KEY_RELATIONSHIPS in data:
            observable._relationships = data[KEY_RELATIONSHIPS]
        if KEY_GROUPING_TARGET in data:
            observable._grouping_target = data[KEY_GROUPING_TARGET]
        if KEY_VOLATILE in data:
            observable._volatile = data[KEY_VOLATILE]
        if KEY_LLM_CONTEXT_DOCUMENTS in data:
            observable.llm_context_documents = data[KEY_LLM_CONTEXT_DOCUMENTS]
        
