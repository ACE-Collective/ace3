from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from saq.analysis.analysis import Analysis, SummaryDetail
    from saq.analysis.pivot_link import PivotLink

# dictionary keys used by the AnalysisSerializer
KEY_UUID = 'uuid'
KEY_INSTANCE = 'instance'
KEY_OBSERVABLES = 'observables'
KEY_SUMMARY = 'summary'
KEY_SUMMARY_DETAILS = 'summary_details'
KEY_PIVOT_LINKS = 'pivot_links'
KEY_COMPLETED = 'completed'
KEY_DELAYED = 'delayed'
KEY_EXTERNAL_DETAILS_PATH = 'file_path'
KEY_DETAILS_SIZE = 'details_size'


class AnalysisSerializer:
    """Handles JSON serialization and deserialization for Analysis objects."""

    @staticmethod
    def serialize(analysis: "Analysis") -> dict:
        """Serialize an Analysis object to a dictionary for JSON storage."""
        result = {}
        
        # Include data from component managers
        result.update(analysis._tag_manager.get_json_data())
        result.update(analysis._detection_manager.get_json_data())
        result.update(analysis._sort_manager.get_json_data())

        # Include analysis-specific data
        result.update({
            KEY_UUID: analysis.uuid,
            KEY_INSTANCE: analysis.instance,
            KEY_OBSERVABLES: [o.id for o in analysis.observables],
            KEY_SUMMARY: analysis.summary,
            KEY_COMPLETED: analysis.completed,
            KEY_DELAYED: analysis.delayed,
            KEY_SUMMARY_DETAILS: [detail.to_dict() for detail in analysis.summary_details],
            KEY_PIVOT_LINKS: [link.to_dict() for link in analysis.pivot_links],
            KEY_EXTERNAL_DETAILS_PATH: analysis.external_details_path,
            KEY_DETAILS_SIZE: analysis.details_size,
        })
        
        return result

    @staticmethod
    def deserialize(analysis: "Analysis", data: dict):
        """Deserialize a dictionary into an Analysis object."""
        assert isinstance(data, dict)
        
        # Set component manager data
        analysis._tag_manager.set_json_data(data)
        analysis._detection_manager.set_json_data(data)
        analysis._sort_manager.set_json_data(data)

        # set uuid
        if KEY_UUID in data:
            analysis._uuid = data[KEY_UUID]

        # Set instance
        if KEY_INSTANCE in data:
            analysis.instance = data[KEY_INSTANCE]

        # Set observables (as UUID strings for now, will be resolved later)
        if KEY_OBSERVABLES in data:
            analysis.observable_references = data[KEY_OBSERVABLES]

        # Set summary
        if KEY_SUMMARY in data:
            analysis.summary = data[KEY_SUMMARY]

        # Set completed status (use underscore to avoid triggering events)
        if KEY_COMPLETED in data:
            analysis._completed = data[KEY_COMPLETED]

        # Set delayed status
        if KEY_DELAYED in data:
            analysis.delayed = data[KEY_DELAYED]

        # Set summary details
        if KEY_SUMMARY_DETAILS in data:
            from saq.analysis.analysis import SummaryDetail
            analysis.summary_details = [SummaryDetail.from_dict(detail) for detail in data[KEY_SUMMARY_DETAILS]]

        # Set pivot links
        if KEY_PIVOT_LINKS in data:
            from saq.analysis.pivot_link import PivotLink
            analysis.pivot_links = [PivotLink.from_dict(link) for link in data[KEY_PIVOT_LINKS]] 

        # Set external details path
        if KEY_EXTERNAL_DETAILS_PATH in data:
            analysis.external_details_path = data[KEY_EXTERNAL_DETAILS_PATH]

        # Set details size
        if KEY_DETAILS_SIZE in data:
            analysis.details_size = data[KEY_DETAILS_SIZE]