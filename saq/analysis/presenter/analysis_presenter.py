from typing import TYPE_CHECKING, Type

if TYPE_CHECKING:
    from saq.analysis.analysis import Analysis

# Registry for custom presenter classes
_ANALYSIS_PRESENTER_REGISTRY: dict[Type["Analysis"], Type["AnalysisPresenter"]] = {}


def register_analysis_presenter(
    analysis_class: Type["Analysis"], presenter_class: Type["AnalysisPresenter"]
):
    """Register a custom presenter for a specific analysis class."""
    from saq.analysis.analysis import Analysis
    assert issubclass(analysis_class, Analysis)
    assert issubclass(presenter_class, AnalysisPresenter)
    _ANALYSIS_PRESENTER_REGISTRY[analysis_class] = presenter_class

def unregister_analysis_presenter(
    analysis_class: Type["Analysis"]
):
    """Unregister a custom presenter for a specific analysis class."""
    assert issubclass(analysis_class, Analysis)
    _ANALYSIS_PRESENTER_REGISTRY.pop(analysis_class, None)


def create_analysis_presenter(analysis):
    """Factory function to create an appropriate presenter for an Analysis object."""
    analysis_class = type(analysis)
    presenter_class = _ANALYSIS_PRESENTER_REGISTRY.get(analysis_class, AnalysisPresenter)
    return presenter_class(analysis)


class AnalysisPresenter:
    """Handles presentation logic for Analysis objects, separating UI concerns from domain logic."""

    def __init__(self, analysis):
        """Initialize presenter with an Analysis instance."""
        from saq.analysis.analysis import Analysis

        assert isinstance(analysis, Analysis)
        self._analysis = analysis

    @property
    def should_render(self) -> bool:
        """Returns True if the Analysis should be rendered in the GUI."""
        if self._analysis.summary is not None:
            return True

        if len(self._analysis.observables) > 0:
            return True

        return False

    @property
    def display_name(self) -> str:
        """Returns a visual name to display in the GUI."""
        if self._analysis.summary is not None:
            return self._analysis.summary

        # if we don't have a summary then just return the name of the class
        return type(self._analysis).__name__

    @property
    def is_drillable(self) -> bool:
        """Returns True if the user is intended to click on the Analysis for more details."""
        return True

    @property
    def template_path(self) -> str:
        """Returns the template path to use when rendering this analysis."""
        return "analysis/default_template.html"

    @property
    def details(self):
        """Returns the details object to be used when displaying in the GUI."""
        return self._analysis.details

    # Delegate access to the underlying analysis object for any other properties needed
    def __getattr__(self, name):
        """Delegate any missing attributes to the underlying analysis object."""
        return getattr(self._analysis, name)




