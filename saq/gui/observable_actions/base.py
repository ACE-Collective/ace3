class ObservableAction:
    """Represents an "action" that a user can take with an Observable in the GUI."""
    def __init__(self):
        self.name = None
        self.description = None
        self.action_path = None
        self.icon = None
        self.display = True
        # When True, this action mutates the analysis tree or triggers re-analysis, so it is
        # disabled in the GUI while the alert is locked (being analyzed). Read-only and
        # metadata-only actions leave this False and remain usable at any time.
        self.modifies_analysis = False

class ObservableActionSeparator(ObservableAction):
    """Use this to place separator bars in your list of action choices."""
    pass