class ExcessiveFileDataSizeError(Exception):
    """Thrown when the size of the RootAnalysis on disk becomes larger than the configured limit."""
    pass

class ExcessiveObservablesError(Exception):
    """Thrown when too many observables have been added to the RootAnalysis object."""
    pass

class AnalysisError(Exception):
    """Raised by an analysis module to say it failed to analyze an observable, and why.

    The module's analysis of the observable is created if it does not exist yet and marked with the
    message (Analysis.error), which the analyst sees in the alert. Unlike any other exception it
    writes no crash report: it is a failure the module expected, like a lookup that timed out or a
    tool that exited non-zero. Raise it from the exception it wraps (raise AnalysisError(...) from e)
    so the log has that exception's traceback. An exception the module did not expect is left to
    raise: the engine writes a crash report for it."""

    def __init__(self, message: str):
        if not isinstance(message, str) or not message.strip():
            raise ValueError(f"an analysis error needs a message (got {message!r})")

        super().__init__(message)
        self.message = message
