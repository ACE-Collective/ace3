"""Authentication schemas for ACE API v2."""

# defined in saq so core code that records who acted (saq.logging.log_audit) can import it
from saq.auth import ApiAuthResult

__all__ = ["ApiAuthResult"]
