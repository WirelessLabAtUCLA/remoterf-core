"""Pure deployment schemas. Importing this package performs no I/O."""
from .schemas import (
    ValidationError, canonical_json, strict_json, canonical_uuid,
    validate_capabilities, local_capabilities, PROTOCOL_VERSION,
)

__version__ = "0.2.0"
__all__ = ["ValidationError", "canonical_json", "strict_json", "canonical_uuid",
           "validate_capabilities", "local_capabilities", "PROTOCOL_VERSION"]
