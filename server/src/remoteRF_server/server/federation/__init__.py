"""Owner-local federation primitives.

Gate C contains identity and containment only.  It intentionally exposes no
trust keys, contracts, grants, execution service, enrollment, or broker path.
"""

from .principals import FederatedPrincipal, FederatedPrincipalStore

__all__ = ["FederatedPrincipal", "FederatedPrincipalStore"]
