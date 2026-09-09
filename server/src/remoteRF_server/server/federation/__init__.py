"""Owner-local Gate C identity and Gate D trust/contract primitives.

This package still exposes no grants, federation execution, enrollment,
permission aggregation, resources, reservations, or broker authorization.
"""

import remoterf_federation_core as _federation_core

if _federation_core.__version__ != "0.7.0":
    raise RuntimeError(
        "RemoteRF Server federation requires remoterf-federation-core==0.7.0; "
        f"found {_federation_core.__version__}"
    )

from .contracts import ContractStore
from .principals import FederatedPrincipal, FederatedPrincipalStore
from .trust import TrustedKeyStore

__all__ = [
    "ContractStore",
    "FederatedPrincipal",
    "FederatedPrincipalStore",
    "TrustedKeyStore",
]
