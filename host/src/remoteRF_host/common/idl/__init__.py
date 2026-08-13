# Copyright (C) 2026 RemoteRF
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

from .schema import (
    DeviceSchema,
    ensure_default_driver_files,
    get_driver_class,
    idl_client,
    idl_client_ctor,
    idl_client_enum,
    idl_client_function,
    idl_client_method,
    idl_client_module,
    idl_client_namespace,
    idl_client_payload_class,
    idl_client_proxy_class,
    idl_client_strict_class,
    idl_expose,
    idl_register,
    install_server_import_compat,
    list_registered_drivers,
    load_drivers,
)
from .v2 import (
    CONTROL_PROTOCOL_VERSION,
    SCHEMA_VERSION as SCHEMA_V2_VERSION,
    STREAMING_PROTOCOL_VERSION,
    build_schema as build_schema_v2,
    method as idl_v2_method,
    object_type as idl_v2_object,
    overload as idl_v2_overload,
    parameter as idl_v2_parameter,
    validate_schema as validate_schema_v2,
)

install_server_import_compat()

__all__ = [
    "DeviceSchema",
    "ensure_default_driver_files",
    "get_driver_class",
    "idl_client",
    "idl_client_ctor",
    "idl_client_enum",
    "idl_client_function",
    "idl_client_method",
    "idl_client_module",
    "idl_client_namespace",
    "idl_client_payload_class",
    "idl_client_proxy_class",
    "idl_client_strict_class",
    "idl_expose",
    "idl_register",
    "install_server_import_compat",
    "list_registered_drivers",
    "load_drivers",
    "CONTROL_PROTOCOL_VERSION",
    "SCHEMA_V2_VERSION",
    "STREAMING_PROTOCOL_VERSION",
    "build_schema_v2",
    "idl_v2_method",
    "idl_v2_object",
    "idl_v2_overload",
    "idl_v2_parameter",
    "validate_schema_v2",
]
