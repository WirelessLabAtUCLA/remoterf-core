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

install_server_import_compat()
