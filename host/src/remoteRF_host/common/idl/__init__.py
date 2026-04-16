from .schema import (
    DeviceSchema,
    get_driver_class,
    idl_expose,
    idl_register,
    install_server_import_compat,
    list_registered_drivers,
    load_drivers,
)

install_server_import_compat()
