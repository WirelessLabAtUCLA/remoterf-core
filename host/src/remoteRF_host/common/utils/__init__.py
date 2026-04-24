from .api_token import validate_token, generate_token, hash_token
from .list_string import list_to_str, str_to_list
from .db_connection import db_connection
from .db_location import get_drivers_dir, get_host_config_dir, get_remoterf_root


def _missing_dependency(name: str, exc: Exception):
    message = f"{name} is unavailable because an optional dependency failed to import: {exc}"

    def _raiser(*args, _exc: Exception = exc, _message: str = message, **kwargs):
        raise RuntimeError(_message) from _exc
    return _raiser


try:
    from .process_arg import unmap_arg, map_arg
except Exception as exc:  # pragma: no cover - exercised indirectly in lean CLI envs
    unmap_arg = _missing_dependency("unmap_arg", exc)
    map_arg = _missing_dependency("map_arg", exc)


try:
    from .ansi_codes import printf, stylize, Sty
except Exception as exc:  # pragma: no cover - exercised indirectly in lean CLI envs
    printf = _missing_dependency("printf", exc)
    stylize = _missing_dependency("stylize", exc)

    class Sty:  # type: ignore[no-redef]
        pass
