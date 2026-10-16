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

"""Lives in remoterf-device-core (remoterf_device_core.idl.schema); this name stays importable."""
import sys

from remoterf_device_core.idl import schema as _schema

from ..utils.db_location import get_drivers_dir

_schema.set_drivers_dir_provider(get_drivers_dir)
sys.modules[__name__] = _schema
