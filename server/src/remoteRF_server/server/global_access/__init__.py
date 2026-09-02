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

"""
RemoteRF Global v1.0 — optional integration between this RemoteRF Server
deployment and the RemoteRF Global coordination layer (global.remoterf.net).

This package is entirely optional and additive. When Global is disabled
(the default, ``REMOTERF_GLOBAL_ENABLED=false``), nothing in this package
runs: no background threads, no outbound network calls, no requirement for
identity/config files to exist. See docs/remoterf-global-server-v1.md.
"""
