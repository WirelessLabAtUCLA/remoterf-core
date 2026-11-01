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

def list_to_str(list:list) -> str:
    """Join items into a comma-separated string, e.g. [1, 2] -> "1,2"."""
    return ','.join(str(x) for x in list)

def str_to_list(s:str) -> list[int]:
    """Parse a comma-separated string into a list of ints, e.g. "1,2" -> [1, 2]."""
    return [int(x) for x in s.split(',')]