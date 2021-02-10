# Copyright (C) 2020 Dmitry Marakasov <amdmi3@amdmi3.ru>
#
# This file is part of repology
#
# repology is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# repology is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with repology.  If not, see <http://www.gnu.org/licenses/>.

from dataclasses import dataclass
from typing import Any, Optional

from vulnupdater.cpe import CPE


@dataclass(unsafe_hash=True)
class CPEMatch:
    vulnerable: bool

    cpe: CPE

    start_version: Optional[str] = None
    end_version: Optional[str] = None
    start_version_excluded: bool = False
    end_version_excluded: bool = False

    valid: bool = True

    def __init__(self, data: Any) -> None:
        self.vulnerable = data['vulnerable']

        self.cpe = CPE(data['cpe23Uri'])

        if self.cpe.version == '*':
            if 'versionStartExcluding' in data:
                self.start_version = data['versionStartExcluding']
                self.start_version_excluded = True
            if 'versionStartIncluding' in data:
                self.start_version = data['versionStartIncluding']
            if 'versionEndExcluding' in data:
                self.end_version = data['versionEndExcluding']
                self.end_version_excluded = True
            if 'versionEndIncluding' in data:
                self.end_version = data['versionEndIncluding']
        elif self.cpe.version != '-':
            self.start_version = self.cpe.version
            if self.cpe.update and self.cpe.update != '*' and self.cpe.update != '-':
                if self.cpe.update[0].isdecimal():
                    self.start_version += '-'
                self.start_version += self.cpe.update
            self.end_version = self.start_version

            assert('versionEndExcluding' not in data)
            assert('versionEndIncluding' not in data)
            assert('versionStartExcluding' not in data)
            assert('versionStartIncluding' not in data)
        else:
            self.valid = False
