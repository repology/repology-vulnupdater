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

from dataclasses import dataclass, field
from typing import Any, List, Optional, Union

from vulnupdater.util import escaped_split


@dataclass(unsafe_hash=True)
class CPEMatch:
    vulnerable: bool
    vendor: str
    product: str
    start_version: Optional[str] = None
    end_version: Optional[str] = None
    start_version_excluded: bool = False
    end_version_excluded: bool = False

    def __repr__(self) -> str:
        return f'{"+" if self.vulnerable else "-"}{self.vendor}:{self.product} {"(" if self.start_version_excluded else "["}{self.start_version}, {self.end_version}{")" if self.end_version_excluded else "]"}'

    @staticmethod
    def parse(data: Any) -> 'CPEMatch':
        cpe_uri = escaped_split(data['cpe23Uri'], ':')

        res = CPEMatch(
            vulnerable=data['vulnerable'],
            vendor=cpe_uri[3],
            product=cpe_uri[4],
        )

        if cpe_uri[5] != '*':
            res.start_version = cpe_uri[5]
            res.end_version = cpe_uri[5]

            assert('versionEndExcluding' not in data)
            assert('versionEndIncluding' not in data)
            assert('versionStartExcluding' not in data)
            assert('versionStartIncluding' not in data)
        else:
            if 'versionStartExcluding' in data:
                res.start_version = data['versionStartExcluding']
                res.start_version_excluded = True
            if 'versionStartIncluding' in data:
                res.start_version = data['versionStartIncluding']
            if 'versionEndExcluding' in data:
                res.end_version = data['versionEndExcluding']
                res.end_version_excluded = True
            if 'versionEndIncluding' in data:
                res.end_version = data['versionEndIncluding']

        return res


@dataclass
class CVEConfigurationNode:
    operator: str
    childs: List[Union['CVEConfigurationNode', CPEMatch]] = field(default_factory=list)

    @staticmethod
    def parse(data: Any) -> 'CVEConfigurationNode':
        res = CVEConfigurationNode(
            operator=data['operator']
        )

        for child in data.get('children', []):
            res.childs.append(CVEConfigurationNode.parse(child))

        for cpe_match in data.get('cpe_match', []):
            res.childs.append(CPEMatch.parse(cpe_match))

        return res


@dataclass
class CVEItem:
    cve_id: str
    last_modified: str

    configuration_nodes: List[CVEConfigurationNode] = field(default_factory=list)

    @staticmethod
    def parse(data: Any) -> 'CVEItem':
        return CVEItem(
            cve_id=data['cve']['CVE_data_meta']['ID'],
            last_modified=data['lastModifiedDate'],
            configuration_nodes=[CVEConfigurationNode.parse(node) for node in data['configurations']['nodes']]
        )
