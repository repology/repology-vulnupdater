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

import xml.etree.cElementTree as ElementTree
from typing import IO, Iterable


def _extract_cpe(elem: ElementTree.Element) -> str:
    deprecations = elem.findall('{http://scap.nist.gov/schema/cpe-extension/2.3}deprecation')

    if len(deprecations) == 0:
        return elem.attrib['name']

    if len(deprecations) > 1:
        raise RuntimeError(f'Unexpected number of CPE deprecations: {len(deprecations)}')

    deprecated_bys = deprecations[0].findall('{http://scap.nist.gov/schema/cpe-extension/2.3}deprecated-by')

    if len(deprecated_bys) != 1:
        raise RuntimeError(f'Unexpected number of CPE deprecated-bys: {len(deprecated_bys)}')

    if list(deprecated_bys[0]):
        raise RuntimeError('Unexpected child elements of CPE deprecated-by' + elem.attrib['name'])

    return deprecated_bys[0].attrib['name']


def iter_cpe_dict(source: IO[bytes]) -> Iterable[str]:
    nestlevel = 0
    rootelem = None
    for event, elem in ElementTree.iterparse(source, events=['start', 'end']):
        if event == 'start':
            if rootelem is None:
                rootelem = elem
            nestlevel += 1
        elif event == 'end':
            nestlevel -= 1
            if nestlevel == 1:
                if elem.tag == '{http://cpe.mitre.org/dictionary/2.0}cpe-item' and elem.attrib.get('deprecated') != 'true':
                    if (cpe23_item := elem.find('{http://scap.nist.gov/schema/cpe-extension/2.3}cpe23-item')) is not None:
                        yield _extract_cpe(cpe23_item)
                if rootelem is not None:
                    rootelem.clear()
