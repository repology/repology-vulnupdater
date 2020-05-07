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

import datetime
from dataclasses import dataclass
from typing import Iterable, Optional


FAST_UPDATE_PERIOD = 60 * 10
SLOW_UPDATE_PERIOD = 60 * 60 * 24


@dataclass
class Source:
    url: str
    update_period: int

    age: Optional[float] = None
    etag: Optional[str] = None


def generate_sources(fast_only: bool = False) -> Iterable[Source]:
    if not fast_only:
        for year in range(2002, datetime.datetime.now().year + 1):
            yield Source(f'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.gz', SLOW_UPDATE_PERIOD)
    yield Source('https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz', FAST_UPDATE_PERIOD)
