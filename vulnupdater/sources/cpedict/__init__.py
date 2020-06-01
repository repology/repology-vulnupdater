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

from typing import ClassVar, IO

from vulnupdater.cpe import CPE
from vulnupdater.source import Source
from vulnupdater.sources.cpedict.batcher import CpeDictBatcher
from vulnupdater.sources.cpedict.parsing import iter_cpe_dict


class CpeDictSource(Source):
    TYPE: ClassVar[str] = 'cpe_dict'

    def get_type(self) -> str:
        return CpeDictSource.TYPE

    def _process(self, stream: IO[bytes]) -> bool:
        with self._db.cursor() as cur:
            cur.execute('DELETE FROM cpe_dictionary')

        with CpeDictBatcher(self._db, 1000) as batcher:
            for cpe in map(CPE, iter_cpe_dict(stream)):
                if cpe.part == 'a':
                    batcher.add(cpe.vendor, cpe.product)

            self._num_updates += batcher.get_num_updates()
            return batcher.get_num_updates() > 0
