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

from typing import Any, MutableSet, Tuple

import psycopg2


class CpeDictBatcher:
    _db: Any

    _batch: MutableSet[Tuple[str, str]]
    _max_batch_size: int

    _num_updates: int = 0

    def __init__(self, db: Any, max_batch_size: int) -> None:
        self._db = db
        self._batch = set()
        self._max_batch_size = max_batch_size

    def _flush(self) -> None:
        with self._db.cursor() as cur:
            cur.execute(
                """
                INSERT INTO cpe_dictionary (
                    cpe_vendor,
                    cpe_product
                )
                SELECT
                    json_array_elements(cpes)->>0,
                    json_array_elements(cpes)->>1
                FROM (
                    SELECT %(cpes)s::json AS cpes
                ) AS tmp
                ON CONFLICT DO NOTHING
                RETURNING 1
                """,
                {
                    'cpes': psycopg2.extras.Json(list(self._batch))
                }
            )

            self._num_updates += sum(row[0] for row in cur.fetchall())

        self._batch = set()

    def add(self, vendor: str, product: str) -> None:
        self._batch.add((vendor, product))

        if len(self._batch) > self._max_batch_size:
            self._flush()

    def get_num_updates(self) -> int:
        return self._num_updates

    def __enter__(self) -> 'CpeDictBatcher':
        return self

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        if exc_type is None and self._batch:
            self._flush()
