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

import gzip
import logging
from abc import ABC, abstractmethod
from typing import Any, IO, Optional

import requests


_USER_AGENT = 'repology-vulnupdater/0 (+{}/docs/bots)'.format('https://repology.org')


class Source(ABC):
    _db: Any

    _url: str
    _update_period: int

    _age: Optional[float] = None
    _etag: Optional[str] = None
    _num_updates: int = 0

    def __init__(self, db: Any, url: str, update_period: int) -> None:
        self._db = db
        self._url = url
        self._update_period = update_period

        self._load_state()

    def _load_state(self) -> None:
        with self._db.cursor() as cur:
            cur.execute(
                """
                SELECT
                    etag,
                    now() - last_update AS age
                FROM vulnerability_sources
                WHERE url = %(url)s
                """,
                {
                    'url': self._url
                }
            )
            if (row := cur.fetchone()) is not None:
                self._etag = row[0]
                self._age = None if row[1] is None else row[1].total_seconds()

    def _save_state(self) -> None:
        with self._db.cursor() as cur:
            cur.execute(
                """
                INSERT INTO vulnerability_sources(
                    url,
                    etag,
                    last_update,
                    total_updates,
                    type
                )
                VALUES (
                    %(url)s,
                    %(etag)s,
                    now(),
                    %(num_updates)s,
                    %(type)s
                )
                ON CONFLICT(url) DO UPDATE
                SET
                    etag = coalesce(%(etag)s, vulnerability_sources.etag),
                    last_update = now(),
                    total_updates = vulnerability_sources.total_updates + %(num_updates)s,
                    type = %(type)s
                """,
                {
                    'url': self._url,
                    'etag': self._etag,
                    'num_updates': self._num_updates,
                    'type': self.get_type(),
                }
            )

        self._num_updates = 0

    def get_time_to_update(self) -> float:
        if self._age is None or self._age > self._update_period:
            return 0
        return self._update_period - self._age

    @abstractmethod
    def _process(self, stream: IO[bytes]) -> bool:
        pass

    @abstractmethod
    def get_type(self) -> str:
        pass

    def update(self) -> bool:
        logging.info(f'source {self._url}: start update')

        headers = {
            'user-agent': _USER_AGENT
        }

        if self._etag is not None:
            headers['if-none-match'] = self._etag

        response = requests.get(self._url, stream=True, headers=headers, timeout=60)
        if response.status_code == 304:
            logging.info(f'source {self._url}: not modified')
            self._save_state()
            return False

        if response.status_code != 200:
            logging.error(f'source {self._url}: got bad HTTP code {response.status_code}')
            self._save_state()
            return False

        logging.info(f'source {self._url}: processing')

        with gzip.open(response.raw) as decompressed:
            updated = self._process(decompressed)

        self._etag = response.headers.get('etag')

        num_updates = self._num_updates

        self._save_state()

        logging.info(f'source {self._url}: update done ({num_updates} updates)')

        return updated
