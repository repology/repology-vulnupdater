#!/usr/bin/env python3
#
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

import argparse
import gzip
import logging
import time
from typing import Any, MutableSet, Optional

from jsonslicer import JsonSlicer

import psycopg2

import requests

import vulnupdater.queries as queries
from vulnupdater.cveinfo import CPEMatch
from vulnupdater.sources import FAST_UPDATE_PERIOD, Source, generate_sources


_USER_AGENT = 'repology-vulnupdater/0 (+{}/bots)'.format('https://repology.org')


class Worker:
    _options: argparse.Namespace

    _db: Any

    def __init__(self, options: argparse.Namespace) -> None:
        self._options = options
        self._db = psycopg2.connect(options.dsn, application_name='repology-vulnupdater')

    def _process_cve(self, cve: Any) -> int:
        cve_id: str = cve['cve']['CVE_data_meta']['ID']
        published: str = cve['publishedDate']
        last_modified: str = cve['lastModifiedDate']
        usable_matches: MutableSet[CPEMatch] = set()

        for configuration in cve['configurations']['nodes']:
            if configuration['operator'] != 'OR':
                continue  # not supported

            if 'cpe_match' not in configuration:
                continue

            for match in map(CPEMatch, configuration['cpe_match']):
                if match.vulnerable and match.end_version and match.end_version != '-':
                    usable_matches.add(match)

        return queries.update_cve(self._db, cve_id, published, last_modified, usable_matches)

    def _process_source(self, source: Source) -> int:
        logging.debug(f'source {source.url}: start update')

        headers = {
            'user-agent': _USER_AGENT
        }

        if source.etag is not None:
            headers['if-none-match'] = source.etag

        response = requests.get(source.url, stream=True, headers=headers)
        if response.status_code == 304:
            logging.debug(f'source {source.url}: not modified')
            queries.update_source(self._db, source.url)
            return 0

        if response.status_code != 200:
            logging.error(f'source {source.url}: got bad HTTP code {response.status_code}')
            queries.update_source(self._db, source.url)
            return 0

        logging.debug(f'source {source.url}: processing')

        num_updates = 0
        with gzip.open(response.raw) as decompressed:
            for item in JsonSlicer(decompressed, ('CVE_Items', None)):
                num_updates += self._process_cve(item)

        queries.update_source(self._db, source.url, response.headers.get('etag'), num_updates)

        logging.debug(f'source {source.url}: update done')

        return num_updates

    def _iteration(self) -> Optional[float]:
        logging.debug('iteration started')

        sources = list(generate_sources(self._options.fast_only))

        queries.fill_sources_statuses(self._db, sources)

        sources_to_update = []
        wait_time = float(FAST_UPDATE_PERIOD)
        for source in sources:
            if source.age is None or source.age > source.update_period:
                sources_to_update.append(source)
            else:
                wait_time = min(wait_time, source.update_period - source.age)

        if not sources_to_update:
            return wait_time

        num_updated_cves = 0
        for source in sources_to_update:
            num_updated_cves += self._process_source(source)

        if num_updated_cves > 0:
            logging.debug('updating simplified vulnerabilities information')
            queries.update_vulnerable_versions(self._db)

        self._db.commit()

        return None

    def run(self) -> None:
        while True:
            wait_time = self._iteration()

            if self._options.once_only:
                return

            if wait_time is not None:
                logging.debug(f'sleeping for {wait_time} second(s)')
                time.sleep(wait_time)


def main() -> None:
    config = {
        'DSN': 'dbname=repology user=repology password=repology',
    }

    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-D', '--dsn', default=config['DSN'], help='database connection params')
    parser.add_argument('-d', '--debug', action='store_true', help='enable debug logging')
    parser.add_argument('-f', '--fast-only', action='store_true', help='operate on fast feed only')
    parser.add_argument('-1', '--once-only', action='store_true', help="do just a single update pass, don't loop")

    args = parser.parse_args()

    logging.basicConfig(format='%(asctime)s %(levelname)-8s %(message)s', level=logging.DEBUG if args.debug else logging.INFO)

    Worker(args).run()


if __name__ == '__main__':
    main()
