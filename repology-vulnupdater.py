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
import asyncio
import datetime
import gzip
import logging
import tempfile
from typing import List, MutableSet

import aiohttp

import aiopg

from jsonslicer import JsonSlicer

from vulnupdater.cveinfo import CPEMatch, CVEItem
from vulnupdater.queries import Source, get_due_sources, get_registered_source_urls
from vulnupdater.queries import get_sleep_till_due_source, register_source, update_cve
from vulnupdater.queries import update_simplified_vulnerabilities, update_source


_CHUNK_SIZE = 65536

_USER_AGENT = 'repology-vulnupdater/0 (+{}/bots)'.format('https://repology.org')


def generate_source_urls(start_year: int = 2002) -> List[str]:
    return [
        f'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.gz'
        for year in range(start_year, datetime.datetime.now().year + 1)
    ]


class Worker:
    _options: argparse.Namespace

    _pgpool: aiopg.Pool
    _session: aiohttp.ClientSession

    def __init__(self, options: argparse.Namespace) -> None:
        self._options = options

    async def _process_updated_cve(self, cve: CVEItem) -> None:
        cpe_matches: MutableSet[CPEMatch] = set()

        for node in cve.configuration_nodes:
            if node.operator != 'OR':
                continue

            for child in node.childs:
                if isinstance(child, CPEMatch) and child.vulnerable and child.end_version and child.end_version != '-':
                    cpe_matches.add(child)

        if cpe_matches:
            logging.info(f'updating {cve.cve_id} - {len(cpe_matches)} item(s)')
            await update_cve(self._pgpool, cve, list(cpe_matches))

    async def _process_source(self, source: Source) -> int:
        logging.debug(f'processing source {source.url}')

        headers = {
            'user-agent': _USER_AGENT
        }

        if source.etag is not None:
            headers['if-none-match'] = source.etag

        async with self._session.get(source.url, headers=headers) as resp:
            if resp.status == 304:
                logging.debug(f'source {source.url} was not modified')
                await update_source(self._pgpool, source.url)
                return 0

            if resp.status != 200:
                logging.error(f'got bad HTTP code {resp.status} for source {source.url}')
                await update_source(self._pgpool, source.url)
                return 0

            logging.debug(f'updating source {source.url}')

            num_updates = 0

            with tempfile.NamedTemporaryFile(mode='wb') as tmpfile:
                while (data := await resp.content.read(_CHUNK_SIZE)):
                    tmpfile.write(data)
                tmpfile.flush()

                max_last_modified = ''
                with gzip.open(tmpfile.name) as decompressor:
                    for item in map(CVEItem.parse, JsonSlicer(decompressor, ('CVE_Items', None))):
                        if item.last_modified > source.max_last_modified:
                            await self._process_updated_cve(item)
                            num_updates += 1
                        max_last_modified = max(max_last_modified, item.last_modified)

                await update_source(self._pgpool, source.url, resp.headers.get('etag'), max_last_modified, num_updates)

            logging.debug(f'done updating source {source.url}')

            return num_updates

    async def _loop(self) -> None:
        while True:
            logging.debug('iteration started')

            all_source_urls = set(generate_source_urls(self._options.start_year))
            registered_source_urls = set(await get_registered_source_urls(self._pgpool))

            for new_url in all_source_urls - registered_source_urls:
                await register_source(self._pgpool, new_url)
                logging.info(f'registered new source {new_url}')

            due_sources = [
                source
                for source in await get_due_sources(self._pgpool, self._options.update_period)
                if source.url in all_source_urls
            ]

            if not due_sources:
                if self._options.once_only:
                    return

                delay = await get_sleep_till_due_source(self._pgpool, self._options.update_period)
                logging.debug(f'nothing to update yet - sleeping for {delay} second(s)')
                await asyncio.sleep(delay)
                continue

            num_updates = 0
            for source in due_sources:
                num_updates += await self._process_source(source)

            if num_updates > 0:
                logging.debug('updating simplified vulnerabilities information')
                await update_simplified_vulnerabilities(self._pgpool)

            if self._options.once_only:
                return

    async def run(self) -> None:
        async with aiopg.create_pool(self._options.dsn, minsize=1, maxsize=1, timeout=60) as self._pgpool:
            async with aiohttp.ClientSession() as self._session:
                await self._loop()


async def main() -> None:
    config = {
        'DSN': 'dbname=repology user=repology password=repology',
    }

    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-D', '--dsn', default=config['DSN'], help='database connection params')
    parser.add_argument('-p', '--update-period', type=float, default=600.0, metavar='SECONDS', help='update period in seconds')
    parser.add_argument('-d', '--debug', action='store_true', help='enable debug logging')
    parser.add_argument('-1', '--once-only', action='store_true', help="do just a single update pass, don't loop")
    parser.add_argument('-y', '--start-year', type=int, default=2002, metavar='YEAR', help='start year for feed retrieval')

    args = parser.parse_args()

    logging.basicConfig(format='%(asctime)s %(levelname)-8s %(message)s', level=logging.DEBUG if args.debug else logging.INFO)

    await Worker(args).run()


if __name__ == '__main__':
    asyncio.run(main())
