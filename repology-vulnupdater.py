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
import datetime
import logging
import time
from typing import Any, Iterable, List, Optional

import psycopg2

from vulnupdater.source import Source
from vulnupdater.sources.cpedict import CpeDictSource
from vulnupdater.sources.cvefeed import CveFeedSource


_FAST_UPDATE_PERIOD = 60 * 10  # for CVE modified feed
_SLOW_UPDATE_PERIOD = 60 * 60 * 24  # for other CVE feeds and CPE dict


class Worker:
    _options: argparse.Namespace

    _db: Any

    def __init__(self, options: argparse.Namespace) -> None:
        self._options = options
        self._db = psycopg2.connect(options.dsn, application_name='repology-vulnupdater')

    def _generate_sources(self) -> Iterable[Source]:
        if not self._options.fast_only:
            for year in range(2002, datetime.datetime.now().year + 1):
                yield CveFeedSource(self._db, f'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.gz', _SLOW_UPDATE_PERIOD)
        yield CveFeedSource(self._db, 'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz', _FAST_UPDATE_PERIOD)
        yield CpeDictSource(self._db, 'https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz', _SLOW_UPDATE_PERIOD)

    def _update_vulnerable_versions(self) -> None:
        with self._db.cursor() as cur:
            cur.execute(
                """
                DELETE FROM vulnerable_versions;

                WITH expanded_matches AS (
                    SELECT
                        jsonb_array_elements(matches)->>0 AS cpe_vendor,
                        jsonb_array_elements(matches)->>1 AS cpe_product,
                        jsonb_array_elements(matches)->>2 AS start_version,
                        jsonb_array_elements(matches)->>3 AS end_version,
                        (jsonb_array_elements(matches)->>4)::boolean AS start_version_excluded,
                        (jsonb_array_elements(matches)->>5)::boolean AS end_version_excluded
                    FROM cves
                ), matches_with_covering_ranges AS (
                    SELECT
                        cpe_vendor,
                        cpe_product,
                        start_version,
                        end_version,
                        start_version_excluded,
                        end_version_excluded,
                        max(end_version::versiontext) FILTER(WHERE start_version IS NULL) OVER (PARTITION BY cpe_vendor, cpe_product) AS covering_end_version
                    FROM expanded_matches
                )
                INSERT INTO vulnerable_versions
                SELECT DISTINCT
                    cpe_vendor,
                    cpe_product,
                    start_version,
                    end_version,
                    start_version_excluded,
                    end_version_excluded
                FROM matches_with_covering_ranges
                WHERE
                    coalesce(version_compare2(end_version, covering_end_version) >= 0, true)
                """
            )

    def _iteration(self) -> Optional[float]:
        logging.debug('iteration started')

        sources = list(self._generate_sources())
        sources_to_update: List[Source] = []

        wait_time = float(_FAST_UPDATE_PERIOD)
        for source in sources:
            if (source_wait_time := source.get_time_to_update()) > 0:
                wait_time = min(wait_time, source_wait_time)
            else:
                sources_to_update.append(source)

        if not sources_to_update:
            logging.debug('nothing to do in this iteration')
            return wait_time

        had_cve_updates = False
        for source in sources_to_update:
            if source.update() and source.get_type() == 'cve_feed':
                had_cve_updates = True

        if had_cve_updates:
            logging.debug('updating simplified vulnerabilities information')
            self._update_vulnerable_versions()

        return None

    def run(self) -> None:
        while True:
            try:
                wait_time = self._iteration()
                self._db.commit()
            except:
                self._db.rollback()
                raise

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
