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

from typing import ClassVar, IO, MutableSet

from jsonslicer import JsonSlicer

import psycopg2.extras

from vulnupdater.source import Source
from vulnupdater.sources.cvefeed.match import CPEMatch


class CveFeedSource(Source):
    TYPE: ClassVar[str] = 'cve_feed'

    def get_type(self) -> str:
        return CveFeedSource.TYPE

    def _process(self, stream: IO[bytes]) -> bool:
        num_updates = 0

        for cve in JsonSlicer(stream, ('CVE_Items', None)):
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
                    if match.vulnerable and match.part == 'a' and match.end_version and match.end_version != '-':
                        usable_matches.add(match)

            matches_for_json = [
                [
                    match.vendor,
                    match.product,
                    match.start_version,
                    match.end_version,
                    match.start_version_excluded,
                    match.end_version_excluded,
                ]
                for match in usable_matches
            ]

            with self._db.cursor() as cur:
                cur.execute(
                    """
                    WITH updated_cves AS (
                        INSERT INTO cves (
                            cve_id,
                            published,
                            last_modified,
                            matches,
                            cpe_pairs
                        )
                        VALUES (
                            %(cve_id)s,
                            %(published)s,
                            %(last_modified)s,
                            %(matches)s,
                            %(cpe_pairs)s
                        )
                        ON CONFLICT(cve_id) DO UPDATE
                        SET
                            published = %(published)s,  -- not expected to change in fact
                            last_modified = %(last_modified)s,
                            matches = %(matches)s,
                            cpe_pairs = %(cpe_pairs)s
                        WHERE
                            %(last_modified)s > cves.last_modified
                        RETURNING cpe_pairs
                    ), register_cpe_updates AS (
                        INSERT INTO cpe_updates (
                            cpe_vendor,
                            cpe_product
                        )
                        SELECT
                            split_part(unnest(cpe_pairs), ':', 1) AS cpe_vendor,
                            split_part(unnest(cpe_pairs), ':', 2) AS cpe_product
                        FROM
                            updated_cves
                    )
                    SELECT 1
                    FROM updated_cves
                    """,
                    {
                        'cve_id': cve_id,
                        'published': published,
                        'last_modified': last_modified,
                        'matches': psycopg2.extras.Json(matches_for_json) if matches_for_json else None,
                        'cpe_pairs': list(set(f'{match.vendor}:{match.product}' for match in usable_matches)) or None
                    }
                )

                num_updates += sum(row[0] for row in cur.fetchall())

        self._num_updates += num_updates

        return num_updates > 0
