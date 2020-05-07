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

from typing import Any, Iterable, List, Optional

import psycopg2
import psycopg2.extras

from vulnupdater.cveinfo import CPEMatch
from vulnupdater.sources import Source


def fill_sources_statuses(db: Any, sources: List[Source]) -> None:
    source_by_url = {source.url: source for source in sources}

    with db.cursor() as cur:
        cur.execute(
            """
            SELECT
                url,
                etag,
                now() - last_update AS age
            FROM vulnerability_sources
            ORDER BY url
            """,
            {
                'urls': [source.url for source in sources]
            }
        )

        for url, etag, age in cur.fetchall():
            if url in source_by_url:
                source_by_url[url].etag = etag
                source_by_url[url].age = age.total_seconds()


def update_source(db: Any, url: str, etag: Optional[str] = None, num_updates: int = 0) -> None:
    with db.cursor() as cur:
        cur.execute(
            """
            INSERT INTO vulnerability_sources(
                url,
                etag,
                last_update,
                total_updates
            )
            VALUES (
                %(url)s,
                %(etag)s,
                now(),
                %(num_updates)s
            )
            ON CONFLICT(url) DO UPDATE
            SET
                etag = coalesce(%(etag)s, vulnerability_sources.etag),
                last_update = now(),
                total_updates = vulnerability_sources.total_updates + %(num_updates)s
            """,
            {
                'url': url,
                'etag': etag,
                'num_updates': num_updates,
            }
        )


def update_cve(db: Any, cve_id: str, last_modified: str, matches: Iterable[CPEMatch]) -> int:
    with db.cursor() as cur:
        cur.execute(
            """
            WITH updated_cves AS (
                INSERT INTO cves (
                    cve_id,
                    last_modified,
                    matches
                )
                VALUES (
                    %(cve_id)s,
                    %(last_modified)s,
                    %(matches)s
                )
                ON CONFLICT(cve_id) DO UPDATE
                SET
                    last_modified = %(last_modified)s,
                    matches = %(matches)s
                WHERE
                    %(last_modified)s > cves.last_modified
                RETURNING cve_id
            )
            INSERT INTO cve_updates
            SELECT cve_id FROM updated_cves
            RETURNING 1
            """,
            {
                'cve_id': cve_id,
                'last_modified': last_modified,
                'matches': psycopg2.extras.Json(
                    [
                        [
                            match.vendor,
                            match.product,
                            match.start_version,
                            match.end_version,
                            match.start_version_excluded,
                            match.end_version_excluded,
                        ]
                        for match in matches
                    ]
                )
            }
        )

        return sum(row[0] for row in cur.fetchall())


def update_vulnerable_versions(db: Any) -> None:
    with db.cursor() as cur:
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
