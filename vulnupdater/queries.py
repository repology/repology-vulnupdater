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

from dataclasses import dataclass
from typing import List, Optional

import aiopg

import psycopg2

from vulnupdater.cveinfo import CPEMatch, CVEItem


__all__ = [
    'Source',
    'get_due_sources',
    'get_registered_source_urls',
    'get_sleep_till_due_source',
    'register_source',
    'update_cve',
    'update_source',
]


@dataclass
class Source:
    url: str

    etag: Optional[str] = None
    max_last_modified: str = ''


async def get_registered_source_urls(pool: aiopg.Pool) -> List[str]:
    async with pool.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute('SELECT url FROM vulnerability_sources')
            return [row[0] for row in await cur.fetchall()]


async def register_source(pool: aiopg.Pool, url: str) -> None:
    async with pool.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute('INSERT INTO vulnerability_sources(url) VALUES(%(url)s)', {'url': url})


async def get_due_sources(pool: aiopg.Pool, update_period: float) -> List[Source]:
    async with pool.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                """
                SELECT
                    url,
                    etag,
                    max_last_modified
                FROM vulnerability_sources
                WHERE last_update IS NULL OR now() > last_update + INTERVAL '%(update_period)s SECONDS'
                ORDER BY url
                """,
                {
                    'update_period': update_period
                }
            )

            return [
                Source(
                    url=row[0],
                    etag=row[1],
                    max_last_modified=row[2]
                ) for row in await cur.fetchall()
            ]


async def get_sleep_till_due_source(pool: aiopg.Pool, update_period: float) -> float:
    async with pool.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                """
                SELECT
                    min(last_update + INTERVAL '%(update_period)s SECONDS' - now())
                FROM vulnerability_sources
                WHERE last_update + INTERVAL '%(update_period)s SECONDS' > now()
                """,
                {
                    'update_period': update_period
                }
            )
            return (await cur.fetchone())[0].total_seconds() or 0.01


async def update_source(pool: aiopg.Pool, url: str, etag: Optional[str] = None, max_last_modified: Optional[str] = None) -> None:
    async with pool.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                """
                UPDATE vulnerability_sources
                SET
                    etag = coalesce(%(etag)s, etag),
                    max_last_modified = coalesce(%(max_last_modified)s, max_last_modified),
                    last_update = now()
                WHERE
                    url = %(url)s
                """,
                {
                    'url': url,
                    'etag': etag,
                    'max_last_modified': max_last_modified
                }
            )


async def update_cve(pool: aiopg.Pool, cve: CVEItem, cpe_matches: List[CPEMatch]) -> None:
    async with pool.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                """
                DELETE
                FROM vulnerabilities
                WHERE cve_id = %(cve_id)s;

                INSERT
                INTO vulnerabilities (
                    cve_id,
                    cpe_vendor,
                    cpe_product,
                    start_version,
                    end_version,
                    start_version_excluded,
                    end_version_excluded
                )
                SELECT
                    %(cve_id)s,
                    unnest(%(matches)s)::json->>0,
                    unnest(%(matches)s)::json->>1,
                    unnest(%(matches)s)::json->>2,
                    unnest(%(matches)s)::json->>3,
                    (unnest(%(matches)s)::json->>4)::boolean,
                    (unnest(%(matches)s)::json->>5)::boolean
                """,
                {
                    'cve_id': cve.cve_id,
                    'matches':
                    [
                        psycopg2.extras.Json(
                            [
                                match.vendor,
                                match.product,
                                match.start_version,
                                match.end_version,
                                match.start_version_excluded,
                                match.end_version_excluded,
                            ]
                        ) for match in cpe_matches
                    ]
                }
            )
