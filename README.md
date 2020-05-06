# Repology vulnerability data updater

[![Build Status](https://travis-ci.org/repology/repology-vulnupdater.svg?branch=master)](https://travis-ci.org/repology/repology-vulnupdater)

## Algorithm

- The program operates on yearly [NVD JSON Feeds](https://nvd.nist.gov/vuln/data-feeds#JSON_FEED)
- Feeds are checked each 10 minutes, fetched if they were modified (using `Etag`/`If-None-Match`) and parsed to extract
  - CVE id
  - Last CVS modification time
  - CPE match information
- CPE match information is converted into simplified form which consists of cpe vendor, product and versions range if that's possible
  - Currently only top-level OR nodes are supported
- CVE ids combined with simplified CPE match information are pushed to the database if they were modified after the previous feed update

## Running

```
usage: repology-vulnupdater.py [-h] [-D DSN] [-p SECONDS] [-d] [-1] [-y YEAR]

optional arguments:
  -h, --help            show this help message and exit
  -D DSN, --dsn DSN     database connection params (default: dbname=repology
                        user=repology password=repology)
  -p SECONDS, --update-period SECONDS
                        update period in seconds (default: 600.0)
  -d, --debug           enable debug logging (default: False)
  -1, --once-only       do just a single update pass, don't loop (default:
                        False)
  -y YEAR, --start-year YEAR
                        start year for feed retrieval (default: 2002)
```

For normal operation (persistent Repology instance with continuous
updates), run without arguments.

For testing purposes, e.g. to just fill database with some usable data,
consider running `repology-vulnupdater.py --once-only --start-year 2020`.

## Author

* [Dmitry Marakasov](https://github.com/AMDmi3) <amdmi3@amdmi3.ru>

## License

GPLv3 or later, see [COPYING](COPYING).
