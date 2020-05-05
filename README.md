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

## Author

* [Dmitry Marakasov](https://github.com/AMDmi3) <amdmi3@amdmi3.ru>

## License

GPLv3 or later, see [COPYING](COPYING).
