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

import unittest

from vulnupdater.cpe import CPE


class TestCPE(unittest.TestCase):
    def test_simple(self):
        cpe = CPE('cpe:2.3:part:vendor:product:version:update:edition:lang:sw_edition:target_sw:target_hw:')

        self.assertEqual(cpe.part, 'part')
        self.assertEqual(cpe.vendor, 'vendor')
        self.assertEqual(cpe.product, 'product')
        self.assertEqual(cpe.version, 'version')
        self.assertEqual(cpe.update, 'update')
        self.assertEqual(cpe.edition, 'edition')
        self.assertEqual(cpe.lang, 'lang')
        self.assertEqual(cpe.sw_edition, 'sw_edition')
        self.assertEqual(cpe.target_sw, 'target_sw')
        self.assertEqual(cpe.target_hw, 'target_hw')

    def test_escaped(self):
        cpe = CPE('cpe:2.3:a:foo\\$bar:foo\\:bar:foo\\\\bar:*:*:*:*:*:*:')

        self.assertEqual(cpe.vendor, 'foo\\$bar')
        self.assertEqual(cpe.product, 'foo\\:bar')
        self.assertEqual(cpe.version, 'foo\\\\bar')


if __name__ == '__main__':
    unittest.main()
