"""
Tests for the domain variation generator module.

This module tests the functionality of the DomainVariationGenerator class,
which generates various permutations of domain names for potential impersonation detection.
"""

import unittest
from domaincheck.generator import DomainVariationGenerator


class TestDomainVariationGenerator(unittest.TestCase):
    """Test cases for the DomainVariationGenerator class."""

    def setUp(self):
        """Set up test fixtures."""
        self.generator = DomainVariationGenerator(max_variations=1000)
        self.test_domain = "example.com"

    def test_parse_domain(self):
        """Test domain parsing into name and TLD parts."""
        # Test standard domain
        name, tld = self.generator.parse_domain("example.com")
        self.assertEqual(name, "example")
        self.assertEqual(tld, "com")

        # Test subdomain
        name, tld = self.generator.parse_domain("sub.example.com")
        self.assertEqual(name, "sub.example")
        self.assertEqual(tld, "com")

        # Test domain with no TLD
        name, tld = self.generator.parse_domain("example")
        self.assertEqual(name, "example")
        self.assertEqual(tld, "")

        # Test domain with multiple dots
        name, tld = self.generator.parse_domain("a.b.c.d.com")
        self.assertEqual(name, "a.b.c.d")
        self.assertEqual(tld, "com")

    def test_generate_typosquatting_variations(self):
        """Test generation of typosquatting variations."""
        variations = self.generator.generate_typosquatting_variations(self.test_domain)

        # Check that we have variations
        self.assertTrue(len(variations) > 0)

        # Check for specific variation types
        # 1. Character swaps
        self.assertIn("xeample.com", variations)

        # 2. Character deletion
        self.assertIn("examle.com", variations)

        # 3. Common typos (character insertion)
        self.assertIn("exampple.com", variations)

        # 4. Adjacent key errors
        self.assertIn("ezample.com", variations)  # 'z' is adjacent to 'x' on QWERTY

    def test_generate_homoglyph_variations(self):
        """Test generation of homoglyph variations."""
        variations = self.generator.generate_homoglyph_variations(self.test_domain)

        # Check that we have variations
        self.assertTrue(len(variations) > 0)

        # Check for specific homoglyph variations
        # The letter 'e' can be replaced with 'е' (Cyrillic) or '3'
        homoglyph_e = False
        for var in variations:
            if var != self.test_domain and 'e' not in var and ('е' in var or '3' in var):
                homoglyph_e = True
                break
        self.assertTrue(homoglyph_e, "No homoglyph variation found for 'e'")

        # The letter 'a' can be replaced with 'а' (Cyrillic) or '4' or '@'
        homoglyph_a = False
        for var in variations:
            if var != self.test_domain and 'a' not in var and ('а' in var or '4' in var or '@' in var):
                homoglyph_a = True
                break
        self.assertTrue(homoglyph_a, "No homoglyph variation found for 'a'")

    def test_generate_tld_variations(self):
        """Test generation of TLD variations."""
        variations = self.generator.generate_tld_variations(self.test_domain)

        # Check that we have variations
        self.assertTrue(len(variations) > 0)

        # Check for specific TLD variations
        common_tlds = ["org", "net", "io"]
        for tld in common_tlds:
            self.assertIn(f"example.{tld}", variations)

        # Original TLD should not be in variations
        self.assertNotIn(self.test_domain, variations)

    def test_generate_all_variations(self):
        """Test generation of all variation types."""
        all_variations = self.generator.generate_all_variations(self.test_domain)

        # Check that we have all three types of variations
        self.assertIn('typosquatting', all_variations)
        self.assertIn('homoglyphs', all_variations)
        self.assertIn('tld_variations', all_variations)

        # Check that each category has variations
        self.assertTrue(len(all_variations['typosquatting']) > 0)
        self.assertTrue(len(all_variations['homoglyphs']) > 0)
        self.assertTrue(len(all_variations['tld_variations']) > 0)

        # Test selective generation
        only_typos = self.generator.generate_all_variations(
            self.test_domain,
            include_homoglyphs=False,
            include_tlds=False
        )
        self.assertIn('typosquatting', only_typos)
        self.assertNotIn('homoglyphs', only_typos)
        self.assertNotIn('tld_variations', only_typos)

        only_homoglyphs = self.generator.generate_all_variations(
            self.test_domain,
            include_typos=False,
            include_tlds=False
        )
        self.assertNotIn('typosquatting', only_homoglyphs)
        self.assertIn('homoglyphs', only_homoglyphs)
        self.assertNotIn('tld_variations', only_homoglyphs)

        only_tlds = self.generator.generate_all_variations(
            self.test_domain,
            include_typos=False,
            include_homoglyphs=False
        )
        self.assertNotIn('typosquatting', only_tlds)
        self.assertNotIn('homoglyphs', only_tlds)
        self.assertIn('tld_variations', only_tlds)

    def test_max_variations_limit(self):
        """Test that the max_variations limit is respected."""
        # Create a generator with a small limit
        small_generator = DomainVariationGenerator(max_variations=5)

        # Generate variations and check they're limited
        typo_variations = small_generator.generate_typosquatting_variations(self.test_domain)
        self.assertLessEqual(len(typo_variations), 5)

        homoglyph_variations = small_generator.generate_homoglyph_variations(self.test_domain)
        self.assertLessEqual(len(homoglyph_variations), 5)


if __name__ == '__main__':
    unittest.main()
