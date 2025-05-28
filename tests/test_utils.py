"""
Tests for the utility functions.

This module tests the functionality of the utility functions in the utils module,
which provide helper functions used across the application.
"""

import unittest
import io
import sys
from datetime import datetime
from typing import Dict, List, Any

from domaincheck.utils import (
    is_valid_domain,
    normalize_domain,
    format_datetime,
    truncate_string,
    print_progress,
    dict_to_table,
    format_risk_level,
    group_domains_by_type,
)


class TestUtils(unittest.TestCase):
    """Test cases for the utility functions."""

    def test_is_valid_domain(self):
        """Test domain validation."""
        # Valid domains
        self.assertTrue(is_valid_domain("example.com"))
        self.assertTrue(is_valid_domain("sub.example.com"))
        self.assertTrue(is_valid_domain("example.co.uk"))
        self.assertTrue(is_valid_domain("xn--80aswg.com"))  # IDN
        self.assertTrue(is_valid_domain("example-site.com"))

        # Invalid domains
        self.assertFalse(is_valid_domain("example"))  # No TLD
        self.assertFalse(is_valid_domain("example."))  # TLD missing
        self.assertFalse(is_valid_domain(".com"))  # Domain missing
        self.assertFalse(is_valid_domain("ex ample.com"))  # Space
        self.assertFalse(is_valid_domain("example..com"))  # Double dot
        self.assertFalse(is_valid_domain("-example.com"))  # Starts with hyphen
        self.assertFalse(is_valid_domain("example-.com"))  # Ends with hyphen
        self.assertFalse(is_valid_domain("example.c"))  # TLD too short

    def test_normalize_domain(self):
        """Test domain normalization."""
        self.assertEqual(normalize_domain("EXAMPLE.COM"), "example.com")
        self.assertEqual(normalize_domain(" example.com "), "example.com")
        self.assertEqual(normalize_domain("Example.Com"), "example.com")
        self.assertEqual(normalize_domain("EXAMPLE.COM/path"), "example.com/path")
        self.assertEqual(normalize_domain(""), "")

    def test_format_datetime(self):
        """Test datetime formatting."""
        # Test with a single datetime
        test_date = datetime(2023, 1, 15)
        self.assertEqual(format_datetime(test_date), "2023-01-15")

        # Test with a list of datetimes
        date_list = [datetime(2023, 1, 15), datetime(2022, 12, 1)]
        self.assertEqual(format_datetime(date_list), "2023-01-15")

        # Test with an empty list
        self.assertEqual(format_datetime([]), "Unknown")

        # Test with None
        self.assertEqual(format_datetime(None), "Unknown")

        # Test with a string
        self.assertEqual(format_datetime("2023-01-15"), "2023-01-15")

        # Test with an invalid datetime object
        class InvalidDatetime:
            pass

        self.assertTrue(isinstance(format_datetime(InvalidDatetime()), str))

    def test_truncate_string(self):
        """Test string truncation."""
        # Test string shorter than max length
        self.assertEqual(truncate_string("Short string", 20), "Short string")

        # Test string exactly max length
        self.assertEqual(truncate_string("12345678901234567890", 20), "12345678901234567890")

        # Test string longer than max length
        self.assertEqual(truncate_string("123456789012345678901234567890", 20), "12345678901234567...")

        # Test with different max length
        self.assertEqual(truncate_string("1234567890", 5), "12...")

    def test_print_progress(self):
        """Test progress bar printing."""
        # Redirect stdout to capture output
        captured_output = io.StringIO()
        sys.stdout = captured_output

        # Test 0% progress
        print_progress(0, 100)
        self.assertIn("0.0%", captured_output.getvalue())

        # Reset captured output
        captured_output = io.StringIO()
        sys.stdout = captured_output

        # Test 50% progress
        print_progress(50, 100)
        self.assertIn("50.0%", captured_output.getvalue())

        # Reset captured output
        captured_output = io.StringIO()
        sys.stdout = captured_output

        # Test 100% progress
        print_progress(100, 100)
        self.assertIn("100.0%", captured_output.getvalue())

        # Reset stdout
        sys.stdout = sys.__stdout__

    def test_dict_to_table(self):
        """Test dictionary to table conversion."""
        # Test with empty data
        self.assertEqual(dict_to_table([], ["col1", "col2"]), [])

        # Test with empty columns
        self.assertEqual(dict_to_table([{"a": 1}], []), [])

        # Test with sample data
        data = [
            {"name": "John", "age": 30, "city": "New York"},
            {"name": "Alice", "age": 25, "city": "London"}
        ]
        columns = ["name", "age"]

        table = dict_to_table(data, columns)

        # Check header and separator
        self.assertEqual(table[0], "name  | age")
        self.assertEqual(table[1], "------+----")

        # Check data rows
        self.assertEqual(table[2], "John  | 30 ")
        self.assertEqual(table[3], "Alice | 25 ")

    def test_format_risk_level(self):
        """Test risk level formatting."""
        self.assertEqual(format_risk_level(0), "Minimal")
        self.assertEqual(format_risk_level(10), "Minimal")
        self.assertEqual(format_risk_level(20), "Low")
        self.assertEqual(format_risk_level(35), "Low")
        self.assertEqual(format_risk_level(40), "Medium")
        self.assertEqual(format_risk_level(55), "Medium")
        self.assertEqual(format_risk_level(60), "High")
        self.assertEqual(format_risk_level(75), "High")
        self.assertEqual(format_risk_level(80), "Critical")
        self.assertEqual(format_risk_level(95), "Critical")
        self.assertEqual(format_risk_level(100), "Critical")

    def test_group_domains_by_type(self):
        """Test grouping domains by variation type."""
        # Setup test data
        domains = ["example.com", "examp1e.com", "example.org", "unknown.com"]
        variations = {
            "typosquatting": ["examp1e.com"],
            "tld_variations": ["example.org"]
        }

        grouped = group_domains_by_type(domains, variations)

        # Check grouping
        self.assertIn("typosquatting", grouped)
        self.assertIn("tld_variations", grouped)
        self.assertIn("unknown", grouped)

        self.assertEqual(grouped["typosquatting"], ["examp1e.com"])
        self.assertEqual(grouped["tld_variations"], ["example.org"])
        self.assertEqual(grouped["unknown"], ["example.com", "unknown.com"])


if __name__ == '__main__':
    unittest.main()
