"""
Tests for the command-line interface module.

This module tests the functionality of the CLI module,
which provides the command-line interface for the domain impersonation checker.
"""

import unittest
import argparse
import json
import sys
from unittest.mock import patch, MagicMock, mock_open
from io import StringIO

from domaincheck.cli import (
    create_parser,
    generate_variations,
    analyze_domains,
    format_text_report,
    save_report,
    main
)
from domaincheck.analyzer import DomainAnalysisResult


class TestCliArgParser(unittest.TestCase):
    """Test cases for the CLI argument parser."""

    def test_create_parser(self):
        """Test creation of argument parser."""
        parser = create_parser()
        
        # Check parser type
        self.assertIsInstance(parser, argparse.ArgumentParser)
        
        # Parse test arguments and check values
        args = parser.parse_args(["example.com"])
        self.assertEqual(args.domain, "example.com")
        self.assertFalse(args.verbose)
        self.assertFalse(args.no_typos)
        self.assertFalse(args.no_homoglyphs)
        self.assertFalse(args.no_tlds)
        self.assertFalse(args.no_dns)
        self.assertFalse(args.no_whois)
        self.assertEqual(args.max_variations, 1000)
        self.assertEqual(args.concurrency, 10)
        self.assertEqual(args.dns_timeout, 2.0)
        self.assertEqual(args.whois_timeout, 5.0)
        self.assertEqual(args.min_risk_score, 60)
        self.assertFalse(args.show_all)
        self.assertEqual(args.format, "text")
        
        # Test with additional arguments
        args = parser.parse_args([
            "example.com",
            "-v",
            "--no-typos",
            "--no-tlds",
            "--max-variations", "500",
            "--min-risk-score", "40",
            "--format", "json"
        ])
        self.assertEqual(args.domain, "example.com")
        self.assertTrue(args.verbose)
        self.assertTrue(args.no_typos)
        self.assertFalse(args.no_homoglyphs)
        self.assertTrue(args.no_tlds)
        self.assertEqual(args.max_variations, 500)
        self.assertEqual(args.min_risk_score, 40)
        self.assertEqual(args.format, "json")


class TestCliVariationGeneration(unittest.TestCase):
    """Test cases for the CLI variation generation function."""

    @patch('domaincheck.cli.DomainVariationGenerator')
    def test_generate_variations(self, mock_generator_class):
        """Test variation generation function."""
        # Setup mock generator
        mock_generator = MagicMock()
        mock_generator.generate_all_variations.return_value = {
            'typosquatting': ['exapmle.com', 'examle.com'],
            'homoglyphs': ['examp1e.com', 'examрle.com'],
            'tld_variations': ['example.org', 'example.net']
        }
        mock_generator_class.return_value = mock_generator
        
        # Setup arguments
        args = MagicMock()
        args.max_variations = 1000
        args.no_typos = False
        args.no_homoglyphs = False
        args.no_tlds = False
        args.verbose = True
        
        # Test with all variation types
        variations = generate_variations("example.com", args)
        
        # Verify the generator was called correctly
        mock_generator_class.assert_called_once_with(max_variations=1000)
        mock_generator.generate_all_variations.assert_called_once_with(
            "example.com",
            include_typos=True,
            include_homoglyphs=True,
            include_tlds=True
        )
        
        # Check results
        self.assertEqual(len(variations), 3)
        self.assertEqual(len(variations['typosquatting']), 2)
        self.assertEqual(len(variations['homoglyphs']), 2)
        self.assertEqual(len(variations['tld_variations']), 2)
        
        # Test with selective variation types
        args.no_typos = True
        args.no_homoglyphs = False
        args.no_tlds = True
        
        mock_generator.generate_all_variations.reset_mock()
        mock_generator.generate_all_variations.return_value = {
            'homoglyphs': ['examp1e.com', 'examрle.com'],
        }
        
        variations = generate_variations("example.com", args)
        
        mock_generator.generate_all_variations.assert_called_once_with(
            "example.com",
            include_typos=False,
            include_homoglyphs=True,
            include_tlds=False
        )
        
        self.assertEqual(len(variations), 1)
        self.assertIn('homoglyphs', variations)


class TestCliDomainAnalysis(unittest.TestCase):
    """Test cases for the CLI domain analysis function."""

    @patch('domaincheck.cli.DomainAnalyzer')
    def test_analyze_domains(self, mock_analyzer_class):
        """Test domain analysis function."""
        # Setup mock analyzer
        mock_analyzer = MagicMock()
        mock_analyzer_class.return_value = mock_analyzer
        
        # Setup sample analysis results
        sample_result = DomainAnalysisResult(
            domain="example.com",
            is_registered=True,
            dns_records={"A": ["192.0.2.1"]}
        )
        mock_analyzer.analyze_domains.return_value = {
            "example.com": sample_result,
            "example.org": sample_result
        }
        
        # Setup variations
        variations = {
            'typosquatting': ['example.com'],
            'tld_variations': ['example.org']
        }
        
        # Setup arguments
        args = MagicMock()
        args.concurrency = 5
        args.dns_timeout = 1.0
        args.whois_timeout = 2.0
        args.no_dns = False
        args.no_whois = False
        args.verbose = True
        
        # Call analyze_domains
        results = analyze_domains(variations, args)
        
        # Verify analyzer creation and call
        mock_analyzer_class.assert_called_once_with(
            max_workers=5,
            dns_timeout=1.0,
            whois_timeout=2.0
        )
        
        # Check results
        self.assertEqual(len(results), 2)
        self.assertIn("example.com", results)
        self.assertIn("example.org", results)
        
        # Test with DNS and WHOIS disabled
        args.no_dns = True
        args.no_whois = True
        
        # Redirect stdout to capture warning
        captured_output = StringIO()
        sys.stdout = captured_output
        
        results = analyze_domains(variations, args)
        
        # Reset stdout
        sys.stdout = sys.__stdout__
        
        # Check warning was printed
        self.assertIn("Warning", captured_output.getvalue())
        self.assertIn("Both DNS and WHOIS checks are disabled", captured_output.getvalue())
        
        # Check empty results
        self.assertEqual(results, {})


class TestCliReportFormatting(unittest.TestCase):
    """Test cases for the CLI report formatting function."""

    def test_format_text_report(self):
        """Test text report formatting."""
        # Setup sample report data
        report = {
            "summary": {
                "total_domains": 100,
                "registered_domains": 20,
                "active_domains": 15,
                "high_risk_domains": 5
            },
            "high_risk_domains": [
                {
                    "domain": "high-risk1.com",
                    "risk_score": 90,
                    "is_registered": True,
                    "has_dns_records": True,
                    "registrar": "Some Registrar",
                    "creation_date": "2023-01-15"
                },
                {
                    "domain": "high-risk2.com",
                    "risk_score": 80,
                    "is_registered": True,
                    "has_dns_records": True
                }
            ],
            "all_domains": [
                {
                    "domain": "high-risk1.com",
                    "risk_score": 90,
                    "is_registered": True,
                    "has_dns_records": True
                },
                {
                    "domain": "medium-risk.com",
                    "risk_score": 50,
                    "is_registered": True,
                    "has_dns_records": False
                }
            ]
        }
        
        # Setup arguments
        args = MagicMock()
        args.domain = "example.com"
        args.show_all = True
        
        # Format report
        text_report = format_text_report(report, args)
        
        # Check report contains expected sections
        self.assertIn("Domain Impersonation Checker - Analysis Report", text_report)
        self.assertIn("Target domain: example.com", text_report)
        self.assertIn("Generated on:", text_report)
        self.assertIn("Summary:", text_report)
        self.assertIn("Total variations analyzed: 100", text_report)
        self.assertIn("Registered domains: 20", text_report)
        self.assertIn("Active domains (with DNS records): 15", text_report)
        self.assertIn("High-risk domains: 5", text_report)
        self.assertIn("High Risk Domains:", text_report)
        self.assertIn("Domain: high-risk1.com", text_report)
        self.assertIn("Risk Score: 90/100", text_report)
        self.assertIn("Registrar: Some Registrar", text_report)
        self.assertIn("Creation Date: 2023-01-15", text_report)
        self.assertIn("All Analyzed Domains:", text_report)
        self.assertIn("medium-risk.com - Risk: 50/100", text_report)
        
        # Test without all domains
        args.show_all = False
        text_report = format_text_report(report, args)
        self.assertNotIn("All Analyzed Domains:", text_report)
        
        # Test with no high-risk domains
        report["high_risk_domains"] = []
        text_report = format_text_report(report, args)
        self.assertIn("No high-risk domains identified.", text_report)


class TestCliSaveReport(unittest.TestCase):
    """Test cases for the CLI report saving function."""

    @patch('builtins.open', new_callable=mock_open)
    @patch('json.dumps')
    def test_save_report(self, mock_json_dumps, mock_file_open):
        """Test report saving."""
        # Setup
        report = {"key": "value"}
        output_path = "output.json"
        mock_json_dumps.return_value = '{"key": "value"}'
        
        # Mock args for text format
        args = MagicMock()
        
        # Redirect stdout to capture output
        captured_output = StringIO()
        sys.stdout = captured_output
        
        # Test saving JSON report
        save_report(report, output_path, "json")
        
        # Verify file was opened for writing
        mock_file_open.assert_called_with(output_path, "w", encoding="utf-8")
        
        # Verify JSON dumps was called
        mock_json_dumps.assert_called_with(report, default=str, indent=2)
        
        # Verify file write
        mock_file_open().write.assert_called_with('{"key": "value"}')
        
        # Check success message
        self.assertIn(f"Report saved to {output_path}", captured_output.getvalue())
        
        # Reset mocks and captured output
        mock_file_open.reset_mock()
        mock_json_dumps.reset_mock()
        captured_output = StringIO()
        sys.stdout = captured_output
        
        # Test exception handling
        mock_file_open.side_effect = IOError("Permission denied")
        
        save_report(report, output_path, "json")
        
        # Check error message
        self.assertIn("Error saving report:", captured_output.getvalue())
        
        # Reset stdout
        sys.stdout = sys.__stdout__


class TestCliMain(unittest.TestCase):
    """Test cases for the CLI main function."""

    @patch('domaincheck.cli.generate_variations')
    @patch('domaincheck.cli.analyze_domains')
    @patch('domaincheck.cli.DomainAnalyzer')
    @patch('domaincheck.cli.format_text_report')
    @patch('sys.stdout', new_callable=StringIO)
    def test_main(self, mock_stdout, mock_format_text, mock_analyzer_class, 
                 mock_analyze_domains, mock_generate_variations):
        """Test main function."""
        # Setup mocks
        mock_generate_variations.return_value = {
            'typosquatting': ['exapmle.com'],
            'homoglyphs': ['examp1e.com']
        }
        mock_analyze_domains.return_value = {
            'exapmle.com': MagicMock(),
            'examp1e.com': MagicMock()
        }
        mock_analyzer = MagicMock()
        mock_analyzer_class.return_value = mock_analyzer
        mock_analyzer.generate_report.return_value = {"key": "value"}
        mock_format_text.return_value = "Formatted text report"
        
        # Mock sys.argv
        with patch('sys.argv', ['domaincheck', 'example.com']):
            # Call main
            result = main()
            
            # Check successful return
            self.assertEqual(result, 0)
            
            # Verify function calls
            mock_generate_variations.assert_called_once()
            mock_analyze_domains.assert_called_once()
            mock_analyzer.generate_report.assert_called_once()
            mock_format_text.assert_called_once()
            
            # Check output
            self.assertEqual(mock_stdout.getvalue(), "Formatted text report\n")
        
        # Test with zero variations
        mock_generate_variations.return_value = {}
        
        with patch('sys.argv', ['domaincheck', 'example.com']):
            result = main()
            
            # Check error return
            self.assertEqual(result, 1)
            
        # Test exception handling
        mock_generate_variations.side_effect = Exception("Test error")
        
        with patch('sys.argv', ['domaincheck', 'example.com']):
            result = main()
            
            # Check error return
            self.assertEqual(result, 1)
        
        # Test keyboard interrupt
        mock_generate_variations.side_effect = KeyboardInterrupt()
        
        with patch('sys.argv', ['domaincheck', 'example.com']):
            result = main()
            
            # Check interrupt return
            self.assertEqual(result, 130)


if __name__ == '__main__':
    unittest.main()