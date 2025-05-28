"""
Tests for the domain analyzer module.

This module tests the functionality of the DomainAnalyzer class,
which analyzes domain variations by checking their DNS resolution status and WHOIS information.
"""

import unittest
import socket
from unittest.mock import patch, MagicMock, Mock
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any

import domaincheck.analyzer
DomainAnalysisResult = domaincheck.analyzer.DomainAnalysisResult


class TestDomainAnalysisResult(unittest.TestCase):
    """Test cases for the DomainAnalysisResult class."""

    def test_risk_score_calculation(self):
        """Test risk score calculation based on domain properties."""
        # Test unregistered domain with no DNS records
        result1 = DomainAnalysisResult(
            domain="example.com",
            is_registered=False,
            dns_records={},
        )
        self.assertEqual(result1.risk_score, 0)

        # Test registered domain with no DNS records
        result2 = DomainAnalysisResult(
            domain="example.com",
            is_registered=True,
            dns_records={},
        )
        self.assertEqual(result2.risk_score, 50)

        # Test registered domain with DNS records
        result3 = DomainAnalysisResult(
            domain="example.com",
            is_registered=True,
            dns_records={"A": ["192.0.2.1"]},
        )
        self.assertEqual(result3.risk_score, 85)  # 50 + 25 + 10

        # Test recently registered domain with DNS records
        recent_date = datetime.now() - timedelta(days=30)
        result4 = DomainAnalysisResult(
            domain="example.com",
            is_registered=True,
            dns_records={"A": ["192.0.2.1"]},
            creation_date=recent_date,
        )
        self.assertEqual(result4.risk_score, 100)  # 50 + 25 + 15 + 10 (capped at 100)

        # Test with list of creation dates
        result5 = DomainAnalysisResult(
            domain="example.com",
            is_registered=True,
            dns_records={"A": ["192.0.2.1"]},
            creation_date=[recent_date, datetime.now() - timedelta(days=100)],
        )
        self.assertEqual(result5.risk_score, 100)  # 50 + 25 + 15 + 10 (capped at 100)


class TestDomainAnalyzer(unittest.TestCase):
    """Test cases for the DomainAnalyzer class."""

    @patch('domaincheck.analyzer.dns.resolver')
    @patch('domaincheck.analyzer.whois')
    def setUp(self, mock_whois, mock_dns_resolver):
        """Set up test fixtures with mocked dependencies."""

        self.mock_whois = mock_whois
        self.mock_dns_resolver = mock_dns_resolver

        # Configure mock resolver
        self.mock_resolver = MagicMock()
        mock_dns_resolver.Resolver.return_value = self.mock_resolver

        # Create analyzer instance
        self.analyzer = domaincheck.analyzer.DomainAnalyzer(
            max_workers=2,
            dns_timeout=1.0,
            whois_timeout=1.0
        )

        self.test_domain = "example.com"

    def test_check_dns_resolution(self):
        """Test DNS resolution checking."""
        # Configure mock resolver to return test data for A record
        mock_answer = MagicMock()
        mock_answer.__str__.return_value = "192.0.2.1"
        self.mock_resolver.resolve.return_value = [mock_answer]

        dns_records = self.analyzer.check_dns_resolution(self.test_domain)

        # Verify resolver was called with correct parameters
        self.mock_resolver.resolve.assert_any_call(self.test_domain, "A")

        # Check that result contains expected data
        self.assertIn("A", dns_records)
        self.assertEqual(dns_records["A"], ["192.0.2.1"])

    def test_check_dns_resolution_exception(self):
        """Test DNS resolution with exceptions."""
        from dns.resolver import NXDOMAIN

        # Configure mock resolver to raise exception for certain record types
        self.mock_resolver.resolve.side_effect = lambda domain, record_type: (
            [MagicMock(__str__=lambda self: "192.0.2.1")] if record_type == "A"
            else (raise_exception(NXDOMAIN()) if record_type == "MX" else [])
        )

        dns_records = self.analyzer.check_dns_resolution(self.test_domain)

        # Check that result contains expected data and empty lists for failed lookups
        self.assertIn("A", dns_records)
        self.assertEqual(dns_records["A"], ["192.0.2.1"])
        self.assertIn("MX", dns_records)
        self.assertEqual(dns_records["MX"], [])

    @patch('socket.getaddrinfo')
    def test_check_basic_resolution(self, mock_getaddrinfo):
        """Test basic domain resolution check."""
        # Test successful resolution
        mock_getaddrinfo.return_value = [(2, 1, 6, '', ('93.184.216.34', 80))]
        self.assertTrue(self.analyzer.check_basic_resolution(self.test_domain))

        # Test failed resolution
        mock_getaddrinfo.side_effect = socket.gaierror
        self.assertFalse(self.analyzer.check_basic_resolution(self.test_domain))

    def test_get_whois_info(self):
        """Test WHOIS information retrieval."""
        # Configure mock whois to return test data
        mock_whois_data = MagicMock()
        mock_whois_data.status = "registered"
        mock_whois_data.creation_date = datetime(1995, 8, 14)
        mock_whois_data.registrar = "ICANN"
        self.mock_whois.whois.return_value = mock_whois_data

        domaincheck.analyzer.whois = self.mock_whois
        is_registered, whois_data, error = self.analyzer.get_whois_info(self.test_domain)

        # Verify whois was called with correct parameters
        self.mock_whois.whois.assert_called_with(self.test_domain)

        # Check result
        self.assertTrue(is_registered)
        self.assertEqual(whois_data, mock_whois_data)
        self.assertIsNone(error)

        # Test unregistered domain
        mock_whois_data.status = None
        is_registered, whois_data, error = self.analyzer.get_whois_info(self.test_domain)
        self.assertFalse(is_registered)
        self.assertIsNone(whois_data)
        self.assertEqual(error, "Domain not registered")

        # Test exception
        self.mock_whois.whois.side_effect = Exception("WHOIS error")
        is_registered, whois_data, error = self.analyzer.get_whois_info(self.test_domain)
        self.assertFalse(is_registered)
        self.assertIsNone(whois_data)
        self.assertEqual(error, "WHOIS error")

    def test_analyze_domain(self):
        """Test analysis of a single domain."""
        # Setup mocks for this test
        self.analyzer.check_dns_resolution = MagicMock(
            return_value={"A": ["192.0.2.1"], "MX": [], "NS": []}
        )
        self.analyzer.get_whois_info = MagicMock(
            return_value=(
                True,
                MagicMock(
                    creation_date=datetime(1995, 8, 14),
                    registrar="ICANN",
                    expiration_date=datetime(2023, 8, 13),
                    name_servers=["ns1.example.com", "ns2.example.com"],
                    emails="admin@example.com"
                ),
                None
            )
        )

        result = self.analyzer.analyze_domain(self.test_domain)

        # Verify calls
        self.analyzer.check_dns_resolution.assert_called_with(self.test_domain)
        self.analyzer.get_whois_info.assert_called_with(self.test_domain)

        # Check result properties
        self.assertEqual(result.domain, self.test_domain)
        self.assertTrue(result.is_registered)
        self.assertEqual(result.dns_records["A"], ["192.0.2.1"])
        self.assertEqual(result.creation_date, datetime(1995, 8, 14))
        self.assertEqual(result.registrar, "ICANN")
        self.assertEqual(result.expiration_date, datetime(2023, 8, 13))
        self.assertEqual(result.name_servers, ["ns1.example.com", "ns2.example.com"])
        self.assertEqual(result.abuse_contact, "admin@example.com")

    def test_analyze_domains(self):
        """Test analysis of multiple domains."""
        # Setup mock for analyze_domain
        sample_result = DomainAnalysisResult(
            domain=self.test_domain,
            is_registered=True,
            dns_records={"A": ["192.0.2.1"]},
            creation_date=datetime(1995, 8, 14),
            registrar="ICANN"
        )

        with patch.object(self.analyzer, 'analyze_domain', return_value=sample_result) as mock_analyze:
            domains = [self.test_domain, "example.org", "example.net"]
            results = self.analyzer.analyze_domains(domains)

            # Check that analyze_domain was called for each domain
            self.assertEqual(mock_analyze.call_count, len(domains))

            # Check results
            self.assertEqual(len(results), len(domains))
            for domain in domains:
                self.assertIn(domain, results)
                self.assertEqual(results[domain], sample_result)

    def test_identify_high_risk_domains(self):
        """Test identification of high-risk domains."""
        # Create sample results with different risk scores
        results = {
            "high-risk.com": DomainAnalysisResult(
                domain="high-risk.com",
                is_registered=True,
                dns_records={"A": ["192.0.2.1"]},
                creation_date=datetime.now() - timedelta(days=30),
            ),
            "medium-risk.com": DomainAnalysisResult(
                domain="medium-risk.com",
                is_registered=True,
                dns_records={},
            ),
            "low-risk.com": DomainAnalysisResult(
                domain="low-risk.com",
                is_registered=False,
                dns_records={},
            )
        }

        # Test with default threshold (60)
        high_risk = self.analyzer.identify_high_risk_domains(results)
        self.assertEqual(len(high_risk), 1)
        self.assertEqual(high_risk[0].domain, "high-risk.com")

        # Test with lower threshold
        high_risk = self.analyzer.identify_high_risk_domains(results, threshold=40)
        self.assertEqual(len(high_risk), 2)
        self.assertEqual(high_risk[0].domain, "high-risk.com")
        self.assertEqual(high_risk[1].domain, "medium-risk.com")

    def test_generate_report(self):
        """Test report generation from analysis results."""
        # Create sample results
        results = {
            "high-risk.com": DomainAnalysisResult(
                domain="high-risk.com",
                is_registered=True,
                dns_records={"A": ["192.0.2.1"]},
                creation_date=datetime.now() - timedelta(days=30),
                registrar="Some Registrar"
            ),
            "medium-risk.com": DomainAnalysisResult(
                domain="medium-risk.com",
                is_registered=True,
                dns_records={},
            ),
            "low-risk.com": DomainAnalysisResult(
                domain="low-risk.com",
                is_registered=False,
                dns_records={},
            )
        }

        # Test basic report
        report = self.analyzer.generate_report(results)

        # Check summary
        self.assertEqual(report["summary"]["total_domains"], 3)
        self.assertEqual(report["summary"]["registered_domains"], 2)
        self.assertEqual(report["summary"]["active_domains"], 1)
        self.assertEqual(report["summary"]["high_risk_domains"], 1)

        # Check high-risk domains
        self.assertEqual(len(report["high_risk_domains"]), 1)
        self.assertEqual(report["high_risk_domains"][0]["domain"], "high-risk.com")

        # Test report with all domains
        report = self.analyzer.generate_report(results, include_all=True)
        self.assertIn("all_domains", report)
        self.assertEqual(len(report["all_domains"]), 3)


# Helper function for side_effect that raises an exception
def raise_exception(exc):
    raise exc


if __name__ == '__main__':
    unittest.main()
