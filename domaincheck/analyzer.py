"""
Domain analyzer module for DNS and WHOIS lookups.

This module provides functionality to analyze domain variations by checking
their DNS resolution status and WHOIS information.
"""

import concurrent.futures
import socket
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple, Union

import dns.resolver
import whois

@dataclass
class DomainAnalysisResult:
    """Container for domain analysis results."""
    domain: str
    is_registered: bool
    dns_records: Dict[str, List[str]]
    creation_date: Optional[Union[datetime, List[datetime]]] = None
    registrar: Optional[str] = None
    expiration_date: Optional[Union[datetime, List[datetime]]] = None
    name_servers: Optional[List[str]] = None
    whois_error: Optional[str] = None
    dns_error: Optional[str] = None
    last_updated: Optional[datetime] = None
    registrant: Optional[str] = None
    abuse_contact: Optional[str] = None

    @property
    def risk_score(self) -> int:
        """Calculate a simple risk score for this domain."""
        score = 0

        # Domain is registered
        if self.is_registered:
            score += 50

        # Domain has DNS records
        if self.dns_records and any(self.dns_records.values()):
            score += 25

        # Recently registered domain (within last 60 days)
        if isinstance(self.creation_date, datetime) and (datetime.now() - self.creation_date).days < 60:
            score += 15
        elif isinstance(self.creation_date, list) and any((datetime.now() - date).days < 60 for date in self.creation_date if isinstance(date, datetime)):
            score += 15

        # Domain has web server (A records and HTTP/HTTPS records)
        if 'A' in self.dns_records and self.dns_records['A']:
            score += 10

        return min(score, 100)  # Cap at 100


class DomainAnalyzer:
    """
    Analyze domains for potential impersonation threats by checking
    DNS resolution and WHOIS information.
    """

    def __init__(self, max_workers: int = 10, dns_timeout: float = 2.0,
                 whois_timeout: float = 5.0):
        """
        Initialize the domain analyzer.

        Args:
            max_workers: Maximum number of worker threads for concurrent processing
            dns_timeout: Timeout in seconds for DNS queries
            whois_timeout: Timeout in seconds for WHOIS queries
        """
        self.max_workers = max_workers
        self.dns_timeout = dns_timeout
        self.whois_timeout = whois_timeout
        self._resolver = dns.resolver.Resolver()
        self._resolver.timeout = dns_timeout
        self._resolver.lifetime = dns_timeout

    def check_dns_resolution(self, domain: str) -> Dict[str, List[str]]:
        """
        Check DNS resolution for a domain.

        Args:
            domain: The domain to check

        Returns:
            Dictionary with record types as keys and lists of values
        """
        results = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']

        for record_type in record_types:
            try:
                answers = self._resolver.resolve(domain, record_type)
                results[record_type] = [str(answer) for answer in answers]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                results[record_type] = []
            except Exception as e:
                results[record_type] = []

        return results

    def check_basic_resolution(self, domain: str) -> bool:
        """
        Simple check if a domain resolves to an IP address.

        Args:
            domain: The domain to check

        Returns:
            True if the domain resolves, False otherwise
        """
        try:
            socket.getaddrinfo(domain, 80)
            return True
        except socket.gaierror:
            return False

    def get_whois_info(self, domain: str) -> Tuple[bool, Optional[Dict[str, any]], Optional[str]]:
        """
        Get WHOIS information for a domain.

        Args:
            domain: The domain to check

        Returns:
            Tuple containing (is_registered, whois_data, error_message)
        """
        try:
            whois_data = whois.whois(domain)
            if whois_data.status is None:
                return False, None, "Domain not registered"
            return True, whois_data, None
        except Exception as e:
            return False, None, str(e)

    def analyze_domain(self, domain: str) -> DomainAnalysisResult:
        """
        Analyze a single domain for DNS and WHOIS information.

        Args:
            domain: The domain to analyze

        Returns:
            DomainAnalysisResult object with analysis results
        """
        # Initialize result with default values
        result = DomainAnalysisResult(
            domain=domain,
            is_registered=False,
            dns_records={},
            dns_error=None,
            whois_error=None
        )

        # Check DNS resolution
        try:
            result.dns_records = self.check_dns_resolution(domain)
        except Exception as e:
            result.dns_error = str(e)

        # Get WHOIS information
        is_registered, whois_data, whois_error = self.get_whois_info(domain)
        result.is_registered = is_registered
        result.whois_error = whois_error

        # Extract WHOIS details if available
        if whois_data:
            result.creation_date = whois_data.creation_date
            result.registrar = whois_data.registrar
            result.expiration_date = whois_data.expiration_date
            result.name_servers = whois_data.name_servers

            # Some WHOIS records have these fields
            if hasattr(whois_data, 'updated_date'):
                result.last_updated = whois_data.updated_date
            if hasattr(whois_data, 'registrant'):
                result.registrant = whois_data.registrant
            if hasattr(whois_data, 'emails'):
                # Use the first email as a potential abuse contact
                if isinstance(whois_data.emails, list) and whois_data.emails:
                    result.abuse_contact = whois_data.emails[0]
                elif isinstance(whois_data.emails, str):
                    result.abuse_contact = whois_data.emails

        return result

    def analyze_domains(self, domains: List[str]) -> Dict[str, DomainAnalysisResult]:
        """
        Analyze multiple domains concurrently.

        Args:
            domains: List of domains to analyze

        Returns:
            Dictionary mapping domains to their analysis results
        """
        results = {}

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_domain = {executor.submit(self.analyze_domain, domain): domain for domain in domains}

            for future in concurrent.futures.as_completed(future_to_domain):
                domain = future_to_domain[future]
                try:
                    results[domain] = future.result()
                except Exception as exc:
                    # Create a result with the error message
                    results[domain] = DomainAnalysisResult(
                        domain=domain,
                        is_registered=False,
                        dns_records={},
                        dns_error=f"Analysis failed: {str(exc)}"
                    )

        return results

    def identify_high_risk_domains(self, results: Dict[str, DomainAnalysisResult],
                                  threshold: int = 60) -> List[DomainAnalysisResult]:
        """
        Identify high-risk domains based on analysis results.

        Args:
            results: Dictionary of domain analysis results
            threshold: Risk score threshold for high-risk domains (0-100)

        Returns:
            List of high-risk domain results sorted by risk score
        """
        high_risk = [result for result in results.values() if result.risk_score >= threshold]
        return sorted(high_risk, key=lambda x: x.risk_score, reverse=True)

    def generate_report(self, results: Dict[str, DomainAnalysisResult],
                       include_all: bool = False,
                       risk_threshold: int = 60) -> Dict[str, any]:
        """
        Generate a comprehensive report from analysis results.

        Args:
            results: Dictionary of domain analysis results
            include_all: Whether to include all domains in the report
            risk_threshold: Risk score threshold for high-risk domains

        Returns:
            Dictionary containing the analysis report
        """
        for r in results.values():
            print(r.dns_records)
            print(r.risk_score)
        high_risk = self.identify_high_risk_domains(results, risk_threshold)

        # Sort all results by risk score
        all_domains = sorted(results.values(), key=lambda x: x.risk_score, reverse=True)

        # Count domains by status
        registered_count = sum(1 for r in results.values() if r.is_registered)
        active_count = sum(1 for r in results.values()
                          if r.dns_records and any(r.dns_records.values()))

        report = {
            "summary": {
                "total_domains": len(results),
                "registered_domains": registered_count,
                "active_domains": active_count,
                "high_risk_domains": len(high_risk)
            },
            "high_risk_domains": [
                {
                    "domain": r.domain,
                    "risk_score": r.risk_score,
                    "is_registered": r.is_registered,
                    "has_dns_records": bool(r.dns_records and any(r.dns_records.values())),
                    "registrar": r.registrar,
                    "creation_date": r.creation_date,
                }
                for r in high_risk
            ],
        }

        if include_all:
            report["all_domains"] = [
                {
                    "domain": r.domain,
                    "risk_score": r.risk_score,
                    "is_registered": r.is_registered,
                    "has_dns_records": bool(r.dns_records and any(r.dns_records.values())),
                }
                for r in all_domains
            ]

        return report
