"""
Command-line interface for the Domain Impersonation Checker.

This module provides a command-line interface for generating and analyzing
domain name variations to identify potential impersonation threats.
"""

import argparse
import json
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Any

from . import __version__
from .generator import DomainVariationGenerator
from .analyzer import DomainAnalyzer, DomainAnalysisResult


def create_parser() -> argparse.ArgumentParser:
    """Create and return the argument parser for the CLI."""
    parser = argparse.ArgumentParser(
        description="Domain Impersonation Checker - Identify potential domain impersonation threats",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument(
        "domain",
        help="Domain to check for potential impersonation (e.g., example.com)"
    )
    
    parser.add_argument(
        "-o", "--output",
        help="Output file path for the results (JSON format)"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version=f"Domain Impersonation Checker v{__version__}"
    )
    
    # Variation generation options
    variation_group = parser.add_argument_group("Variation Generation Options")
    
    variation_group.add_argument(
        "--no-typos",
        action="store_true",
        help="Disable typosquatting variation generation"
    )
    
    variation_group.add_argument(
        "--no-homoglyphs",
        action="store_true",
        help="Disable homoglyph variation generation"
    )
    
    variation_group.add_argument(
        "--no-tlds",
        action="store_true",
        help="Disable TLD variation generation"
    )
    
    variation_group.add_argument(
        "--max-variations",
        type=int,
        default=1000,
        help="Maximum number of variations to generate per category"
    )
    
    # Analysis options
    analysis_group = parser.add_argument_group("Analysis Options")
    
    analysis_group.add_argument(
        "--no-dns",
        action="store_true",
        help="Skip DNS resolution checking"
    )
    
    analysis_group.add_argument(
        "--no-whois",
        action="store_true",
        help="Skip WHOIS lookups"
    )
    
    analysis_group.add_argument(
        "--concurrency",
        type=int,
        default=10,
        help="Maximum number of concurrent domain checks"
    )
    
    analysis_group.add_argument(
        "--dns-timeout",
        type=float,
        default=2.0,
        help="Timeout in seconds for DNS queries"
    )
    
    analysis_group.add_argument(
        "--whois-timeout",
        type=float,
        default=5.0,
        help="Timeout in seconds for WHOIS queries"
    )
    
    analysis_group.add_argument(
        "--min-risk-score",
        type=int,
        default=60,
        help="Minimum risk score (0-100) to consider a domain high-risk"
    )
    
    # Display options
    display_group = parser.add_argument_group("Display Options")
    
    display_group.add_argument(
        "--show-all",
        action="store_true",
        help="Show all domains in the report, not just high-risk ones"
    )
    
    display_group.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format"
    )
    
    return parser


def generate_variations(domain: str, args: argparse.Namespace) -> Dict[str, List[str]]:
    """
    Generate domain variations based on command-line arguments.
    
    Args:
        domain: The domain to generate variations for
        args: Command-line arguments
        
    Returns:
        Dictionary mapping variation types to lists of domain variations
    """
    if args.verbose:
        print(f"Generating variations for {domain}...")
    
    generator = DomainVariationGenerator(max_variations=args.max_variations)
    
    variations = generator.generate_all_variations(
        domain,
        include_typos=not args.no_typos,
        include_homoglyphs=not args.no_homoglyphs,
        include_tlds=not args.no_tlds
    )
    
    if args.verbose:
        for var_type, var_list in variations.items():
            print(f"Generated {len(var_list)} {var_type} variations")
    
    return variations


def analyze_domains(variations: Dict[str, List[str]], args: argparse.Namespace) -> Dict[str, DomainAnalysisResult]:
    """
    Analyze domain variations for potential impersonation threats.
    
    Args:
        variations: Dictionary of domain variations by type
        args: Command-line arguments
        
    Returns:
        Dictionary mapping domains to their analysis results
    """
    # Flatten all variations into a single list
    all_domains = set()
    for var_list in variations.values():
        all_domains.update(var_list)
    
    total_domains = len(all_domains)
    
    if args.verbose:
        print(f"Analyzing {total_domains} unique domain variations...")
    
    if args.no_dns and args.no_whois:
        print("Warning: Both DNS and WHOIS checks are disabled. No analysis will be performed.")
        return {}
    
    try:
        analyzer = DomainAnalyzer(
            max_workers=args.concurrency,
            dns_timeout=args.dns_timeout,
            whois_timeout=args.whois_timeout
        )
    except ImportError as e:
        print(f"Error: {e}")
        print("Please install the required dependencies and try again.")
        sys.exit(1)
    
    domains_list = list(all_domains)
    results = {}
    
    # Simple progress indicator
    if args.verbose:
        start_time = time.time()
        print("Analysis progress:")
    
    batch_size = min(100, args.concurrency * 10)
    for i in range(0, len(domains_list), batch_size):
        batch = domains_list[i:i+batch_size]
        batch_results = analyzer.analyze_domains(batch)
        results.update(batch_results)
        
        if args.verbose:
            progress = min(100, int((i + len(batch)) / total_domains * 100))
            elapsed = time.time() - start_time
            domains_per_second = (i + len(batch)) / elapsed if elapsed > 0 else 0
            remaining = (total_domains - (i + len(batch))) / domains_per_second if domains_per_second > 0 else 0
            print(f"Progress: {progress}% ({i + len(batch)}/{total_domains}) - "
                  f"~{remaining:.1f}s remaining ({domains_per_second:.1f} domains/s)")
    
    if args.verbose:
        print(f"Analysis completed in {time.time() - start_time:.1f} seconds")
    
    return results


def format_text_report(report: Dict[str, Any], args: argparse.Namespace) -> str:
    """
    Format the analysis report as text.
    
    Args:
        report: The analysis report dictionary
        args: Command-line arguments
        
    Returns:
        Formatted text report
    """
    summary = report["summary"]
    high_risk = report["high_risk_domains"]
    
    lines = [
        "Domain Impersonation Checker - Analysis Report",
        "=" * 50,
        f"Target domain: {args.domain}",
        f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "Summary:",
        f"  Total variations analyzed: {summary['total_domains']}",
        f"  Registered domains: {summary['registered_domains']}",
        f"  Active domains (with DNS records): {summary['active_domains']}",
        f"  High-risk domains: {summary['high_risk_domains']}",
        "",
    ]
    
    if high_risk:
        lines.append("High Risk Domains:")
        lines.append("-" * 50)
        for domain in high_risk:
            creation_date = domain.get("creation_date")
            if isinstance(creation_date, list) and creation_date:
                creation_date = creation_date[0]
            
            date_str = ""
            if creation_date:
                try:
                    if isinstance(creation_date, str):
                        date_str = creation_date
                    else:
                        date_str = creation_date.strftime("%Y-%m-%d")
                except:
                    date_str = str(creation_date)
            
            lines.append(f"Domain: {domain['domain']}")
            lines.append(f"  Risk Score: {domain['risk_score']}/100")
            lines.append(f"  Registered: {'Yes' if domain['is_registered'] else 'No'}")
            lines.append(f"  Active DNS: {'Yes' if domain['has_dns_records'] else 'No'}")
            if domain.get("registrar"):
                lines.append(f"  Registrar: {domain['registrar']}")
            if date_str:
                lines.append(f"  Creation Date: {date_str}")
            lines.append("")
    else:
        lines.append("No high-risk domains identified.")
    
    if args.show_all and "all_domains" in report:
        lines.append("")
        lines.append("All Analyzed Domains:")
        lines.append("-" * 50)
        for domain in report["all_domains"]:
            lines.append(f"{domain['domain']} - Risk: {domain['risk_score']}/100 - "
                        f"Registered: {'Yes' if domain['is_registered'] else 'No'} - "
                        f"Active DNS: {'Yes' if domain['has_dns_records'] else 'No'}")
    
    return "\n".join(lines)


def save_report(report: Dict[str, Any], output_path: str, format_type: str) -> None:
    """
    Save the report to a file.
    
    Args:
        report: The analysis report dictionary
        output_path: Path to save the report to
        format_type: Format type ('json' or 'text')
    """
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            if format_type == "json":
                # Convert datetime objects to strings for JSON serialization
                json_report = json.dumps(report, default=str, indent=2)
                f.write(json_report)
            else:
                # For text format, we need to generate the text report
                text_report = format_text_report(report, args)
                f.write(text_report)
        print(f"Report saved to {output_path}")
    except Exception as e:
        print(f"Error saving report: {e}")


def main() -> int:
    """
    Main entry point for the CLI.
    
    Returns:
        Exit code (0 for success, non-zero for errors)
    """
    parser = create_parser()
    args = parser.parse_args()
    
    try:
        # Generate domain variations
        variations = generate_variations(args.domain, args)
        
        # Count total variations
        total_variations = sum(len(var_list) for var_list in variations.values())
        if total_variations == 0:
            print("No domain variations were generated. Check your configuration.")
            return 1
        
        # Analyze domains
        results = analyze_domains(variations, args)
        
        # Generate report
        if args.verbose:
            print("Generating report...")
        
        analyzer = DomainAnalyzer()
        report = analyzer.generate_report(
            results,
            include_all=args.show_all,
            risk_threshold=args.min_risk_score
        )
        
        # Output report
        if args.format == "json":
            if args.output:
                save_report(report, args.output, "json")
            else:
                print(json.dumps(report, default=str, indent=2))
        else:
            text_report = format_text_report(report, args)
            if args.output:
                save_report({"text_report": text_report}, args.output, "text")
            else:
                print(text_report)
        
        return 0
    
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        return 130
    except Exception as e:
        print(f"Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())