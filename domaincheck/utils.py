"""
Utility functions for the Domain Impersonation Checker.

This module provides helper functions used across the application.
"""

import re
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional, Union


def is_valid_domain(domain: str) -> bool:
    """
    Check if a string is a valid domain name.
    
    Args:
        domain: The domain name to validate
        
    Returns:
        True if the domain is valid, False otherwise
    """
    # Domain validation regex
    # Allows for IDNs and subdomains, with TLDs between 2-63 chars
    pattern = r'^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,63}$'
    return bool(re.match(pattern, domain))


def normalize_domain(domain: str) -> str:
    """
    Normalize a domain name by removing whitespace and converting to lowercase.
    
    Args:
        domain: The domain name to normalize
        
    Returns:
        Normalized domain name
    """
    return domain.strip().lower()


def format_datetime(dt: Optional[Union[datetime, List[datetime], str]]) -> str:
    """
    Format a datetime object or list of datetime objects as a string.
    
    Args:
        dt: Datetime object, list of datetime objects, or string
        
    Returns:
        Formatted datetime string
    """
    if dt is None:
        return "Unknown"
    
    if isinstance(dt, list):
        if not dt:
            return "Unknown"
        # Use the first datetime in the list
        dt = dt[0]
    
    if isinstance(dt, str):
        return dt
    
    try:
        return dt.strftime("%Y-%m-%d")
    except (AttributeError, ValueError):
        return str(dt)


def truncate_string(s: str, max_length: int = 80) -> str:
    """
    Truncate a string to a maximum length.
    
    Args:
        s: The string to truncate
        max_length: Maximum length of the truncated string
        
    Returns:
        Truncated string with ellipsis if necessary
    """
    if len(s) <= max_length:
        return s
    return s[:max_length-3] + "..."


def print_progress(current: int, total: int, prefix: str = "", suffix: str = "", 
                  bar_length: int = 40, fill_char: str = "█") -> None:
    """
    Print a progress bar to the console.
    
    Args:
        current: Current progress value
        total: Total progress value
        prefix: Prefix string
        suffix: Suffix string
        bar_length: Length of the progress bar
        fill_char: Character to use for the progress bar
    """
    percent = float(current) / total if total > 0 else 0
    filled_length = int(bar_length * percent)
    bar = fill_char * filled_length + "-" * (bar_length - filled_length)
    sys.stdout.write(f"\r{prefix} |{bar}| {percent:.1%} {suffix}")
    sys.stdout.flush()
    if current >= total:
        sys.stdout.write("\n")
        sys.stdout.flush()


def dict_to_table(data: List[Dict[str, Any]], columns: List[str]) -> List[str]:
    """
    Convert a list of dictionaries to a formatted text table.
    
    Args:
        data: List of dictionaries containing the data
        columns: List of column keys to include in the table
        
    Returns:
        List of strings representing the formatted table
    """
    if not data or not columns:
        return []
    
    # Get column widths
    widths = {col: len(col) for col in columns}
    for row in data:
        for col in columns:
            if col in row:
                widths[col] = max(widths[col], len(str(row[col])))
    
    # Create header
    header = " | ".join(col.ljust(widths[col]) for col in columns)
    separator = "-+-".join("-" * widths[col] for col in columns)
    
    # Create rows
    rows = []
    for row in data:
        formatted_row = " | ".join(
            str(row.get(col, "")).ljust(widths[col]) for col in columns
        )
        rows.append(formatted_row)
    
    return [header, separator] + rows


def format_risk_level(score: int) -> str:
    """
    Format a risk score as a human-readable risk level.
    
    Args:
        score: Risk score (0-100)
        
    Returns:
        Risk level string
    """
    if score >= 80:
        return "Critical"
    elif score >= 60:
        return "High"
    elif score >= 40:
        return "Medium"
    elif score >= 20:
        return "Low"
    else:
        return "Minimal"


def group_domains_by_type(
    domains: List[str], variations: Dict[str, List[str]]
) -> Dict[str, List[str]]:
    """
    Group a list of domains by their variation type.
    
    Args:
        domains: List of domain names
        variations: Dictionary mapping variation types to lists of domains
        
    Returns:
        Dictionary mapping variation types to the domains in the input list
    """
    result = {}
    # Create a mapping of domain to type for quick lookup
    domain_to_type = {}
    for var_type, var_list in variations.items():
        for domain in var_list:
            domain_to_type[domain] = var_type
    
    # Group the domains by type
    for domain in domains:
        var_type = domain_to_type.get(domain, "unknown")
        if var_type not in result:
            result[var_type] = []
        result[var_type].append(domain)
    
    return result