"""
Domain name variation generator module.

This module provides functionality to generate various permutations of domain names
that could be used for impersonation attacks.
"""

import itertools
import re
from typing import List, Dict, Set, Generator, Tuple


class DomainVariationGenerator:
    """Generate domain name variations for potential impersonation detection."""

    # Common TLDs that might be used for impersonation
    COMMON_TLDS = [
        "com", "org", "net", "io", "co", "info", "biz", "xyz",
        "online", "site", "website", "app", "dev", "tech"
    ]

    # Homoglyphs mapping - characters that look similar
    HOMOGLYPHS = {
        'a': ['а', '4', '@'],  # Latin 'a' to Cyrillic 'а', '4', '@'
        'b': ['6', '8', 'ʙ'],
        'c': ['ϲ', '¢', '©'],
        'd': ['ԁ', 'ɗ'],
        'e': ['е', '3'],  # Latin 'e' to Cyrillic 'е', '3'
        'g': ['ɡ', '9', 'ƍ'],
        'h': ['һ', 'н'],
        'i': ['і', '1', '!', '|'],  # Latin 'i' to Cyrillic 'і', '1', '!', '|'
        'j': ['ј'],
        'k': ['к', 'ҝ'],
        'l': ['1', '|', 'ӏ'],
        'm': ['m', 'ṃ'],
        'n': ['n', 'ո', 'ռ'],
        'o': ['0', 'о', 'ο'],  # Latin 'o' to Cyrillic 'о', Greek 'ο', '0'
        'p': ['р', 'ρ'],  # Latin 'p' to Cyrillic 'р', Greek 'ρ'
        'q': ['q', 'ԛ'],
        'r': ['г', 'ᴦ'],
        's': ['ѕ', '$', '5'],
        't': ['т', 'τ'],
        'u': ['υ', 'ս'],
        'v': ['ν', 'v'],
        'w': ['ԝ', 'ѡ', 'ԝ'],
        'x': ['х', '×'],  # Latin 'x' to Cyrillic 'х', '×'
        'y': ['у', 'ʏ'],  # Latin 'y' to Cyrillic 'у', 'ʏ'
        'z': ['z', 'ᴢ']
    }

    # Adjacent keys on a QWERTY keyboard for typo simulation
    ADJACENT_KEYS = {
        'a': ['q', 'w', 's', 'z'],
        'b': ['v', 'g', 'h', 'n'],
        'c': ['x', 'd', 'f', 'v'],
        'd': ['s', 'e', 'r', 'f', 'c', 'x'],
        'e': ['w', 's', 'd', 'r'],
        'f': ['d', 'r', 't', 'g', 'v', 'c'],
        'g': ['f', 't', 'y', 'h', 'b', 'v'],
        'h': ['g', 'y', 'u', 'j', 'n', 'b'],
        'i': ['u', 'j', 'k', 'o'],
        'j': ['h', 'u', 'i', 'k', 'm', 'n'],
        'k': ['j', 'i', 'o', 'l', 'm'],
        'l': ['k', 'o', 'p', ';'],
        'm': ['n', 'j', 'k', ','],
        'n': ['b', 'h', 'j', 'm'],
        'o': ['i', 'k', 'l', 'p'],
        'p': ['o', 'l', '[', ';'],
        'q': ['1', '2', 'w', 'a'],
        'r': ['e', 'd', 'f', 't'],
        's': ['a', 'w', 'e', 'd', 'x', 'z'],
        't': ['r', 'f', 'g', 'y'],
        'u': ['y', 'h', 'j', 'i'],
        'v': ['c', 'f', 'g', 'b'],
        'w': ['q', 'a', 's', 'e', '2', '3'],
        'x': ['z', 's', 'd', 'c'],
        'y': ['t', 'g', 'h', 'u'],
        'z': ['a', 's', 'x']
    }

    def __init__(self, max_variations: int = 1000):
        """
        Initialize the domain variation generator.

        Args:
            max_variations: Maximum number of variations to generate per category
                            to prevent excessive resource usage
        """
        self.max_variations = max_variations

    def parse_domain(self, domain: str) -> Tuple[str, str]:
        """
        Parse a domain into name and TLD parts.

        Args:
            domain: The domain to parse (e.g., 'example.com')

        Returns:
            Tuple containing (domain_name, tld)
        """
        # Extract the domain and TLD parts
        parts = domain.lower().strip().split('.')
        if len(parts) < 2:
            # If no TLD provided, assume it's just a name
            return parts[0], ""

        tld = parts[-1]
        name = '.'.join(parts[:-1])
        return name, tld

    def generate_typosquatting_variations(self, domain: str) -> List[str]:
        """
        Generate typosquatting variations of the given domain.

        Args:
            domain: The domain to generate variations for

        Returns:
            List of domain variations
        """
        domain_name, tld = self.parse_domain(domain)
        variations = set()

        # Add variations with original TLD
        tld_suffix = f".{tld}" if tld else ""

        # 1. Character swaps (transposition)
        for i in range(len(domain_name) - 1):
            swapped = domain_name[:i] + domain_name[i+1] + domain_name[i] + domain_name[i+2:]
            domain_variant = swapped + tld_suffix
            if domain != domain_variant:
                variations.add(domain_variant)

        # 2. Character deletion
        for i in range(len(domain_name)):
            deleted = domain_name[:i] + domain_name[i+1:]
            if deleted:  # Ensure we don't add empty domain names
                domain_variant = deleted + tld_suffix
                if domain != domain_variant:
                    variations.add(domain_variant)

        # 3. Character insertion (simulate common typos)
        for i in range(len(domain_name) + 1):
            for char in "abcdefghijklmnopqrstuvwxyz0123456789-":
                inserted = domain_name[:i] + char + domain_name[i:]
                domain_variant = inserted + tld_suffix
                if domain != domain_variant:
                    variations.add(domain_variant)

        # 4. Character replacement (adjacent keys)
        for i, char in enumerate(domain_name):
            if char.lower() in self.ADJACENT_KEYS:
                for adjacent in self.ADJACENT_KEYS[char.lower()]:
                    replaced = domain_name[:i] + adjacent + domain_name[i+1:]
                    domain_variant = replaced + tld_suffix
                    if domain != domain_variant:
                        variations.add(domain_variant)

        # 5. Double character (repetition)
        for i, char in enumerate(domain_name):
            doubled = domain_name[:i] + char + domain_name[i:]
            domain_variant = doubled + tld_suffix
            if domain != domain_variant:
                variations.add(domain_variant)

        # 6. Missing dot in subdomain
        if '.' in domain_name:
            nodot = domain_name.replace('.', '')
            domain_variant = nodot + tld_suffix
            if domain != domain_variant:
                variations.add(domain_variant)

        return list(variations)[:self.max_variations]

    def generate_homoglyph_variations(self, domain: str) -> List[str]:
        """
        Generate homoglyph variations of the domain.

        Args:
            domain: The domain to generate variations for

        Returns:
            List of domain variations using similar-looking characters
        """
        domain_name, tld = self.parse_domain(domain)
        variations = set()

        tld_suffix = f".{tld}" if tld else ""

        # Find all possible homoglyph substitutions
        indices = [i for i, char in enumerate(domain_name.lower())
                  if char in self.HOMOGLYPHS]

        # Generate all combinations of substitutions up to a reasonable limit
        for r in range(1, min(len(indices) + 1, 4)):  # Limit to 3 substitutions at once
            for combo in itertools.combinations(indices, r):
                for replacements in itertools.product(*[self.HOMOGLYPHS[domain_name[i].lower()] for i in combo]):
                    new_domain = list(domain_name)
                    for idx, replacement in zip(combo, replacements):
                        new_domain[idx] = replacement
                    variations.add(''.join(new_domain) + tld_suffix)

                    if len(variations) >= self.max_variations:
                        return list(variations)

        return list(variations)

    def generate_tld_variations(self, domain: str) -> List[str]:
        """
        Generate TLD variations of the domain.

        Args:
            domain: The domain to generate variations for

        Returns:
            List of domain variations with different TLDs
        """
        domain_name, tld = self.parse_domain(domain)
        variations = set()

        # Generate variations with different TLDs
        for new_tld in self.COMMON_TLDS:
            if new_tld != tld:  # Skip the original TLD
                variations.add(f"{domain_name}.{new_tld}")

        return list(variations)

    def generate_all_variations(self, domain: str, include_typos: bool = True,
                               include_homoglyphs: bool = True,
                               include_tlds: bool = True) -> Dict[str, List[str]]:
        """
        Generate all types of domain variations.

        Args:
            domain: The domain to generate variations for
            include_typos: Whether to include typosquatting variations
            include_homoglyphs: Whether to include homoglyph variations
            include_tlds: Whether to include TLD variations

        Returns:
            Dictionary with variation types as keys and lists of variations as values
        """
        results = {}

        if include_typos:
            results['typosquatting'] = self.generate_typosquatting_variations(domain)

        if include_homoglyphs:
            results['homoglyphs'] = self.generate_homoglyph_variations(domain)

        if include_tlds:
            results['tld_variations'] = self.generate_tld_variations(domain)

        return results
