#!/usr/bin/env python3
"""
Domain Impersonation Checker

A Python CLI tool to identify potential domain impersonation threats
by generating and analyzing domain name variations.
"""

import sys
from domaincheck.cli import main

if __name__ == "__main__":
    sys.exit(main())