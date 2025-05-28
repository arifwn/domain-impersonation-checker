# Domain Impersonation Checker

A Python CLI tool to identify potential domain impersonation threats by generating and analyzing domain name variations.

## Features

- Generates typosquatting variations (character swaps, insertions, deletions, etc.)
- Generates homoglyph variations (similar-looking characters)
- Generates TLD variations (same name with different top-level domains)
- Optional DNS resolution checking to identify active domains
- Optional WHOIS lookup to identify domain registration information
- Risk scoring to prioritize potential threats
- Comprehensive reporting in both text and JSON formats

## Installation

### From PyPI (Recommended)

```bash
pip install domain-impersonation-checker
```

### From Source

```bash
git clone https://github.com/username/domain-impersonation-checker.git
cd domain-impersonation-checker
pip install -e .
```

### Requirements

- Python 3.7 or higher
- Required dependencies:
  - dnspython
  - python-whois

## Usage

### Basic Usage

```bash
domaincheck example.com
```

### Command-line Options

```bash
# Show help
domaincheck --help

# Enable verbose output
domaincheck example.com --verbose

# Save results to a file (JSON format)
domaincheck example.com --output results.json

# Use specific variation types only
domaincheck example.com --no-typos --no-tlds  # Only use homoglyphs

# Skip DNS or WHOIS lookups
domaincheck example.com --no-dns
domaincheck example.com --no-whois

# Change risk threshold (default is 60)
domaincheck example.com --min-risk-score 40

# Show all domains in the report
domaincheck example.com --show-all
```

### Example Output

```
Domain Impersonation Checker - Analysis Report
==================================================
Target domain: example.com
Generated on: 2023-06-15 14:30:22

Summary:
  Total variations analyzed: 213
  Registered domains: 42
  Active domains (with DNS records): 37
  High-risk domains: 8

High Risk Domains:
--------------------------------------------------
Domain: examp1e.com
  Risk Score: 95/100
  Registered: Yes
  Active DNS: Yes
  Registrar: Some Registrar Inc.
  Creation Date: 2023-01-15

Domain: exampl3.com
  Risk Score: 85/100
  Registered: Yes
  Active DNS: Yes
  Registrar: Another Registrar LLC
  Creation Date: 2023-02-28

...
```

## How It Works

1. **Domain Variation Generation**:
   - Typosquatting: Creates variations by swapping, inserting, deleting, or replacing characters
   - Homoglyphs: Substitutes characters with similar-looking ones (e.g., 'o' → '0')
   - TLD Variations: Changes the top-level domain (e.g., .com → .org)

2. **Analysis**:
   - DNS Resolution: Checks if domains resolve to IP addresses
   - WHOIS Lookup: Retrieves registration information
   - Risk Scoring: Calculates a risk score based on multiple factors

3. **Reporting**:
   - Identifies high-risk domains
   - Provides summary statistics
   - Offers detailed information about concerning domains

## Use Cases

- Security audits for brand protection
- Phishing campaign detection and prevention
- Domain monitoring for trademark enforcement
- Security awareness training examples

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Testing

The project includes a comprehensive test suite to ensure functionality and reliability.

### Running Tests

You can run the tests using the provided test runner script:

```bash
# Run all tests
python run_tests.py

# Run tests with verbose output
python run_tests.py --verbose

# Run a specific test file
python run_tests.py tests/test_generator.py
```

Alternatively, you can use pytest:

```bash
# Install pytest if not already installed
pip install pytest

# Run all tests
pytest

# Run with verbose output
pytest -v

# Run a specific test file
pytest tests/test_generator.py
```

### Test Structure

The test suite includes:

- **Unit Tests**: Tests for individual components (generator, analyzer, utils)
- **Integration Tests**: Tests for component interactions
- **CLI Tests**: Tests for command-line interface functionality

### Test Coverage

To generate a test coverage report:

```bash
# Install coverage tool
pip install pytest-cov

# Run tests with coverage
pytest --cov=domaincheck tests/

# Generate HTML report
pytest --cov=domaincheck --cov-report=html tests/
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.
