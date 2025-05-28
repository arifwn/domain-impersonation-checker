#!/usr/bin/env python3
"""
Test runner for Domain Impersonation Checker.

This script discovers and runs all tests for the domain impersonation checker.
"""

import unittest
import sys
import os
import argparse


def run_tests(test_path=None, verbosity=1, pattern="test_*.py"):
    """
    Discover and run tests.
    
    Args:
        test_path: Path to the test directory or specific test module
        verbosity: Verbosity level for test output
        pattern: Pattern to match test files
    
    Returns:
        True if all tests pass, False otherwise
    """
    # Determine test directory
    if test_path is None:
        # Default to tests directory
        test_path = os.path.join(os.path.dirname(__file__), "tests")
    
    # Create test suite
    print(f"Discovering tests in {test_path} matching pattern '{pattern}'...")
    
    try:
        loader = unittest.TestLoader()
        
        if os.path.isfile(test_path):
            # If a specific file is provided, load it directly
            suite = loader.discover(os.path.dirname(test_path), pattern=os.path.basename(test_path))
        else:
            # Otherwise discover all tests
            suite = loader.discover(test_path, pattern=pattern)
        
        # Count tests
        test_count = suite.countTestCases()
        print(f"Found {test_count} tests.")
        
        # Run tests
        print("\nRunning tests:")
        print("=" * 70)
        
        runner = unittest.TextTestRunner(verbosity=verbosity)
        result = runner.run(suite)
        
        # Print summary
        print("\nTest Summary:")
        print("-" * 70)
        print(f"Ran {result.testsRun} tests")
        print(f"Failures: {len(result.failures)}")
        print(f"Errors: {len(result.errors)}")
        print(f"Skipped: {len(result.skipped)}")
        
        # Return True if tests were successful
        return result.wasSuccessful()
    except Exception as e:
        print(f"Error running tests: {e}")
        return False


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Run tests for Domain Impersonation Checker")
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    parser.add_argument(
        "-p", "--pattern",
        default="test_*.py",
        help="Pattern to match test files (default: test_*.py)"
    )
    
    parser.add_argument(
        "test_path",
        nargs="?",
        default=None,
        help="Path to test directory or specific test module"
    )
    
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    
    verbosity = 2 if args.verbose else 1
    success = run_tests(args.test_path, verbosity, args.pattern)
    
    sys.exit(0 if success else 1)