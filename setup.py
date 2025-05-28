#!/usr/bin/env python3
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="domain-impersonation-checker",
    version="0.1.0",
    author="Domain Impersonation Checker Team",
    author_email="user@example.com",
    description="A tool to identify potential domain impersonation threats",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/username/domain-impersonation-checker",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Internet",
        "Topic :: Security",
    ],
    python_requires=">=3.7",
    install_requires=[
        "dnspython>=2.0.0",
        "python-whois>=0.7.3",
    ],
    entry_points={
        "console_scripts": [
            "domaincheck=domaincheck.cli:main",
        ],
    },
)