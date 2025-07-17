#!/usr/bin/env python
from setuptools import setup, find_packages

setup(
    name="surin",
    version="1.0.0",
    description="Subdomain Utility for Rapid Identification and Naming",
    author="SURIN Team",
    packages=find_packages(),
    install_requires=[
        "dnspython",
        "requests",
        "tqdm",
    ],
    entry_points={
        "console_scripts": [
            "surin=surin.cli:main",
        ],
    },
    python_requires=">=3.9",
)