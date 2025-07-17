"""
Pytest configuration file for SURIN tests.
"""
import os
import sys
import pytest

# Add the parent directory to sys.path to allow importing surin
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Common fixtures for tests
@pytest.fixture
def sample_domain():
    """Return a sample domain for testing."""
    return "example.com"

@pytest.fixture
def sample_subdomains():
    """Return a list of sample subdomains for testing."""
    return [
        "www.example.com",
        "api.example.com",
        "mail.example.com",
        "blog.example.com",
        "dev.example.com"
    ]

@pytest.fixture
def mock_dns_response():
    """Return a mock DNS response."""
    return {
        "www.example.com": "93.184.216.34",
        "api.example.com": "93.184.216.34",
        "mail.example.com": "93.184.216.34",
        "blog.example.com": "93.184.216.34",
        "dev.example.com": None  # Simulating no resolution
    }

@pytest.fixture
def mock_ct_response():
    """Return a mock Certificate Transparency response."""
    return {
        "www.example.com": True,
        "api.example.com": True,
        "secure.example.com": True,
        "login.example.com": True
    }

@pytest.fixture
def mock_api_response():
    """Return a mock API response for threat intelligence services."""
    return {
        "subdomains": [
            "www.example.com",
            "api.example.com",
            "cdn.example.com",
            "static.example.com"
        ]
    }