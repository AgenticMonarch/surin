"""
Unit tests for exception handling.
"""
import pytest

from surin.core.exceptions import (
    SurinError, ValidationError, NetworkError, 
    APIError, ConfigurationError, DiscoveryError
)


class TestExceptions:
    """Test exception classes."""

    def test_surin_error(self):
        """Test SurinError base exception."""
        error = SurinError("Base error")
        assert str(error) == "Base error"
        assert isinstance(error, Exception)

    def test_validation_error(self):
        """Test ValidationError exception."""
        error = ValidationError("Invalid input")
        assert str(error) == "Invalid input"
        assert isinstance(error, SurinError)
        assert isinstance(error, Exception)

    def test_network_error(self):
        """Test NetworkError exception."""
        error = NetworkError("Connection failed")
        assert str(error) == "Connection failed"
        assert isinstance(error, SurinError)
        assert isinstance(error, Exception)

    def test_api_error(self):
        """Test APIError exception."""
        error = APIError("API request failed")
        assert str(error) == "API request failed"
        assert isinstance(error, SurinError)
        assert isinstance(error, Exception)

    def test_configuration_error(self):
        """Test ConfigurationError exception."""
        error = ConfigurationError("Invalid configuration")
        assert str(error) == "Invalid configuration"
        assert isinstance(error, SurinError)
        assert isinstance(error, Exception)

    def test_discovery_error(self):
        """Test DiscoveryError exception."""
        error = DiscoveryError("Discovery failed")
        assert str(error) == "Discovery failed"
        assert isinstance(error, SurinError)
        assert isinstance(error, Exception)

    def test_exception_with_cause(self):
        """Test exception with a cause."""
        cause = ValueError("Original error")
        try:
            raise NetworkError("Connection failed") from cause
        except NetworkError as error:
            assert str(error) == "Connection failed"
            assert error.__cause__ == cause