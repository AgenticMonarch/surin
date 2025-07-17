"""
Unit tests for Certificate Transparency module.
"""
import pytest
from unittest.mock import patch, MagicMock
import json

from surin.discovery.certificate_transparency import CertificateTransparencyModule
from surin.core.exceptions import APIError


class TestCertificateTransparencyModule:
    """Test Certificate Transparency module."""

    def test_init(self):
        """Test module initialization."""
        module = CertificateTransparencyModule("example.com", timeout=15, show_progress=False)
        
        assert module.domain == "example.com"
        assert module.timeout == 15
        assert module.show_progress is False
        assert module.crt_sh_url == "https://crt.sh/"

    @patch('surin.utils.http_utils.HTTPUtils.make_request')
    def test_discover_success(self, mock_request):
        """Test successful subdomain discovery."""
        # Setup mock response
        mock_response = MagicMock()
        mock_response.json.return_value = [
            {"name_value": "www.example.com\napi.example.com"},
            {"name_value": "*.dev.example.com\nsecure.example.com"},
            {"name_value": "example.com"},  # Should be filtered out
            {"name_value": "test.other.com"}  # Should be filtered out
        ]
        mock_request.return_value = mock_response
        
        # Test
        module = CertificateTransparencyModule("example.com", show_progress=False)
        result = module.discover()
        
        # Verify
        assert len(result) == 3
        assert "www.example.com" in result
        assert "api.example.com" in result
        assert "secure.example.com" in result
        assert "dev.example.com" in result  # Extracted from wildcard
        assert "example.com" not in result  # Base domain filtered out
        assert "test.other.com" not in result  # Different domain filtered out
        
        # Verify API call
        mock_request.assert_called_once_with(
            url="https://crt.sh/",
            method="GET",
            params={"q": "%.example.com", "output": "json"}
        )

    @patch('surin.utils.http_utils.HTTPUtils.make_request')
    def test_discover_json_error(self, mock_request):
        """Test error handling for JSON parsing errors."""
        # Setup mock response
        mock_response = MagicMock()
        mock_response.json.side_effect = json.JSONDecodeError("Invalid JSON", "", 0)
        mock_request.return_value = mock_response
        
        # Test
        module = CertificateTransparencyModule("example.com", show_progress=False)
        with pytest.raises(APIError) as excinfo:
            module.discover()
        
        # Verify
        assert "Failed to parse crt.sh response" in str(excinfo.value)

    @patch('surin.utils.http_utils.HTTPUtils.make_request')
    def test_discover_network_error(self, mock_request):
        """Test error handling for network errors."""
        # Setup mock
        from surin.core.exceptions import NetworkError
        mock_request.side_effect = NetworkError("Connection failed")
        
        # Test
        module = CertificateTransparencyModule("example.com", show_progress=False)
        with pytest.raises(APIError) as excinfo:
            module.discover()
        
        # Verify
        assert "Network error querying crt.sh" in str(excinfo.value)

    def test_extract_subdomains_from_cert(self):
        """Test subdomain extraction from certificate data."""
        module = CertificateTransparencyModule("example.com")
        
        # Test with multiple subdomains
        name_value = "www.example.com\napi.example.com\ndev.example.com"
        result = module._extract_subdomains_from_cert(name_value)
        assert len(result) == 3
        assert "www.example.com" in result
        assert "api.example.com" in result
        assert "dev.example.com" in result
        
        # Test with wildcard
        name_value = "*.dev.example.com\n*.prod.example.com"
        result = module._extract_subdomains_from_cert(name_value)
        assert len(result) == 2
        assert "dev.example.com" in result
        assert "prod.example.com" in result
        
        # Test with base domain (should be filtered)
        name_value = "example.com"
        result = module._extract_subdomains_from_cert(name_value)
        assert len(result) == 0
        
        # Test with different domain (should be filtered)
        name_value = "test.other.com"
        result = module._extract_subdomains_from_cert(name_value)
        assert len(result) == 0
        
        # Test with empty input
        result = module._extract_subdomains_from_cert("")
        assert len(result) == 0
        result = module._extract_subdomains_from_cert(None)
        assert len(result) == 0

    def test_is_valid_subdomain(self):
        """Test subdomain validation."""
        module = CertificateTransparencyModule("example.com")
        
        # Valid subdomains
        assert module._is_valid_subdomain("www.example.com") is True
        assert module._is_valid_subdomain("sub.domain.example.com") is True
        assert module._is_valid_subdomain("sub-domain.example.com") is True
        
        # Invalid subdomains
        assert module._is_valid_subdomain("example.com") is False  # Base domain
        assert module._is_valid_subdomain("test.other.com") is False  # Different domain
        assert module._is_valid_subdomain("") is False  # Empty
        assert module._is_valid_subdomain("a" * 300 + ".example.com") is False  # Too long
        assert module._is_valid_subdomain(".example.com") is False  # Invalid format
        assert module._is_valid_subdomain("sub..example.com") is False  # Invalid format

    @patch('surin.utils.http_utils.HTTPUtils.make_request')
    def test_validate_success(self, mock_request):
        """Test successful validation."""
        # Setup mock
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response
        
        # Test
        module = CertificateTransparencyModule("example.com")
        result = module.validate()
        
        # Verify
        assert result is True
        mock_request.assert_called_once()

    @patch('surin.utils.http_utils.HTTPUtils.make_request')
    def test_validate_failure(self, mock_request):
        """Test validation failure."""
        # Setup mock
        mock_request.side_effect = Exception("Connection failed")
        
        # Test
        module = CertificateTransparencyModule("example.com")
        result = module.validate()
        
        # Verify
        assert result is False