"""
Unit tests for HTTP utilities.
"""
import pytest
from unittest.mock import patch, MagicMock
import requests
from requests.exceptions import RequestException, Timeout, ConnectionError

from surin.utils.http_utils import HTTPUtils
from surin.core.exceptions import NetworkError


class TestHTTPUtils:
    """Test HTTP utility functions."""

    def test_init(self):
        """Test initialization with default and custom values."""
        # Default values
        http_utils = HTTPUtils()
        assert http_utils.timeout == 5
        assert http_utils.user_agent == "SURIN/1.0"
        
        # Custom values
        http_utils = HTTPUtils(timeout=10, user_agent="Custom/1.0")
        assert http_utils.timeout == 10
        assert http_utils.user_agent == "Custom/1.0"

    @patch('requests.Session')
    def test_get_status_success(self, mock_session):
        """Test successful status check."""
        # Setup mock
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {'Server': 'nginx', 'Content-Type': 'text/html'}
        
        mock_session_instance = MagicMock()
        mock_session_instance.head.return_value = mock_response
        mock_session.return_value = mock_session_instance
        
        # Test
        http_utils = HTTPUtils()
        status, headers = http_utils.get_status("http://example.com")
        
        # Verify
        assert status == 200
        assert headers == {'Server': 'nginx', 'Content-Type': 'text/html'}
        mock_session_instance.head.assert_called_once_with(
            "http://example.com", 
            timeout=5, 
            allow_redirects=True
        )

    @patch('requests.Session')
    def test_get_status_timeout(self, mock_session):
        """Test status check with timeout."""
        # Setup mock
        mock_session_instance = MagicMock()
        mock_session_instance.head.side_effect = Timeout("Connection timed out")
        mock_session.return_value = mock_session_instance
        
        # Test
        http_utils = HTTPUtils()
        with pytest.raises(NetworkError) as excinfo:
            http_utils.get_status("http://slow.example.com")
        
        # Verify
        assert "Timeout connecting to" in str(excinfo.value)

    @patch('requests.Session')
    def test_get_status_connection_error(self, mock_session):
        """Test status check with connection error."""
        # Setup mock
        mock_session_instance = MagicMock()
        mock_session_instance.head.side_effect = ConnectionError("Connection refused")
        mock_session.return_value = mock_session_instance
        
        # Test
        http_utils = HTTPUtils()
        with pytest.raises(NetworkError) as excinfo:
            http_utils.get_status("http://nonexistent.example.com")
        
        # Verify
        assert "Connection error for" in str(excinfo.value)

    @patch('surin.utils.http_utils.HTTPUtils.get_status')
    def test_check_website_both_protocols(self, mock_get_status):
        """Test website check with both protocols working."""
        # Setup mock
        mock_get_status.side_effect = [
            (200, {'Server': 'nginx'}),  # HTTP
            (200, {'Server': 'nginx'})   # HTTPS
        ]
        
        # Test
        http_utils = HTTPUtils()
        result = http_utils.check_website("example.com")
        
        # Verify
        assert result['http_status'] == 200
        assert result['https_status'] == 200
        assert result['http_headers'] == {'Server': 'nginx'}
        assert result['https_headers'] == {'Server': 'nginx'}
        assert mock_get_status.call_count == 2

    @patch('surin.utils.http_utils.HTTPUtils.get_status')
    def test_check_website_http_only(self, mock_get_status):
        """Test website check with only HTTP working."""
        # Setup mock
        mock_get_status.side_effect = [
            (200, {'Server': 'nginx'}),  # HTTP
            NetworkError("Connection error for https://example.com")  # HTTPS
        ]
        
        # Test
        http_utils = HTTPUtils()
        result = http_utils.check_website("example.com")
        
        # Verify
        assert result['http_status'] == 200
        assert result['https_status'] is None
        assert result['http_headers'] == {'Server': 'nginx'}
        assert result['https_headers'] == {}

    @patch('requests.Session')
    def test_make_request_success(self, mock_session):
        """Test successful API request."""
        # Setup mock
        mock_response = MagicMock()
        mock_response.status_code = 200
        
        mock_session_instance = MagicMock()
        mock_session_instance.request.return_value = mock_response
        mock_session.return_value = mock_session_instance
        
        # Test
        http_utils = HTTPUtils()
        response = http_utils.make_request(
            url="https://api.example.com/data",
            method="GET",
            params={"key": "value"},
            headers={"X-API-Key": "test-key"}
        )
        
        # Verify
        assert response == mock_response
        mock_session_instance.request.assert_called_once_with(
            method="GET",
            url="https://api.example.com/data",
            params={"key": "value"},
            headers={"X-API-Key": "test-key"},
            json=None,
            timeout=5
        )

    @patch('requests.Session')
    def test_make_request_error(self, mock_session):
        """Test API request with error."""
        # Setup mock
        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = requests.HTTPError("404 Client Error")
        
        mock_session_instance = MagicMock()
        mock_session_instance.request.return_value = mock_response
        mock_session.return_value = mock_session_instance
        
        # Test
        http_utils = HTTPUtils()
        with pytest.raises(NetworkError) as excinfo:
            http_utils.make_request("https://api.example.com/nonexistent")
        
        # Verify
        assert "Request error for" in str(excinfo.value)