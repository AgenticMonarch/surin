"""HTTP utility functions for SURIN."""

import requests
from typing import Dict, Optional, Tuple
import logging
from requests.exceptions import RequestException, Timeout, ConnectionError

from surin.core.exceptions import NetworkError


class HTTPUtils:
    """HTTP utility functions."""

    def __init__(self, timeout: int = 5, user_agent: Optional[str] = None):
        """Initialize HTTP utilities.
        
        Args:
            timeout: HTTP request timeout in seconds
            user_agent: Custom User-Agent string
        """
        self.timeout = timeout
        self.user_agent = user_agent or "SURIN/1.0"
        self.logger = logging.getLogger('surin.http_utils')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': self.user_agent
        })

    def get_status(self, url: str) -> Tuple[int, Dict]:
        """Get HTTP status code and headers for a URL.
        
        Args:
            url: URL to check
            
        Returns:
            Tuple of (status_code, headers)
            
        Raises:
            NetworkError: If request fails
        """
        try:
            response = self.session.head(
                url, 
                timeout=self.timeout, 
                allow_redirects=True
            )
            return response.status_code, dict(response.headers)
        except Timeout:
            self.logger.debug(f"Timeout connecting to {url}")
            raise NetworkError(f"Timeout connecting to {url}")
        except ConnectionError:
            self.logger.debug(f"Connection error for {url}")
            raise NetworkError(f"Connection error for {url}")
        except RequestException as e:
            self.logger.debug(f"Request error for {url}: {e}")
            raise NetworkError(f"Request error for {url}") from e
        except Exception as e:
            self.logger.debug(f"Unexpected error for {url}: {e}")
            raise NetworkError(f"Unexpected error for {url}") from e

    def check_website(self, domain: str) -> Dict:
        """Check both HTTP and HTTPS status for a domain.
        
        Args:
            domain: Domain to check
            
        Returns:
            Dictionary with HTTP and HTTPS status information
        """
        result = {
            'http_status': None,
            'https_status': None,
            'http_headers': {},
            'https_headers': {}
        }
        
        # Check HTTP
        try:
            status, headers = self.get_status(f"http://{domain}")
            result['http_status'] = status
            result['http_headers'] = headers
        except NetworkError as e:
            self.logger.debug(f"HTTP check failed for {domain}: {e}")
        
        # Check HTTPS
        try:
            status, headers = self.get_status(f"https://{domain}")
            result['https_status'] = status
            result['https_headers'] = headers
        except NetworkError as e:
            self.logger.debug(f"HTTPS check failed for {domain}: {e}")
        
        return result

    def make_request(self, url: str, method: str = 'GET', 
                    params: Optional[Dict] = None, 
                    headers: Optional[Dict] = None,
                    json_data: Optional[Dict] = None) -> requests.Response:
        """Make an HTTP request.
        
        Args:
            url: URL to request
            method: HTTP method (GET, POST, etc.)
            params: URL parameters
            headers: HTTP headers
            json_data: JSON data for POST requests
            
        Returns:
            Response object
            
        Raises:
            NetworkError: If request fails
        """
        try:
            request_headers = {}
            if headers:
                request_headers.update(headers)
            
            response = self.session.request(
                method=method,
                url=url,
                params=params,
                headers=request_headers,
                json=json_data,
                timeout=self.timeout
            )
            
            response.raise_for_status()
            return response
        except Timeout:
            self.logger.debug(f"Timeout connecting to {url}")
            raise NetworkError(f"Timeout connecting to {url}")
        except ConnectionError:
            self.logger.debug(f"Connection error for {url}")
            raise NetworkError(f"Connection error for {url}")
        except RequestException as e:
            self.logger.debug(f"Request error for {url}: {e}")
            raise NetworkError(f"Request error for {url}") from e
        except Exception as e:
            self.logger.debug(f"Unexpected error for {url}: {e}")
            raise NetworkError(f"Unexpected error for {url}") from e