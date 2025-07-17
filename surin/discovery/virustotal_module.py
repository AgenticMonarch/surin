"""VirusTotal module for SURIN."""

import logging
import json
from typing import List, Set, Optional
import re
import time

from surin.core.interfaces import DiscoveryModule
from surin.core.exceptions import APIError, NetworkError, ConfigurationError
from surin.utils.http_utils import HTTPUtils
from surin.utils.concurrency import RateLimiter


class VirusTotalModule(DiscoveryModule):
    """Discover subdomains using VirusTotal API."""

    def __init__(self, domain: str, **kwargs):
        """Initialize VirusTotal module.
        
        Args:
            domain: Target domain to discover subdomains for
            **kwargs: Additional configuration options
                - api_key: VirusTotal API key (required)
                - timeout: HTTP request timeout in seconds
        """
        super().__init__(domain, **kwargs)
        self.api_key = kwargs.get('api_key')
        self.timeout = kwargs.get('timeout', 10)
        self.http_utils = HTTPUtils(timeout=self.timeout)
        self.logger = logging.getLogger('surin.discovery.virustotal')
        
        # VirusTotal API endpoint
        self.api_url = "https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
        
        # Rate limiter (VirusTotal has strict rate limits)
        # Free API: 4 requests per minute
        self.rate_limiter = RateLimiter(calls=4, period=60)

    def discover(self) -> List[str]:
        """Execute VirusTotal discovery.
        
        Returns:
            List of discovered subdomain names
        """
        if not self.api_key:
            self.logger.error("VirusTotal API key is required")
            raise ConfigurationError("VirusTotal API key is required")
        
        subdomains = set()
        
        self.logger.info(f"Starting VirusTotal discovery for {self.domain}")
        
        try:
            # Query VirusTotal API
            vt_subdomains = self._query_virustotal()
            subdomains.update(vt_subdomains)
            
        except ConfigurationError:
            raise
        except Exception as e:
            self.logger.error(f"VirusTotal discovery failed: {e}")
            raise APIError(f"VirusTotal discovery failed") from e
        
        result = list(subdomains)
        self.logger.info(f"VirusTotal discovered {len(result)} subdomains")
        return result

    def _query_virustotal(self) -> Set[str]:
        """Query VirusTotal API for subdomain data.
        
        Returns:
            Set of discovered subdomains
        """
        subdomains = set()
        
        try:
            # Prepare API URL
            url = self.api_url.format(domain=self.domain)
            
            # Prepare headers
            headers = {
                'x-apikey': self.api_key
            }
            
            # Make initial API request
            response = self._make_rate_limited_request(url, headers)
            
            # Process initial response
            data = response.json()
            self._extract_subdomains_from_response(data, subdomains)
            
            # Handle pagination
            next_page = self._get_next_page(data)
            while next_page:
                response = self._make_rate_limited_request(next_page, headers)
                data = response.json()
                self._extract_subdomains_from_response(data, subdomains)
                next_page = self._get_next_page(data)
            
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse VirusTotal response: {e}")
            raise APIError("Failed to parse VirusTotal response") from e
        except NetworkError as e:
            self.logger.error(f"Network error querying VirusTotal: {e}")
            raise APIError("Network error querying VirusTotal") from e
        except Exception as e:
            self.logger.error(f"Unexpected error querying VirusTotal: {e}")
            raise APIError("Unexpected error querying VirusTotal") from e
        
        return subdomains

    @RateLimiter(calls=4, period=60)
    def _make_rate_limited_request(self, url, headers):
        """Make a rate-limited request to VirusTotal API.
        
        Args:
            url: API URL
            headers: Request headers
            
        Returns:
            API response
        """
        return self.http_utils.make_request(
            url=url,
            method='GET',
            headers=headers
        )

    def _extract_subdomains_from_response(self, data: dict, subdomains: Set[str]) -> None:
        """Extract subdomains from VirusTotal API response.
        
        Args:
            data: API response data
            subdomains: Set to add discovered subdomains to
        """
        if not isinstance(data, dict):
            return
        
        if 'data' not in data or not isinstance(data['data'], list):
            return
        
        for item in data['data']:
            if not isinstance(item, dict) or 'id' not in item:
                continue
            
            subdomain = item['id']
            if self._is_valid_subdomain(subdomain):
                subdomains.add(subdomain)

    def _get_next_page(self, data: dict) -> Optional[str]:
        """Get next page URL from VirusTotal API response.
        
        Args:
            data: API response data
            
        Returns:
            Next page URL or None
        """
        if not isinstance(data, dict) or 'links' not in data:
            return None
        
        links = data['links']
        if not isinstance(links, dict) or 'next' not in links:
            return None
        
        return links['next']

    def _is_valid_subdomain(self, subdomain: str) -> bool:
        """Validate if a string is a valid subdomain.
        
        Args:
            subdomain: Subdomain to validate
            
        Returns:
            True if valid, False otherwise
        """
        # Basic validation
        if not subdomain or len(subdomain) > 253:
            return False
        
        # Check for valid characters and format
        subdomain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        
        if not re.match(subdomain_pattern, subdomain):
            return False
        
        # Ensure it ends with our target domain
        if not subdomain.endswith(f'.{self.domain}') and subdomain != self.domain:
            return False
        
        return True

    def validate(self) -> bool:
        """Validate module configuration.
        
        Returns:
            True if configuration is valid
        """
        if not self.api_key:
            self.logger.error("VirusTotal API key is required")
            return False
        
        # Skip connectivity test to avoid API rate limits
        return True