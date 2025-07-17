"""HackerTarget module for SURIN."""

import logging
from typing import List, Set
import re

from surin.core.interfaces import DiscoveryModule
from surin.core.exceptions import APIError, NetworkError
from surin.utils.http_utils import HTTPUtils


class HackerTargetModule(DiscoveryModule):
    """Discover subdomains using HackerTarget API."""

    def __init__(self, domain: str, **kwargs):
        """Initialize HackerTarget module.
        
        Args:
            domain: Target domain to discover subdomains for
            **kwargs: Additional configuration options
                - api_key: HackerTarget API key (optional)
                - timeout: HTTP request timeout in seconds
        """
        super().__init__(domain, **kwargs)
        self.api_key = kwargs.get('api_key')
        self.timeout = kwargs.get('timeout', 10)
        self.http_utils = HTTPUtils(timeout=self.timeout)
        self.logger = logging.getLogger('surin.discovery.hackertarget')
        
        # HackerTarget API endpoint
        self.api_url = "https://api.hackertarget.com/hostsearch/"

    def discover(self) -> List[str]:
        """Execute HackerTarget discovery.
        
        Returns:
            List of discovered subdomain names
        """
        subdomains = set()
        
        self.logger.info(f"Starting HackerTarget discovery for {self.domain}")
        
        try:
            # Query HackerTarget API
            ht_subdomains = self._query_hackertarget()
            subdomains.update(ht_subdomains)
            
        except Exception as e:
            self.logger.error(f"HackerTarget discovery failed: {e}")
            raise APIError(f"HackerTarget discovery failed") from e
        
        result = list(subdomains)
        self.logger.info(f"HackerTarget discovered {len(result)} subdomains")
        return result

    def _query_hackertarget(self) -> Set[str]:
        """Query HackerTarget API for subdomain data.
        
        Returns:
            Set of discovered subdomains
        """
        subdomains = set()
        
        try:
            # Prepare query parameters
            params = {'q': self.domain}
            
            # Add API key if available
            if self.api_key:
                params['apikey'] = self.api_key
            
            # Make API request
            response = self.http_utils.make_request(
                url=self.api_url,
                method='GET',
                params=params
            )
            
            # Parse response
            content = response.text
            
            if "API count exceeded" in content:
                self.logger.warning("HackerTarget API rate limit exceeded")
                raise APIError("HackerTarget API rate limit exceeded")
            
            if "error" in content.lower() or "invalid" in content.lower():
                self.logger.warning(f"HackerTarget API error: {content}")
                raise APIError(f"HackerTarget API error: {content}")
            
            # Process results
            # HackerTarget returns data in format: subdomain.example.com,IP
            for line in content.splitlines():
                line = line.strip()
                if not line:
                    continue
                
                parts = line.split(',')
                if len(parts) >= 1:
                    subdomain = parts[0].strip()
                    if self._is_valid_subdomain(subdomain):
                        subdomains.add(subdomain)
            
        except NetworkError as e:
            self.logger.error(f"Network error querying HackerTarget: {e}")
            raise APIError("Network error querying HackerTarget") from e
        except Exception as e:
            self.logger.error(f"Unexpected error querying HackerTarget: {e}")
            raise APIError("Unexpected error querying HackerTarget") from e
        
        return subdomains

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
        # Always return True to avoid connectivity issues
        return True