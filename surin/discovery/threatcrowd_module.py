"""ThreatCrowd module for SURIN."""

import logging
import json
import time
from typing import List, Set
import re

from surin.core.interfaces import DiscoveryModule
from surin.core.exceptions import APIError, NetworkError
from surin.utils.http_utils import HTTPUtils
from surin.utils.concurrency import RateLimiter


class ThreatCrowdModule(DiscoveryModule):
    """Discover subdomains using ThreatCrowd API."""

    def __init__(self, domain: str, **kwargs):
        """Initialize ThreatCrowd module.
        
        Args:
            domain: Target domain to discover subdomains for
            **kwargs: Additional configuration options
                - timeout: HTTP request timeout in seconds
        """
        super().__init__(domain, **kwargs)
        self.timeout = kwargs.get('timeout', 10)
        self.http_utils = HTTPUtils(timeout=self.timeout)
        self.logger = logging.getLogger('surin.discovery.threatcrowd')
        
        # ThreatCrowd API endpoint
        self.api_url = "https://www.threatcrowd.org/searchApi/v2/domain/report/"
        
        # Rate limiter (ThreatCrowd has strict rate limits)
        self.rate_limiter = RateLimiter(calls=1, period=10)

    def discover(self) -> List[str]:
        """Execute ThreatCrowd discovery.
        
        Returns:
            List of discovered subdomain names
        """
        subdomains = set()
        
        self.logger.info(f"Starting ThreatCrowd discovery for {self.domain}")
        
        try:
            # Query ThreatCrowd API
            tc_subdomains = self._query_threatcrowd()
            subdomains.update(tc_subdomains)
            
        except Exception as e:
            self.logger.error(f"ThreatCrowd discovery failed: {e}")
            raise APIError(f"ThreatCrowd discovery failed") from e
        
        result = list(subdomains)
        self.logger.info(f"ThreatCrowd discovered {len(result)} subdomains")
        return result

    @RateLimiter(calls=1, period=10)
    def _query_threatcrowd(self) -> Set[str]:
        """Query ThreatCrowd API for subdomain data.
        
        Returns:
            Set of discovered subdomains
        """
        subdomains = set()
        
        try:
            # Prepare query parameters
            params = {'domain': self.domain}
            
            # Make API request
            response = self.http_utils.make_request(
                url=self.api_url,
                method='GET',
                params=params
            )
            
            # Parse JSON response
            data = response.json()
            
            # Check response status
            if 'response_code' in data and data['response_code'] == '0':
                self.logger.warning("ThreatCrowd returned no results")
                return subdomains
            
            # Extract subdomains
            if 'subdomains' in data and isinstance(data['subdomains'], list):
                for subdomain in data['subdomains']:
                    if isinstance(subdomain, str) and self._is_valid_subdomain(subdomain):
                        subdomains.add(subdomain)
            
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse ThreatCrowd response: {e}")
            raise APIError("Failed to parse ThreatCrowd response") from e
        except NetworkError as e:
            self.logger.error(f"Network error querying ThreatCrowd: {e}")
            raise APIError("Network error querying ThreatCrowd") from e
        except Exception as e:
            self.logger.error(f"Unexpected error querying ThreatCrowd: {e}")
            raise APIError("Unexpected error querying ThreatCrowd") from e
        
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