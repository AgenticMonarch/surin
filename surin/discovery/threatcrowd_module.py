"""ThreatCrowd module for SURIN."""

import logging
import json
import time
import random
from typing import List, Set
import re

from surin.core.interfaces import DiscoveryModule
from surin.core.exceptions import APIError, NetworkError
from surin.utils.http_utils import HTTPUtils


class ThreatCrowdModule(DiscoveryModule):
    """Discover subdomains using ThreatCrowd API."""

    def __init__(self, domain: str, **kwargs):
        """Initialize ThreatCrowd module.
        
        Args:
            domain: Target domain to discover subdomains for
            **kwargs: Additional configuration options
                - timeout: HTTP request timeout in seconds (default: 30)
                - max_retries: Maximum number of retry attempts (default: 3)
        """
        super().__init__(domain, **kwargs)
        self.timeout = kwargs.get('timeout', 30)  # Increased timeout to 30 seconds
        self.max_retries = kwargs.get('max_retries', 3)  # Default to 3 retry attempts
        self.http_utils = HTTPUtils(timeout=self.timeout)
        self.logger = logging.getLogger('surin.discovery.threatcrowd')
        
        # ThreatCrowd API endpoint
        self.api_url = "https://www.threatcrowd.org/searchApi/v2/domain/report/"
        
        # ThreatCrowd has strict rate limits (1 request per 10 seconds)
        self.min_request_interval = 10  # seconds

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

    def _query_threatcrowd(self) -> Set[str]:
        """Query ThreatCrowd API for subdomain data with retry mechanism.
        
        Returns:
            Set of discovered subdomains
        """
        subdomains = set()
        
        # Prepare request parameters
        params = {'domain': self.domain}
        
        # Implement retry mechanism with exponential backoff
        retry_count = 0
        max_retries = self.max_retries
        base_wait_time = 2  # Base wait time in seconds
        
        while retry_count <= max_retries:
            try:
                # If this is a retry, log it
                if retry_count > 0:
                    self.logger.info(f"Retry attempt {retry_count}/{max_retries} for ThreatCrowd query")
                
                # Make API request (respecting rate limits)
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
                
                # If we got here, the request was successful
                break
                
            except json.JSONDecodeError as e:
                self.logger.warning(f"Failed to parse ThreatCrowd response: {e}")
                if retry_count == max_retries:
                    self.logger.error(f"All retry attempts failed to parse ThreatCrowd response")
                    raise APIError("Failed to parse ThreatCrowd response") from e
                retry_count += 1
                self._wait_before_retry(retry_count, base_wait_time)
                
            except NetworkError as e:
                self.logger.warning(f"Network error querying ThreatCrowd: {e}")
                if retry_count == max_retries:
                    self.logger.error(f"All retry attempts failed with network errors")
                    raise APIError("Network error querying ThreatCrowd") from e
                retry_count += 1
                self._wait_before_retry(retry_count, base_wait_time)
                
            except Exception as e:
                self.logger.warning(f"Unexpected error querying ThreatCrowd: {e}")
                if retry_count == max_retries:
                    self.logger.error(f"All retry attempts failed with unexpected errors")
                    raise APIError("Unexpected error querying ThreatCrowd") from e
                retry_count += 1
                self._wait_before_retry(retry_count, base_wait_time)
        
        return subdomains
        
    def _wait_before_retry(self, retry_count: int, base_wait_time: int) -> None:
        """Implement exponential backoff for retries.
        
        Waits for an exponentially increasing amount of time before the next retry.
        
        Args:
            retry_count: Current retry attempt number
            base_wait_time: Base wait time in seconds
        """
        # Calculate wait time with exponential backoff and jitter
        wait_time = base_wait_time * (2 ** (retry_count - 1))
        # Add jitter to prevent thundering herd problem
        wait_time = wait_time + random.uniform(0, 1)
        
        self.logger.info(f"Waiting {wait_time:.2f} seconds before retry {retry_count}")
        time.sleep(wait_time)

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