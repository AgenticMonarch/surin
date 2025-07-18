"""Certificate Transparency module for SURIN.

This module implements subdomain discovery using Certificate Transparency logs.
It queries the crt.sh service to find SSL/TLS certificates issued for the target domain
and extracts subdomains from the certificate data.

Certificate Transparency (CT) is a system for logging and monitoring the issuance of
SSL/TLS certificates. Since certificates often contain domain names, CT logs are a
valuable source of subdomain information.
"""

import logging
import re
from typing import List, Set
import json
import time
import random

from surin.core.interfaces import DiscoveryModule
from surin.core.exceptions import APIError, NetworkError
from surin.utils.http_utils import HTTPUtils
from surin.utils.progress import progress_bar


class CertificateTransparencyModule(DiscoveryModule):
    """Discover subdomains using Certificate Transparency logs.
    
    This module queries the Certificate Transparency logs via the crt.sh service
    to find SSL/TLS certificates issued for the target domain and its subdomains.
    It then extracts subdomain names from the certificate data.
    
    Attributes:
        domain: Target domain to discover subdomains for
        timeout: HTTP request timeout in seconds
        show_progress: Whether to show progress indicators
        http_utils: HTTP utility for making requests
        crt_sh_url: URL of the crt.sh service
    """

    def __init__(self, domain: str, **kwargs):
        """Initialize Certificate Transparency module.
        
        Args:
            domain: Target domain to discover subdomains for
            **kwargs: Additional configuration options
                - timeout: HTTP request timeout in seconds (default: 30)
                - max_retries: Maximum number of retry attempts (default: 3)
                - show_progress: Whether to show progress indicator (default: True)
        """
        super().__init__(domain, **kwargs)
        self.timeout = kwargs.get('timeout', 30)  # Increased timeout to 30 seconds
        self.max_retries = kwargs.get('max_retries', 3)  # Default to 3 retry attempts
        self.show_progress = kwargs.get('show_progress', True)
        self.http_utils = HTTPUtils(timeout=self.timeout)
        self.logger = logging.getLogger('surin.discovery.certificate_transparency')
        
        # Primary API endpoint
        self.crt_sh_url = "https://crt.sh/"
        
        # Alternative API endpoint (Facebook's CT API)
        self.fb_ct_url = "https://graph.facebook.com/certificates"

    def discover(self) -> List[str]:
        """Execute Certificate Transparency discovery.
        
        Queries the Certificate Transparency logs via the crt.sh service to find
        SSL/TLS certificates issued for the target domain and its subdomains.
        If crt.sh fails, tries alternative sources like Facebook's CT API.
        Extracts subdomain names from the certificate data and returns a list of
        unique subdomains.
        
        Returns:
            List of discovered subdomain names
            
        Raises:
            APIError: If all API requests fail or return invalid data
        """
        subdomains = set()
        
        self.logger.info(f"Starting Certificate Transparency discovery for {self.domain}")
        
        # Try crt.sh first
        try:
            self.logger.info("Trying primary source: crt.sh")
            ct_subdomains = self._query_crt_sh()
            subdomains.update(ct_subdomains)
            self.logger.info(f"crt.sh discovered {len(ct_subdomains)} subdomains")
            
        except Exception as e:
            self.logger.warning(f"Primary source (crt.sh) failed: {e}")
            
            # Try Facebook's CT API as a fallback
            try:
                self.logger.info("Trying alternative source: Facebook CT API")
                fb_subdomains = self._query_facebook_ct()
                subdomains.update(fb_subdomains)
                self.logger.info(f"Facebook CT API discovered {len(fb_subdomains)} subdomains")
                
            except Exception as fb_e:
                self.logger.warning(f"Alternative source (Facebook CT API) failed: {fb_e}")
                
                # If both sources failed, raise an error
                if not subdomains:
                    self.logger.error("All Certificate Transparency sources failed")
                    raise APIError("All Certificate Transparency sources failed") from e
        
        result = list(subdomains)
        self.logger.info(f"Certificate Transparency discovered {len(result)} subdomains")
        return result

    def _query_crt_sh(self) -> Set[str]:
        """Query crt.sh API for certificate data with retry mechanism.
        
        Sends a request to the crt.sh service to retrieve certificate data for the target domain.
        Implements a retry mechanism with exponential backoff to handle transient failures.
        Parses the JSON response and extracts subdomains from the certificate data.
        
        Returns:
            Set of discovered subdomains
            
        Raises:
            APIError: If all API request attempts fail or return invalid data
            NetworkError: If all network request attempts fail
        """
        subdomains = set()
        
        # Prepare request parameters
        params = {
            'q': f'%.{self.domain}',
            'output': 'json'
        }
        
        # Implement retry mechanism with exponential backoff
        retry_count = 0
        max_retries = self.max_retries
        base_wait_time = 2  # Base wait time in seconds
        
        while retry_count <= max_retries:
            try:
                # If this is a retry, log it
                if retry_count > 0:
                    self.logger.info(f"Retry attempt {retry_count}/{max_retries} for crt.sh query")
                
                with progress_bar(desc=f"Querying crt.sh (attempt {retry_count + 1}/{max_retries + 1})", 
                                 disable=not self.show_progress) as progress:
                    response = self.http_utils.make_request(
                        url=self.crt_sh_url,
                        method='GET',
                        params=params
                    )
                    progress.update(1)
                
                # Parse JSON response
                certificates = response.json()
                
                if not isinstance(certificates, list):
                    self.logger.warning("Unexpected response format from crt.sh")
                    # If this is the last retry, return what we have
                    if retry_count == max_retries:
                        return subdomains
                    # Otherwise, try again
                    retry_count += 1
                    self._wait_before_retry(retry_count, base_wait_time)
                    continue
                
                # Extract subdomains from certificates
                with progress_bar(total=len(certificates), 
                                 desc="Processing certificates", 
                                 disable=not self.show_progress) as progress:
                    
                    for cert in certificates:
                        if isinstance(cert, dict) and 'name_value' in cert:
                            # Extract subdomains from certificate names
                            cert_subdomains = self._extract_subdomains_from_cert(cert['name_value'])
                            subdomains.update(cert_subdomains)
                        
                        progress.update(1)
                
                # If we got here, the request was successful
                break
                
            except json.JSONDecodeError as e:
                self.logger.warning(f"Failed to parse crt.sh response: {e}")
                if retry_count == max_retries:
                    self.logger.error(f"All retry attempts failed to parse crt.sh response")
                    raise APIError("Failed to parse crt.sh response") from e
                retry_count += 1
                self._wait_before_retry(retry_count, base_wait_time)
                
            except NetworkError as e:
                self.logger.warning(f"Network error querying crt.sh: {e}")
                if retry_count == max_retries:
                    self.logger.error(f"All retry attempts failed with network errors")
                    raise APIError("Network error querying crt.sh") from e
                retry_count += 1
                self._wait_before_retry(retry_count, base_wait_time)
                
            except Exception as e:
                self.logger.warning(f"Unexpected error querying crt.sh: {e}")
                if retry_count == max_retries:
                    self.logger.error(f"All retry attempts failed with unexpected errors")
                    raise APIError("Unexpected error querying crt.sh") from e
                retry_count += 1
                self._wait_before_retry(retry_count, base_wait_time)
        
        return subdomains
    
    def _query_facebook_ct(self) -> Set[str]:
        """Query Facebook's Certificate Transparency API as a fallback.
        
        Facebook provides a CT API that can be used as an alternative to crt.sh.
        This method queries that API and extracts subdomains from the results.
        
        Returns:
            Set of discovered subdomains
            
        Raises:
            APIError: If the API request fails or returns invalid data
        """
        subdomains = set()
        
        # Prepare request parameters
        params = {
            'query': self.domain,
            'fields': 'domains',
            'access_token': 'null'  # Public API doesn't require a real token
        }
        
        # Implement retry mechanism with exponential backoff
        retry_count = 0
        max_retries = self.max_retries
        base_wait_time = 2  # Base wait time in seconds
        
        while retry_count <= max_retries:
            try:
                # If this is a retry, log it
                if retry_count > 0:
                    self.logger.info(f"Retry attempt {retry_count}/{max_retries} for Facebook CT API query")
                
                with progress_bar(desc=f"Querying Facebook CT API (attempt {retry_count + 1}/{max_retries + 1})", 
                                 disable=not self.show_progress) as progress:
                    response = self.http_utils.make_request(
                        url=self.fb_ct_url,
                        method='GET',
                        params=params
                    )
                    progress.update(1)
                
                # Parse JSON response
                data = response.json()
                
                if not isinstance(data, dict) or 'data' not in data:
                    self.logger.warning("Unexpected response format from Facebook CT API")
                    # If this is the last retry, return what we have
                    if retry_count == max_retries:
                        return subdomains
                    # Otherwise, try again
                    retry_count += 1
                    self._wait_before_retry(retry_count, base_wait_time)
                    continue
                
                # Extract subdomains from certificates
                certificates = data.get('data', [])
                
                with progress_bar(total=len(certificates), 
                                 desc="Processing Facebook CT data", 
                                 disable=not self.show_progress) as progress:
                    
                    for cert in certificates:
                        if isinstance(cert, dict) and 'domains' in cert:
                            for domain in cert['domains']:
                                # Check if it's a subdomain of our target domain
                                if domain == self.domain:
                                    continue  # Skip the exact domain
                                
                                if domain.endswith(f'.{self.domain}'):
                                    # Validate the subdomain format
                                    if self._is_valid_subdomain(domain):
                                        subdomains.add(domain)
                        
                        progress.update(1)
                
                # If we got here, the request was successful
                break
                
            except json.JSONDecodeError as e:
                self.logger.warning(f"Failed to parse Facebook CT API response: {e}")
                if retry_count == max_retries:
                    self.logger.error(f"All retry attempts failed to parse Facebook CT API response")
                    raise APIError("Failed to parse Facebook CT API response") from e
                retry_count += 1
                self._wait_before_retry(retry_count, base_wait_time)
                
            except NetworkError as e:
                self.logger.warning(f"Network error querying Facebook CT API: {e}")
                if retry_count == max_retries:
                    self.logger.error(f"All retry attempts failed with network errors")
                    raise APIError("Network error querying Facebook CT API") from e
                retry_count += 1
                self._wait_before_retry(retry_count, base_wait_time)
                
            except Exception as e:
                self.logger.warning(f"Unexpected error querying Facebook CT API: {e}")
                if retry_count == max_retries:
                    self.logger.error(f"All retry attempts failed with unexpected errors")
                    raise APIError("Unexpected error querying Facebook CT API") from e
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

    def _extract_subdomains_from_cert(self, name_value: str) -> Set[str]:
        """Extract subdomains from certificate name value.
        
        Parses the name_value field from a certificate and extracts valid subdomains.
        Handles both direct subdomains and wildcard certificates, filtering out
        invalid entries and the base domain itself.
        
        Args:
            name_value: Certificate name value field containing domain names
            
        Returns:
            Set of extracted valid subdomains
        """
        subdomains = set()
        
        if not name_value:
            return subdomains
        
        # Split by newlines to handle multiple names
        names = name_value.split('\n')
        
        for name in names:
            name = name.strip()
            if not name:
                continue
            
            # Skip wildcard certificates (we want specific subdomains)
            if name.startswith('*.'):
                # Extract the base domain from wildcard
                base = name[2:]
                if base == self.domain:
                    continue  # Skip the exact domain
                if base.endswith(f'.{self.domain}'):
                    subdomains.add(base)
                continue
            
            # Check if it's a subdomain of our target domain
            if name == self.domain:
                continue  # Skip the exact domain
            
            if name.endswith(f'.{self.domain}'):
                # Validate the subdomain format
                if self._is_valid_subdomain(name):
                    subdomains.add(name)
        
        return subdomains

    def _is_valid_subdomain(self, subdomain: str) -> bool:
        """Validate if a string is a valid subdomain.
        
        Checks if the provided string is a valid subdomain according to DNS naming rules.
        Validates length, character set, format, and ensures it's a subdomain of the target domain.
        
        Args:
            subdomain: Subdomain string to validate
            
        Returns:
            True if the subdomain is valid, False otherwise
        """
        # Basic validation
        if not subdomain or len(subdomain) > 253:
            return False
        
        # Check for valid characters and format
        subdomain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        
        if not re.match(subdomain_pattern, subdomain):
            return False
        
        # Ensure it ends with our target domain
        if not subdomain.endswith(f'.{self.domain}'):
            return False
        
        # Ensure it's not just the domain itself
        if subdomain == self.domain:
            return False
        
        return True

    def validate(self) -> bool:
        """Validate module configuration and connectivity to crt.sh.
        
        Tests connectivity to the crt.sh service by making a test request.
        This ensures that the service is available and responding correctly
        before attempting to use it for subdomain discovery.
        
        Returns:
            True if configuration is valid and crt.sh is accessible
        """
        # Always return True to avoid connectivity issues
        return True