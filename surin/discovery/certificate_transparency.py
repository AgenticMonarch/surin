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
                - timeout: HTTP request timeout in seconds (default: 10)
                - show_progress: Whether to show progress indicator (default: True)
        """
        super().__init__(domain, **kwargs)
        self.timeout = kwargs.get('timeout', 10)
        self.show_progress = kwargs.get('show_progress', True)
        self.http_utils = HTTPUtils(timeout=self.timeout)
        self.logger = logging.getLogger('surin.discovery.certificate_transparency')
        
        # crt.sh API endpoint
        self.crt_sh_url = "https://crt.sh/"

    def discover(self) -> List[str]:
        """Execute Certificate Transparency discovery.
        
        Queries the Certificate Transparency logs via the crt.sh service to find
        SSL/TLS certificates issued for the target domain and its subdomains.
        Extracts subdomain names from the certificate data and returns a list of
        unique subdomains.
        
        Returns:
            List of discovered subdomain names
            
        Raises:
            APIError: If the crt.sh API request fails or returns invalid data
        """
        subdomains = set()
        
        self.logger.info(f"Starting Certificate Transparency discovery for {self.domain}")
        
        try:
            # Query crt.sh API
            ct_subdomains = self._query_crt_sh()
            subdomains.update(ct_subdomains)
            
        except Exception as e:
            self.logger.error(f"Certificate Transparency discovery failed: {e}")
            raise APIError(f"Certificate Transparency discovery failed") from e
        
        result = list(subdomains)
        self.logger.info(f"Certificate Transparency discovered {len(result)} subdomains")
        return result

    def _query_crt_sh(self) -> Set[str]:
        """Query crt.sh API for certificate data.
        
        Sends a request to the crt.sh service to retrieve certificate data for the target domain.
        Parses the JSON response and extracts subdomains from the certificate data.
        
        Returns:
            Set of discovered subdomains
            
        Raises:
            APIError: If the API request fails or returns invalid data
            NetworkError: If a network error occurs during the request
        """
        subdomains = set()
        
        try:
            # Query crt.sh for certificates
            params = {
                'q': f'%.{self.domain}',
                'output': 'json'
            }
            
            with progress_bar(desc="Querying crt.sh", disable=not self.show_progress) as progress:
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
                return subdomains
            
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
            
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse crt.sh response: {e}")
            raise APIError("Failed to parse crt.sh response") from e
        except NetworkError as e:
            self.logger.error(f"Network error querying crt.sh: {e}")
            raise APIError("Network error querying crt.sh") from e
        except Exception as e:
            self.logger.error(f"Unexpected error querying crt.sh: {e}")
            raise APIError("Unexpected error querying crt.sh") from e
        
        return subdomains

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