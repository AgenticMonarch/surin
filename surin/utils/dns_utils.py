"""DNS utility functions for SURIN.

This module provides utility functions for DNS operations, including domain validation,
DNS resolution, IP address classification, and port scanning. It handles concurrent
DNS resolution for efficient subdomain enumeration and provides helper methods for
working with IP addresses and network ranges.
"""

import socket
import ipaddress
import re
from typing import List, Optional, Tuple, Union, Dict, Set
import logging
import concurrent.futures
from dns.resolver import Resolver, NXDOMAIN, NoAnswer, Timeout, NoNameservers
import dns.reversename
import dns.exception

from surin.core.exceptions import ValidationError, NetworkError
from surin.utils.progress import progress_bar


class DNSUtils:
    """DNS utility functions for domain resolution and validation.
    
    This class provides methods for validating domain names, resolving domains to IP addresses,
    classifying IP addresses as public or private, scanning ports, and grouping IP addresses
    into network ranges. It supports concurrent DNS resolution for efficient subdomain enumeration.
    
    Attributes:
        timeout: DNS query timeout in seconds
        max_workers: Maximum number of concurrent DNS resolution workers
        logger: Logger instance for this class
        resolver: DNS resolver instance
    """

    def __init__(self, timeout: int = 3, max_workers: int = 50):
        """Initialize DNS utilities.
        
        Args:
            timeout: DNS query timeout in seconds
            max_workers: Maximum number of concurrent DNS resolution workers
        """
        self.timeout = timeout
        self.max_workers = max_workers
        self.logger = logging.getLogger('surin.dns_utils')
        self.resolver = Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    def validate_domain(self, domain: str) -> bool:
        """Validate if a string is a valid domain name.
        
        Args:
            domain: Domain name to validate
            
        Returns:
            True if domain is valid, False otherwise
            
        Raises:
            ValidationError: If domain is invalid
        """
        # Simple domain validation regex
        domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        
        if not domain or not isinstance(domain, str):
            raise ValidationError("Domain must be a non-empty string")
        
        if not re.match(domain_pattern, domain):
            raise ValidationError(f"Invalid domain format: {domain}")
        
        return True

    def resolve_domain(self, domain: str) -> List[str]:
        """Resolve a domain name to IP addresses.
        
        Performs DNS resolution to convert a domain name to its corresponding IP addresses.
        Handles various DNS exceptions and provides appropriate error handling.
        
        Args:
            domain: Domain name to resolve (e.g., example.com, subdomain.example.com)
            
        Returns:
            List of IP addresses as strings
            
        Raises:
            NetworkError: If DNS resolution fails due to network issues
        """
        try:
            # Try to get A records
            ips = []
            answers = self.resolver.resolve(domain, 'A')
            for answer in answers:
                ips.append(answer.to_text())
            return ips
        except NXDOMAIN:
            self.logger.debug(f"Domain {domain} does not exist")
            return []
        except NoAnswer:
            self.logger.debug(f"No A records for {domain}")
            return []
        except Timeout:
            self.logger.debug(f"Timeout resolving {domain}")
            raise NetworkError(f"Timeout resolving {domain}")
        except NoNameservers:
            self.logger.debug(f"No nameservers available for {domain}")
            raise NetworkError(f"No nameservers available for {domain}")
        except Exception as e:
            self.logger.debug(f"Error resolving {domain}: {e}")
            raise NetworkError(f"Error resolving {domain}") from e

    def is_ip_public(self, ip: str) -> bool:
        """Check if an IP address is public.
        
        Determines whether an IP address is public (routable on the internet)
        or private (used in local networks). Uses the ipaddress module to
        classify the IP address based on standard IP address ranges.
        
        Args:
            ip: IP address to check as a string
            
        Returns:
            True if IP is public, False if private or invalid
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            return not ip_obj.is_private
        except ValueError:
            return False

    def resolve_subdomains(self, base_domain: str, subdomains: List[str]) -> List[Tuple[str, List[str]]]:
        """Resolve multiple subdomains concurrently.
        
        Performs concurrent DNS resolution for a list of subdomains to improve performance.
        Uses a thread pool to execute multiple DNS queries in parallel, respecting the
        configured maximum number of workers.
        
        Args:
            base_domain: Base domain name (e.g., example.com)
            subdomains: List of subdomain prefixes (e.g., ["www", "mail", "api"])
            
        Returns:
            List of tuples (subdomain, ip_addresses) for successfully resolved subdomains
        """
        results = []
        full_domains = [f"{sub}.{base_domain}" for sub in subdomains]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_domain = {
                executor.submit(self._resolve_single_domain, domain): domain
                for domain in full_domains
            }
            
            for future in concurrent.futures.as_completed(future_to_domain):
                domain = future_to_domain[future]
                try:
                    ips = future.result()
                    if ips:
                        results.append((domain, ips))
                except Exception as e:
                    self.logger.debug(f"Error resolving {domain}: {e}")
        
        return results
    
    def _resolve_single_domain(self, domain: str) -> List[str]:
        """Resolve a single domain with error handling.
        
        Helper method used by resolve_subdomains for concurrent resolution.
        Wraps the resolve_domain method with additional error handling to
        ensure that exceptions don't propagate to the thread pool.
        
        Args:
            domain: Domain name to resolve
            
        Returns:
            List of IP addresses or empty list if resolution fails
        """
        try:
            return self.resolve_domain(domain)
        except NetworkError:
            return []
        except Exception as e:
            self.logger.debug(f"Unexpected error resolving {domain}: {e}")
            return []
            
    def scan_common_ports(self, host: str, ports: List[int] = None, 
                         timeout: float = 1.0) -> List[int]:
        """Scan common ports on a host.
        
        Attempts to connect to specified ports on the target host to determine
        if they are open. Uses socket connections with a configurable timeout
        to efficiently check multiple ports.
        
        Args:
            host: Hostname or IP address to scan
            ports: List of ports to scan (default: common web ports [21, 22, 25, 53, 80, 443, 8080, 8443])
            timeout: Connection timeout in seconds
            
        Returns:
            List of open ports found on the host
        """
        if ports is None:
            # Default to common web ports
            ports = [21, 22, 25, 53, 80, 443, 8080, 8443]
        
        open_ports = []
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((host, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except Exception as e:
                self.logger.debug(f"Error scanning port {port} on {host}: {e}")
        
        return open_ports
    
    def scan_ports_for_subdomains(self, subdomains: List[str], 
                                 ports: List[int] = None,
                                 show_progress: bool = True) -> Dict[str, List[int]]:
        """Scan ports for multiple subdomains.
        
        Performs port scanning on multiple subdomains, with optional progress reporting.
        This is a convenience method that calls scan_common_ports for each subdomain
        and aggregates the results.
        
        Args:
            subdomains: List of subdomains to scan
            ports: List of ports to scan (defaults to common web ports)
            show_progress: Whether to show progress indicator
            
        Returns:
            Dictionary mapping subdomains to lists of open ports
        """
        results = {}
        
        with progress_bar(total=len(subdomains), 
                         desc="Scanning ports", 
                         disable=not show_progress) as progress:
            for subdomain in subdomains:
                try:
                    open_ports = self.scan_common_ports(subdomain, ports)
                    if open_ports:
                        results[subdomain] = open_ports
                except Exception as e:
                    self.logger.debug(f"Error scanning ports for {subdomain}: {e}")
                finally:
                    progress.update(1)
        
        return results
    
    def reverse_dns_lookup(self, ip: str) -> Optional[str]:
        """Perform reverse DNS lookup for an IP address.
        
        Attempts to resolve an IP address back to its hostname using reverse DNS lookup.
        Uses the dns.reversename module to create the proper reverse lookup format
        and handles any exceptions that might occur during the lookup process.
        
        Args:
            ip: IP address to look up (e.g., "93.184.216.34")
            
        Returns:
            Hostname as a string or None if lookup fails
        """
        try:
            rev_name = dns.reversename.from_address(ip)
            answers = self.resolver.resolve(rev_name, "PTR")
            if answers:
                return str(answers[0]).rstrip('.')
            return None
        except (dns.exception.DNSException, Exception) as e:
            self.logger.debug(f"Reverse DNS lookup failed for {ip}: {e}")
            return None
    
    def get_network_ranges(self, ips: List[str]) -> List[str]:
        """Group IP addresses into network ranges.
        
        Categorizes a list of IP addresses into their respective network ranges.
        IPv4 addresses are grouped into /24 networks, while IPv6 addresses are
        grouped into /64 networks. This is useful for identifying network segments
        and understanding the network topology of discovered subdomains.
        
        Args:
            ips: List of IP addresses as strings
            
        Returns:
            List of network ranges in CIDR notation, sorted alphabetically
        """
        networks = set()
        
        for ip in ips:
            try:
                # Group into /24 networks
                ip_obj = ipaddress.ip_address(ip)
                if ip_obj.version == 4:
                    network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
                    networks.add(str(network))
                elif ip_obj.version == 6:
                    network = ipaddress.IPv6Network(f"{ip}/64", strict=False)
                    networks.add(str(network))
            except ValueError:
                continue
        
        return sorted(list(networks))