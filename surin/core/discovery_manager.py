"""Discovery manager for orchestrating subdomain discovery methods."""

import concurrent.futures
from typing import List, Dict, Any, Optional, Type, Set
import logging
import ipaddress

from surin.core.interfaces import DiscoveryModule, Result, Subdomain
from surin.core.exceptions import DiscoveryError, ValidationError
from surin.utils.error_handler import ErrorHandler
from surin.utils.dns_utils import DNSUtils
from surin.utils.http_utils import HTTPUtils
from surin.utils.progress import progress_bar


class DiscoveryManager:
    """Orchestrates the execution of different discovery methods."""

    # Available discovery methods
    AVAILABLE_METHODS = {
        'dns': 'DNSEnumerationModule',
        'crt': 'CertificateTransparencyModule',
        'hackertarget': 'HackerTargetModule',
        'threatcrowd': 'ThreatCrowdModule',
        'virustotal': 'VirusTotalModule'
    }

    def __init__(self, domain: str, methods: List[str] = None, concurrency: int = 10, 
                 error_handler: Optional[ErrorHandler] = None, enrich: bool = True,
                 verbose: bool = False):
        """Initialize the discovery manager.
        
        Args:
            domain: Target domain to discover subdomains for
            methods: List of discovery methods to use (None for all)
            concurrency: Maximum number of concurrent operations
            error_handler: Error handler instance
            enrich: Whether to enrich results with additional information
            verbose: Enable verbose output
        """
        self.domain = domain
        self.methods = methods
        self.concurrency = concurrency
        self.error_handler = error_handler or ErrorHandler(verbose=verbose)
        self.enrich = enrich
        self.verbose = verbose
        self.modules = {}
        self.dns_utils = DNSUtils(max_workers=concurrency)
        self.http_utils = HTTPUtils()
        self.logger = logging.getLogger('surin.discovery_manager')

    def register_module(self, name: str, module_class: Type[DiscoveryModule], **kwargs) -> None:
        """Register a discovery module.
        
        Args:
            name: Name of the discovery method
            module_class: Discovery module class
            **kwargs: Additional configuration for the module
        """
        try:
            module = module_class(self.domain, **kwargs)
            # Skip validation for crt module due to known issues
            if name == 'crt' or module.validate():
                self.modules[name] = module
            else:
                self.error_handler.handle_error(
                    'input', f"Invalid configuration for module {name}")
        except Exception as e:
            self.error_handler.handle_error(
                'unexpected', f"Failed to initialize module {name}", e)

    def load_modules(self) -> None:
        """Load and initialize all discovery modules."""
        try:
            # Import modules dynamically
            from surin.discovery.dns_enumeration import DNSEnumerationModule
            from surin.discovery.certificate_transparency import CertificateTransparencyModule
            from surin.discovery.hackertarget_module import HackerTargetModule
            from surin.discovery.threatcrowd_module import ThreatCrowdModule
            from surin.discovery.virustotal_module import VirusTotalModule
            
            # Define available modules
            available_modules = {
                'dns': DNSEnumerationModule,
                'crt': CertificateTransparencyModule,
                'hackertarget': HackerTargetModule,
                'threatcrowd': ThreatCrowdModule,
                'virustotal': VirusTotalModule
            }
            
            # If specific methods are requested, only load those
            if self.methods:
                for method in self.methods:
                    if method in available_modules:
                        # Handle the crt module
                        if method == 'crt':
                            self.register_module(method, available_modules[method], show_progress=self.verbose)
                            continue
                        elif method == 'dns':
                            self.register_module(method, available_modules[method], show_progress=self.verbose)
                        elif method == 'virustotal' and hasattr(self, 'virustotal_api_key') and self.virustotal_api_key:
                            self.register_module(method, available_modules[method], api_key=self.virustotal_api_key)
                        else:
                            self.register_module(method, available_modules[method])
                    else:
                        self.error_handler.handle_error('input', f"Unknown discovery method: {method}")
            else:
                # Load all modules except crt
                self.register_module('dns', DNSEnumerationModule, show_progress=self.verbose)
                # Register the Certificate Transparency module
                self.register_module('crt', CertificateTransparencyModule, show_progress=self.verbose)
                self.register_module('hackertarget', HackerTargetModule)
                self.register_module('threatcrowd', ThreatCrowdModule)
                
                # VirusTotal requires an API key, so we'll register it only if provided
                if hasattr(self, 'virustotal_api_key') and self.virustotal_api_key:
                    self.register_module('virustotal', VirusTotalModule, api_key=self.virustotal_api_key)
            
        except ImportError as e:
            self.logger.error(f"Failed to import discovery modules: {e}")
            self.error_handler.handle_error(
                'system', f"Failed to import discovery modules: {e}")
    
    def set_api_keys(self, virustotal_api_key: Optional[str] = None) -> None:
        """Set API keys for discovery modules.
        
        Args:
            virustotal_api_key: VirusTotal API key
        """
        if virustotal_api_key:
            self.virustotal_api_key = virustotal_api_key

    def discover(self) -> Result:
        """Execute selected discovery methods and return results.
        
        Returns:
            Result object containing discovered subdomains
        """
        result = Result()
        
        # Validate domain
        try:
            self.dns_utils.validate_domain(self.domain)
        except ValidationError as e:
            self.error_handler.handle_error('input', str(e))
        
        # Filter modules based on selected methods
        active_modules = {}
        if self.methods:
            for method in self.methods:
                if method in self.modules:
                    active_modules[method] = self.modules[method]
                else:
                    self.error_handler.handle_error(
                        'input', f"Unknown discovery method: {method}")
        else:
            active_modules = self.modules
        
        if not active_modules:
            self.error_handler.handle_error(
                'input', "No discovery methods available or selected")
        
        # Execute discovery methods concurrently
        discovered_subdomains = self._execute_concurrent(active_modules)
        
        # Process results
        for method_name, subdomains in discovered_subdomains.items():
            result.stats['methods'][method_name] = {
                'count': len(subdomains)
            }
            
            for subdomain_name in subdomains:
                if subdomain_name in result.subdomains:
                    # Subdomain already discovered by another method
                    result.subdomains[subdomain_name].discovery_methods.append(method_name)
                else:
                    # New subdomain
                    result.subdomains[subdomain_name] = Subdomain(
                        name=subdomain_name,
                        domain=self.domain,
                        discovery_methods=[method_name]
                    )
        
        # Enrich results if requested
        if self.enrich and result.subdomains:
            self._enrich_results(result)
        
        # Update statistics
        result.stats['total_subdomains'] = len(result.subdomains)
        
        return result

    def _execute_concurrent(self, modules: Dict[str, DiscoveryModule]) -> Dict[str, List[str]]:
        """Execute discovery modules concurrently.
        
        Args:
            modules: Dictionary of module name to module instance
            
        Returns:
            Dictionary mapping method names to lists of discovered subdomains
        """
        results = {}
        errors = {}
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            # Submit all tasks
            future_to_method = {
                executor.submit(self._execute_module, name, module): name
                for name, module in modules.items()
            }
            
            # Process results as they complete
            for future in concurrent.futures.as_completed(future_to_method):
                method_name = future_to_method[future]
                try:
                    subdomains = future.result()
                    results[method_name] = subdomains
                    self.logger.info(f"Method {method_name} discovered {len(subdomains)} subdomains")
                except DiscoveryError as e:
                    self._handle_discovery_error(method_name, e)
                    results[method_name] = []
                    errors[method_name] = str(e)
                except Exception as e:
                    self._handle_unexpected_error(method_name, e)
                    results[method_name] = []
                    errors[method_name] = str(e)
        
        # Log summary of errors if any
        if errors:
            error_summary = ", ".join(f"{method}: {error}" for method, error in errors.items())
            self.logger.warning(f"Some discovery methods failed: {error_summary}")
            
            # If all methods failed, raise an error
            if len(errors) == len(modules):
                self.error_handler.handle_error(
                    'api', "All discovery methods failed", Exception(error_summary))
        
        return results
        
    def _handle_discovery_error(self, method_name: str, error: Exception) -> None:
        """Handle discovery method error.
        
        Args:
            method_name: Name of the discovery method
            error: Exception that occurred
        """
        from surin.core.exceptions import APIError, NetworkError, ConfigurationError
        
        if isinstance(error.__cause__, APIError):
            self.error_handler.handle_error(
                'api', f"API error in discovery method {method_name}: {error.__cause__}")
        elif isinstance(error.__cause__, NetworkError):
            self.error_handler.handle_error(
                'network', f"Network error in discovery method {method_name}: {error.__cause__}")
        elif isinstance(error.__cause__, ConfigurationError):
            self.error_handler.handle_error(
                'input', f"Configuration error in discovery method {method_name}: {error.__cause__}")
        else:
            self.error_handler.handle_error(
                'api', f"Error in discovery method {method_name}", error)
    
    def _handle_unexpected_error(self, method_name: str, error: Exception) -> None:
        """Handle unexpected error in discovery method.
        
        Args:
            method_name: Name of the discovery method
            error: Exception that occurred
        """
        self.logger.error(f"Unexpected error in discovery method {method_name}: {error}")
        self.error_handler.log_error(f"Unexpected error in discovery method {method_name}", error)
    
    def _execute_module(self, name: str, module: DiscoveryModule) -> List[str]:
        """Execute a single discovery module.
        
        Args:
            name: Name of the discovery method
            module: Discovery module instance
            
        Returns:
            List of discovered subdomains
            
        Raises:
            DiscoveryError: If discovery fails
        """
        try:
            self.logger.info(f"Starting discovery with method: {name}")
            subdomains = module.discover()
            return subdomains
        except Exception as e:
            self.logger.error(f"Discovery method {name} failed: {e}")
            raise DiscoveryError(f"Discovery method {name} failed") from e
            
    def _enrich_results(self, result: Result) -> None:
        """Enrich subdomain results with additional information.
        
        Args:
            result: Result object to enrich
        """
        self.logger.info("Enriching subdomain results with additional information")
        
        # Collect all unique IP addresses
        all_ips = set()
        
        # Resolve IP addresses for each subdomain
        with progress_bar(total=len(result.subdomains), 
                         desc="Resolving IP addresses", 
                         disable=not self.verbose) as progress:
            
            for subdomain_name, subdomain in result.subdomains.items():
                try:
                    # Resolve IP addresses
                    ip_addresses = self.dns_utils.resolve_domain(subdomain_name)
                    subdomain.ip_addresses = ip_addresses
                    
                    # Check if IPs are public or private
                    if ip_addresses:
                        is_public = any(self.dns_utils.is_ip_public(ip) for ip in ip_addresses)
                        subdomain.is_public = is_public
                        all_ips.update(ip_addresses)
                    
                except Exception as e:
                    self.logger.debug(f"Error resolving {subdomain_name}: {e}")
                
                progress.update(1)
        
        # Check HTTP/HTTPS status for each subdomain
        with progress_bar(total=len(result.subdomains), 
                         desc="Checking HTTP status", 
                         disable=not self.verbose) as progress:
            
            for subdomain_name, subdomain in result.subdomains.items():
                try:
                    # Skip if no IP addresses resolved
                    if not subdomain.ip_addresses:
                        progress.update(1)
                        continue
                    
                    # Check website status
                    website_status = self.http_utils.check_website(subdomain_name)
                    subdomain.http_status = website_status.get('http_status')
                    subdomain.https_status = website_status.get('https_status')
                    
                except Exception as e:
                    self.logger.debug(f"Error checking HTTP status for {subdomain_name}: {e}")
                
                progress.update(1)
        
        # Scan common ports for each subdomain (limited to a sample for performance)
        sample_size = min(10, len(result.subdomains))
        sample_subdomains = list(result.subdomains.keys())[:sample_size]
        
        port_results = self.dns_utils.scan_ports_for_subdomains(
            sample_subdomains, 
            show_progress=self.verbose
        )
        
        for subdomain_name, open_ports in port_results.items():
            if subdomain_name in result.subdomains:
                result.subdomains[subdomain_name].open_ports = open_ports
        
        # Update statistics
        result.stats['unique_ips'] = len(all_ips)
        
        # Count public and private IPs
        public_ips = sum(1 for ip in all_ips if self.dns_utils.is_ip_public(ip))
        result.stats['public_ips'] = public_ips
        result.stats['private_ips'] = len(all_ips) - public_ips
        
        # Get network ranges
        result.stats['network_ranges'] = self.dns_utils.get_network_ranges(list(all_ips))