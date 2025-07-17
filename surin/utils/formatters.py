"""Output formatters for SURIN."""

import json
import csv
import io
import sys
from typing import Dict, Any, List, TextIO, Optional
from abc import ABC, abstractmethod

from surin.core.interfaces import Result, OutputFormatter


class TextFormatter(OutputFormatter):
    """Format results as plain text."""

    def __init__(self, scan_mode: str = 'fast', show_ip: bool = False):
        """Initialize the text formatter.
        
        Args:
            scan_mode: Scan mode ('fast' or 'deep')
            show_ip: Whether to show IP addresses in fast scan mode
        """
        self.scan_mode = scan_mode
        self.show_ip = show_ip

    def format(self, result: Result) -> str:
        """Format the result as plain text.
        
        Args:
            result: The discovery result to format
            
        Returns:
            Formatted text output
        """
        output = io.StringIO()
        
        # Header
        output.write("SURIN Subdomain Discovery Results\n")
        output.write("=" * 40 + "\n\n")
        
        # Subdomains by method
        methods = set()
        for subdomain in result.subdomains.values():
            methods.update(subdomain.discovery_methods)
        
        for method in sorted(methods):
            output.write(f"Method: {method}\n")
            output.write("-" * 40 + "\n")
            
            # Get subdomains discovered by this method
            method_subdomains = [
                subdomain for subdomain in result.subdomains.values()
                if method in subdomain.discovery_methods
            ]
            
            if not method_subdomains:
                output.write("No subdomains found.\n\n")
                continue
            
            # Sort subdomains by name
            method_subdomains.sort(key=lambda s: s.name)
            
            for subdomain in method_subdomains:
                output.write(f"{subdomain.name}\n")
                
                # In fast scan mode, only show subdomain names and optionally IP addresses
                if self.scan_mode == 'fast':
                    # Show IP addresses if requested
                    if self.show_ip and subdomain.ip_addresses:
                        ips_str = ", ".join(subdomain.ip_addresses)
                        output.write(f"  IP: {ips_str}\n")
                    
                    # Always show discovery methods
                    methods_str = ", ".join(subdomain.discovery_methods)
                    output.write(f"  Discovered by: {methods_str}\n")
                    
                    output.write("\n")
                    continue
                
                # Deep scan mode - show all details
                # IP addresses
                if subdomain.ip_addresses:
                    ips_str = ", ".join(subdomain.ip_addresses)
                    public_private = []
                    for ip in subdomain.ip_addresses:
                        if subdomain.is_public is True:
                            public_private.append("public")
                        elif subdomain.is_public is False:
                            public_private.append("private")
                        else:
                            public_private.append("unknown")
                    
                    ip_types = ", ".join(public_private)
                    output.write(f"  IP: {ips_str} ({ip_types})\n")
                
                # HTTP/HTTPS status
                if subdomain.http_status:
                    output.write(f"  HTTP: {subdomain.http_status}\n")
                if subdomain.https_status:
                    output.write(f"  HTTPS: {subdomain.https_status}\n")
                
                # Open ports
                if subdomain.open_ports:
                    ports_str = ", ".join(map(str, subdomain.open_ports))
                    output.write(f"  Open ports: {ports_str}\n")
                
                # Services
                if subdomain.services:
                    services_str = ", ".join(f"{k}: {v}" for k, v in subdomain.services.items())
                    output.write(f"  Services: {services_str}\n")
                
                # Discovery methods
                methods_str = ", ".join(subdomain.discovery_methods)
                output.write(f"  Discovered by: {methods_str}\n")
                
                output.write("\n")
            
            output.write("\n")
        
        # Summary
        output.write("Summary\n")
        output.write("-" * 40 + "\n")
        output.write(f"Total subdomains: {result.stats['total_subdomains']}\n")
        
        if 'unique_ips' in result.stats:
            output.write(f"Unique IP addresses: {result.stats['unique_ips']}\n")
        
        if 'public_ips' in result.stats and 'private_ips' in result.stats:
            output.write(f"Public IPs: {result.stats['public_ips']}\n")
            output.write(f"Private IPs: {result.stats['private_ips']}\n")
        
        if 'network_ranges' in result.stats and result.stats['network_ranges']:
            output.write("Network ranges:\n")
            for network_range in result.stats['network_ranges']:
                output.write(f"  {network_range}\n")
        
        # Method statistics
        if 'methods' in result.stats:
            output.write("\nDiscovery method statistics:\n")
            for method_name, method_stats in result.stats['methods'].items():
                if 'count' in method_stats:
                    output.write(f"  {method_name}: {method_stats['count']} subdomains\n")
        
        return output.getvalue()


class JSONFormatter(OutputFormatter):
    """Format results as JSON."""

    def format(self, result: Result) -> str:
        """Format the result as JSON.
        
        Args:
            result: The discovery result to format
            
        Returns:
            Formatted JSON output
        """
        # Convert Result to a serializable dictionary
        output = {
            'subdomains': {},
            'stats': result.stats
        }
        
        # Convert Subdomain objects to dictionaries
        for name, subdomain in result.subdomains.items():
            output['subdomains'][name] = {
                'name': subdomain.name,
                'domain': subdomain.domain,
                'ip_addresses': subdomain.ip_addresses,
                'discovery_methods': subdomain.discovery_methods,
                'is_public': subdomain.is_public,
                'http_status': subdomain.http_status,
                'https_status': subdomain.https_status,
                'open_ports': subdomain.open_ports,
                'services': subdomain.services
            }
        
        return json.dumps(output, indent=2)


class CSVFormatter(OutputFormatter):
    """Format results as CSV."""

    def format(self, result: Result) -> str:
        """Format the result as CSV.
        
        Args:
            result: The discovery result to format
            
        Returns:
            Formatted CSV output
        """
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            'Subdomain', 
            'IP Addresses', 
            'Public/Private', 
            'HTTP Status', 
            'HTTPS Status', 
            'Open Ports', 
            'Services', 
            'Discovery Methods'
        ])
        
        # Write data rows
        for name, subdomain in sorted(result.subdomains.items()):
            ip_addresses = ', '.join(subdomain.ip_addresses) if subdomain.ip_addresses else ''
            
            public_private = ''
            if subdomain.is_public is not None:
                public_private = 'Public' if subdomain.is_public else 'Private'
            
            http_status = str(subdomain.http_status) if subdomain.http_status else ''
            https_status = str(subdomain.https_status) if subdomain.https_status else ''
            
            open_ports = ', '.join(map(str, subdomain.open_ports)) if subdomain.open_ports else ''
            
            services = ', '.join(f"{k}:{v}" for k, v in subdomain.services.items()) if subdomain.services else ''
            
            discovery_methods = ', '.join(subdomain.discovery_methods) if subdomain.discovery_methods else ''
            
            writer.writerow([
                subdomain.name,
                ip_addresses,
                public_private,
                http_status,
                https_status,
                open_ports,
                services,
                discovery_methods
            ])
        
        return output.getvalue()


class FormatterFactory:
    """Factory for creating output formatters."""
    
    @staticmethod
    def create_formatter(format_type: str, scan_mode: str = 'fast', show_ip: bool = False) -> OutputFormatter:
        """Create an output formatter based on the format type.
        
        Args:
            format_type: Type of formatter (text, json, csv)
            scan_mode: Scan mode ('fast' or 'deep')
            show_ip: Whether to show IP addresses in fast scan mode
            
        Returns:
            OutputFormatter instance
            
        Raises:
            ValueError: If format type is invalid
        """
        if format_type == 'text':
            return TextFormatter(scan_mode=scan_mode, show_ip=show_ip)
        elif format_type == 'json':
            return JSONFormatter()
        elif format_type == 'csv':
            return CSVFormatter()
        else:
            raise ValueError(f"Invalid format type: {format_type}")


def write_output(result: Result, format_type: str, output_file: Optional[str] = None, 
               scan_mode: str = 'fast', show_ip: bool = False) -> None:
    """Write formatted output to file or stdout.
    
    Args:
        result: Discovery result
        format_type: Output format (text, json, csv)
        output_file: Optional output file path
        scan_mode: Scan mode ('fast' or 'deep')
        show_ip: Whether to show IP addresses in fast scan mode
    """
    formatter = FormatterFactory.create_formatter(format_type, scan_mode=scan_mode, show_ip=show_ip)
    formatted_output = formatter.format(result)
    
    if output_file:
        with open(output_file, 'w') as f:
            f.write(formatted_output)
    else:
        sys.stdout.write(formatted_output)