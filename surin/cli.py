"""Command-line interface for SURIN."""

import argparse
import sys
import logging
from typing import List, Dict, Any, Optional

from surin.core.exceptions import ValidationError
from surin.core.interfaces import Result
from surin.utils.error_handler import ErrorHandler
from surin.utils.dns_utils import DNSUtils


class CLI:
    """Command-line interface for SURIN."""

    def __init__(self):
        """Initialize the CLI."""
        self.parser = self._create_parser()
        self.error_handler = ErrorHandler()
        self.dns_utils = DNSUtils()
        self.logger = logging.getLogger('surin.cli')

    def _create_parser(self) -> argparse.ArgumentParser:
        """Create argument parser with all options.
        
        Returns:
            Configured argument parser
        """
        parser = argparse.ArgumentParser(
            prog='surin',
            description='SURIN - Subdomain Utility for Rapid Identification and Naming',
            epilog='Example: surin example.com --methods dns,crt'
        )
        
        # Required arguments
        parser.add_argument(
            'domain',
            help='Target domain to discover subdomains for'
        )
        
        # Discovery method options
        parser.add_argument(
            '--methods',
            help='Comma-separated list of discovery methods to use (default: all)',
            default=None
        )
        
        # Scan mode options
        parser.add_argument(
            '--scan-mode',
            choices=['fast', 'deep'],
            default='fast',
            help='Scan mode: fast (subdomain names only) or deep (with IP resolution and additional checks) (default: fast)'
        )
        
        # Output options
        parser.add_argument(
            '--output',
            choices=['text', 'json', 'csv'],
            default='text',
            help='Output format (default: text)'
        )
        
        parser.add_argument(
            '--output-file',
            help='Write output to file instead of stdout'
        )
        
        parser.add_argument(
            '--show-ip',
            action='store_true',
            help='Show IP addresses in fast scan mode (default: False)'
        )
        
        # Concurrency options
        parser.add_argument(
            '--concurrency',
            type=int,
            default=10,
            help='Maximum number of concurrent operations (default: 10)'
        )
        
        # API key options
        parser.add_argument(
            '--virustotal-key',
            help='VirusTotal API key'
        )
        
        # Verbosity options
        parser.add_argument(
            '-v', '--verbose',
            action='store_true',
            help='Enable verbose output'
        )
        
        parser.add_argument(
            '-q', '--quiet',
            action='store_true',
            help='Suppress all non-error output'
        )
        
        # Version
        parser.add_argument(
            '--version',
            action='version',
            version='%(prog)s 1.0.0'
        )
        
        return parser

    def parse_arguments(self, args: Optional[List[str]] = None) -> argparse.Namespace:
        """Parse command-line arguments.
        
        Args:
            args: Command-line arguments (None for sys.argv)
            
        Returns:
            Parsed arguments namespace
        """
        parsed_args = self.parser.parse_args(args)
        
        # Process methods
        if parsed_args.methods:
            parsed_args.methods = [m.strip() for m in parsed_args.methods.split(',')]
        
        return parsed_args

    def validate_input(self, args: argparse.Namespace) -> bool:
        """Validate user input.
        
        Args:
            args: Parsed arguments namespace
            
        Returns:
            True if input is valid
            
        Raises:
            ValidationError: If input is invalid
        """
        # Validate domain
        try:
            self.dns_utils.validate_domain(args.domain)
        except ValidationError as e:
            self.error_handler.handle_error('input', str(e))
            return False
        
        # Validate concurrency
        if args.concurrency < 1:
            self.error_handler.handle_error(
                'input', "Concurrency must be at least 1")
            return False
        
        # Validate conflicting options
        if args.verbose and args.quiet:
            self.error_handler.handle_error(
                'input', "Cannot specify both --verbose and --quiet")
            return False
        
        return True

    def display_results(self, result: Result, output_format: str, 
                       output_file: Optional[str] = None, scan_mode: str = 'fast',
                       show_ip: bool = False) -> None:
        """Display results in the specified format.
        
        Args:
            result: Discovery results
            output_format: Output format (text, json, csv)
            output_file: Optional output file path
            scan_mode: Scan mode ('fast' or 'deep')
            show_ip: Whether to show IP addresses in fast scan mode
        """
        from surin.utils.formatters import write_output
        write_output(result, output_format, output_file, scan_mode=scan_mode, show_ip=show_ip)

    def display_summary(self, result: Result) -> None:
        """Display summary of results.
        
        Args:
            result: Discovery results
        """
        print(f"\nSummary:")
        print(f"Total subdomains discovered: {result.stats['total_subdomains']}")
        
        if 'unique_ips' in result.stats:
            print(f"Unique IP addresses: {result.stats['unique_ips']}")
        
        if 'public_ips' in result.stats and 'private_ips' in result.stats:
            print(f"Public IPs: {result.stats['public_ips']}")
            print(f"Private IPs: {result.stats['private_ips']}")
        
        if 'methods' in result.stats:
            print("\nDiscovery method statistics:")
            for method_name, method_stats in result.stats['methods'].items():
                if 'count' in method_stats:
                    print(f"  {method_name}: {method_stats['count']} subdomains")


def main():
    """Main entry point for the CLI."""
    cli = CLI()
    args = cli.parse_arguments()
    
    # Configure error handler based on verbosity
    error_handler = ErrorHandler(verbose=args.verbose)
    
    try:
        if cli.validate_input(args):
            # Import here to avoid circular imports
            from surin.core.discovery_manager import DiscoveryManager
            
            # Create discovery manager
            manager = DiscoveryManager(
                domain=args.domain,
                methods=args.methods,
                concurrency=args.concurrency,
                error_handler=error_handler,
                enrich=args.scan_mode == 'deep',
                show_ip=args.show_ip,
                scan_mode=args.scan_mode,
                verbose=args.verbose
            )
            
            # Set API keys
            manager.set_api_keys(
                virustotal_api_key=args.virustotal_key
            )
            
            # Load discovery modules
            manager.load_modules()
            
            # Execute discovery
            result = manager.discover()
            
            # Display results
            cli.display_results(result, args.output, args.output_file, 
                              scan_mode=args.scan_mode, show_ip=args.show_ip)
            
            # Display summary if not quiet
            if not args.quiet:
                cli.display_summary(result)
                
            return 0
    except Exception as e:
        error_handler.handle_error('unexpected', "An unexpected error occurred", e)
        return 1


if __name__ == '__main__':
    main()