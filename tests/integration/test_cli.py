"""
Integration tests for the CLI module.
"""
import pytest
from unittest.mock import patch, MagicMock
import sys
import io
import json
import tempfile
import os

from surin.cli import CLI, main
from surin.core.interfaces import Result, Subdomain


class TestCLIIntegration:
    """Integration tests for the CLI module."""
    
    @pytest.fixture
    def mock_result(self):
        """Create a mock result for testing."""
        result = Result()
        
        # Add subdomains
        subdomain1 = Subdomain(
            name="www.example.com",
            domain="example.com",
            ip_addresses=["93.184.216.34"],
            discovery_methods=["DNS", "CT"],
            is_public=True,
            http_status=200,
            https_status=200,
            open_ports=[80, 443],
            services={"http": "nginx"}
        )
        
        subdomain2 = Subdomain(
            name="api.example.com",
            domain="example.com",
            ip_addresses=["93.184.216.35"],
            discovery_methods=["DNS"],
            is_public=True,
            http_status=200,
            https_status=200,
            open_ports=[80, 443],
            services={"http": "apache"}
        )
        
        result.subdomains = {
            "www.example.com": subdomain1,
            "api.example.com": subdomain2
        }
        
        # Add stats
        result.stats = {
            'total_subdomains': 2,
            'unique_ips': 2,
            'public_ips': 2,
            'private_ips': 0,
            'network_ranges': ['93.184.216.0/24'],
            'methods': {
                'DNS': {'count': 2},
                'CT': {'count': 1}
            }
        }
        
        return result
    
    def test_parse_arguments(self):
        """Test argument parsing."""
        cli = CLI()
        
        # Test with minimal arguments
        args = cli.parse_arguments(['example.com'])
        assert args.domain == 'example.com'
        assert args.methods is None
        assert args.output == 'text'
        assert args.output_file is None
        assert args.concurrency == 10
        assert args.verbose is False
        assert args.quiet is False
        
        # Test with all arguments
        args = cli.parse_arguments([
            'example.com',
            '--methods', 'dns,crt',
            '--output', 'json',
            '--output-file', 'output.json',
            '--concurrency', '5',
            '--virustotal-key', 'api_key',
            '--verbose'
        ])
        assert args.domain == 'example.com'
        assert args.methods == ['dns', 'crt']
        assert args.output == 'json'
        assert args.output_file == 'output.json'
        assert args.concurrency == 5
        assert args.virustotal_key == 'api_key'
        assert args.verbose is True
    
    @patch('surin.utils.dns_utils.DNSUtils.validate_domain')
    def test_validate_input_valid(self, mock_validate_domain):
        """Test input validation with valid input."""
        mock_validate_domain.return_value = True
        
        cli = CLI()
        args = cli.parse_arguments(['example.com'])
        
        assert cli.validate_input(args) is True
    
    @patch('surin.utils.dns_utils.DNSUtils.validate_domain')
    def test_validate_input_invalid_domain(self, mock_validate_domain):
        """Test input validation with invalid domain."""
        from surin.core.exceptions import ValidationError
        mock_validate_domain.side_effect = ValidationError("Invalid domain")
        
        cli = CLI()
        args = cli.parse_arguments(['invalid'])
        
        assert cli.validate_input(args) is False
    
    def test_validate_input_invalid_concurrency(self):
        """Test input validation with invalid concurrency."""
        cli = CLI()
        args = cli.parse_arguments(['example.com', '--concurrency', '0'])
        
        assert cli.validate_input(args) is False
    
    def test_validate_input_conflicting_options(self):
        """Test input validation with conflicting options."""
        cli = CLI()
        args = cli.parse_arguments(['example.com', '--verbose', '--quiet'])
        
        assert cli.validate_input(args) is False
    
    @patch('surin.utils.formatters.write_output')
    def test_display_results_stdout(self, mock_write_output, mock_result):
        """Test result display to stdout."""
        cli = CLI()
        cli.display_results(mock_result, 'text', None)
        
        mock_write_output.assert_called_once_with(mock_result, 'text', None)
    
    @patch('surin.utils.formatters.write_output')
    def test_display_results_file(self, mock_write_output, mock_result):
        """Test result display to file."""
        cli = CLI()
        cli.display_results(mock_result, 'json', 'output.json')
        
        mock_write_output.assert_called_once_with(mock_result, 'json', 'output.json')
    
    @patch('builtins.print')
    def test_display_summary(self, mock_print, mock_result):
        """Test summary display."""
        cli = CLI()
        cli.display_summary(mock_result)
        
        # Verify print was called with summary information
        assert mock_print.call_count >= 5
    
    @patch('surin.cli.CLI.validate_input')
    @patch('surin.core.discovery_manager.DiscoveryManager')
    def test_main_success(self, mock_manager_class, mock_validate_input):
        """Test main function with successful execution."""
        # Setup mocks
        mock_validate_input.return_value = True
        
        mock_manager = MagicMock()
        mock_manager.discover.return_value = Result()
        mock_manager_class.return_value = mock_manager
        
        # Test
        with patch.object(sys, 'argv', ['surin', 'example.com']):
            exit_code = main()
        
        # Verify
        assert exit_code == 0
        mock_validate_input.assert_called_once()
        mock_manager.load_modules.assert_called_once()
        mock_manager.discover.assert_called_once()
    
    @patch('surin.cli.CLI.validate_input')
    def test_main_validation_failure(self, mock_validate_input):
        """Test main function with validation failure."""
        # Setup mock
        mock_validate_input.return_value = False
        
        # Test
        with patch.object(sys, 'argv', ['surin', 'invalid']):
            exit_code = main()
        
        # Verify
        assert exit_code == 0  # Still returns 0 as it's a handled error
        mock_validate_input.assert_called_once()
    
    @patch('surin.cli.CLI.validate_input')
    @patch('surin.core.discovery_manager.DiscoveryManager')
    def test_main_unexpected_error(self, mock_manager_class, mock_validate_input):
        """Test main function with unexpected error."""
        # Setup mocks
        mock_validate_input.return_value = True
        
        mock_manager = MagicMock()
        mock_manager.discover.side_effect = Exception("Unexpected error")
        mock_manager_class.return_value = mock_manager
        
        # Test
        with patch.object(sys, 'argv', ['surin', 'example.com']):
            exit_code = main()
        
        # Verify
        assert exit_code == 1
        mock_validate_input.assert_called_once()
        mock_manager.load_modules.assert_called_once()
        mock_manager.discover.assert_called_once()
    
    @patch('surin.cli.CLI.validate_input')
    @patch('surin.core.discovery_manager.DiscoveryManager')
    @patch('surin.utils.formatters.write_output')
    def test_end_to_end_with_mocks(self, mock_write_output, mock_manager_class, mock_validate_input, mock_result):
        """Test end-to-end flow with mocks."""
        # Setup mocks
        mock_validate_input.return_value = True
        
        mock_manager = MagicMock()
        mock_manager.discover.return_value = mock_result
        mock_manager_class.return_value = mock_manager
        
        # Test with JSON output to file
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as temp_file:
            output_file = temp_file.name
        
        try:
            with patch.object(sys, 'argv', [
                'surin', 
                'example.com',
                '--methods', 'dns,crt',
                '--output', 'json',
                '--output-file', output_file
            ]):
                exit_code = main()
            
            # Verify
            assert exit_code == 0
            mock_validate_input.assert_called_once()
            mock_manager.load_modules.assert_called_once()
            mock_manager.discover.assert_called_once()
            mock_write_output.assert_called_once_with(mock_result, 'json', output_file)
            
        finally:
            # Clean up
            if os.path.exists(output_file):
                os.unlink(output_file)