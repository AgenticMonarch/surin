"""
Integration tests for the discovery manager.
"""
import pytest
from unittest.mock import patch, MagicMock
import json
import os

from surin.core.discovery_manager import DiscoveryManager
from surin.core.interfaces import DiscoveryModule, Result
from surin.core.exceptions import DiscoveryError


class MockDiscoveryModule(DiscoveryModule):
    """Mock discovery module for testing."""
    
    def __init__(self, domain, **kwargs):
        super().__init__(domain, **kwargs)
        self.should_fail = kwargs.get('should_fail', False)
        self.mock_subdomains = kwargs.get('mock_subdomains', [])
    
    def discover(self):
        if self.should_fail:
            raise DiscoveryError("Mock discovery failure")
        return self.mock_subdomains
    
    def validate(self):
        return True


class TestDiscoveryManagerIntegration:
    """Integration tests for the discovery manager."""
    
    @pytest.fixture
    def mock_modules(self):
        """Create mock discovery modules."""
        return {
            'dns': MockDiscoveryModule,
            'crt': MockDiscoveryModule,
            'hackertarget': MockDiscoveryModule,
            'threatcrowd': MockDiscoveryModule,
            'virustotal': MockDiscoveryModule
        }
    
    @pytest.fixture
    def mock_subdomains(self):
        """Create mock subdomain data."""
        return {
            'dns': [
                'www.example.com',
                'api.example.com',
                'mail.example.com'
            ],
            'crt': [
                'www.example.com',
                'secure.example.com',
                'login.example.com'
            ],
            'hackertarget': [
                'www.example.com',
                'dev.example.com'
            ],
            'threatcrowd': [
                'www.example.com',
                'blog.example.com'
            ],
            'virustotal': [
                'www.example.com',
                'cdn.example.com'
            ]
        }
    
    @patch('surin.core.discovery_manager.DNSUtils')
    @patch('surin.core.discovery_manager.HTTPUtils')
    def test_discovery_manager_with_mock_modules(self, mock_http_utils, mock_dns_utils, mock_modules, mock_subdomains):
        """Test discovery manager with mock modules."""
        # Setup mock DNS utils
        mock_dns_instance = MagicMock()
        mock_dns_instance.validate_domain.return_value = True
        mock_dns_instance.resolve_domain.return_value = ["93.184.216.34"]
        mock_dns_instance.is_ip_public.return_value = True
        mock_dns_instance.scan_ports_for_subdomains.return_value = {
            'www.example.com': [80, 443]
        }
        mock_dns_instance.get_network_ranges.return_value = ["93.184.216.0/24"]
        mock_dns_utils.return_value = mock_dns_instance
        
        # Setup mock HTTP utils
        mock_http_instance = MagicMock()
        mock_http_instance.check_website.return_value = {
            'http_status': 200,
            'https_status': 200,
            'http_headers': {},
            'https_headers': {}
        }
        mock_http_utils.return_value = mock_http_instance
        
        # Create discovery manager
        manager = DiscoveryManager("example.com", methods=['dns', 'crt', 'hackertarget'], verbose=False)
        
        # Replace module loading with our mock modules
        def register_mock_module(name, module_class, **kwargs):
            mock_subdomains_for_module = mock_subdomains.get(name, [])
            manager.modules[name] = MockDiscoveryModule(
                "example.com", 
                mock_subdomains=mock_subdomains_for_module,
                **kwargs
            )
        
        # Patch the register_module method
        with patch.object(manager, 'register_module', side_effect=register_mock_module):
            manager.load_modules()
        
        # Execute discovery
        result = manager.discover()
        
        # Verify results
        assert isinstance(result, Result)
        assert len(result.subdomains) == 7  # Total unique subdomains across methods
        
        # Check that subdomains were discovered by the correct methods
        assert 'www.example.com' in result.subdomains
        assert set(result.subdomains['www.example.com'].discovery_methods) == {'dns', 'crt', 'hackertarget'}
        
        assert 'api.example.com' in result.subdomains
        assert result.subdomains['api.example.com'].discovery_methods == ['dns']
        
        assert 'secure.example.com' in result.subdomains
        assert result.subdomains['secure.example.com'].discovery_methods == ['crt']
        
        assert 'dev.example.com' in result.subdomains
        assert result.subdomains['dev.example.com'].discovery_methods == ['hackertarget']
        
        # Check that enrichment was performed
        assert result.subdomains['www.example.com'].ip_addresses == ["93.184.216.34"]
        assert result.subdomains['www.example.com'].is_public is True
        assert result.subdomains['www.example.com'].http_status == 200
        assert result.subdomains['www.example.com'].https_status == 200
        
        # Check statistics
        assert result.stats['total_subdomains'] == 7
        assert result.stats['unique_ips'] > 0
        assert result.stats['public_ips'] > 0
        assert result.stats['network_ranges'] == ["93.184.216.0/24"]
        
        # Check method statistics
        assert result.stats['methods']['dns']['count'] == 3
        assert result.stats['methods']['crt']['count'] == 3
        assert result.stats['methods']['hackertarget']['count'] == 2
    
    @patch('surin.core.discovery_manager.DNSUtils')
    @patch('surin.core.discovery_manager.HTTPUtils')
    def test_discovery_manager_with_failing_module(self, mock_http_utils, mock_dns_utils, mock_modules):
        """Test discovery manager with a failing module."""
        # Setup mock DNS utils
        mock_dns_instance = MagicMock()
        mock_dns_instance.validate_domain.return_value = True
        mock_dns_utils.return_value = mock_dns_instance
        
        # Setup mock HTTP utils
        mock_http_instance = MagicMock()
        mock_http_utils.return_value = mock_http_instance
        
        # Create discovery manager
        manager = DiscoveryManager("example.com", methods=['dns', 'crt'], verbose=False)
        
        # Register modules with one failing
        manager.modules['dns'] = MockDiscoveryModule(
            "example.com", 
            mock_subdomains=['www.example.com', 'api.example.com']
        )
        manager.modules['crt'] = MockDiscoveryModule(
            "example.com", 
            should_fail=True
        )
        
        # Execute discovery
        result = manager.discover()
        
        # Verify results
        assert isinstance(result, Result)
        assert len(result.subdomains) == 2  # Only from DNS module
        
        # Check that subdomains were discovered by the correct methods
        assert 'www.example.com' in result.subdomains
        assert result.subdomains['www.example.com'].discovery_methods == ['dns']
        
        assert 'api.example.com' in result.subdomains
        assert result.subdomains['api.example.com'].discovery_methods == ['dns']
        
        # Check method statistics
        assert result.stats['methods']['dns']['count'] == 2
        assert result.stats['methods']['crt']['count'] == 0