"""
Unit tests for DNS utilities.
"""
import pytest
from unittest.mock import patch, MagicMock
import socket
import ipaddress
from dns.resolver import NXDOMAIN, NoAnswer, Timeout, NoNameservers

from surin.utils.dns_utils import DNSUtils
from surin.core.exceptions import ValidationError, NetworkError


class TestDNSUtils:
    """Test DNS utility functions."""

    def test_validate_domain_valid(self):
        """Test domain validation with valid domains."""
        dns_utils = DNSUtils()
        
        # Test valid domains
        assert dns_utils.validate_domain("example.com") is True
        assert dns_utils.validate_domain("sub.example.com") is True
        assert dns_utils.validate_domain("sub-domain.example.com") is True
        assert dns_utils.validate_domain("example.co.uk") is True

    def test_validate_domain_invalid(self):
        """Test domain validation with invalid domains."""
        dns_utils = DNSUtils()
        
        # Test invalid domains
        with pytest.raises(ValidationError):
            dns_utils.validate_domain("")
        
        with pytest.raises(ValidationError):
            dns_utils.validate_domain(None)
        
        with pytest.raises(ValidationError):
            dns_utils.validate_domain("invalid")
        
        with pytest.raises(ValidationError):
            dns_utils.validate_domain("invalid..")
        
        with pytest.raises(ValidationError):
            dns_utils.validate_domain(".com")
        
        with pytest.raises(ValidationError):
            dns_utils.validate_domain("example..com")

    @patch('surin.utils.dns_utils.Resolver')
    def test_resolve_domain_success(self, mock_resolver):
        """Test successful domain resolution."""
        # Setup mock
        mock_answer = MagicMock()
        mock_answer.to_text.return_value = "93.184.216.34"
        mock_answers = [mock_answer]
        
        mock_resolver_instance = MagicMock()
        mock_resolver_instance.resolve.return_value = mock_answers
        mock_resolver.return_value = mock_resolver_instance
        
        # Test
        dns_utils = DNSUtils()
        result = dns_utils.resolve_domain("example.com")
        
        # Verify
        assert result == ["93.184.216.34"]
        mock_resolver_instance.resolve.assert_called_once_with("example.com", 'A')

    @patch('surin.utils.dns_utils.Resolver')
    def test_resolve_domain_nxdomain(self, mock_resolver):
        """Test domain resolution with NXDOMAIN."""
        # Setup mock
        mock_resolver_instance = MagicMock()
        mock_resolver_instance.resolve.side_effect = NXDOMAIN()
        mock_resolver.return_value = mock_resolver_instance
        
        # Test
        dns_utils = DNSUtils()
        result = dns_utils.resolve_domain("nonexistent.example.com")
        
        # Verify
        assert result == []

    @patch('surin.utils.dns_utils.Resolver')
    def test_resolve_domain_timeout(self, mock_resolver):
        """Test domain resolution with timeout."""
        # Setup mock
        mock_resolver_instance = MagicMock()
        mock_resolver_instance.resolve.side_effect = Timeout()
        mock_resolver.return_value = mock_resolver_instance
        
        # Test
        dns_utils = DNSUtils()
        with pytest.raises(NetworkError):
            dns_utils.resolve_domain("slow.example.com")

    def test_is_ip_public(self):
        """Test IP address public/private detection."""
        dns_utils = DNSUtils()
        
        # Public IPs
        assert dns_utils.is_ip_public("8.8.8.8") is True
        assert dns_utils.is_ip_public("93.184.216.34") is True
        
        # Private IPs
        assert dns_utils.is_ip_public("192.168.1.1") is False
        assert dns_utils.is_ip_public("10.0.0.1") is False
        assert dns_utils.is_ip_public("172.16.0.1") is False
        
        # Invalid IP
        assert dns_utils.is_ip_public("invalid") is False

    @patch('surin.utils.dns_utils.DNSUtils._resolve_single_domain')
    def test_resolve_subdomains(self, mock_resolve):
        """Test concurrent subdomain resolution."""
        # Setup mock
        mock_resolve.side_effect = [
            ["93.184.216.34"],  # www.example.com
            ["93.184.216.35"],  # api.example.com
            [],                 # nonexistent.example.com
            ["93.184.216.36"]   # mail.example.com
        ]
        
        # Test
        dns_utils = DNSUtils()
        result = dns_utils.resolve_subdomains(
            "example.com", 
            ["www", "api", "nonexistent", "mail"]
        )
        
        # Verify
        assert len(result) == 3
        assert ("www.example.com", ["93.184.216.34"]) in result
        assert ("api.example.com", ["93.184.216.35"]) in result
        assert ("mail.example.com", ["93.184.216.36"]) in result

    @patch('socket.socket')
    def test_scan_common_ports(self, mock_socket):
        """Test port scanning."""
        # Setup mock
        mock_socket_instance = MagicMock()
        mock_socket.return_value = mock_socket_instance
        
        # Mock successful connection to ports 80 and 443
        mock_socket_instance.connect_ex.side_effect = [0, 1, 0, 1]
        
        # Test
        dns_utils = DNSUtils()
        result = dns_utils.scan_common_ports("example.com", [80, 22, 443, 8080])
        
        # Verify
        assert result == [80, 443]
        assert mock_socket_instance.connect_ex.call_count == 4

    @patch('surin.utils.dns_utils.Resolver')
    def test_reverse_dns_lookup(self, mock_resolver):
        """Test reverse DNS lookup."""
        # Setup mock
        mock_answer = MagicMock()
        mock_answer.__str__.return_value = "example.com."
        mock_answers = [mock_answer]
        
        mock_resolver_instance = MagicMock()
        mock_resolver_instance.resolve.return_value = mock_answers
        mock_resolver.return_value = mock_resolver_instance
        
        # Test
        dns_utils = DNSUtils()
        result = dns_utils.reverse_dns_lookup("93.184.216.34")
        
        # Verify
        assert result == "example.com"
        assert mock_resolver_instance.resolve.call_count == 1

    def test_get_network_ranges(self):
        """Test IP network range grouping."""
        dns_utils = DNSUtils()
        
        # Test with IPv4 addresses
        ips = [
            "192.168.1.1",
            "192.168.1.2",
            "192.168.2.1",
            "10.0.0.1"
        ]
        
        result = dns_utils.get_network_ranges(ips)
        
        # Verify
        assert len(result) == 3
        assert "192.168.1.0/24" in result
        assert "192.168.2.0/24" in result
        assert "10.0.0.0/24" in result
        
        # Test with invalid IPs
        result = dns_utils.get_network_ranges(["invalid", "192.168.1.1"])
        assert len(result) == 1
        assert "192.168.1.0/24" in result