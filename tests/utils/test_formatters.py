"""
Unit tests for output formatters.
"""
import pytest
import json
import csv
import io
from unittest.mock import patch, mock_open

from surin.utils.formatters import (
    TextFormatter, JSONFormatter, CSVFormatter, 
    FormatterFactory, write_output
)
from surin.core.interfaces import Result, Subdomain


class TestFormatters:
    """Test output formatters."""

    @pytest.fixture
    def sample_result(self):
        """Create a sample result for testing."""
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
        
        subdomain3 = Subdomain(
            name="internal.example.com",
            domain="example.com",
            ip_addresses=["192.168.1.1"],
            discovery_methods=["HackerTarget"],
            is_public=False,
            http_status=None,
            https_status=None,
            open_ports=[22],
            services={"ssh": "OpenSSH"}
        )
        
        result.subdomains = {
            "www.example.com": subdomain1,
            "api.example.com": subdomain2,
            "internal.example.com": subdomain3
        }
        
        # Add stats
        result.stats = {
            'total_subdomains': 3,
            'unique_ips': 3,
            'public_ips': 2,
            'private_ips': 1,
            'network_ranges': ['93.184.216.0/24', '192.168.1.0/24'],
            'methods': {
                'DNS': {'count': 2},
                'CT': {'count': 1},
                'HackerTarget': {'count': 1}
            }
        }
        
        return result

    def test_text_formatter(self, sample_result):
        """Test text formatter output."""
        formatter = TextFormatter()
        output = formatter.format(sample_result)
        
        # Check header
        assert "SURIN Subdomain Discovery Results" in output
        
        # Check method sections
        assert "Method: CT" in output
        assert "Method: DNS" in output
        assert "Method: HackerTarget" in output
        
        # Check subdomain details
        assert "www.example.com" in output
        assert "api.example.com" in output
        assert "internal.example.com" in output
        
        # Check IP addresses
        assert "93.184.216.34" in output
        assert "93.184.216.35" in output
        assert "192.168.1.1" in output
        
        # Check public/private
        assert "public" in output.lower()
        assert "private" in output.lower()
        
        # Check HTTP/HTTPS status
        assert "HTTP: 200" in output
        assert "HTTPS: 200" in output
        
        # Check open ports
        assert "Open ports: 80, 443" in output
        assert "Open ports: 22" in output
        
        # Check services
        assert "Services: http: nginx" in output
        assert "Services: http: apache" in output
        assert "Services: ssh: OpenSSH" in output
        
        # Check summary
        assert "Total subdomains: 3" in output
        assert "Unique IP addresses: 3" in output
        assert "Public IPs: 2" in output
        assert "Private IPs: 1" in output
        assert "Network ranges:" in output
        assert "93.184.216.0/24" in output
        assert "192.168.1.0/24" in output
        
        # Check method statistics
        assert "Discovery method statistics:" in output
        assert "DNS: 2 subdomains" in output
        assert "CT: 1 subdomains" in output
        assert "HackerTarget: 1 subdomains" in output

    def test_json_formatter(self, sample_result):
        """Test JSON formatter output."""
        formatter = JSONFormatter()
        output = formatter.format(sample_result)
        
        # Parse JSON to verify structure
        data = json.loads(output)
        
        # Check structure
        assert 'subdomains' in data
        assert 'stats' in data
        
        # Check subdomains
        assert 'www.example.com' in data['subdomains']
        assert 'api.example.com' in data['subdomains']
        assert 'internal.example.com' in data['subdomains']
        
        # Check subdomain details
        www = data['subdomains']['www.example.com']
        assert www['name'] == 'www.example.com'
        assert www['domain'] == 'example.com'
        assert www['ip_addresses'] == ['93.184.216.34']
        assert set(www['discovery_methods']) == {'DNS', 'CT'}
        assert www['is_public'] is True
        assert www['http_status'] == 200
        assert www['https_status'] == 200
        assert www['open_ports'] == [80, 443]
        assert www['services'] == {'http': 'nginx'}
        
        # Check stats
        assert data['stats']['total_subdomains'] == 3
        assert data['stats']['unique_ips'] == 3
        assert data['stats']['public_ips'] == 2
        assert data['stats']['private_ips'] == 1
        assert '93.184.216.0/24' in data['stats']['network_ranges']
        assert '192.168.1.0/24' in data['stats']['network_ranges']
        assert data['stats']['methods']['DNS']['count'] == 2
        assert data['stats']['methods']['CT']['count'] == 1
        assert data['stats']['methods']['HackerTarget']['count'] == 1

    def test_csv_formatter(self, sample_result):
        """Test CSV formatter output."""
        formatter = CSVFormatter()
        output = formatter.format(sample_result)
        
        # Parse CSV to verify structure
        reader = csv.reader(io.StringIO(output))
        rows = list(reader)
        
        # Check header
        assert rows[0] == [
            'Subdomain', 
            'IP Addresses', 
            'Public/Private', 
            'HTTP Status', 
            'HTTPS Status', 
            'Open Ports', 
            'Services', 
            'Discovery Methods'
        ]
        
        # Check data rows (should be sorted by subdomain name)
        assert len(rows) == 4  # Header + 3 subdomains
        
        # Find row for www.example.com
        www_row = None
        for row in rows[1:]:
            if row[0] == 'www.example.com':
                www_row = row
                break
        
        assert www_row is not None
        assert www_row[1] == '93.184.216.34'
        assert www_row[2] == 'Public'
        assert www_row[3] == '200'
        assert www_row[4] == '200'
        assert www_row[5] == '80, 443'
        assert www_row[6] == 'http:nginx'
        assert set(www_row[7].split(', ')) == {'DNS', 'CT'}

    def test_formatter_factory(self):
        """Test formatter factory."""
        # Test valid formats
        assert isinstance(FormatterFactory.create_formatter('text'), TextFormatter)
        assert isinstance(FormatterFactory.create_formatter('json'), JSONFormatter)
        assert isinstance(FormatterFactory.create_formatter('csv'), CSVFormatter)
        
        # Test invalid format
        with pytest.raises(ValueError):
            FormatterFactory.create_formatter('invalid')

    @patch('builtins.open', new_callable=mock_open)
    @patch('sys.stdout')
    def test_write_output_to_file(self, mock_stdout, mock_file, sample_result):
        """Test writing output to file."""
        write_output(sample_result, 'text', 'output.txt')
        
        # Verify file was opened and written to
        mock_file.assert_called_once_with('output.txt', 'w')
        mock_file().write.assert_called_once()
        
        # Verify stdout was not used
        mock_stdout.write.assert_not_called()

    @patch('builtins.open', new_callable=mock_open)
    @patch('sys.stdout')
    def test_write_output_to_stdout(self, mock_stdout, mock_file, sample_result):
        """Test writing output to stdout."""
        write_output(sample_result, 'text', None)
        
        # Verify stdout was used
        mock_stdout.write.assert_called_once()
        
        # Verify file was not opened
        mock_file.assert_not_called()