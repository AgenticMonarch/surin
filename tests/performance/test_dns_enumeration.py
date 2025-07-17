"""
Performance tests for DNS enumeration with large inputs.
"""
import pytest
import time
from unittest.mock import patch, MagicMock
import random
import string

from surin.discovery.dns_enumeration import DNSEnumerationModule


class TestDNSEnumerationPerformance:
    """Performance tests for DNS enumeration module."""
    
    def generate_random_subdomain(self, length=10):
        """Generate a random subdomain prefix."""
        return ''.join(random.choices(string.ascii_lowercase, k=length))
    
    def generate_large_wordlist(self, size):
        """Generate a large wordlist of random subdomain prefixes."""
        return [self.generate_random_subdomain() for _ in range(size)]
    
    @patch('surin.utils.dns_utils.DNSUtils.resolve_subdomains')
    def test_dns_enumeration_scaling(self, mock_resolve_subdomains):
        """Test DNS enumeration performance with different wordlist sizes."""
        # Setup mock to return some successful resolutions
        def mock_resolve(domain, subdomains):
            # Simulate ~10% success rate
            results = []
            for sub in subdomains:
                if random.random() < 0.1:
                    results.append((f"{sub}.{domain}", ["93.184.216.34"]))
            return results
        
        mock_resolve_subdomains.side_effect = mock_resolve
        
        # Test with different wordlist sizes
        wordlist_sizes = [100, 500, 1000, 2000]
        execution_times = {}
        
        for size in wordlist_sizes:
            # Create module with custom wordlist
            module = DNSEnumerationModule(
                "example.com",
                show_progress=False,
                max_workers=50
            )
            
            # Override the wordlist
            wordlist = self.generate_large_wordlist(size)
            with patch.object(module, '_load_wordlist', return_value=wordlist):
                start_time = time.time()
                results = module.discover()
                end_time = time.time()
                
                execution_time = end_time - start_time
                execution_times[size] = execution_time
                
                # Verify that some results were returned
                assert len(results) > 0
        
        # Print performance results
        print("\nDNS Enumeration Performance:")
        for size, execution_time in execution_times.items():
            print(f"  Wordlist size {size}: {execution_time:.4f} seconds")
    
    @patch('surin.utils.dns_utils.DNSUtils.resolve_subdomains')
    def test_dns_enumeration_concurrency(self, mock_resolve_subdomains):
        """Test DNS enumeration performance with different concurrency levels."""
        # Setup mock with delay to simulate network latency
        def mock_resolve_with_delay(domain, subdomains):
            time.sleep(0.01 * len(subdomains) / 10)  # Scale delay with batch size
            # Simulate ~10% success rate
            results = []
            for sub in subdomains:
                if random.random() < 0.1:
                    results.append((f"{sub}.{domain}", ["93.184.216.34"]))
            return results
        
        mock_resolve_subdomains.side_effect = mock_resolve_with_delay
        
        # Fixed wordlist size
        wordlist_size = 500
        wordlist = self.generate_large_wordlist(wordlist_size)
        
        # Test with different concurrency levels
        concurrency_levels = [10, 25, 50, 100]
        execution_times = {}
        
        for concurrency in concurrency_levels:
            # Create module with specific concurrency
            module = DNSEnumerationModule(
                "example.com",
                show_progress=False,
                max_workers=concurrency
            )
            
            # Override the wordlist
            with patch.object(module, '_load_wordlist', return_value=wordlist):
                start_time = time.time()
                results = module.discover()
                end_time = time.time()
                
                execution_time = end_time - start_time
                execution_times[concurrency] = execution_time
        
        # Print performance results
        print("\nDNS Enumeration Concurrency Performance:")
        for concurrency, execution_time in execution_times.items():
            print(f"  Concurrency {concurrency}: {execution_time:.4f} seconds")
    
    @patch('surin.utils.dns_utils.DNSUtils.resolve_subdomains')
    def test_dns_enumeration_chunk_size(self, mock_resolve_subdomains):
        """Test DNS enumeration performance with different chunk sizes."""
        # Setup mock
        mock_resolve_subdomains.side_effect = lambda domain, subdomains: [
            (f"{sub}.{domain}", ["93.184.216.34"]) 
            for sub in subdomains[:int(len(subdomains) * 0.1)]  # ~10% success rate
        ]
        
        # Fixed wordlist size
        wordlist_size = 1000
        wordlist = self.generate_large_wordlist(wordlist_size)
        
        # Test with different chunk sizes
        chunk_sizes = [10, 50, 100, 200, 500]
        execution_times = {}
        
        for chunk_size in chunk_sizes:
            # Create module
            module = DNSEnumerationModule(
                "example.com",
                show_progress=False,
                max_workers=50
            )
            
            # Override the wordlist and patch the chunk size
            with patch.object(module, '_load_wordlist', return_value=wordlist):
                # Patch the discover method to use our chunk size
                original_discover = module.discover
                
                def patched_discover():
                    # Save the original chunk size
                    original_chunk_size = 100
                    
                    # Modify the chunk size in the discover method's scope
                    nonlocal chunk_size
                    chunk_size_to_use = chunk_size
                    
                    # Call the original method with our chunk size
                    subdomains = []
                    wordlist = module._load_wordlist()
                    
                    # Process subdomains in chunks
                    for i in range(0, len(wordlist), chunk_size_to_use):
                        chunk = wordlist[i:i+chunk_size_to_use]
                        results = module.dns_utils.resolve_subdomains(module.domain, chunk)
                        
                        for subdomain, _ in results:
                            subdomains.append(subdomain)
                    
                    return subdomains
                
                # Replace the discover method
                module.discover = patched_discover
                
                start_time = time.time()
                results = module.discover()
                end_time = time.time()
                
                execution_time = end_time - start_time
                execution_times[chunk_size] = execution_time
        
        # Print performance results
        print("\nDNS Enumeration Chunk Size Performance:")
        for chunk_size, execution_time in execution_times.items():
            print(f"  Chunk size {chunk_size}: {execution_time:.4f} seconds")