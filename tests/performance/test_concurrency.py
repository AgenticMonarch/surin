"""
Performance tests for concurrency behavior.
"""
import pytest
import time
import random
from concurrent.futures import ThreadPoolExecutor

from surin.utils.concurrency import ConcurrentExecutor, RateLimiter


class TestConcurrencyPerformance:
    """Performance tests for concurrency utilities."""
    
    def test_concurrent_executor_performance(self):
        """Test performance of concurrent executor with different concurrency levels."""
        # Define a task that simulates network I/O with random delay
        def network_task(item):
            time.sleep(random.uniform(0.01, 0.05))  # Simulate network delay
            return item * 2
        
        items = list(range(100))  # 100 items to process
        
        # Test with different concurrency levels
        concurrency_levels = [1, 5, 10, 20, 50]
        execution_times = {}
        
        for concurrency in concurrency_levels:
            executor = ConcurrentExecutor(max_workers=concurrency)
            
            start_time = time.time()
            results = executor.execute(network_task, items)
            end_time = time.time()
            
            execution_time = end_time - start_time
            execution_times[concurrency] = execution_time
            
            # Verify results
            assert len(results) == len(items)
            assert sorted(results) == [item * 2 for item in sorted(items)]
        
        # Verify that higher concurrency levels are faster (up to a point)
        assert execution_times[1] > execution_times[5]
        
        # Print performance results
        print("\nConcurrent Executor Performance:")
        for concurrency, execution_time in execution_times.items():
            print(f"  Concurrency {concurrency}: {execution_time:.4f} seconds")
    
    def test_rate_limiter_performance(self):
        """Test performance of rate limiter with different rate limits."""
        # Define a task that simulates API call
        def api_task(item):
            return item * 2
        
        items = list(range(50))  # 50 items to process
        
        # Test with different rate limits
        rate_limits = [5, 10, 20, 50]  # calls per second
        execution_times = {}
        
        for rate_limit in rate_limits:
            # Create rate limiter
            rate_limiter = RateLimiter(calls=rate_limit, period=1.0, jitter=0.0)
            
            # Apply rate limiter to task
            @rate_limiter
            def rate_limited_task(item):
                return api_task(item)
            
            # Execute tasks
            start_time = time.time()
            results = [rate_limited_task(item) for item in items]
            end_time = time.time()
            
            execution_time = end_time - start_time
            execution_times[rate_limit] = execution_time
            
            # Verify results
            assert len(results) == len(items)
            assert results == [item * 2 for item in items]
        
        # Verify that higher rate limits are faster
        assert execution_times[5] > execution_times[10] > execution_times[20]
        
        # Print performance results
        print("\nRate Limiter Performance:")
        for rate_limit, execution_time in execution_times.items():
            print(f"  Rate limit {rate_limit}/s: {execution_time:.4f} seconds")
    
    def test_backoff_strategy_performance(self):
        """Test performance of different backoff strategies."""
        # Define a flaky task that fails with decreasing probability
        def flaky_task(item, failure_rate=0.5):
            if random.random() < failure_rate:
                raise ValueError(f"Simulated failure for {item}")
            return item * 2
        
        items = list(range(20))  # 20 items to process
        
        # Test with different backoff factors
        backoff_factors = [1.0, 2.0, 4.0]
        execution_times = {}
        
        for factor in backoff_factors:
            executor = ConcurrentExecutor(max_workers=5)
            
            start_time = time.time()
            results = executor.execute_with_backoff(
                lambda x: flaky_task(x, failure_rate=0.3),  # 30% failure rate
                items,
                max_retries=3,
                backoff_factor=factor
            )
            end_time = time.time()
            
            execution_time = end_time - start_time
            execution_times[factor] = execution_time
        
        # Print performance results
        print("\nBackoff Strategy Performance:")
        for factor, execution_time in execution_times.items():
            print(f"  Backoff factor {factor}: {execution_time:.4f} seconds")
    
    def test_thread_pool_scaling(self):
        """Test thread pool scaling with different workloads."""
        # Define CPU-bound and I/O-bound tasks
        def cpu_task(item):
            # CPU-bound task (compute prime factors)
            n = item + 100  # Make numbers larger
            factors = []
            d = 2
            while d * d <= n:
                while (n % d) == 0:
                    factors.append(d)
                    n //= d
                d += 1
            if n > 1:
                factors.append(n)
            return factors
        
        def io_task(item):
            # I/O-bound task (simulated network delay)
            time.sleep(0.02)
            return item * 2
        
        # Test with different workloads and thread counts
        workloads = [10, 50, 100]
        thread_counts = [1, 2, 4, 8, 16]
        
        # Test CPU-bound tasks
        print("\nCPU-bound Task Performance:")
        for workload in workloads:
            items = list(range(workload))
            print(f"  Workload: {workload} items")
            
            for threads in thread_counts:
                start_time = time.time()
                with ThreadPoolExecutor(max_workers=threads) as executor:
                    results = list(executor.map(cpu_task, items))
                end_time = time.time()
                
                print(f"    Threads: {threads}, Time: {end_time - start_time:.4f} seconds")
        
        # Test I/O-bound tasks
        print("\nI/O-bound Task Performance:")
        for workload in workloads:
            items = list(range(workload))
            print(f"  Workload: {workload} items")
            
            for threads in thread_counts:
                start_time = time.time()
                with ThreadPoolExecutor(max_workers=threads) as executor:
                    results = list(executor.map(io_task, items))
                end_time = time.time()
                
                print(f"    Threads: {threads}, Time: {end_time - start_time:.4f} seconds")