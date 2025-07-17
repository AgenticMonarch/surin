"""
Unit tests for concurrency utilities.
"""
import pytest
from unittest.mock import patch, MagicMock, call
import time
import concurrent.futures

from surin.utils.concurrency import RateLimiter, ConcurrentExecutor


class TestRateLimiter:
    """Test rate limiter functionality."""

    @patch('time.time')
    @patch('time.sleep')
    def test_rate_limiting(self, mock_sleep, mock_time):
        """Test rate limiting behavior."""
        # Setup mock time
        mock_time.side_effect = [
            100.0,  # First call timestamp check
            100.0,  # First call record
            100.1,  # Second call timestamp check
            100.1,  # Second call record
            100.2,  # Third call timestamp check
            100.2,  # Third call record
            100.3,  # Fourth call timestamp check - should hit rate limit
        ]
        
        # Create rate limiter: 3 calls per second
        rate_limiter = RateLimiter(calls=3, period=1.0, jitter=0.0)
        
        # Define test function
        @rate_limiter
        def test_func():
            return "called"
        
        # First three calls should not wait
        assert test_func() == "called"
        assert test_func() == "called"
        assert test_func() == "called"
        
        # Fourth call should wait
        test_func()
        
        # Verify sleep was called with appropriate wait time
        mock_sleep.assert_called_once()
        # Wait time should be close to 0.7 seconds (1.0 - (100.3 - 100.0))
        assert mock_sleep.call_args[0][0] > 0.6

    @patch('time.time')
    def test_cleanup_old_timestamps(self, mock_time):
        """Test cleanup of old timestamps."""
        # Setup mock time
        mock_time.side_effect = [
            100.0,  # First call timestamp check
            100.0,  # First call record
            101.0,  # Second call timestamp check
            101.0,  # Second call record
            102.0,  # Third call timestamp check
            102.0,  # Third call record
            105.0,  # Fourth call timestamp check - old timestamps should be removed
        ]
        
        # Create rate limiter: 3 calls per second
        rate_limiter = RateLimiter(calls=3, period=1.0, jitter=0.0)
        
        # Define test function
        @rate_limiter
        def test_func():
            return "called"
        
        # Make calls
        test_func()
        test_func()
        test_func()
        
        # Fourth call should not wait because old timestamps are removed
        test_func()
        
        # Verify timestamps were cleaned up
        assert len(rate_limiter.timestamps) == 1
        assert rate_limiter.timestamps[0] == 102.0


class TestConcurrentExecutor:
    """Test concurrent executor functionality."""

    def test_execute(self):
        """Test concurrent execution of functions."""
        # Define test function
        def square(x):
            return x * x
        
        # Create executor
        executor = ConcurrentExecutor(max_workers=5)
        
        # Execute function on multiple items
        results = executor.execute(square, [1, 2, 3, 4, 5])
        
        # Verify results
        assert sorted(results) == [1, 4, 9, 16, 25]

    def test_execute_with_error(self):
        """Test concurrent execution with errors."""
        # Define test function that raises error for even numbers
        def risky_function(x):
            if x % 2 == 0:
                raise ValueError(f"Error for {x}")
            return x * x
        
        # Create executor
        executor = ConcurrentExecutor(max_workers=5)
        
        # Execute function on multiple items
        results = executor.execute(risky_function, [1, 2, 3, 4, 5])
        
        # Verify results (only odd numbers should succeed)
        assert sorted(results) == [1, 9, 25]

    @patch('time.sleep')
    def test_execute_with_backoff(self, mock_sleep):
        """Test execution with exponential backoff."""
        # Counter for tracking attempts
        attempts = {}
        
        # Define test function that succeeds on the second attempt
        def flaky_function(x):
            attempts[x] = attempts.get(x, 0) + 1
            if attempts[x] < 2:
                raise ValueError(f"Temporary error for {x}")
            return x * x
        
        # Create executor
        executor = ConcurrentExecutor(max_workers=2)
        
        # Execute function with backoff
        results = executor.execute_with_backoff(
            flaky_function, 
            [1, 2, 3], 
            max_retries=3, 
            backoff_factor=1.0
        )
        
        # Verify results
        assert sorted(results) == [1, 4, 9]
        
        # Verify each item was attempted twice
        assert attempts == {1: 2, 2: 2, 3: 2}
        
        # Verify sleep was called for each retry
        assert mock_sleep.call_count == 3

    @patch('time.sleep')
    def test_execute_with_backoff_max_retries(self, mock_sleep):
        """Test execution with backoff reaching max retries."""
        # Define test function that always fails
        def failing_function(x):
            raise ValueError(f"Always fails for {x}")
        
        # Create executor
        executor = ConcurrentExecutor(max_workers=2)
        
        # Execute function with backoff
        results = executor.execute_with_backoff(
            failing_function, 
            [1, 2], 
            max_retries=2, 
            backoff_factor=1.0
        )
        
        # Verify no results
        assert results == []
        
        # Verify sleep was called for each retry (2 items * 2 retries)
        assert mock_sleep.call_count == 4

    @patch('time.time')
    @patch('time.sleep')
    def test_execute_with_rate_limiting(self, mock_sleep, mock_time):
        """Test execution with rate limiting."""
        # Setup mock time
        mock_time.return_value = 100.0
        
        # Define test function
        def test_func(x):
            return x * x
        
        # Create executor with rate limiting (2 calls per second)
        executor = ConcurrentExecutor(max_workers=5, calls_per_second=2)
        
        # Execute function on multiple items
        results = executor.execute(test_func, [1, 2, 3, 4, 5])
        
        # Verify results
        assert sorted(results) == [1, 4, 9, 16, 25]
        
        # Verify sleep was called for rate limiting
        # First two calls don't wait, next three do
        assert mock_sleep.call_count == 3