"""Concurrency utilities for SURIN."""

import time
import logging
import random
from typing import List, Callable, TypeVar, Generic, Any, Dict, Optional
import concurrent.futures
from functools import wraps

T = TypeVar('T')


class RateLimiter:
    """Rate limiter for API calls."""

    def __init__(self, calls: int, period: int, jitter: float = 0.1):
        """Initialize rate limiter.
        
        Args:
            calls: Number of calls allowed in the period
            period: Time period in seconds
            jitter: Random jitter factor (0.0 to 1.0) to avoid thundering herd
        """
        self.calls = calls
        self.period = period
        self.jitter = jitter
        self.timestamps = []
        self.logger = logging.getLogger('surin.rate_limiter')

    def __call__(self, func):
        """Decorator for rate-limited functions."""
        @wraps(func)
        def wrapper(*args, **kwargs):
            self._wait_if_needed()
            result = func(*args, **kwargs)
            self._record_call()
            return result
        return wrapper

    def _wait_if_needed(self):
        """Wait if rate limit would be exceeded."""
        now = time.time()
        
        # Remove timestamps older than the period
        self.timestamps = [ts for ts in self.timestamps if now - ts <= self.period]
        
        if len(self.timestamps) >= self.calls:
            # Rate limit reached, calculate wait time
            oldest = min(self.timestamps)
            wait_time = self.period - (now - oldest)
            
            if wait_time > 0:
                # Add jitter to avoid thundering herd
                jitter_amount = wait_time * self.jitter * random.random()
                total_wait = wait_time + jitter_amount
                
                self.logger.debug(f"Rate limit reached. Waiting {total_wait:.2f}s")
                time.sleep(total_wait)

    def _record_call(self):
        """Record a call timestamp."""
        self.timestamps.append(time.time())


class ConcurrentExecutor(Generic[T]):
    """Executor for concurrent operations with rate limiting."""

    def __init__(self, max_workers: int = 10, calls_per_second: Optional[int] = None):
        """Initialize concurrent executor.
        
        Args:
            max_workers: Maximum number of concurrent workers
            calls_per_second: Optional rate limit (calls per second)
        """
        self.max_workers = max_workers
        self.calls_per_second = calls_per_second
        self.logger = logging.getLogger('surin.concurrent_executor')
        
        if calls_per_second:
            self.rate_limiter = RateLimiter(calls_per_second, 1)
        else:
            self.rate_limiter = None

    def execute(self, func: Callable[..., T], items: List[Any], *args, **kwargs) -> List[T]:
        """Execute a function concurrently on multiple items.
        
        Args:
            func: Function to execute
            items: List of items to process
            *args: Additional positional arguments for func
            **kwargs: Additional keyword arguments for func
            
        Returns:
            List of results
        """
        results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_item = {}
            
            for item in items:
                if self.rate_limiter:
                    self.rate_limiter._wait_if_needed()
                
                future = executor.submit(func, item, *args, **kwargs)
                future_to_item[future] = item
                
                if self.rate_limiter:
                    self.rate_limiter._record_call()
            
            for future in concurrent.futures.as_completed(future_to_item):
                item = future_to_item[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    self.logger.error(f"Error processing {item}: {e}")
        
        return results

    def execute_with_backoff(self, func: Callable[..., T], items: List[Any], 
                           max_retries: int = 3, backoff_factor: float = 2.0,
                           *args, **kwargs) -> List[T]:
        """Execute a function with exponential backoff retry.
        
        Args:
            func: Function to execute
            items: List of items to process
            max_retries: Maximum number of retries
            backoff_factor: Backoff multiplier
            *args: Additional positional arguments for func
            **kwargs: Additional keyword arguments for func
            
        Returns:
            List of results
        """
        def _with_backoff(item):
            retries = 0
            while True:
                try:
                    return func(item, *args, **kwargs)
                except Exception as e:
                    retries += 1
                    if retries > max_retries:
                        self.logger.error(f"Max retries reached for {item}: {e}")
                        raise
                    
                    wait_time = backoff_factor ** retries
                    jitter = random.uniform(0, 0.1 * wait_time)
                    total_wait = wait_time + jitter
                    
                    self.logger.debug(f"Retry {retries}/{max_retries} for {item} in {total_wait:.2f}s")
                    time.sleep(total_wait)
        
        return self.execute(_with_backoff, items)