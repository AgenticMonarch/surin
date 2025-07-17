"""Progress indicator utilities for SURIN."""

import sys
import time
from typing import Optional, Any, Iterator
from contextlib import contextmanager
import threading

try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False


class ProgressIndicator:
    """Progress indicator for long-running operations."""

    def __init__(self, total: Optional[int] = None, desc: str = "", 
                 disable: bool = False, unit: str = "it"):
        """Initialize progress indicator.
        
        Args:
            total: Total number of items (None for indeterminate)
            desc: Description of the operation
            disable: Whether to disable the progress indicator
            unit: Unit of items
        """
        self.total = total
        self.desc = desc
        self.disable = disable
        self.unit = unit
        self.current = 0
        self.start_time = None
        self.tqdm_instance = None
        self._lock = threading.Lock()

    def start(self) -> None:
        """Start the progress indicator."""
        if self.disable:
            return
        
        self.start_time = time.time()
        
        if TQDM_AVAILABLE:
            self.tqdm_instance = tqdm(
                total=self.total,
                desc=self.desc,
                unit=self.unit,
                file=sys.stderr
            )
        else:
            # Simple fallback if tqdm is not available
            if self.total:
                print(f"{self.desc} (0/{self.total})", file=sys.stderr, end="", flush=True)
            else:
                print(f"{self.desc} ...", file=sys.stderr, end="", flush=True)

    def update(self, n: int = 1) -> None:
        """Update progress by n units.
        
        Args:
            n: Number of units to increment by
        """
        if self.disable:
            return
        
        with self._lock:
            self.current += n
            
            if TQDM_AVAILABLE and self.tqdm_instance:
                self.tqdm_instance.update(n)
            else:
                # Simple fallback
                if self.total:
                    print(f"\r{self.desc} ({self.current}/{self.total})", 
                          file=sys.stderr, end="", flush=True)
                else:
                    # For indeterminate progress, just print a dot
                    print(".", file=sys.stderr, end="", flush=True)

    def set_description(self, desc: str) -> None:
        """Set the description of the progress indicator.
        
        Args:
            desc: New description
        """
        if self.disable:
            return
        
        self.desc = desc
        
        if TQDM_AVAILABLE and self.tqdm_instance:
            self.tqdm_instance.set_description(desc)
        else:
            # Simple fallback
            if self.total:
                print(f"\r{self.desc} ({self.current}/{self.total})", 
                      file=sys.stderr, end="", flush=True)
            else:
                print(f"\r{self.desc} ...", file=sys.stderr, end="", flush=True)

    def close(self) -> None:
        """Close the progress indicator."""
        if self.disable:
            return
        
        if TQDM_AVAILABLE and self.tqdm_instance:
            self.tqdm_instance.close()
        else:
            # Simple fallback
            elapsed = time.time() - self.start_time
            print(f"\r{self.desc} completed in {elapsed:.2f}s", file=sys.stderr)


@contextmanager
def progress_bar(total: Optional[int] = None, desc: str = "", 
                disable: bool = False, unit: str = "it") -> Iterator[ProgressIndicator]:
    """Context manager for progress indicator.
    
    Args:
        total: Total number of items (None for indeterminate)
        desc: Description of the operation
        disable: Whether to disable the progress indicator
        unit: Unit of items
        
    Yields:
        ProgressIndicator instance
    """
    progress = ProgressIndicator(total, desc, disable, unit)
    progress.start()
    try:
        yield progress
    finally:
        progress.close()


def progress_map(func: callable, items: list, desc: str = "", 
                disable: bool = False, unit: str = "it") -> list:
    """Map a function over items with progress indicator.
    
    Args:
        func: Function to apply to each item
        items: List of items to process
        desc: Description of the operation
        disable: Whether to disable the progress indicator
        unit: Unit of items
        
    Returns:
        List of results
    """
    results = []
    
    with progress_bar(total=len(items), desc=desc, disable=disable, unit=unit) as progress:
        for item in items:
            result = func(item)
            results.append(result)
            progress.update(1)
    
    return results