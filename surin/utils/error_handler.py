"""Error handling utilities for SURIN."""

import logging
import sys
from typing import Optional
from surin.core.exceptions import SurinError


class ErrorHandler:
    """Centralized error handling for SURIN."""

    def __init__(self, verbose: bool = False):
        """Initialize the error handler.
        
        Args:
            verbose: Enable verbose error reporting
        """
        self.verbose = verbose
        self._setup_logging()

    def _setup_logging(self):
        """Set up logging configuration."""
        level = logging.DEBUG if self.verbose else logging.INFO
        logging.basicConfig(
            level=level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(sys.stderr)
            ]
        )
        self.logger = logging.getLogger('surin')

    def handle_error(self, error_type: str, message: str, exception: Optional[Exception] = None) -> None:
        """Handle errors based on type.
        
        Args:
            error_type: Type of error (input, network, api, system, unexpected)
            message: Error message to display
            exception: Optional exception object
        """
        if error_type == 'input':
            self._handle_input_error(message, exception)
        elif error_type == 'network':
            self._handle_network_error(message, exception)
        elif error_type == 'api':
            self._handle_api_error(message, exception)
        elif error_type == 'system':
            self._handle_system_error(message, exception)
        else:
            self._handle_unexpected_error(message, exception)

    def _handle_input_error(self, message: str, exception: Optional[Exception] = None):
        """Handle input validation errors."""
        print(f"Input Error: {message}", file=sys.stderr)
        if self.verbose and exception:
            self.logger.debug(f"Exception details: {exception}")
        sys.exit(1)

    def _handle_network_error(self, message: str, exception: Optional[Exception] = None):
        """Handle network-related errors."""
        print(f"Network Error: {message}", file=sys.stderr)
        if self.verbose and exception:
            self.logger.debug(f"Exception details: {exception}")

    def _handle_api_error(self, message: str, exception: Optional[Exception] = None):
        """Handle API-related errors."""
        print(f"API Error: {message}", file=sys.stderr)
        if self.verbose and exception:
            self.logger.debug(f"Exception details: {exception}")

    def _handle_system_error(self, message: str, exception: Optional[Exception] = None):
        """Handle system-related errors."""
        print(f"System Error: {message}", file=sys.stderr)
        if self.verbose and exception:
            self.logger.debug(f"Exception details: {exception}")
        sys.exit(1)

    def _handle_unexpected_error(self, message: str, exception: Optional[Exception] = None):
        """Handle unexpected errors."""
        print(f"Unexpected Error: {message}", file=sys.stderr)
        if exception:
            self.logger.error(f"Exception: {exception}", exc_info=True)
        sys.exit(1)

    def log_error(self, message: str, exception: Optional[Exception] = None) -> None:
        """Log error details.
        
        Args:
            message: Error message to log
            exception: Optional exception object
        """
        if exception:
            self.logger.error(f"{message}: {exception}")
        else:
            self.logger.error(message)