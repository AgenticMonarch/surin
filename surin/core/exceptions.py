"""Custom exceptions for SURIN.

This module defines the exception hierarchy used throughout the SURIN application.
All exceptions inherit from the base SurinError class to allow for consistent
error handling and identification of SURIN-specific exceptions.
"""


class SurinError(Exception):
    """Base exception for all SURIN errors.
    
    All custom exceptions in the SURIN application should inherit from this class
    to allow for consistent error handling and identification.
    """
    pass


class ValidationError(SurinError):
    """Raised when input validation fails.
    
    This exception is raised when user input or configuration values fail validation,
    such as invalid domain names, invalid API keys, or invalid command-line arguments.
    """
    pass


class NetworkError(SurinError):
    """Raised when network operations fail.
    
    This exception is raised when network-related operations fail, such as DNS resolution,
    HTTP requests, or socket connections. It typically indicates connectivity issues,
    timeouts, or other network-related problems.
    """
    pass


class APIError(SurinError):
    """Raised when API operations fail.
    
    This exception is raised when operations against external APIs fail, such as
    authentication failures, rate limiting, service unavailability, or unexpected
    response formats.
    """
    pass


class ConfigurationError(SurinError):
    """Raised when configuration is invalid.
    
    This exception is raised when the application configuration is invalid or incomplete,
    such as missing required configuration values or incompatible settings.
    """
    pass


class DiscoveryError(SurinError):
    """Raised when discovery operations fail.
    
    This exception is raised when subdomain discovery operations fail. It typically
    wraps more specific exceptions like APIError or NetworkError to provide context
    about which discovery method failed.
    """
    pass