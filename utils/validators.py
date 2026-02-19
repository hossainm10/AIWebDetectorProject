"""
Validators Module
=================
Input validation functions for data integrity.

This module provides:
- URL validation
- Data type validation
- Feature vector validation
- Configuration validation
- File validation

Why validate inputs?
- Prevent crashes from bad data
- Security (prevent injection attacks)
- Data integrity
- Clear error messages

Author: Your Name
Date: 2025
"""

import re
import os
from urllib.parse import urlparse
import numpy as np


class ValidationError(Exception):
    """Custom exception for validation errors."""
    pass


# =========================================================================
# URL VALIDATION
# =========================================================================

def validate_url(url, require_scheme=True, allowed_schemes=None):
    """
    Validate URL format.
    
    Checks:
    - URL is not empty
    - URL has valid structure
    - Scheme is allowed (http/https)
    - Domain exists
    
    Args:
        url (str): URL to validate
        require_scheme (bool): URL must have http:// or https://
        allowed_schemes (list): Allowed URL schemes
    
    Returns:
        tuple: (is_valid, error_message)
            - is_valid (bool): True if valid
            - error_message (str): Error description (None if valid)
    
    Example:
        is_valid, error = validate_url('https://google.com')
        if not is_valid:
            print(f"Invalid: {error}")
    """
    
    # Default allowed schemes
    if allowed_schemes is None:
        allowed_schemes = ['http', 'https']
    
    # Check if URL exists
    if not url or not isinstance(url, str):
        return False, "URL is empty or not a string"
    
    # Check length (avoid processing extremely long URLs)
    if len(url) > 2048:  # Browser max URL length
        return False, f"URL too long ({len(url)} chars, max 2048)"
    
    # Try to parse URL
    try:
        parsed = urlparse(url)
    except Exception as e:
        return False, f"URL parsing failed: {e}"
    
    # Check scheme
    if require_scheme:
        if not parsed.scheme:
            return False, "URL missing scheme (http:// or https://)"
        
        if parsed.scheme not in allowed_schemes:
            return False, f"Invalid scheme '{parsed.scheme}', allowed: {allowed_schemes}"
    
    # Check domain
    if not parsed.netloc:
        return False, "URL missing domain"
    
    # Check for obvious invalid characters
    # URLs shouldn't have spaces, quotes, etc.
    invalid_chars = [' ', '"', "'", '<', '>']
    for char in invalid_chars:
        if char in url:
            return False, f"URL contains invalid character: '{char}'"
    
    # All checks passed
    return True, None


def is_valid_url(url):
    """
    Quick boolean check if URL is valid.
    
    Args:
        url (str): URL to check
    
    Returns:
        bool: True if valid
    
    Example:
        if is_valid_url('https://example.com'):
            process_url(url)
    """
    is_valid, _ = validate_url(url)
    return is_valid


def validate_url_list(urls):
    """
    Validate a list of URLs.
    
    Args:
        urls (list): List of URLs
    
    Returns:
        dict: Validation results
            - valid_urls: List of valid URLs
            - invalid_urls: List of (url, error) tuples
            - total: Total count
            - valid_count: Valid count
            - invalid_count: Invalid count
    
    Example:
        results = validate_url_list(['https://google.com', 'invalid'])
        print(f"Valid: {results['valid_count']}/{results['total']}")
    """
    
    valid_urls = []
    invalid_urls = []
    
    for url in urls:
        is_valid, error = validate_url(url)
        
        if is_valid:
            valid_urls.append(url)
        else:
            invalid_urls.append((url, error))
    
    return {
        'valid_urls': valid_urls,
        'invalid_urls': invalid_urls,
        'total': len(urls),
        'valid_count': len(valid_urls),
        'invalid_count': len(invalid_urls)
    }


# =========================================================================
# FEATURE VALIDATION
# =========================================================================

def validate_feature_vector(features, expected_length=None, allow_nan=False):
    """
    Validate feature vector for ML model.
    
    Checks:
    - Correct length
    - All numerical values
    - No NaN or infinite values
    - Values in reasonable ranges
    
    Args:
        features (list/array): Feature vector
        expected_length (int): Expected number of features
        allow_nan (bool): Allow NaN values
    
    Returns:
        tuple: (is_valid, error_message)
    
    Example:
        features = [22, 2.5, 1, 0, ...]
        is_valid, error = validate_feature_vector(features, expected_length=60)
    """
    
    # Convert to numpy array for easier checking
    try:
        arr = np.array(features)
    except Exception as e:
        return False, f"Cannot convert to array: {e}"
    
    # Check length
    if expected_length is not None:
        if len(arr) != expected_length:
            return False, f"Wrong feature count: expected {expected_length}, got {len(arr)}"
    
    # Check for NaN values
    if not allow_nan and np.isnan(arr).any():
        nan_indices = np.where(np.isnan(arr))[0]
        return False, f"Contains NaN values at indices: {nan_indices.tolist()}"
    
    # Check for infinite values
    if np.isinf(arr).any():
        inf_indices = np.where(np.isinf(arr))[0]
        return False, f"Contains infinite values at indices: {inf_indices.tolist()}"
    
    # Check data type (should be numeric)
    if not np.issubdtype(arr.dtype, np.number):
        return False, f"Features must be numeric, got dtype: {arr.dtype}"
    
    # All checks passed
    return True, None


def validate_training_data(data, min_samples=50, expected_features=None):
    """
    Validate training dataset.
    
    Checks:
    - Sufficient samples
    - Consistent feature counts
    - No invalid values
    - Reasonable feature variance
    
    Args:
        data (list): List of feature vectors
        min_samples (int): Minimum required samples
        expected_features (int): Expected feature count
    
    Returns:
        dict: Validation results
    
    Example:
        results = validate_training_data(training_data, min_samples=50)
        if not results['is_valid']:
            for issue in results['issues']:
                print(f"Issue: {issue}")
    """
    
    issues = []
    
    # Check if data exists
    if not data or len(data) == 0:
        return {
            'is_valid': False,
            'issues': ['No training data provided']
        }
    
    # Convert to numpy array
    try:
        arr = np.array(data)
    except Exception as e:
        return {
            'is_valid': False,
            'issues': [f'Cannot convert to array: {e}']
        }
    
    # Check sample count
    n_samples, n_features = arr.shape
    
    if n_samples < min_samples:
        issues.append(f'Insufficient samples: {n_samples} (minimum: {min_samples})')
    
    # Check feature count consistency
    if expected_features is not None and n_features != expected_features:
        issues.append(f'Wrong feature count: {n_features} (expected: {expected_features})')
    
    # Check for NaN values
    if np.isnan(arr).any():
        nan_count = np.isnan(arr).sum()
        issues.append(f'Contains {nan_count} NaN values')
    
    # Check for infinite values
    if np.isinf(arr).any():
        inf_count = np.isinf(arr).sum()
        issues.append(f'Contains {inf_count} infinite values')
    
    # Check for constant features (no variance)
    # Features with no variance are useless for ML
    for i in range(n_features):
        if np.std(arr[:, i]) == 0:
            issues.append(f'Feature {i} has no variance (constant value)')
    
    # Check for extremely low variance features
    # Might indicate extraction bug
    low_variance_threshold = 1e-10
    for i in range(n_features):
        if 0 < np.std(arr[:, i]) < low_variance_threshold:
            issues.append(f'Feature {i} has very low variance')
    
    return {
        'is_valid': len(issues) == 0,
        'issues': issues,
        'n_samples': n_samples,
        'n_features': n_features
    }


# =========================================================================
# FILE VALIDATION
# =========================================================================

def validate_file_path(filepath, must_exist=False, must_be_file=True, 
                      allowed_extensions=None):
    """
    Validate file path.
    
    Args:
        filepath (str): Path to validate
        must_exist (bool): File must already exist
        must_be_file (bool): Must be a file (not directory)
        allowed_extensions (list): Allowed file extensions
    
    Returns:
        tuple: (is_valid, error_message)
    
    Example:
        is_valid, error = validate_file_path(
            'model.pkl',
            must_exist=True,
            allowed_extensions=['.pkl', '.joblib']
        )
    """
    
    if not filepath or not isinstance(filepath, str):
        return False, "File path is empty or not a string"
    
    # Check if file exists (if required)
    if must_exist:
        if not os.path.exists(filepath):
            return False, f"File does not exist: {filepath}"
        
        if must_be_file and not os.path.isfile(filepath):
            return False, f"Path is not a file: {filepath}"
    
    # Check file extension
    if allowed_extensions:
        ext = os.path.splitext(filepath)[1].lower()
        if ext not in allowed_extensions:
            return False, f"Invalid extension '{ext}', allowed: {allowed_extensions}"
    
    # Check for invalid path characters
    # Different OS have different invalid chars
    # This is a basic check for common issues
    invalid_chars = ['<', '>', ':', '"', '|', '?', '*']
    for char in invalid_chars:
        if char in os.path.basename(filepath):
            return False, f"Filename contains invalid character: '{char}'"
    
    return True, None


def validate_directory(dirpath, must_exist=False, create_if_missing=False):
    """
    Validate directory path.
    
    Args:
        dirpath (str): Directory path
        must_exist (bool): Directory must exist
        create_if_missing (bool): Create if doesn't exist
    
    Returns:
        tuple: (is_valid, error_message)
    
    Example:
        is_valid, error = validate_directory('data/training', create_if_missing=True)
    """
    
    if not dirpath or not isinstance(dirpath, str):
        return False, "Directory path is empty or not a string"
    
    # Check if directory exists
    exists = os.path.exists(dirpath)
    
    if must_exist and not exists:
        if create_if_missing:
            try:
                os.makedirs(dirpath, exist_ok=True)
                return True, None
            except Exception as e:
                return False, f"Cannot create directory: {e}"
        else:
            return False, f"Directory does not exist: {dirpath}"
    
    # If exists, verify it's a directory
    if exists and not os.path.isdir(dirpath):
        return False, f"Path exists but is not a directory: {dirpath}"
    
    return True, None


# =========================================================================
# CONFIGURATION VALIDATION
# =========================================================================

def validate_config(config, required_keys=None, type_checks=None):
    """
    Validate configuration dictionary.
    
    Args:
        config (dict): Configuration to validate
        required_keys (list): Keys that must exist
        type_checks (dict): Expected types for keys
            Example: {'browser': dict, 'delay': (int, float)}
    
    Returns:
        tuple: (is_valid, errors_list)
    
    Example:
        is_valid, errors = validate_config(
            config,
            required_keys=['browser', 'model'],
            type_checks={'browser': dict, 'delay': (int, float)}
        )
    """
    
    errors = []
    
    # Check if config is a dictionary
    if not isinstance(config, dict):
        return False, ["Config must be a dictionary"]
    
    # Check required keys
    if required_keys:
        for key in required_keys:
            if key not in config:
                errors.append(f"Missing required key: '{key}'")
    
    # Check types
    if type_checks:
        for key, expected_type in type_checks.items():
            if key in config:
                value = config[key]
                
                # Handle multiple allowed types
                if isinstance(expected_type, tuple):
                    if not isinstance(value, expected_type):
                        errors.append(
                            f"Key '{key}' has wrong type: "
                            f"expected {expected_type}, got {type(value)}"
                        )
                else:
                    if not isinstance(value, expected_type):
                        errors.append(
                            f"Key '{key}' has wrong type: "
                            f"expected {expected_type}, got {type(value)}"
                        )
    
    return len(errors) == 0, errors


# =========================================================================
# RANGE VALIDATION
# =========================================================================

def validate_range(value, min_value=None, max_value=None, name='value'):
    """
    Validate numeric value is in range.
    
    Args:
        value: Value to check
        min_value: Minimum allowed value
        max_value: Maximum allowed value
        name (str): Name for error messages
    
    Returns:
        tuple: (is_valid, error_message)
    
    Example:
        is_valid, error = validate_range(
            contamination,
            min_value=0.0,
            max_value=0.5,
            name='contamination'
        )
    """
    
    # Check if numeric
    if not isinstance(value, (int, float)):
        return False, f"{name} must be numeric, got {type(value)}"
    
    # Check minimum
    if min_value is not None and value < min_value:
        return False, f"{name} must be >= {min_value}, got {value}"
    
    # Check maximum
    if max_value is not None and value > max_value:
        return False, f"{name} must be <= {max_value}, got {value}"
    
    return True, None


# =========================================================================
# CONVENIENCE FUNCTIONS
# =========================================================================

def require_valid_url(url):
    """
    Validate URL or raise exception.
    
    Args:
        url (str): URL to validate
    
    Raises:
        ValidationError: If URL is invalid
    
    Example:
        try:
            require_valid_url(user_input)
        except ValidationError as e:
            print(f"Invalid URL: {e}")
    """
    is_valid, error = validate_url(url)
    if not is_valid:
        raise ValidationError(f"Invalid URL: {error}")


def require_valid_features(features, expected_length):
    """
    Validate features or raise exception.
    
    Args:
        features: Feature vector
        expected_length (int): Expected length
    
    Raises:
        ValidationError: If features invalid
    """
    is_valid, error = validate_feature_vector(features, expected_length)
    if not is_valid:
        raise ValidationError(f"Invalid features: {error}")


# =========================================================================
# TEST CODE
# =========================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("VALIDATORS MODULE - TEST MODE")
    print("=" * 70)
    
    # Test 1: URL Validation
    print("\n[TEST 1] URL Validation")
    print("-" * 70)
    
    test_urls = [
        ('https://google.com', True),
        ('http://example.com/path', True),
        ('invalid url with spaces', False),
        ('', False),
        ('ftp://example.com', False),  # Wrong scheme
        ('https://example.com' + 'a' * 3000, False)  # Too long
    ]
    
    for url, expected in test_urls:
        is_valid, error = validate_url(url)
        status = "✓" if is_valid == expected else "✗"
        display_url = url[:50] + '...' if len(url) > 50 else url
        print(f"{status} {display_url:55} Valid: {is_valid}")
        if error and not expected:
            print(f"   Error: {error}")
    
    # Test 2: Feature Vector Validation
    print("\n[TEST 2] Feature Vector Validation")
    print("-" * 70)
    
    good_features = [1.0, 2.5, 3.0, 4.2, 5.1]
    bad_features_nan = [1.0, float('nan'), 3.0]
    bad_features_inf = [1.0, float('inf'), 3.0]
    
    for features, label in [
        (good_features, "Good features"),
        (bad_features_nan, "Features with NaN"),
        (bad_features_inf, "Features with Inf")
    ]:
        is_valid, error = validate_feature_vector(features)
        print(f"{label:25} Valid: {is_valid}")
        if error:
            print(f"  Error: {error}")
    
    # Test 3: Training Data Validation
    print("\n[TEST 3] Training Data Validation")
    print("-" * 70)
    
    # Good training data
    good_data = [[1, 2, 3], [4, 5, 6], [7, 8, 9]] * 20  # 60 samples
    results = validate_training_data(good_data, min_samples=50)
    print(f"Good data: Valid={results['is_valid']}, Samples={results['n_samples']}")
    
    # Insufficient samples
    bad_data = [[1, 2, 3], [4, 5, 6]]  # Only 2 samples
    results = validate_training_data(bad_data, min_samples=50)
    print(f"Too few samples: Valid={results['is_valid']}")
    if results['issues']:
        for issue in results['issues']:
            print(f"  Issue: {issue}")
    
    # Test 4: File Path Validation
    print("\n[TEST 4] File Path Validation")
    print("-" * 70)
    
    # This file (should exist)
    is_valid, error = validate_file_path(__file__, must_exist=True)
    print(f"This file: Valid={is_valid}")
    
    # Non-existent file
    is_valid, error = validate_file_path('nonexistent.txt', must_exist=True)
    print(f"Nonexistent file: Valid={is_valid}")
    if error:
        print(f"  Error: {error}")
    
    # Test 5: Range Validation
    print("\n[TEST 5] Range Validation")
    print("-" * 70)
    
    test_values = [
        (0.05, 0.0, 0.5, True),   # In range
        (-0.1, 0.0, 0.5, False),  # Below min
        (0.6, 0.0, 0.5, False),   # Above max
    ]
    
    for value, min_val, max_val, expected in test_values:
        is_valid, error = validate_range(value, min_val, max_val, 'test_value')
        status = "✓" if is_valid == expected else "✗"
        print(f"{status} Value {value} in [{min_val}, {max_val}]: {is_valid}")
    
    print("\n" + "=" * 70)
    print("✓ All tests complete!")
    print("=" * 70)