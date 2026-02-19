"""
Logging Module
==============
Centralized logging for the entire application.

This module provides:
- Consistent log formatting across all modules
- File and console logging
- Log rotation (automatic cleanup of old logs)
- Different log levels (DEBUG, INFO, WARNING, ERROR)
- Colored console output

Why proper logging?
- Debug issues without print() everywhere
- Track application behavior in production
- Audit trail of actions
- Performance monitoring

Author: Your Name
Date: 2025
"""

import logging
import os
import sys
from datetime import datetime
from logging.handlers import RotatingFileHandler


# ANSI color codes for console output
class LogColors:
    """ANSI color codes for terminal output."""
    RESET = '\033[0m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'


class ColoredFormatter(logging.Formatter):
    """
    Custom formatter that adds colors to console output.
    
    Colors by log level:
    - DEBUG: Cyan
    - INFO: Green
    - WARNING: Yellow
    - ERROR: Red
    - CRITICAL: Bold Red
    """
    
    # Map log levels to colors
    COLORS = {
        logging.DEBUG: LogColors.CYAN,
        logging.INFO: LogColors.GREEN,
        logging.WARNING: LogColors.YELLOW,
        logging.ERROR: LogColors.RED,
        logging.CRITICAL: LogColors.BOLD + LogColors.RED
    }
    
    def format(self, record):
        """
        Format log record with colors.
        
        Args:
            record: LogRecord object
        
        Returns:
            str: Formatted log message with color codes
        """
        
        # Add color based on level
        color = self.COLORS.get(record.levelno, LogColors.WHITE)
        
        # Format the message
        formatted = super().format(record)
        
        # Add color codes
        # Format: [COLOR]message[RESET]
        return f"{color}{formatted}{LogColors.RESET}"


def setup_logger(name, config=None):
    """
    Set up a logger with file and console handlers.
    
    This is the main function to create loggers throughout the app.
    Each module should call this with its __name__.
    
    Args:
        name (str): Logger name (usually module __name__)
        config (dict): Configuration dictionary (optional)
            If None, uses default settings
    
    Returns:
        logging.Logger: Configured logger
    
    Example:
        # In any module:
        from utils.logger import setup_logger
        
        logger = setup_logger(__name__)
        logger.info("Module started")
        logger.warning("Something unusual")
        logger.error("Something failed")
    """
    
    # ===== GET CONFIGURATION =====
    if config is None:
        # Default configuration
        config = {
            'level': 'INFO',
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            'file': 'logs/app.log',
            'console': True,
            'max_bytes': 10485760,  # 10MB
            'backup_count': 5
        }
    
    # ===== CREATE LOGGER =====
    logger = logging.getLogger(name)
    
    # Set level
    # Convert string to logging constant
    # 'DEBUG' → logging.DEBUG (value: 10)
    # 'INFO' → logging.INFO (value: 20)
    level_name = config.get('level', 'INFO')
    level = getattr(logging, level_name.upper(), logging.INFO)
    logger.setLevel(level)
    
    # Prevent duplicate handlers if logger already exists
    if logger.handlers:
        return logger
    
    # ===== FILE HANDLER =====
    # Logs to a file with automatic rotation
    
    log_file = config.get('file', 'logs/app.log')
    
    # Create logs directory if it doesn't exist
    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    # RotatingFileHandler automatically:
    # 1. Creates new log file when size limit reached
    # 2. Keeps N backup files
    # 3. Deletes oldest backup when limit exceeded
    #
    # Example with max_bytes=10MB, backup_count=5:
    # app.log         (current, max 10MB)
    # app.log.1       (backup)
    # app.log.2       (backup)
    # app.log.3       (backup)
    # app.log.4       (backup)
    # app.log.5       (oldest, deleted when new backup created)
    
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=config.get('max_bytes', 10485760),  # 10MB default
        backupCount=config.get('backup_count', 5)
    )
    
    # Set format for file (no colors in file)
    file_format = logging.Formatter(config.get('format'))
    file_handler.setFormatter(file_format)
    
    # Add to logger
    logger.addHandler(file_handler)
    
    # ===== CONSOLE HANDLER =====
    # Logs to terminal (stdout) with colors
    
    if config.get('console', True):
        console_handler = logging.StreamHandler(sys.stdout)
        
        # Use colored formatter for console
        console_format = ColoredFormatter(config.get('format'))
        console_handler.setFormatter(console_format)
        
        # Add to logger
        logger.addHandler(console_handler)
    
    return logger


def log_function_call(logger):
    """
    Decorator to log function calls.
    
    This decorator automatically logs when a function is called
    and when it returns/fails.
    
    Args:
        logger: Logger instance
    
    Returns:
        Decorator function
    
    Example:
        logger = setup_logger(__name__)
        
        @log_function_call(logger)
        def process_data(data):
            # Function logic
            return result
        
        # When called, automatically logs:
        # INFO - Calling process_data(data=...)
        # INFO - process_data returned successfully
    """
    
    def decorator(func):
        """Actual decorator."""
        
        def wrapper(*args, **kwargs):
            """Wrapper function that adds logging."""
            
            # Log function call
            func_name = func.__name__
            logger.debug(f"Calling {func_name}(args={args}, kwargs={kwargs})")
            
            try:
                # Execute function
                result = func(*args, **kwargs)
                
                # Log success
                logger.debug(f"{func_name} returned successfully")
                
                return result
                
            except Exception as e:
                # Log error
                logger.error(f"{func_name} failed with error: {e}", exc_info=True)
                raise  # Re-raise exception
        
        return wrapper
    
    return decorator


class LogContext:
    """
    Context manager for logging code blocks.
    
    Automatically logs entry and exit of a code block.
    Useful for tracking execution flow.
    
    Example:
        logger = setup_logger(__name__)
        
        with LogContext(logger, "Processing data"):
            # Code here
            process_step_1()
            process_step_2()
        
        # Logs:
        # INFO - Starting: Processing data
        # INFO - Completed: Processing data (took 2.5s)
    """
    
    def __init__(self, logger, description, level=logging.INFO):
        """
        Initialize log context.
        
        Args:
            logger: Logger instance
            description: What this block does
            level: Log level (default: INFO)
        """
        self.logger = logger
        self.description = description
        self.level = level
        self.start_time = None
    
    def __enter__(self):
        """Called when entering 'with' block."""
        self.start_time = datetime.now()
        self.logger.log(self.level, f"Starting: {self.description}")
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Called when exiting 'with' block."""
        
        # Calculate duration
        duration = (datetime.now() - self.start_time).total_seconds()
        
        if exc_type is None:
            # No exception - success
            self.logger.log(
                self.level,
                f"Completed: {self.description} (took {duration:.2f}s)"
            )
        else:
            # Exception occurred
            self.logger.error(
                f"Failed: {self.description} (after {duration:.2f}s)",
                exc_info=True
            )
        
        # Return False to propagate exception
        return False


def log_performance(logger, operation):
    """
    Decorator to log function performance (execution time).
    
    Args:
        logger: Logger instance
        operation: Description of operation
    
    Example:
        @log_performance(logger, "Data processing")
        def process_data(data):
            # ... processing ...
            return result
        
        # Logs: "Data processing completed in 2.5s"
    """
    
    def decorator(func):
        def wrapper(*args, **kwargs):
            start_time = datetime.now()
            
            try:
                result = func(*args, **kwargs)
                
                # Calculate duration
                duration = (datetime.now() - start_time).total_seconds()
                logger.info(f"{operation} completed in {duration:.2f}s")
                
                return result
                
            except Exception as e:
                duration = (datetime.now() - start_time).total_seconds()
                logger.error(f"{operation} failed after {duration:.2f}s: {e}")
                raise
        
        return wrapper
    return decorator


# =========================================================================
# CONVENIENCE FUNCTIONS
# =========================================================================

def get_logger(name, level='INFO'):
    """
    Quick way to get a simple logger.
    
    Args:
        name (str): Logger name
        level (str): Log level
    
    Returns:
        logging.Logger: Configured logger
    
    Example:
        from utils.logger import get_logger
        
        logger = get_logger(__name__)
        logger.info("Hello world")
    """
    return setup_logger(name, {'level': level, 'console': True})


# =========================================================================
# TEST CODE
# =========================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("LOGGING MODULE - TEST MODE")
    print("=" * 70)
    
    # Test 1: Basic logging
    print("\n[TEST 1] Basic Logging")
    print("-" * 70)
    
    logger = setup_logger('test_logger')
    
    logger.debug("This is a DEBUG message (cyan)")
    logger.info("This is an INFO message (green)")
    logger.warning("This is a WARNING message (yellow)")
    logger.error("This is an ERROR message (red)")
    logger.critical("This is a CRITICAL message (bold red)")
    
    # Test 2: Log levels
    print("\n[TEST 2] Log Levels")
    print("-" * 70)
    
    # Create logger with DEBUG level
    debug_logger = setup_logger('debug_logger', {'level': 'DEBUG'})
    print("DEBUG level logger (shows everything):")
    debug_logger.debug("Debug message - visible")
    debug_logger.info("Info message - visible")
    
    # Create logger with WARNING level
    warn_logger = setup_logger('warn_logger', {'level': 'WARNING'})
    print("\nWARNING level logger (shows only warnings and above):")
    warn_logger.debug("Debug message - hidden")
    warn_logger.info("Info message - hidden")
    warn_logger.warning("Warning message - visible")
    
    # Test 3: Function decorator
    print("\n[TEST 3] Function Logging Decorator")
    print("-" * 70)
    
    @log_function_call(logger)
    def example_function(x, y):
        """Example function to test decorator."""
        return x + y
    
    result = example_function(5, 3)
    print(f"Result: {result}")
    
    # Test 4: Context manager
    print("\n[TEST 4] Log Context Manager")
    print("-" * 70)
    
    import time
    
    with LogContext(logger, "Example task"):
        print("  Doing work...")
        time.sleep(1)
        print("  Work done!")
    
    # Test 5: Performance decorator
    print("\n[TEST 5] Performance Logging")
    print("-" * 70)
    
    @log_performance(logger, "Heavy computation")
    def slow_function():
        time.sleep(0.5)
        return "done"
    
    result = slow_function()
    
    # Test 6: Check log file
    print("\n[TEST 6] Log File")
    print("-" * 70)
    
    log_file = 'logs/app.log'
    if os.path.exists(log_file):
        with open(log_file, 'r') as f:
            lines = f.readlines()
        print(f"Log file has {len(lines)} lines")
        print("Last 3 entries:")
        for line in lines[-3:]:
            print(f"  {line.strip()}")
    
    print("\n" + "=" * 70)
    print("✓ All tests complete!")
    print(f"✓ Logs saved to: {log_file}")
    print("=" * 70)