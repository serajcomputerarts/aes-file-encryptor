"""
Utility functions for file management and progress tracking
"""

import os
import sys
from pathlib import Path
from typing import List, Optional
from datetime import datetime


class FileManager:
    """Handle file and directory operations"""

    @staticmethod
    def get_all_files(directory: str, exclude_patterns: Optional[List[str]] = None) -> List[Path]:
        """
        Get all files in directory recursively

        Args:
            directory: Root directory path
            exclude_patterns: List of patterns to exclude

        Returns:
            List of file paths
        """
        directory = Path(directory)
        exclude_patterns = exclude_patterns or []

        if not directory.exists():
            raise ValueError(f"Directory does not exist: {directory}")

        files = []
        for file_path in directory.rglob('*'):
            if file_path.is_file():
                should_exclude = any(
                    pattern in str(file_path) 
                    for pattern in exclude_patterns
                )
                if not should_exclude:
                    files.append(file_path)

        return files

    @staticmethod
    def get_encrypted_files(directory: str) -> List[Path]:
        """
        Get all encrypted files in directory

        Args:
            directory: Root directory path

        Returns:
            List of encrypted file paths
        """
        directory = Path(directory)
        return list(directory.rglob('*.encrypted'))

    @staticmethod
    def format_size(size_bytes: int) -> str:
        """
        Format bytes to human-readable size

        Args:
            size_bytes: Size in bytes

        Returns:
            Formatted size string
        """
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} PB"


class ProgressBar:
    """Display progress bar for operations"""

    def __init__(self, total: int, prefix: str = '', length: int = 50):
        """
        Initialize progress bar

        Args:
            total: Total number of items
            prefix: Prefix text
            length: Length of progress bar
        """
        self.total = total
        self.prefix = prefix
        self.length = length
        self.current = 0

    def update(self, step: int = 1):
        """Update progress bar"""
        self.current += step
        self._print()

    def _print(self):
        """Print progress bar"""
        if self.total == 0:
            percent = 100
        else:
            percent = (self.current / self.total) * 100
        filled = int(self.length * self.current // self.total) if self.total > 0 else self.length
        bar = '█' * filled + '-' * (self.length - filled)
        sys.stdout.write(f'\r{self.prefix} |{bar}| {percent:.1f}% ({self.current}/{self.total})')
        sys.stdout.flush()
        if self.current >= self.total:
            print()


class Logger:
    """Simple logging utility"""
    LOG_FILE = 'encryption.log'
    @staticmethod
    def log(message: str, level: str = 'INFO'):
        """
        Log message to file and console
        Args:
            message: Message to log
            level: Log level (INFO, WARNING, ERROR)
        """
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_message = f"[{timestamp}] [{level}] {message}"
        print(log_message)
        with open(Logger.LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(log_message + '\n')
    @staticmethod
    def info(message: str):
        """Log info message"""
        Logger.log(message, 'INFO')
    @staticmethod
    def warning(message: str):
        """Log warning message"""
        Logger.log(message, 'WARNING')
    @staticmethod
    def error(message: str):
        """Log error message"""
        Logger.log(message, 'ERROR')
