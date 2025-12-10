#!/usr/bin/env python3
"""
AES File Encryption Tool - Main Entry Point
"""

import sys
import argparse
from pathlib import Path
from getpass import getpass
from src.encryptor import AESFileEncryptor
from src.utils import FileManager, ProgressBar, Logger


def encrypt_directory(directory: str, password: str, exclude: list = None):
    """Encrypt all files in directory"""
    try:
        files = FileManager.get_all_files(directory, exclude)
        
        if not files:
            Logger.warning("No files found to encrypt")
            return
        
        Logger.info(f"Found {len(files)} files to encrypt")
        
        encryptor = AESFileEncryptor(password)
        
        progress = ProgressBar(len(files), prefix='Encrypting')
        
        success_count = 0
        failed_files = []
        
        for file_path in files:
            success, result = encryptor.encrypt_file(str(file_path))
            
            if success:
                success_count += 1
            else:
                failed_files.append((str(file_path), result))
            
            progress.update()
        
        Logger.info(f"\nEncryption completed:")
        Logger.info(f"  ✓ Successfully encrypted: {success_count} files")
        Logger.info(f"  ✗ Failed: {len(failed_files)} files")
        
        if failed_files:
            Logger.error("\nFailed files:")
            for file_path, error in failed_files:
                Logger.error(f"  - {file_path}: {error}")
    
    except Exception as e:
        Logger.error(f"Encryption failed: {str(e)}")
        sys.exit(1)


def decrypt_directory(directory: str, password: str):
    """Decrypt all encrypted files in directory"""
    try:
        files = FileManager.get_encrypted_files(directory)
        
        if not files:
            Logger.warning("No encrypted files found")
            return
        
        Logger.info(f"Found {len(files)} encrypted files")
        
        encryptor = AESFileEncryptor(password)
        
        progress = ProgressBar(len(files), prefix='Decrypting')
        
        success_count = 0
        failed_files = []
        
        for file_path in files:
            success, result = encryptor.decrypt_file(str(file_path))
            
            if success:
                success_count += 1
            else:
                failed_files.append((str(file_path), result))
            
            progress.update()
        
        Logger.info(f"\nDecryption completed:")
        Logger.info(f"  ✓ Successfully decrypted: {success_count} files")
        Logger.info(f"  ✗ Failed: {len(failed_files)} files")
        
        if failed_files:
            Logger.error("\nFailed files:")
            for file_path, error in failed_files:
                Logger.error(f"  - {file_path}: {error}")
    
    except Exception as e:
        Logger.error(f"Decryption failed: {str(e)}")
        sys.exit(1)


def get_password_safely(prompt: str = "Enter password: ") -> str:
    """Get password with proper handling of whitespace"""
    while True:
        password = getpass(prompt)
        password_stripped = password.strip()
        
        if not password_stripped:
            Logger.error("Password cannot be empty!")
            continue
        
        if len(password) != len(password_stripped):
            Logger.warning("Warning: Leading/trailing spaces were removed from password")
        
        return password_stripped


def confirm_action(prompt: str = "Continue? (y/n): ", default: bool = False) -> bool:
    """
    Ask user for confirmation with flexible input
    
    Args:
        prompt: The prompt to display
        default: Default value if user just presses Enter
        
    Returns:
        True if user confirms, False otherwise
    """
    valid_yes = ['yes', 'y', 'ye', '1', 'true', 't']
    valid_no = ['no', 'n', '0', 'false', 'f']
    
    while True:
        response = input(prompt).strip().lower()
        
        # Handle empty input
        if not response:
            return default
        
        # Check for yes
        if response in valid_yes:
            return True
        
        # Check for no
        if response in valid_no:
            return False
        
        # Invalid input
        print("Please enter 'y' for yes or 'n' for no")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='AES-256 File Encryption Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Encrypt directory:
    python main.py encrypt /path/to/directory
  
  Decrypt directory:
    python main.py decrypt /path/to/directory
  
  Encrypt with exclusions:
    python main.py encrypt /path/to/directory --exclude "*.log" "*.tmp"
  
  Use password from command line (not recommended):
    python main.py encrypt /path/to/directory --password "your_password"
        """
    )
    
    parser.add_argument(
        'action',
        choices=['encrypt', 'decrypt'],
        help='Action to perform'
    )
    
    parser.add_argument(
        'directory',
        help='Directory path to process'
    )
    
    parser.add_argument(
        '--exclude',
        nargs='+',
        help='Patterns to exclude during encryption',
        default=[]
    )
    
    parser.add_argument(
        '--password',
        help='Encryption password (will prompt if not provided - RECOMMENDED)'
    )
    
    parser.add_argument(
        '--yes', '-y',
        action='store_true',
        help='Skip all confirmations (use with caution!)'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='%(prog)s 1.0.0'
    )
    
    args = parser.parse_args()
    
    # Validate directory
    if not Path(args.directory).exists():
        Logger.error(f"Directory does not exist: {args.directory}")
        sys.exit(1)
    
    # Get password
    if args.password:
        password = args.password.strip()
        Logger.warning("Password provided via command line - this is not secure!")
    else:
        password = get_password_safely("Enter encryption password: ")
        
        if args.action == 'encrypt':
            # Confirm password for encryption
            max_attempts = 3
            attempts = 0
            
            while attempts < max_attempts:
                confirm = get_password_safely("Confirm password: ")
                
                if password == confirm:
                    break
                else:
                    attempts += 1
                    remaining = max_attempts - attempts
                    
                    if remaining > 0:
                        Logger.error(f"Passwords do not match! {remaining} attempts remaining.")
                        if confirm_action("Re-enter original password? (y/n): "):
                            password = get_password_safely("Enter encryption password: ")
                            attempts = 0  # Reset attempts
                    else:
                        Logger.error("Maximum attempts reached. Exiting.")
                        sys.exit(1)
    
    # Validate password strength
    if len(password) < 8:
        Logger.warning("Password is less than 8 characters. Consider using a stronger password.")
        Logger.warning("Recommended: At least 12 characters with mix of letters, numbers, and symbols")
        
        if not args.yes:
            if not confirm_action("Continue anyway? (y/n): "):
                Logger.info("Operation cancelled by user")
                sys.exit(0)
    
    # Show summary before proceeding
    print("\n" + "="*60)
    print("Operation Summary:")
    print("="*60)
    print(f"Action: {args.action.upper()}")
    print(f"Directory: {args.directory}")
    if args.exclude:
        print(f"Exclusions: {', '.join(args.exclude)}")
    print(f"Password length: {len(password)} characters")
    print("="*60)
    
    # Final confirmation
    if not args.yes:
        if args.action == 'encrypt':
            print("\n⚠️  WARNING: Original files will be deleted after encryption!")
            print("Make sure you have backups of important data.")
        
        if not confirm_action("\nProceed with operation? (y/n): "):
            Logger.info("Operation cancelled by user")
            sys.exit(0)
    
    # Perform action
    Logger.info(f"\nStarting {args.action} operation on: {args.directory}")
    
    if args.action == 'encrypt':
        encrypt_directory(args.directory, password, args.exclude)
    else:
        decrypt_directory(args.directory, password)
    
    Logger.info("\n" + "="*60)
    Logger.info("Operation completed successfully!")
    Logger.info("="*60)


if __name__ == '__main__':
    main()