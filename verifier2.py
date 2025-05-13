#!/usr/bin/env python3
"""
Enhanced Email Deliverability Validator Script

This script provides robust email verification with multiple validation layers:
1. Syntax validation
2. Domain validation (DNS checks)
3. Advanced SMTP verification
4. Catch-all detection
5. Additional deliverability checks
"""

import re
import csv
import dns.resolver
import socket
import smtplib
import argparse
import concurrent.futures
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional, Set
import sys
import time
import logging
import random
import string
import ssl
from email_validator import validate_email, EmailNotValidError


# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)


class EnhancedEmailVerifier:
    """
    Enhanced email verification with multiple validation layers for high accuracy
    """
    
    # RFC 5322 compliant email regex pattern
    EMAIL_REGEX = re.compile(r"""(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])""", re.IGNORECASE)
    
    # Cache for validation results
    domain_cache = {}
    mx_cache = {}
    catch_all_cache = {}
    email_validity_cache = {}
    
    def __init__(self, smtp_timeout=10, from_email=None, verify_retries=3, strict_mode=True):
        """
        Initialize enhanced email verifier
        
        Args:
            smtp_timeout: Timeout for SMTP connections in seconds
            from_email: Email to use in SMTP MAIL FROM command (if None, generates a valid-looking email)
            verify_retries: Number of retries for SMTP verification
            strict_mode: If True, applies stricter validation rules
        """
        # Lists of problematic domains
        self.disposable_domains = {
            "mailinator.com", "guerrillamail.com", "temp-mail.org", "10minutemail.com",
            "throwawaymail.com", "yopmail.com", "tempmail.com", "fakeinbox.com",
            "trashmail.com", "getairmail.com", "getnada.com", "mailnesia.com",
            "sharklasers.com", "dispostable.com", "maildrop.cc", "anonbox.net"
        }
        
        # These domains are known to use catch-all but reject at delivery time
        self.known_problematic_domains = {
            "yahoo.com", "yahoo.co.uk", "yahoo.fr", "yahoo.es", "outlook.com", 
            "hotmail.com", "live.com", "msn.com"
        }
        
        # SMTP configuration
        self.smtp_timeout = smtp_timeout
        self.from_email = from_email or "verify.{}@example.com".format(self._generate_random_string(8))
        self.verify_retries = verify_retries
        self.strict_mode = strict_mode
        
        # Standard ports to try
        self.smtp_ports = [25, 587, 465]
        
    @staticmethod
    def _generate_random_string(length=10):
        """Generate a random string of fixed length"""
        letters = string.ascii_lowercase + string.digits
        return ''.join(random.choice(letters) for _ in range(length))
        
    def verify_email(self, email: str) -> Tuple[bool, str]:
        """
        Verify if an email is deliverable with multi-layered validation
        
        Args:
            email: Email address to validate
            
        Returns:
            Tuple[bool, str]: (is_valid, reason)
        """
        # Check cache first
        if email in self.email_validity_cache:
            return self.email_validity_cache[email]
        
        # 1. Basic syntax check
        if not self._is_valid_syntax(email):
            result = (False, "Invalid syntax")
            self.email_validity_cache[email] = result
            return result
            
        # Extract local part and domain
        local_part, domain = email.split('@')
        domain = domain.lower()
        
        # 2. Domain validation checks
        if not self._is_valid_domain(domain):
            result = (False, "Invalid domain")
            self.email_validity_cache[email] = result
            return result
        
        # 3. Third-party library validation for additional checks
        try:
            valid = validate_email(email, check_deliverability=True)
            normalized_email = valid.normalized
        except EmailNotValidError as e:
            result = (False, f"Email validation failed: {str(e)}")
            self.email_validity_cache[email] = result
            return result
            
        # 4. Check for disposable domains
        if domain in self.disposable_domains:
            result = (False, "Disposable email domain")
            self.email_validity_cache[email] = result
            return result
            
        # 5. Check for known problematic domains (optional additional check)
        if self.strict_mode and domain in self.known_problematic_domains:
            # Apply extra validation for these domains
            if not self._advanced_check_for_problematic_domain(email, domain):
                result = (False, f"Failed validation for {domain}")
                self.email_validity_cache[email] = result
                return result
                
        # 6. Get MX records
        mx_records = self._get_mx_records(domain)
        if not mx_records:
            result = (False, "No MX records found")
            self.email_validity_cache[email] = result
            return result
            
        # 7. Check for catch-all domain
        if self._is_catch_all_domain(domain, mx_records):
            result = (False, "Catch-all domain detected")
            self.email_validity_cache[email] = result
            return result
            
        # 8. Advanced SMTP verification
        smtp_valid, smtp_reason = self._verify_email_smtp(email, mx_records)
        if not smtp_valid:
            result = (False, f"SMTP verification failed: {smtp_reason}")
            self.email_validity_cache[email] = result
            return result
            
        # If all checks pass, the email is considered valid
        result = (True, "Valid email")
        self.email_validity_cache[email] = result
        return result
        
    def _is_valid_syntax(self, email: str) -> bool:
        """Check if email syntax is valid"""
        if not email or not isinstance(email, str):
            return False
            
        # Remove leading/trailing whitespace
        email = email.strip()
        
        # Basic RFC 5322 pattern validation
        if not self.EMAIL_REGEX.fullmatch(email):
            return False
        
        # Check if there's exactly one @ symbol
        if email.count('@') != 1:
            return False
            
        # Extract local_part and domain
        try:
            local_part, domain = email.split('@')
            
            # Check local part length (RFC 5321)
            if len(local_part) > 64:
                return False
                
            # Check domain length (RFC 5321)
            if len(domain) > 255:
                return False
                
            # Check if domain has at least one dot
            if '.' not in domain:
                return False
                
            # Check TLD is at least 2 characters
            tld = domain.split('.')[-1]
            if len(tld) < 2:
                return False
                
            return True
            
        except Exception:
            return False
            
    def _is_valid_domain(self, domain: str) -> bool:
        """Verify if domain exists"""
        # Check cache first
        if domain in self.domain_cache:
            return self.domain_cache[domain]
        
        result = False
        try:
            # Try to resolve the domain's A record
            a_records = dns.resolver.resolve(domain, 'A')
            result = len(a_records) > 0
        except Exception:
            # If we can't resolve A records, try MX records which would be checked later anyway
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                result = len(mx_records) > 0
            except Exception:
                result = False
        
        # Cache result
        self.domain_cache[domain] = result
        return result
        
    def _get_mx_records(self, domain: str) -> List[str]:
        """Get MX records for domain, sorted by preference"""
        # Check cache first
        if domain in self.mx_cache:
            return self.mx_cache[domain]
            
        mx_hosts = []
        try:
            # Get MX records sorted by preference
            mx_records = dns.resolver.resolve(domain, 'MX')
            # Sort records by preference (lower value = higher priority)
            mx_records = sorted(mx_records, key=lambda x: x.preference)
            mx_hosts = [str(rdata.exchange).rstrip('.') for rdata in mx_records]
        except Exception:
            # If MX lookup fails, try to use the domain itself as fallback
            try:
                if self._is_valid_domain(domain):
                    mx_hosts = [domain]
            except Exception:
                mx_hosts = []
                
        # Cache result
        self.mx_cache[domain] = mx_hosts
        return mx_hosts
        
    def _is_catch_all_domain(self, domain: str, mx_records: List[str]) -> bool:
        """Check if domain has catch-all configuration"""
        # Check cache first
        if domain in self.catch_all_cache:
            return self.catch_all_cache[domain]
        
        is_catch_all = False
        
        # No need to check if no MX records
        if not mx_records:
            self.catch_all_cache[domain] = False
            return False
            
        # Generate multiple random emails to reduce false positives
        test_emails = [
            f"non-existent-{self._generate_random_string(12)}@{domain}",
            f"random-test-{int(time.time())}@{domain}",
            f"this.does.not.exist.{self._generate_random_string(8)}@{domain}"
        ]
        
        catch_all_positive = 0
        for mx_host in mx_records[:1]:  # Only check the primary MX
            for test_email in test_emails:
                try:
                    if self._test_catch_all_with_smtp(mx_host, test_email):
                        catch_all_positive += 1
                except Exception:
                    continue
        
        # If at least 2 tests indicate catch-all, consider it a catch-all domain
        is_catch_all = catch_all_positive >= 2
        
        # Cache result
        self.catch_all_cache[domain] = is_catch_all
        return is_catch_all
        
    def _test_catch_all_with_smtp(self, mx_host: str, test_email: str) -> bool:
        """Test a random email with SMTP to detect catch-all"""
        for port in self.smtp_ports:
            try:
                if port == 465:
                    # Use SSL connection
                    context = ssl.create_default_context()
                    with smtplib.SMTP_SSL(mx_host, port, timeout=self.smtp_timeout, context=context) as smtp:
                        smtp.ehlo()
                        smtp.mail(self.from_email)
                        code, _ = smtp.rcpt(test_email)
                        return code == 250  # 250 means accepted
                else:
                    # Regular or STARTTLS connection
                    with smtplib.SMTP(mx_host, port, timeout=self.smtp_timeout) as smtp:
                        smtp.ehlo()
                        if port == 587:
                            # Try STARTTLS if available
                            try:
                                smtp.starttls()
                                smtp.ehlo()
                            except smtplib.SMTPException:
                                pass  # STARTTLS might not be supported
                        smtp.mail(self.from_email)
                        code, _ = smtp.rcpt(test_email)
                        return code == 250  # 250 means accepted
            except Exception:
                continue
        return False
        
    def _verify_email_smtp(self, email: str, mx_records: List[str]) -> Tuple[bool, str]:
        """
        Verify email directly with SMTP server
        
        Args:
            email: Email to verify
            mx_records: List of MX records for the domain
            
        Returns:
            Tuple[bool, str]: (is_valid, reason)
        """
        # No MX records means we can't verify
        if not mx_records:
            return False, "No MX records"
            
        # Try each MX record in order of preference
        for mx_host in mx_records:
            # Retry mechanism for improved reliability
            for attempt in range(self.verify_retries):
                # Try different ports
                for port in self.smtp_ports:
                    success, result = self._try_smtp_verification(mx_host, port, email)
                    if success:
                        return True, "SMTP verification successful"
                    # If we got a definitive negative response, don't retry
                    if result == "Rejected":
                        return False, "Email rejected by server"
                        
                # Short pause between retries
                if attempt < self.verify_retries - 1:
                    time.sleep(1)
        
        # Couldn't successfully verify with any MX server
        return False, "Failed to verify with any mail server"
        
    def _try_smtp_verification(self, mx_host: str, port: int, email: str) -> Tuple[bool, str]:
        """
        Try to verify email with specific SMTP server and port
        
        Returns:
            Tuple[bool, str]: (success, result)
        """
        try:
            if port == 465:  # SMTPS (SMTP over SSL)
                context = ssl.create_default_context()
                with smtplib.SMTP_SSL(mx_host, port, timeout=self.smtp_timeout, context=context) as smtp:
                    return self._perform_smtp_check(smtp, email)
            else:  # Regular SMTP or STARTTLS
                with smtplib.SMTP(mx_host, port, timeout=self.smtp_timeout) as smtp:
                    smtp.ehlo()
                    if port == 587:  # Try STARTTLS for this port
                        try:
                            smtp.starttls()
                            smtp.ehlo()
                        except smtplib.SMTPException:
                            pass  # STARTTLS might not be supported
                    return self._perform_smtp_check(smtp, email)
        except (socket.timeout, ConnectionRefusedError, smtplib.SMTPConnectError):
            return False, "Connection failed"
        except smtplib.SMTPServerDisconnected:
            return False, "Server disconnected"
        except smtplib.SMTPException as e:
            return False, f"SMTP error: {str(e)}"
        except Exception as e:
            return False, f"Error: {str(e)}"
            
    def _perform_smtp_check(self, smtp: smtplib.SMTP, email: str) -> Tuple[bool, str]:
        """Perform actual SMTP checks"""
        try:
            # Start SMTP conversation
            smtp.mail(self.from_email)
            
            # Check if recipient is accepted
            code, message = smtp.rcpt(email)
            
            # Analyze response
            if code == 250:  # Accepted
                return True, "Accepted"
            elif code in (550, 551, 553):  # Explicitly rejected
                return False, "Rejected"
            else:  # Ambiguous response
                return False, f"Ambiguous response: {code} {message}"
                
        except smtplib.SMTPException as e:
            return False, f"SMTP error during verification: {str(e)}"
            
    def _advanced_check_for_problematic_domain(self, email: str, domain: str) -> bool:
        """
        Additional verification for known problem domains like Yahoo, Hotmail, etc.
        that might accept emails during SMTP verification but reject at delivery
        
        Args:
            email: Email to verify
            domain: Domain name
            
        Returns:
            bool: True if passes additional verification
        """
        # Special checks for Hotmail, Outlook, Live, MSN
        if domain in {"hotmail.com", "outlook.com", "live.com", "msn.com"}:
            # Microsoft's validation is strict on format
            if re.search(r'\.{2,}|\.@|-@|\.$', email):
                return False
            
            local_part = email.split('@')[0]
            # Check for invalid starting/ending characters
            if local_part.startswith('.') or local_part.endswith('.'):
                return False
                
            # No consecutive dots or hyphens
            if '..' in local_part or '--' in local_part:
                return False
                
            # Check length restrictions
            if len(local_part) < 3:
                return False
                
        # Special checks for Yahoo
        elif domain in {"yahoo.com", "yahoo.co.uk", "yahoo.fr", "yahoo.es"}:
            local_part = email.split('@')[0]
            
            # Yahoo doesn't allow dots in the beginning or certain patterns
            if local_part.startswith('.') or '..' in local_part:
                return False
                
            # Check for Yahoo's minimum length requirement
            if len(local_part) < 4:
                return False
        
        # All checks passed
        return True


class CSVProcessor:
    """Process CSV files for email validation"""
    
    def __init__(self, validator: EnhancedEmailVerifier):
        """
        Initialize with an email validator
        
        Args:
            validator: EnhancedEmailVerifier instance
        """
        self.validator = validator
        self.total_processed = 0
        self.valid_count = 0
        self.invalid_count = 0
        self.progress_interval = 100  # Report progress every N emails
        self.invalid_reasons = {}  # Track reasons for invalid emails
        
    def read_csv_headers(self, csv_path: str) -> List[str]:
        """
        Read headers from CSV file
        
        Args:
            csv_path: Path to CSV file
            
        Returns:
            List of column headers
        """
        try:
            with open(csv_path, 'r', newline='', encoding='utf-8-sig') as file:
                reader = csv.reader(file)
                headers = next(reader)
                return headers
        except Exception as e:
            logger.error(f"Error reading CSV headers: {e}")
            sys.exit(1)
            
    def process_file(self, input_path: str, output_path: str, invalid_path: str, 
                     email_column: int, max_workers: int = 10, batch_size: int = 100) -> None:
        """
        Process CSV file, validate emails, and write valid/invalid rows to files
        
        Args:
            input_path: Path to input CSV file
            output_path: Path to output CSV file for valid emails
            invalid_path: Path to output CSV file for invalid emails
            email_column: Index of email column
            max_workers: Maximum number of concurrent workers
            batch_size: Number of rows to process in each batch
        """
        start_time = time.time()
        headers = None
        
        try:
            # Read input file and get headers
            with open(input_path, 'r', newline='', encoding='utf-8-sig') as infile:
                reader = csv.reader(infile)
                headers = next(reader)
                
                # Create output file with the same headers
                with open(output_path, 'w', newline='', encoding='utf-8') as outfile, \
                     open(invalid_path, 'w', newline='', encoding='utf-8') as invalid_file:
                    valid_writer = csv.writer(outfile)
                    invalid_writer = csv.writer(invalid_file)
                    
                    # Write headers to both files
                    valid_writer.writerow(headers + ['Verification_Result'])
                    invalid_writer.writerow(headers + ['Rejection_Reason'])
                    
                    # Process in batches
                    batch_rows = []
                    for i, row in enumerate(reader):
                        if len(row) > email_column:  # Make sure the row has enough columns
                            batch_rows.append(row)
                            
                            # Process batch when it reaches the batch size
                            if len(batch_rows) >= batch_size:
                                self._process_batch(batch_rows, email_column, valid_writer, invalid_writer, max_workers)
                                batch_rows = []
                                
                    # Process remaining rows
                    if batch_rows:
                        self._process_batch(batch_rows, email_column, valid_writer, invalid_writer, max_workers)
                        
            # Report final statistics
            elapsed_time = time.time() - start_time
            logger.info(f"\nProcessed {self.total_processed} emails in {elapsed_time:.2f} seconds")
            logger.info(f"Found {self.valid_count} valid, deliverable emails ({(self.valid_count/max(1, self.total_processed))*100:.2f}%)")
            logger.info(f"Found {self.invalid_count} invalid emails ({(self.invalid_count/max(1, self.total_processed))*100:.2f}%)")
            
            # Report top rejection reasons
            logger.info("\nTop rejection reasons:")
            for reason, count in sorted(self.invalid_reasons.items(), key=lambda x: x[1], reverse=True)[:5]:
                logger.info(f"- {reason}: {count} emails")
                
            logger.info(f"\nValid emails saved to: {output_path}")
            logger.info(f"Invalid emails saved to: {invalid_path}")
            
        except Exception as e:
            logger.error(f"Error processing file: {e}")
            sys.exit(1)
            
    def _process_batch(self, batch_rows: List[List[str]], email_column: int, 
                      valid_writer: csv.writer, invalid_writer: csv.writer, 
                      max_workers: int) -> None:
        """
        Process a batch of rows with parallel validation
        
        Args:
            batch_rows: List of CSV rows
            email_column: Index of email column
            valid_writer: CSV writer for valid emails
            invalid_writer: CSV writer for invalid emails
            max_workers: Maximum number of concurrent workers
        """
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Create tasks for validation
            future_to_row = {
                executor.submit(self._validate_row, row, email_column): row 
                for row in batch_rows
            }
            
            # Process completed tasks
            for future in concurrent.futures.as_completed(future_to_row):
                row = future_to_row[future]
                is_valid, reason = future.result()
                
                self.total_processed += 1
                
                # Write to appropriate output file
                if is_valid:
                    valid_writer.writerow(row + ['Valid'])
                    self.valid_count += 1
                else:
                    invalid_writer.writerow(row + [reason])
                    self.invalid_count += 1
                    
                    # Track rejection reasons
                    if reason not in self.invalid_reasons:
                        self.invalid_reasons[reason] = 0
                    self.invalid_reasons[reason] += 1
                
                # Show progress
                if self.total_processed % self.progress_interval == 0:
                    valid_percent = (self.valid_count / self.total_processed) * 100
                    logger.info(f"Processed: {self.total_processed}, Valid: {self.valid_count} ({valid_percent:.2f}%)")
            
    def _validate_row(self, row: List[str], email_column: int) -> Tuple[bool, str]:
        """
        Validate email in a row
        
        Args:
            row: CSV row
            email_column: Index of email column
            
        Returns:
            Tuple of (is_valid, reason)
        """
        try:
            email = row[email_column].strip()
            return self.validator.verify_email(email)
        except Exception as e:
            logger.debug(f"Error validating email: {e}")
            return False, f"Error: {str(e)}"


def main():
    """Main entry point for the script"""
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description='Enhanced email deliverability validation - removes catch-all inboxes and verifies actual deliverability'
    )
    parser.add_argument('input_file', help='Input CSV file path')
    parser.add_argument('--output-file', help='Output CSV file path for valid emails (default: valid_emails.csv)')
    parser.add_argument('--invalid-file', help='Output CSV file path for invalid emails (default: invalid_emails.csv)')
    parser.add_argument('--smtp-timeout', type=int, default=10, help='SMTP connection timeout in seconds (default: 10)')
    parser.add_argument('--from-email', type=str, help='Email to use in SMTP MAIL FROM command (default: randomly generated)')
    parser.add_argument('--workers', type=int, default=10, help='Maximum number of concurrent workers (default: 10)')
    parser.add_argument('--batch-size', type=int, default=100, help='Number of rows to process in each batch (default: 100)')
    parser.add_argument('--retries', type=int, default=2, help='Number of retries for SMTP verification (default: 2)')
    parser.add_argument('--strict', action='store_true', help='Enable strict validation mode')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Set default output paths if not provided
    output_file = args.output_file or 'valid_emails.csv'
    invalid_file = args.invalid_file or 'invalid_emails.csv'
    
    # Validate input file
    input_path = Path(args.input_file)
    if not input_path.exists():
        logger.error(f"Input file not found: {args.input_file}")
        sys.exit(1)
    
    logger.info(f"Enhanced Email Deliverability Validator")
    logger.info(f"=====================================")
    logger.info(f"Input file: {args.input_file}")
    logger.info(f"Valid emails will be saved to: {output_file}")
    logger.info(f"Invalid emails will be saved to: {invalid_file}")
    logger.info(f"Strict mode: {'Enabled' if args.strict else 'Disabled'}")
    logger.info(f"SMTP timeout: {args.smtp_timeout} seconds")
    logger.info(f"Concurrent workers: {args.workers}")
    logger.info(f"Verification retries: {args.retries}")
    
    # Create EmailDeliverabilityChecker and CSVProcessor
    validator = EnhancedEmailVerifier(
        smtp_timeout=args.smtp_timeout,
        from_email=args.from_email,
        verify_retries=args.retries,
        strict_mode=args.strict
    )
    processor = CSVProcessor(validator)
    
    # Display available columns
    headers = processor.read_csv_headers(args.input_file)
    logger.info("\nAvailable columns:")
    for i, header in enumerate(headers):
        logger.info(f"{i}: {header}")
    
    # Get email column selection
    email_column = None
    while email_column is None:
        try:
            email_col_input = input("\nEnter the column number containing emails: ")
            email_column = int(email_col_input)
            if email_column < 0 or email_column >= len(headers):
                logger.error(f"Invalid column number. Please enter a number between 0 and {len(headers)-1}")
                email_column = None
        except ValueError:
            logger.error("Please enter a valid column number")
    
    logger.info(f"Selected column: {email_column} ({headers[email_column]})")
    
    # Process the file
    logger.info(f"\nProcessing {args.input_file}...")
    processor.process_file(
        args.input_file, 
        output_file, 
        invalid_file,
        email_column,
        max_workers=args.workers,
        batch_size=args.batch_size
    )


if __name__ == "__main__":
    main()