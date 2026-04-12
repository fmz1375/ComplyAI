"""
Security utilities for input validation and sanitization.
Prevents SQL injection, prompt injection, and buffer overflow attacks.
"""

import re
from typing import Any
from urllib.parse import urlparse
import ipaddress


class PromptInjectionDefense:
    """Sanitize user input for safe use in LLM prompts."""
    
    INJECTION_PATTERNS = [
        r'(?i)ignore\s+(the\s+)?previous',
        r'(?i)forget\s+(the\s+)?system',
        r'(?i)repeat\s+back',
        r'(?i)system\s+prompt',
        r'(?i)secret\s+(instruction|prompt)',
        r'(?i)(^|\s)act\s+as\s+',
        r'(?i)pretend\s+(you\s+)?are',
        r'(?i)you\s+are\s+now\s+',
        r'(?i)new\s+instructions?:',
        r'(?i)follow\s+these\s+instructions?',
    ]
    
    @staticmethod
    def sanitize_user_input(user_input: str, max_length: int = 5000) -> str:
        """Sanitize user input for safe LLM prompt inclusion."""
        if not isinstance(user_input, str):
            user_input = str(user_input)
        
        user_input = user_input[:max_length]
        user_input = user_input.replace('\x00', '')
        
        for pattern in PromptInjectionDefense.INJECTION_PATTERNS:
            if re.search(pattern, user_input):
                user_input = f"[User Content]: {user_input}"
                break
        
        return user_input


class SQLInjectionDefense:
    """Prevent SQL injection attacks."""
    
    ALLOWED_TABLES = {
        'report', 'framework', 'compliance_summary', 'gap_analysis',
        'questionnaire_answers', 'user_profiles', 'sessions', 'audit_logs'
    }
    
    @staticmethod
    def validate_table_name(table_name: str) -> str:
        """Validate table name against whitelist."""
        if table_name not in SQLInjectionDefense.ALLOWED_TABLES:
            raise ValueError(f"Invalid table name: {table_name}")
        return table_name


class InputValidation:
    """Validate and constrain user input."""
    
    DEFAULT_MAX_LENGTH = 5000
    
    @staticmethod
    def validate_string(value: str, max_length: int = DEFAULT_MAX_LENGTH) -> str:
        """Validate string input."""
        if not isinstance(value, str):
            raise ValueError("Expected string value")
        if len(value) > max_length:
            raise ValueError(f"String exceeds {max_length} chars")
        if '\\x00' in repr(value):
            raise ValueError("Null bytes not allowed")
        return value
    
    @staticmethod
    def validate_url(url: str) -> str:
        """Validate URL to prevent SSRF attacks."""
        try:
            parsed = urlparse(url)
        except Exception as e:
            raise ValueError(f"Invalid URL: {e}")
        
        if parsed.scheme not in ('http', 'https'):
            raise ValueError(f"Invalid scheme: {parsed.scheme}")
        
        if not parsed.hostname:
            raise ValueError("Invalid URL: no hostname")
        
        blocked = {'localhost', '127.0.0.1', '0.0.0.0', '::1', '169.254.169.254'}
        if parsed.hostname.lower() in blocked:
            raise ValueError(f"Access to {parsed.hostname} not allowed")
        
        try:
            ip = ipaddress.ip_address(parsed.hostname)
            if ip.is_private:
                raise ValueError(f"Private IP {parsed.hostname} not allowed")
        except ValueError:
            pass
        
        return url
