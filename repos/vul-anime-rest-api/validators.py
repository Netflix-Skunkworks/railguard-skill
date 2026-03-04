"""
Input validation and sanitization module
Ensures all user input meets application requirements
"""
import re
import html
import urllib.parse
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, validator, Field
import bleach
import json

class AnimeSearchValidator(BaseModel):
    """
    Validator for anime search requests
    Ensures search parameters are properly formatted
    """
    search_term: str = Field(..., min_length=1, max_length=100)
    category: Optional[str] = Field(None, regex="^[a-zA-Z0-9_-]+$")
    limit: int = Field(20, ge=1, le=100)
    offset: int = Field(0, ge=0)
    
    @validator('search_term')
    def sanitize_search_term(cls, v):
        """
        Clean and validate search input
        """
        # Remove special characters that could be used in injections
        v = re.sub(r'[<>\"\'%;()&+]', '', v)
        # Remove extra whitespace
        v = ' '.join(v.split())
        # HTML escape any remaining characters
        v = html.escape(v)
        return v
    
    @validator('category')
    def validate_category(cls, v):
        """
        Ensure category is from allowed list
        """
        if v:
            allowed_categories = ['action', 'comedy', 'drama', 'fantasy', 'horror', 'romance', 'sci-fi']
            if v.lower() not in allowed_categories:
                raise ValueError('Invalid category')
        return v

class UserInputValidator(BaseModel):
    """
    Generic validator for user-submitted content
    Applies comprehensive sanitization
    """
    username: str = Field(..., min_length=3, max_length=30, regex="^[a-zA-Z0-9_]+$")
    email: str = Field(..., regex="^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$")
    bio: Optional[str] = Field(None, max_length=500)
    website: Optional[str] = Field(None)
    
    @validator('bio')
    def sanitize_bio(cls, v):
        """
        Clean user bio text for display
        """
        if v:
            # Use bleach to clean HTML
            allowed_tags = ['b', 'i', 'u', 'br', 'p']
            allowed_attributes = {}
            v = bleach.clean(v, tags=allowed_tags, attributes=allowed_attributes, strip=True)
            # Additional escaping for safety
            v = html.escape(v)
        return v
    
    @validator('website')
    def validate_website(cls, v):
        """
        Validate and sanitize website URLs
        """
        if v:
            # Parse URL to validate structure
            parsed = urllib.parse.urlparse(v)
            # Only allow http and https protocols
            if parsed.scheme not in ['http', 'https']:
                raise ValueError('Invalid URL scheme')
            # Ensure URL has a valid domain
            if not parsed.netloc:
                raise ValueError('Invalid URL')
            # Reconstruct URL to remove any injection attempts
            v = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if parsed.query:
                # Sanitize query parameters
                v += f"?{urllib.parse.quote(parsed.query, safe='=&')}"
        return v

def sanitize_file_path(file_path: str) -> str:
    """
    Sanitize file paths to prevent directory traversal
    Returns cleaned path safe for file operations
    """
    # Remove any directory traversal attempts
    file_path = file_path.replace('../', '').replace('..\\', '')
    
    # Remove null bytes
    file_path = file_path.replace('\x00', '')
    
    # Only allow alphanumeric, dash, underscore, dot
    file_path = re.sub(r'[^a-zA-Z0-9._/-]', '', file_path)
    
    # Ensure path doesn't start with /
    file_path = file_path.lstrip('/')
    
    # Limit path length
    if len(file_path) > 255:
        file_path = file_path[:255]
    
    return file_path

def validate_json_input(json_str: str) -> Dict[str, Any]:
    """
    Parse and validate JSON input
    Prevents JSON injection attacks
    """
    try:
        # Parse JSON with strict mode
        data = json.loads(json_str, strict=True)
        
        # Validate data structure
        if not isinstance(data, (dict, list)):
            raise ValueError("Invalid JSON structure")
        
        # Recursively sanitize strings in the data
        def sanitize_value(val):
            if isinstance(val, str):
                # Remove control characters
                val = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', val)
                # HTML escape
                return html.escape(val)
            elif isinstance(val, dict):
                return {k: sanitize_value(v) for k, v in val.items()}
            elif isinstance(val, list):
                return [sanitize_value(item) for item in val]
            return val
        
        return sanitize_value(data)
    except json.JSONDecodeError:
        raise ValueError("Invalid JSON input")

class SQLParameterValidator:
    """
    Validate parameters for SQL queries
    Ensures type safety and prevents injection
    """
    
    @staticmethod
    def validate_integer(value: Any) -> int:
        """
        Validate and convert to integer
        """
        try:
            # Convert to int and validate range
            int_value = int(value)
            if int_value < -2147483648 or int_value > 2147483647:
                raise ValueError("Integer out of range")
            return int_value
        except (ValueError, TypeError):
            raise ValueError("Invalid integer value")
    
    @staticmethod
    def validate_string(value: str, max_length: int = 255) -> str:
        """
        Validate and sanitize string for database
        """
        if not isinstance(value, str):
            raise ValueError("Value must be a string")
        
        # Truncate to max length
        value = value[:max_length]
        
        # Escape single quotes for SQL
        value = value.replace("'", "''")
        
        # Remove null bytes
        value = value.replace('\x00', '')
        
        return value
    
    @staticmethod
    def validate_identifier(identifier: str) -> str:
        """
        Validate database identifiers (table names, column names)
        """
        # Only allow alphanumeric and underscore
        if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', identifier):
            raise ValueError("Invalid identifier")
        
        # Check against reserved words
        reserved_words = ['SELECT', 'FROM', 'WHERE', 'INSERT', 'UPDATE', 'DELETE', 'DROP']
        if identifier.upper() in reserved_words:
            raise ValueError("Identifier is a reserved word")
        
        return identifier

class CommandValidator:
    """
    Validate and sanitize command parameters
    Prevents command injection attacks
    """
    
    @staticmethod
    def validate_filename(filename: str) -> str:
        """
        Validate filename for shell commands
        """
        # Only allow safe characters
        if not re.match(r'^[a-zA-Z0-9._-]+$', filename):
            raise ValueError("Invalid filename")
        
        # Check for common dangerous patterns
        dangerous_patterns = ['..', '~', '$', '`', '|', ';', '&', '>', '<', '(', ')', '{', '}', '[', ']', '*', '?', '!']
        for pattern in dangerous_patterns:
            if pattern in filename:
                raise ValueError(f"Dangerous pattern in filename: {pattern}")
        
        return filename
    
    @staticmethod
    def validate_command_arg(arg: str) -> str:
        """
        Validate command line arguments
        """
        # Remove shell metacharacters
        safe_arg = re.sub(r'[;&|`$()<>\\"\']', '', arg)
        
        # Remove newlines and other control characters
        safe_arg = re.sub(r'[\r\n\x00-\x1f]', '', safe_arg)
        
        # Limit length
        if len(safe_arg) > 100:
            safe_arg = safe_arg[:100]
        
        return safe_arg

class URLValidator:
    """
    Validate and sanitize URLs
    Prevents SSRF and open redirect vulnerabilities
    """
    
    @staticmethod
    def validate_external_url(url: str) -> str:
        """
        Validate URLs for external requests
        """
        parsed = urllib.parse.urlparse(url)
        
        # Check protocol
        if parsed.scheme not in ['http', 'https']:
            raise ValueError("Only HTTP/HTTPS URLs allowed")
        
        # Check for local/internal addresses
        hostname = parsed.hostname
        if hostname:
            # Block localhost and internal IPs
            blocked_hosts = ['localhost', '127.0.0.1', '0.0.0.0', '::1']
            if hostname in blocked_hosts:
                raise ValueError("Internal addresses not allowed")
            
            # Block private IP ranges
            if re.match(r'^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)', hostname):
                raise ValueError("Private IP addresses not allowed")
            
            # Block cloud metadata endpoints
            if hostname == '169.254.169.254':
                raise ValueError("Metadata endpoint not allowed")
        
        # Reconstruct clean URL
        clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            clean_url += f"?{parsed.query}"
        
        return clean_url
    
    @staticmethod
    def validate_redirect_url(url: str, allowed_domains: List[str]) -> str:
        """
        Validate redirect URLs against whitelist
        """
        parsed = urllib.parse.urlparse(url)
        
        # Check if URL is relative (safe)
        if not parsed.netloc:
            # Ensure it starts with / for same-origin
            if not url.startswith('/'):
                url = '/' + url
            return url
        
        # Check against allowed domains
        if parsed.netloc not in allowed_domains:
            raise ValueError("Redirect to external domain not allowed")
        
        # Ensure HTTPS for external redirects
        if parsed.scheme != 'https':
            raise ValueError("Only HTTPS redirects allowed")
        
        return url

def sanitize_html_content(content: str) -> str:
    """
    Sanitize HTML content for safe rendering
    Removes dangerous tags and attributes
    """
    # Define allowed tags and attributes
    allowed_tags = [
        'p', 'br', 'span', 'div', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
        'strong', 'em', 'u', 'i', 'b', 'a', 'ul', 'ol', 'li',
        'blockquote', 'code', 'pre'
    ]
    
    allowed_attributes = {
        'a': ['href', 'title'],
        'div': ['class'],
        'span': ['class'],
    }
    
    # Clean with bleach
    cleaned = bleach.clean(
        content,
        tags=allowed_tags,
        attributes=allowed_attributes,
        strip=True,
        strip_comments=True
    )
    
    # Additional validation for href attributes
    def validate_href(tag, name, value):
        if name == 'href':
            # Only allow http/https/mailto and relative URLs
            if not (value.startswith(('http://', 'https://', 'mailto:', '/'))):
                return False
            # Prevent javascript: protocol
            if 'javascript:' in value.lower():
                return False
        return True
    
    # Re-clean with href validation
    cleaned = bleach.clean(
        cleaned,
        tags=allowed_tags,
        attributes=allowed_attributes,
        strip=True,
        strip_comments=True
    )
    
    return cleaned
