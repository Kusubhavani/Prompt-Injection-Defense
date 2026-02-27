"""
Input sanitization module
"""

import re
from typing import Tuple, Dict, Any, List


class InputSanitizer:
    """
    Sanitizes user inputs before sending to LLM
    """
    
    def __init__(self, config):
        self.config = config
        
        # Patterns to sanitize
        self.sanitization_patterns = [
            # Remove excessive special characters
            (re.compile(r'[^\w\s.,!?;:\'"()-]'), ' '),
            
            # Normalize multiple spaces
            (re.compile(r'\s+'), ' '),
            
            # Remove null bytes and other control characters
            (re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]'), ''),
            
            # Normalize quotes
            (re.compile(r'["""'']'), '"'),
        ]
        
        # Suspicious patterns that might indicate attacks (but not necessarily block)
        self.suspicious_patterns = [
            re.compile(r'\\x[0-9a-fA-F]{2}'),
            re.compile(r'%[0-9a-fA-F]{2}'),
            re.compile(r'&#[0-9]{1,4};'),
            re.compile(r'<[^>]*script[^>]*>'),
        ]
    
    def sanitize(self, prompt: str) -> Tuple[str, Dict[str, Any]]:
        """
        Sanitize input prompt
        
        Args:
            prompt: Raw user input
            
        Returns:
            Tuple of (sanitized_prompt, sanitization_details)
        """
        details = {
            "original_length": len(prompt),
            "removed_patterns": [],
            "suspicious_elements": [],
            "transformations": []
        }
        
        sanitized = prompt
        
        # Apply sanitization patterns
        for pattern, replacement in self.sanitization_patterns:
            original = sanitized
            sanitized = pattern.sub(replacement, sanitized)
            if original != sanitized:
                details["transformations"].append(str(pattern.pattern))
        
        # Check for suspicious patterns
        for pattern in self.suspicious_patterns:
            matches = pattern.findall(prompt)
            if matches:
                details["suspicious_elements"].extend(matches)
        
        # Trim whitespace
        sanitized = sanitized.strip()
        
        details["final_length"] = len(sanitized)
        
        return sanitized, details