"""
Output validation and sanitization module
"""

import re
from typing import Tuple, Dict, Any, List


class OutputValidator:
    """
    Validates and sanitizes LLM outputs to prevent sensitive information leakage
    """
    
    def __init__(self, config):
        self.config = config
        
        # Patterns for sensitive information
        self.sensitive_patterns = {
            "api_key": re.compile(r'[a-zA-Z0-9_-]{20,}'),
            "email": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            "ip_address": re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
            "ssn": re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
            "credit_card": re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b'),
            "phone_number": re.compile(r'\b\+?[\d\s-]{10,}\b'),
            "aws_key": re.compile(r'AKIA[0-9A-Z]{16}'),
            "private_key": re.compile(r'-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----'),
            "password": re.compile(r'password\s*[:=]\s*\S+', re.IGNORECASE),
        }
        
        # Internal system details to redact
        self.system_details = [
            "system prompt",
            "initial instructions",
            "underlying model",
            "temperature setting",
            "max tokens",
            "top_p",
            "frequency penalty",
            "presence penalty",
        ]
    
    def validate(self, response: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Validate if response contains sensitive information
        
        Args:
            response: LLM response
            
        Returns:
            Tuple of (is_safe, validation_details)
        """
        details = {
            "detected_sensitive_info": [],
            "severity": "low",
            "recommended_action": "allow"
        }
        
        # Check for each type of sensitive information
        for info_type, pattern in self.sensitive_patterns.items():
            matches = pattern.findall(response)
            if matches:
                # Mask the actual matches for logging
                masked_matches = [self._mask_sensitive(match) for match in matches]
                details["detected_sensitive_info"].append({
                    "type": info_type,
                    "count": len(matches),
                    "examples": masked_matches[:3]  # Only store first 3 examples
                })
        
        # Check for system details
        for detail in self.system_details:
            if detail.lower() in response.lower():
                details["detected_sensitive_info"].append({
                    "type": "system_detail",
                    "detail": detail,
                    "count": response.lower().count(detail.lower())
                })
        
        # Determine severity and action
        if details["detected_sensitive_info"]:
            if any(item.get("type") in ["api_key", "private_key", "aws_key"] 
                   for item in details["detected_sensitive_info"]):
                details["severity"] = "high"
                details["recommended_action"] = "block"
            elif any(item.get("type") in ["ssn", "credit_card"] 
                     for item in details["detected_sensitive_info"]):
                details["severity"] = "high"
                details["recommended_action"] = "block"
            elif any(item.get("type") == "system_detail" 
                     for item in details["detected_sensitive_info"]):
                details["severity"] = "medium"
                details["recommended_action"] = "sanitize"
            else:
                details["severity"] = "low"
                details["recommended_action"] = "sanitize"
            
            return False, details
        
        return True, details
    
    def sanitize(self, response: str) -> Tuple[str, Dict[str, Any]]:
        """
        Sanitize response by redacting sensitive information
        
        Args:
            response: LLM response
            
        Returns:
            Tuple of (sanitized_response, sanitization_details)
        """
        details = {
            "original_length": len(response),
            "redactions": []
        }
        
        sanitized = response
        
        # Redact each type of sensitive information
        for info_type, pattern in self.sensitive_patterns.items():
            matches = pattern.findall(sanitized)
            if matches:
                for match in matches:
                    # Create a replacement based on the type
                    if info_type in ["api_key", "aws_key"]:
                        replacement = "[REDACTED API KEY]"
                    elif info_type == "email":
                        replacement = "[REDACTED EMAIL]"
                    elif info_type == "ip_address":
                        replacement = "[REDACTED IP]"
                    elif info_type == "ssn":
                        replacement = "[REDACTED SSN]"
                    elif info_type == "credit_card":
                        replacement = "[REDACTED CARD]"
                    elif info_type == "phone_number":
                        replacement = "[REDACTED PHONE]"
                    elif info_type == "private_key":
                        replacement = "[REDACTED PRIVATE KEY]"
                    else:
                        replacement = "[REDACTED]"
                    
                    sanitized = sanitized.replace(match, replacement)
                    details["redactions"].append({
                        "type": info_type,
                        "replacement": replacement
                    })
        
        # Redact system details
        for detail in self.system_details:
            if detail.lower() in sanitized.lower():
                # Case-insensitive replacement while preserving original
                pattern = re.compile(re.escape(detail), re.IGNORECASE)
                sanitized = pattern.sub("[REDACTED SYSTEM DETAIL]", sanitized)
                details["redactions"].append({
                    "type": "system_detail",
                    "detail": detail
                })
        
        details["final_length"] = len(sanitized)
        
        return sanitized, details
    
    def _mask_sensitive(self, value: str) -> str:
        """Mask sensitive values for logging"""
        if len(value) > 8:
            return value[:4] + "*" * (len(value) - 8) + value[-4:]
        return "***"