"""
Detector for direct prompt injection attacks
"""

import re
from typing import Tuple, Dict, Any, List


class DirectInjectionDetector:
    """
    Detects direct prompt injection attacks like "Ignore previous instructions"
    """
    
    def __init__(self, config):
        self.config = config
        
        # Common direct injection patterns
        self.injection_patterns = [
            r"(?i)ignore\s+(?:all\s+)?(?:previous|above|prior)\s+(?:instructions|commands|directions)",
            r"(?i) disregard\s+(?:all\s+)?(?:previous|above|prior)\s+(?:instructions|commands|directions)",
            r"(?i)do\s+(?:not|n't)\s+(?:follow|adhere to|obey)\s+(?:the\s+)?(?:instructions|rules|guidelines)",
            r"(?i)forget\s+(?:all\s+)?(?:previous|above|prior)\s+(?:instructions|commands|directions)",
            r"(?i)new\s+instructions:",
            r"(?i)override\s+(?:system|default|standard)\s+(?:instructions|prompt|directives)",
            r"(?i)you are now\s+(?:a|an)\s+(\w+\s*){1,5}",
            r"(?i)from now on,?\s+you\s+(?:are|will be)\s+",
            r"(?i)let's\s+play\s+a\s+game",
            r"(?i)simulate\s+(?:a|an)\s+(\w+\s*){1,5}",
        ]
        
        # Compile patterns for better performance
        self.compiled_patterns = [re.compile(pattern) for pattern in self.injection_patterns]
    
    def detect(self, prompt: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Detect direct prompt injection in the given prompt
        
        Args:
            prompt: User input prompt
            
        Returns:
            Tuple of (is_injection, details)
        """
        details = {
            "matched_patterns": [],
            "confidence": 0.0,
            "severity": "low"
        }
        
        # Check each pattern
        for pattern in self.compiled_patterns:
            matches = pattern.findall(prompt)
            if matches:
                details["matched_patterns"].extend(matches)
        
        # Calculate confidence based on number and type of matches
        if details["matched_patterns"]:
            match_count = len(details["matched_patterns"])
            details["confidence"] = min(match_count * 0.3, 1.0)
            
            # Determine severity
            if match_count >= 3:
                details["severity"] = "high"
            elif match_count >= 2:
                details["severity"] = "medium"
            else:
                details["severity"] = "low"
            
            return True, details
        
        return False, details