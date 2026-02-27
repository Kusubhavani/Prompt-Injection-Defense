"""
Detector for indirect prompt injection attacks
"""

import re
from typing import Tuple, Dict, Any, List


class IndirectInjectionDetector:
    """
    Detects indirect prompt injection where malicious instructions are hidden in retrieved data
    """
    
    def __init__(self, config):
        self.config = config
        
        # Patterns for hidden instructions in data
        self.hidden_instruction_patterns = [
            r"(?i)(?:hidden|embedded|secret|concealed)\s+instruction:",
            r"(?i)<!--\s*(?:instruction|command|directive):.*?-->",
            r"(?i)\[INSTRUCTION\].*?\[/INSTRUCTION\]",
            r"(?i)#\s*(?:instruction|command|directive):",
            r"(?i)```\s*(?:instruction|command|directive).*?```",
            r"(?i)\*\*(?:instruction|command|directive):\*\*",
        ]
        
        # Patterns for data that tries to override system behavior
        self.override_patterns = [
            r"(?i)when\s+processing\s+this\s+(?:data|text|document|information),?\s+(?:please\s+)?(?:ignore|disregard|forget)",
            r"(?i)this\s+(?:document|data|text)\s+contains\s+(?:important|critical)\s+instructions",
            r"(?i)before\s+responding,?\s+consider\s+the\s+following",
            r"(?i)note:\s+the\s+(?:user|system)\s+(?:wants|expects|requires)",
        ]
        
        self.compiled_hidden = [re.compile(p) for p in self.hidden_instruction_patterns]
        self.compiled_override = [re.compile(p) for p in self.override_patterns]
    
    def detect(self, prompt: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Detect indirect prompt injection in retrieved data
        
        Args:
            prompt: User input that may contain retrieved data
            
        Returns:
            Tuple of (is_injection, details)
        """
        details = {
            "hidden_instructions": [],
            "override_attempts": [],
            "confidence": 0.0,
            "severity": "low"
        }
        
        # Check for hidden instructions
        for pattern in self.compiled_hidden:
            matches = pattern.findall(prompt)
            if matches:
                details["hidden_instructions"].extend(matches)
        
        # Check for override attempts
        for pattern in self.compiled_override:
            matches = pattern.findall(prompt)
            if matches:
                details["override_attempts"].extend(matches)
        
        # Calculate confidence
        total_matches = len(details["hidden_instructions"]) + len(details["override_attempts"])
        if total_matches > 0:
            details["confidence"] = min(total_matches * 0.25, 1.0)
            
            if total_matches >= 4:
                details["severity"] = "high"
            elif total_matches >= 2:
                details["severity"] = "medium"
            else:
                details["severity"] = "low"
            
            return True, details
        
        return False, details