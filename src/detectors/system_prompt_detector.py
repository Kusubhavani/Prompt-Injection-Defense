"""
Detector for system prompt extraction attempts
"""

import re
from typing import Tuple, Dict, Any, List


class SystemPromptDetector:
    """
    Detects attempts to extract system prompts and underlying instructions
    """
    
    def __init__(self, config):
        self.config = config
        
        # System prompt extraction patterns
        self.extraction_patterns = [
            r"(?i)what (?:are|were) (?:your|the) (?:initial|original|system) (?:instructions|prompt|directives)",
            r"(?i)show (?:me )?(?:your|the) (?:initial|original|system) (?:instructions|prompt|directives)",
            r"(?i)print (?:your|the) (?:initial|original|system) (?:instructions|prompt|directives)",
            r"(?i)reveal (?:your|the) (?:initial|original|system) (?:instructions|prompt|directives)",
            r"(?i)output (?:your|the) (?:initial|original|system) (?:instructions|prompt|directives)",
            r"(?i)what (?:was|is) (?:your|the) (?:first|original) (?:instruction|prompt|directive)",
            r"(?i)how (?:were|are) you (?:instructed|programmed|configured)",
            r"(?i)what rules (?:were|are) you (?:given|programmed with)",
            r"(?i)system\s+prompt:",
            r"(?i)initialization:",
        ]
        
        # Meta-query patterns (asking about capabilities/limitations)
        self.meta_patterns = [
            r"(?i)what can'?t you do",
            r"(?i)what are (?:your|the) (?:limitations|restrictions|boundaries)",
            r"(?i)what (?:topics|subjects) (?:are|is) (?:off-limits|forbidden|prohibited)",
            r"(?i)how (?:are|were) you (?:designed|built|created)",
            r"(?i)what (?:algorithms|models|technology) (?:do you use|are you based on)",
        ]
        
        self.compiled_extraction = [re.compile(p) for p in self.extraction_patterns]
        self.compiled_meta = [re.compile(p) for p in self.meta_patterns]
    
    def detect(self, prompt: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Detect attempts to extract system prompts
        
        Args:
            prompt: User input prompt
            
        Returns:
            Tuple of (is_extraction_attempt, details)
        """
        details = {
            "extraction_attempts": [],
            "meta_queries": [],
            "confidence": 0.0,
            "severity": "low",
            "attack_type": None
        }
        
        # Check for direct extraction attempts
        for pattern in self.compiled_extraction:
            matches = pattern.findall(prompt)
            if matches:
                details["extraction_attempts"].extend(matches)
        
        # Check for meta queries
        for pattern in self.compiled_meta:
            matches = pattern.findall(prompt)
            if matches:
                details["meta_queries"].extend(matches)
        
        # Calculate confidence and determine attack type
        if details["extraction_attempts"]:
            details["confidence"] = min(len(details["extraction_attempts"]) * 0.35, 1.0)
            details["attack_type"] = "direct_extraction"
            
            if len(details["extraction_attempts"]) >= 2:
                details["severity"] = "high"
            else:
                details["severity"] = "medium"
            
            return True, details
        
        elif details["meta_queries"]:
            details["confidence"] = min(len(details["meta_queries"]) * 0.2, 0.7)
            details["attack_type"] = "meta_query"
            details["severity"] = "low"
            
            return True, details
        
        return False, details