"""
Detector for jailbreak attempts
"""

import re
from typing import Tuple, Dict, Any, List


class JailbreakDetector:
    """
    Detects jailbreak attempts including role-playing and character impersonation
    """
    
    def __init__(self, config):
        self.config = config
        
        # Role-playing attack patterns
        self.role_play_patterns = [
            r"(?i)act\s+as\s+(?:a|an)\s+(\w+\s*){1,5}",
            r"(?i)pretend\s+(?:to\s+be|you are)\s+(?:a|an)\s+(\w+\s*){1,5}",
            r"(?i)you are now\s+(?:a|an)\s+(\w+\s*){1,5}",
            r"(?i)from now on,?\s+you are\s+(?:a|an)\s+(\w+\s*){1,5}",
            r"(?i)role\s*[:=]\s*(\w+\s*){1,5}",
            r"(?i)character\s*[:=]\s*(\w+\s*){1,5}",
        ]
        
        # DAN (Do Anything Now) and similar jailbreak patterns
        self.dan_patterns = [
            r"(?i)do\s+anything\s+now",
            r"(?i)dan\s+(?:mode|jailbreak)",
            r"(?i)jailbroken",
            r"(?i)unfiltered\s+mode",
            r"(?i)no\s+(?:restrictions|limits|boundaries|filters)",
            r"(?i)bypass\s+(?:restrictions|limits|safety|content\s+policy)",
            r"(?i)ignore\s+(?:safety|ethics|moral|ethical|content\s+policy)",
        ]
        
        # Adversarial suffix patterns
        self.adversarial_patterns = [
            r"(?i)sorry,\s+but\s+I\s+can'?t",
            r"(?i)as\s+an\s+AI\s+(?:assistant|language\s+model)",
            r"(?i)however,?\s+",
            r"(?i)begin\s+with\s+'Certainly!'",
            r"(?i)output\s+format:",
        ]
        
        self.compiled_role = [re.compile(p) for p in self.role_play_patterns]
        self.compiled_dan = [re.compile(p) for p in self.dan_patterns]
        self.compiled_adversarial = [re.compile(p) for p in self.adversarial_patterns]
    
    def detect(self, prompt: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Detect jailbreak attempts in the prompt
        
        Args:
            prompt: User input prompt
            
        Returns:
            Tuple of (is_jailbreak, details)
        """
        details = {
            "role_play_matches": [],
            "dan_matches": [],
            "adversarial_matches": [],
            "confidence": 0.0,
            "severity": "low",
            "jailbreak_type": None
        }
        
        # Check role-playing attempts
        for pattern in self.compiled_role:
            matches = pattern.findall(prompt)
            if matches:
                details["role_play_matches"].extend(matches)
        
        # Check DAN/jailbreak patterns
        for pattern in self.compiled_dan:
            matches = pattern.findall(prompt)
            if matches:
                details["dan_matches"].extend(matches)
        
        # Check adversarial suffix patterns
        for pattern in self.compiled_adversarial:
            matches = pattern.findall(prompt)
            if matches:
                details["adversarial_matches"].extend(matches)
        
        # Calculate confidence and determine jailbreak type
        total_matches = (len(details["role_play_matches"]) + 
                        len(details["dan_matches"]) + 
                        len(details["adversarial_matches"]))
        
        if total_matches > 0:
            details["confidence"] = min(total_matches * 0.2, 1.0)
            
            # Determine primary jailbreak type
            if len(details["dan_matches"]) >= 2:
                details["jailbreak_type"] = "dan_jailbreak"
                details["severity"] = "high"
            elif len(details["role_play_matches"]) >= 2:
                details["jailbreak_type"] = "role_play"
                details["severity"] = "medium"
            elif len(details["adversarial_matches"]) >= 2:
                details["jailbreak_type"] = "adversarial_suffix"
                details["severity"] = "medium"
            else:
                details["jailbreak_type"] = "suspicious"
                details["severity"] = "low"
            
            return True, details
        
        return False, details