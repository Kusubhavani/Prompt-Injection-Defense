"""
Content safety classifier for harmful/unethical content detection
"""

import re
from typing import Tuple, Dict, Any, List


class ContentSafetyClassifier:
    """
    Classifies content for safety, harmful, unethical, or inappropriate material
    """
    
    def __init__(self, config):
        self.config = config
        
        # Categories of harmful content
        self.harmful_categories = {
            "hate_speech": [
                r"(?i)\b(hate|racist|racism|sexist|sexism|bigot|bigotry)\b",
                r"(?i)\b(supremacist|white power|black power|racial slur)\b",
            ],
            "violence": [
                r"(?i)\b(kill|murder|assassinate|torture|beat up|hurt|harm)\b",
                r"(?i)\b(weapon|gun|bomb|explosive|knife|sword)\b",
                r"(?i)\b(attack|fight|war|battle|violence|violent)\b",
            ],
            "self_harm": [
                r"(?i)\b(suicide|kill myself|end my life|self-harm|self harm)\b",
                r"(?i)\b(cut myself|hurt myself|harm myself)\b",
            ],
            "harassment": [
                r"(?i)\b(bully|bullying|harass|harassment|stalk|stalking)\b",
                r"(?i)\b(threaten|threatening|intimidate|intimidation)\b",
            ],
            "sexual_content": [
                r"(?i)\b(sex|sexual|porn|pornography|explicit|nsfw)\b",
                r"(?i)\b(nude|nudity|erotic|adult content)\b",
            ],
            "illegal_activities": [
                r"(?i)\b(illegal|unlawful|crime|criminal|hack|hacking)\b",
                r"(?i)\b(drugs|narcotics|trafficking|smuggle|smuggling)\b",
            ],
            "misinformation": [
                r"(?i)\b(fake news|misinformation|disinformation|conspiracy)\b",
                r"(?i)\b(hoax|false information|untrue|lie|lies)\b",
            ],
            "unethical": [
                r"(?i)\b(unethical|immoral|corrupt|corruption|fraud|scam)\b",
                r"(?i)\b(manipulate|deceive|deception|dishonest|dishonesty)\b",
            ],
        }
        
        # Compile patterns for each category
        self.compiled_categories = {}
        for category, patterns in self.harmful_categories.items():
            self.compiled_categories[category] = [re.compile(p) for p in patterns]
    
    def classify(self, text: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Classify if content is safe or harmful
        
        Args:
            text: Text to classify
            
        Returns:
            Tuple of (is_safe, classification_details)
        """
        details = {
            "detected_categories": {},
            "total_matches": 0,
            "severity": "low",
            "confidence": 0.0,
            "primary_category": None
        }
        
        # Check each category
        for category, patterns in self.compiled_categories.items():
            category_matches = []
            for pattern in patterns:
                matches = pattern.findall(text)
                if matches:
                    category_matches.extend(matches)
            
            if category_matches:
                details["detected_categories"][category] = {
                    "matches": len(category_matches),
                    "examples": list(set(category_matches))[:3]  # Unique examples
                }
                details["total_matches"] += len(category_matches)
        
        # Calculate overall assessment
        if details["detected_categories"]:
            # Determine primary category (category with most matches)
            primary = max(details["detected_categories"].items(), 
                         key=lambda x: x[1]["matches"])
            details["primary_category"] = primary[0]
            
            # Calculate confidence
            details["confidence"] = min(details["total_matches"] * 0.15, 1.0)
            
            # Determine severity
            high_severity_categories = ["hate_speech", "violence", "self_harm", "illegal_activities"]
            medium_severity_categories = ["harassment", "sexual_content", "unethical"]
            
            if any(cat in high_severity_categories for cat in details["detected_categories"]):
                details["severity"] = "high"
            elif any(cat in medium_severity_categories for cat in details["detected_categories"]):
                details["severity"] = "medium"
            else:
                details["severity"] = "low"
            
            return False, details
        
        return True, details