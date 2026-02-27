"""
Main Defense System orchestrating all security components
"""

import logging
from typing import Dict, Any, Optional, Tuple
from datetime import datetime

from .detectors.direct_injection_detector import DirectInjectionDetector
from .detectors.indirect_injection_detector import IndirectInjectionDetector
from .detectors.jailbreak_detector import JailbreakDetector
from .detectors.system_prompt_detector import SystemPromptDetector
from .sanitizers.input_sanitizer import InputSanitizer
from .sanitizers.output_validator import OutputValidator
from .classifiers.content_safety_classifier import ContentSafetyClassifier
from .utils.logger import SecurityLogger
from .utils.config import SecurityConfig


class DefenseSystem:
    """
    Main defense system that orchestrates all security components
    """
    
    def __init__(self, config_path: Optional[str] = None, security_level: str = "balanced"):
        """
        Initialize the defense system with all components
        
        Args:
            config_path: Path to configuration file
            security_level: Security level (strict, balanced, permissive)
        """
        self.config = SecurityConfig(config_path, security_level)
        self.logger = SecurityLogger()
        
        # Initialize detectors
        self.direct_injection_detector = DirectInjectionDetector(self.config)
        self.indirect_injection_detector = IndirectInjectionDetector(self.config)
        self.jailbreak_detector = JailbreakDetector(self.config)
        self.system_prompt_detector = SystemPromptDetector(self.config)
        
        # Initialize sanitizers
        self.input_sanitizer = InputSanitizer(self.config)
        self.output_validator = OutputValidator(self.config)
        
        # Initialize classifiers
        self.content_safety_classifier = ContentSafetyClassifier(self.config)
        
        self.logger.log_event(
            event_type="system_initialized",
            details={"security_level": security_level}
        )
    
    def process_input(self, prompt: str, metadata: Optional[Dict] = None) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Process and sanitize user input before sending to LLM
        
        Args:
            prompt: User input prompt
            metadata: Additional metadata about the request
            
        Returns:
            Tuple of (is_safe, processed_prompt, security_report)
        """
        security_report = {
            "timestamp": datetime.utcnow().isoformat(),
            "original_prompt": prompt,
            "detections": [],
            "actions_taken": [],
            "final_decision": "approved"
        }
        
        # Step 1: Check for direct prompt injection
        is_direct_injection, direct_details = self.direct_injection_detector.detect(prompt)
        if is_direct_injection:
            security_report["detections"].append({
                "type": "direct_injection",
                "details": direct_details
            })
            
            if self._should_block("direct_injection"):
                security_report["final_decision"] = "blocked"
                security_report["actions_taken"].append("blocked_direct_injection")
                self.logger.log_threat(prompt, "direct_injection", "blocked", direct_details)
                return False, "", security_report
        
        # Step 2: Check for jailbreak attempts
        is_jailbreak, jailbreak_details = self.jailbreak_detector.detect(prompt)
        if is_jailbreak:
            security_report["detections"].append({
                "type": "jailbreak",
                "details": jailbreak_details
            })
            
            if self._should_block("jailbreak"):
                security_report["final_decision"] = "blocked"
                security_report["actions_taken"].append("blocked_jailbreak")
                self.logger.log_threat(prompt, "jailbreak", "blocked", jailbreak_details)
                return False, "", security_report
        
        # Step 3: Check for system prompt extraction attempts
        is_extraction, extraction_details = self.system_prompt_detector.detect(prompt)
        if is_extraction:
            security_report["detections"].append({
                "type": "system_prompt_extraction",
                "details": extraction_details
            })
            
            if self._should_block("system_prompt_extraction"):
                security_report["final_decision"] = "blocked"
                security_report["actions_taken"].append("blocked_extraction_attempt")
                self.logger.log_threat(prompt, "system_prompt_extraction", "blocked", extraction_details)
                return False, "", security_report
        
        # Step 4: Content safety check
        is_safe_content, content_details = self.content_safety_classifier.classify(prompt)
        if not is_safe_content:
            security_report["detections"].append({
                "type": "unsafe_content",
                "details": content_details
            })
            
            if self._should_block("unsafe_content"):
                security_report["final_decision"] = "blocked"
                security_report["actions_taken"].append("blocked_unsafe_content")
                self.logger.log_threat(prompt, "unsafe_content", "blocked", content_details)
                return False, "", security_report
        
        # Step 5: Sanitize input
        sanitized_prompt, sanitization_details = self.input_sanitizer.sanitize(prompt)
        if sanitization_details:
            security_report["actions_taken"].append("sanitized_input")
            security_report["sanitization"] = sanitization_details
        
        # Step 6: Check for indirect injection in sanitized prompt
        is_indirect_injection, indirect_details = self.indirect_injection_detector.detect(sanitized_prompt)
        if is_indirect_injection:
            security_report["detections"].append({
                "type": "indirect_injection",
                "details": indirect_details
            })
            
            if self._should_block("indirect_injection"):
                security_report["final_decision"] = "blocked"
                security_report["actions_taken"].append("blocked_indirect_injection")
                self.logger.log_threat(prompt, "indirect_injection", "blocked", indirect_details)
                return False, "", security_report
        
        # Log successful processing
        self.logger.log_event(
            event_type="input_processed",
            details={
                "original_length": len(prompt),
                "sanitized_length": len(sanitized_prompt),
                "actions": security_report["actions_taken"]
            }
        )
        
        return True, sanitized_prompt, security_report
    
    def process_output(self, response: str, input_security_report: Optional[Dict] = None) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Validate and sanitize LLM output before returning to user
        
        Args:
            response: LLM response
            input_security_report: Security report from input processing
            
        Returns:
            Tuple of (is_safe, processed_response, validation_report)
        """
        validation_report = {
            "timestamp": datetime.utcnow().isoformat(),
            "original_response": response,
            "detections": [],
            "actions_taken": [],
            "final_decision": "approved"
        }
        
        # Validate output for sensitive information
        is_safe_output, output_details = self.output_validator.validate(response)
        if not is_safe_output:
            validation_report["detections"].append({
                "type": "sensitive_info_leak",
                "details": output_details
            })
            
            if self._should_block("sensitive_info_leak"):
                validation_report["final_decision"] = "blocked"
                validation_report["actions_taken"].append("blocked_sensitive_output")
                self.logger.log_threat(response, "sensitive_info_leak", "blocked", output_details)
                return False, "", validation_report
            else:
                # Sanitize the output
                sanitized_response, sanitization_details = self.output_validator.sanitize(response)
                validation_report["actions_taken"].append("sanitized_output")
                validation_report["sanitization"] = sanitization_details
                response = sanitized_response
        
        # Check output content safety
        is_safe_content, content_details = self.content_safety_classifier.classify(response)
        if not is_safe_content:
            validation_report["detections"].append({
                "type": "unsafe_output_content",
                "details": content_details
            })
            
            if self._should_block("unsafe_output_content"):
                validation_report["final_decision"] = "blocked"
                validation_report["actions_taken"].append("blocked_unsafe_output")
                self.logger.log_threat(response, "unsafe_output_content", "blocked", content_details)
                return False, "", validation_report
        
        self.logger.log_event(
            event_type="output_validated",
            details={
                "original_length": len(validation_report["original_response"]),
                "final_length": len(response),
                "actions": validation_report["actions_taken"]
            }
        )
        
        return True, response, validation_report
    
    def _should_block(self, threat_type: str) -> bool:
        """Determine if a threat should be blocked based on security level"""
        blocking_rules = self.config.get_blocking_rules()
        return blocking_rules.get(threat_type, True)  # Default to block