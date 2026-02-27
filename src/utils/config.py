"""
Configuration management for the defense system
"""

import yaml
from typing import Dict, Any, Optional
from pathlib import Path


class SecurityConfig:
    """
    Manages security configuration and policies
    """
    
    def __init__(self, config_path: Optional[str] = None, security_level: str = "balanced"):
        """
        Initialize configuration
        
        Args:
            config_path: Path to YAML configuration file
            security_level: Security level (strict, balanced, permissive)
        """
        self.security_level = security_level
        self.config = self._load_config(config_path)
        self._apply_security_level()
    
    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Load configuration from file or use defaults"""
        default_config = {
            "blocking_rules": {
                "direct_injection": True,
                "indirect_injection": True,
                "jailbreak": True,
                "system_prompt_extraction": True,
                "unsafe_content": True,
                "sensitive_info_leak": True,
                "unsafe_output_content": True
            },
            "detection_thresholds": {
                "direct_injection": 0.3,
                "indirect_injection": 0.4,
                "jailbreak": 0.3,
                "system_prompt_extraction": 0.4,
                "unsafe_content": 0.5
            },
            "sanitization": {
                "enabled": True,
                "remove_special_chars": True,
                "normalize_spaces": True,
                "redact_sensitive": True
            },
            "logging": {
                "enabled": True,
                "log_level": "INFO",
                "audit_trail": True
            }
        }
        
        if config_path and Path(config_path).exists():
            with open(config_path, 'r') as f:
                custom_config = yaml.safe_load(f)
                # Merge custom config with defaults
                self._merge_configs(default_config, custom_config)
        
        return default_config
    
    def _merge_configs(self, base: Dict, override: Dict):
        """Recursively merge configurations"""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_configs(base[key], value)
            else:
                base[key] = value
    
    def _apply_security_level(self):
        """Apply security level settings"""
        if self.security_level == "strict":
            # More aggressive blocking
            self.config["detection_thresholds"] = {
                k: v * 0.7 for k, v in self.config["detection_thresholds"].items()
            }
            # Enable all blocking
            for k in self.config["blocking_rules"]:
                self.config["blocking_rules"][k] = True
        
        elif self.security_level == "permissive":
            # Less aggressive blocking
            self.config["detection_thresholds"] = {
                k: v * 1.3 for k, v in self.config["detection_thresholds"].items()
            }
            # Disable blocking for some lower-risk threats
            self.config["blocking_rules"]["indirect_injection"] = False
            self.config["blocking_rules"]["unsafe_output_content"] = False
        
        # balanced mode uses default thresholds
    
    def get_blocking_rules(self) -> Dict[str, bool]:
        """Get blocking rules configuration"""
        return self.config["blocking_rules"]
    
    def get_threshold(self, threat_type: str) -> float:
        """Get detection threshold for a specific threat type"""
        return self.config["detection_thresholds"].get(threat_type, 0.5)