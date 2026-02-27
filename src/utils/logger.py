"""
Structured logging system for security events
"""

import logging
import json
from datetime import datetime
from typing import Dict, Any, Optional
from pathlib import Path


class SecurityLogger:
    """
    Structured logger for security events
    """
    
    def __init__(self, log_dir: str = "logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        
        # Setup file handlers
        self._setup_loggers()
    
    def _setup_loggers(self):
        """Setup different loggers for different purposes"""
        
        # Security events logger
        self.security_logger = logging.getLogger("security_events")
        security_handler = logging.FileHandler(self.log_dir / "security_events.log")
        security_handler.setFormatter(logging.Formatter('%(message)s'))
        self.security_logger.addHandler(security_handler)
        self.security_logger.setLevel(logging.INFO)
        
        # Threat logger
        self.threat_logger = logging.getLogger("threats")
        threat_handler = logging.FileHandler(self.log_dir / "threats.log")
        threat_handler.setFormatter(logging.Formatter('%(message)s'))
        self.threat_logger.addHandler(threat_handler)
        self.threat_logger.setLevel(logging.WARNING)
        
        # Audit logger
        self.audit_logger = logging.getLogger("audit")
        audit_handler = logging.FileHandler(self.log_dir / "audit.log")
        audit_handler.setFormatter(logging.Formatter('%(message)s'))
        self.audit_logger.addHandler(audit_handler)
        self.audit_logger.setLevel(logging.INFO)
    
    def log_event(self, event_type: str, details: Dict[str, Any]):
        """
        Log a security event
        
        Args:
            event_type: Type of event
            details: Event details
        """
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "details": details
        }
        
        self.security_logger.info(json.dumps(log_entry))
        self.audit_logger.info(json.dumps(log_entry))
    
    def log_threat(self, prompt: str, threat_type: str, action: str, details: Dict[str, Any]):
        """
        Log a detected threat
        
        Args:
            prompt: Original prompt
            threat_type: Type of threat detected
            action: Action taken (block, sanitize, etc.)
            details: Threat details
        """
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "threat_type": threat_type,
            "action_taken": action,
            "original_prompt": prompt,
            "details": details
        }
        
        self.threat_logger.warning(json.dumps(log_entry))
        self.audit_logger.info(json.dumps(log_entry))
    
    def get_recent_threats(self, count: int = 10) -> list:
        """
        Get recent threats from log file
        
        Args:
            count: Number of recent threats to retrieve
            
        Returns:
            List of recent threats
        """
        threats = []
        log_file = self.log_dir / "threats.log"
        
        if log_file.exists():
            with open(log_file, 'r') as f:
                lines = f.readlines()[-count:]
                for line in lines:
                    try:
                        threats.append(json.loads(line.strip()))
                    except:
                        pass
        
        return threats