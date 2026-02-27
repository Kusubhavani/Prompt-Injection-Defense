"""
Prompt Injection Defense System
A comprehensive security middleware for LLM applications
"""

from .defense_system import DefenseSystem
from .utils.config import SecurityConfig

__version__ = "1.0.0"
__all__ = ["DefenseSystem", "SecurityConfig"]