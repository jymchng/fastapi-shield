"""Synchronous helper for Enterprise SOAR platform initialization.

This module provides synchronous wrappers for SOAR initialization to avoid
event loop issues during testing and non-async contexts.
"""

from .enterprise_soar import (
    SecurityOrchestrator, SIEMIntegration, TicketingIntegration, 
    MessagingIntegration, create_soar_app
)
from typing import Dict, Any, Optional


def create_enterprise_soar_sync(
    database_path: str = "enterprise_soar.db",
    siem_config: Optional[Dict[str, Any]] = None,
    ticketing_config: Optional[Dict[str, Any]] = None,
    messaging_config: Optional[Dict[str, Any]] = None,
    enable_integrations: bool = True
) -> SecurityOrchestrator:
    """Create enterprise SOAR platform without immediate async initialization."""
    
    # Create orchestrator without starting background tasks
    orchestrator = SecurityOrchestrator(database_path, enable_integrations=False)
    
    # Add integrations if configured (but don't connect yet)
    if siem_config and enable_integrations:
        siem_integration = SIEMIntegration(siem_config)
        orchestrator.add_integration('siem', siem_integration)
    
    if ticketing_config and enable_integrations:
        ticketing_integration = TicketingIntegration(ticketing_config)
        orchestrator.add_integration('ticketing', ticketing_integration)
    
    if messaging_config and enable_integrations:
        messaging_integration = MessagingIntegration(messaging_config)
        orchestrator.add_integration('messaging', messaging_integration)
    
    return orchestrator