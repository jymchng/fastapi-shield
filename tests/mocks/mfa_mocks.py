"""Mock objects for MFA testing."""

from typing import Dict, List
from datetime import datetime, timezone

from fastapi_shield.multi_factor_auth import MFAProvider


class MockSMSProvider(MFAProvider):
    """Mock SMS provider for testing."""
    
    def __init__(self):
        self.sent_messages: List[Dict[str, str]] = []
        self.should_fail = False
    
    async def send_sms_code(self, phone_number: str, code: str) -> bool:
        """Mock SMS sending."""
        if self.should_fail:
            return False
        
        self.sent_messages.append({
            'phone': phone_number,
            'code': code,
            'timestamp': datetime.now(timezone.utc).isoformat()
        })
        return True
    
    async def send_email_code(self, email: str, code: str) -> bool:
        """Mock email sending."""
        if self.should_fail:
            return False
        
        self.sent_messages.append({
            'email': email,
            'code': code,
            'timestamp': datetime.now(timezone.utc).isoformat()
        })
        return True
    
    async def validate_provider_config(self) -> bool:
        """Mock validation."""
        return not self.should_fail
    
    def get_last_code(self) -> str:
        """Get the last sent code for testing."""
        if self.sent_messages:
            return self.sent_messages[-1]['code']
        return ""
    
    def clear_messages(self):
        """Clear sent messages."""
        self.sent_messages.clear()


class MockMFAProvider(MFAProvider):
    """Mock MFA provider for testing."""
    
    def __init__(self):
        self.sent_sms: List[Dict[str, str]] = []
        self.sent_emails: List[Dict[str, str]] = []
    
    async def send_sms_code(self, phone_number: str, code: str) -> bool:
        """Mock SMS sending."""
        self.sent_sms.append({'phone': phone_number, 'code': code})
        return True
    
    async def send_email_code(self, email: str, code: str) -> bool:
        """Mock email sending."""
        self.sent_emails.append({'email': email, 'code': code})
        return True
    
    async def validate_provider_config(self) -> bool:
        """Mock validation."""
        return True


class MockEmailProvider(MFAProvider):
    """Mock email provider for testing."""
    
    def __init__(self):
        self.sent_emails: List[Dict[str, str]] = []
        self.should_fail = False
    
    async def send_sms_code(self, phone_number: str, code: str) -> bool:
        """Mock SMS sending (not implemented)."""
        return False
    
    async def send_email_code(self, email: str, code: str) -> bool:
        """Mock email sending."""
        if self.should_fail:
            return False
        
        self.sent_emails.append({
            'email': email,
            'code': code,
            'timestamp': datetime.now(timezone.utc).isoformat()
        })
        return True
    
    async def validate_provider_config(self) -> bool:
        """Mock validation."""
        return not self.should_fail
    
    def get_last_code(self) -> str:
        """Get the last sent code for testing."""
        if self.sent_emails:
            return self.sent_emails[-1]['code']
        return ""
    
    def clear_emails(self):
        """Clear sent emails."""
        self.sent_emails.clear()