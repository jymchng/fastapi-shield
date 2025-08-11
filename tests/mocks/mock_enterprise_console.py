"""Mock infrastructure for Enterprise Management Console testing."""

import asyncio
import json
import secrets
import time
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Tuple
from unittest.mock import Mock, AsyncMock
import uuid

from src.fastapi_shield.enterprise_console import (
    ConsoleUser, ConsoleSession, ConfigurationEntry, SecurityPolicy,
    AuditLogEntry, ConsoleNotification,
    UserRole, PermissionLevel, ConfigurationScope, 
    AuditEventType, NotificationSeverity
)


class MockConsoleDatabase:
    """Mock console database for testing."""
    
    def __init__(self):
        self.users = {}
        self.sessions = {}
        self.configurations = {}
        self.policies = {}
        self.audit_logs = []
        self.notifications = {}
        self.storage_calls = []
        self.query_calls = []
        self._encryption_key = b'mock_key_32_bytes_for_testing_only'
        
    def store_user(self, user: ConsoleUser) -> bool:
        """Mock store user."""
        self.storage_calls.append(('user', user.id))
        self.users[user.id] = user
        return True
    
    def get_user_by_username(self, username: str) -> Optional[ConsoleUser]:
        """Mock get user by username."""
        self.query_calls.append(('get_user_by_username', username))
        for user in self.users.values():
            if user.username == username:
                return user
        return None
    
    def store_session(self, session: ConsoleSession) -> bool:
        """Mock store session."""
        self.storage_calls.append(('session', session.id))
        self.sessions[session.token] = session
        return True
    
    def get_session_by_token(self, token: str) -> Optional[ConsoleSession]:
        """Mock get session by token."""
        self.query_calls.append(('get_session_by_token', token))
        return self.sessions.get(token)
    
    def store_audit_log(self, entry: AuditLogEntry) -> bool:
        """Mock store audit log."""
        self.storage_calls.append(('audit_log', entry.id))
        self.audit_logs.append(entry)
        return True


class MockUserManager:
    """Mock user manager for testing."""
    
    def __init__(self, database):
        self.database = database
        self.sessions = {}
        self.auth_calls = []
        self.create_calls = []
        self.logout_calls = []
        self.jwt_secret = "test_secret"
        
        # Create test users
        self._create_test_users()
    
    def _create_test_users(self):
        """Create test users."""
        # Admin user
        admin = ConsoleUser(
            id="admin-001",
            username="admin",
            email="admin@test.com",
            password_hash="$2b$12$mock_hash",
            role=UserRole.SUPER_ADMIN,
            permissions=[PermissionLevel.ADMIN]
        )
        self.database.store_user(admin)
        
        # Analyst user
        analyst = ConsoleUser(
            id="analyst-001",
            username="analyst",
            email="analyst@test.com",
            password_hash="$2b$12$mock_hash",
            role=UserRole.SECURITY_ANALYST,
            permissions=[PermissionLevel.READ, PermissionLevel.WRITE],
            tenant_id="tenant-001"
        )
        self.database.store_user(analyst)
        
        # Viewer user
        viewer = ConsoleUser(
            id="viewer-001",
            username="viewer",
            email="viewer@test.com",
            password_hash="$2b$12$mock_hash",
            role=UserRole.VIEWER,
            permissions=[PermissionLevel.READ],
            tenant_id="tenant-001"
        )
        self.database.store_user(viewer)
    
    async def authenticate_user(self, username: str, password: str, 
                               ip_address: str = "", user_agent: str = "") -> Optional[str]:
        """Mock authenticate user."""
        self.auth_calls.append({
            'username': username,
            'password': password,
            'ip_address': ip_address,
            'user_agent': user_agent,
            'timestamp': datetime.now(timezone.utc).isoformat()
        })
        
        user = self.database.get_user_by_username(username)
        if not user:
            return None
        
        # Mock password verification (accept "password" for all test users)
        if password != "password":
            return None
        
        # Create mock session
        token = f"mock_token_{secrets.token_urlsafe(16)}"
        session = ConsoleSession(
            id=str(uuid.uuid4()),
            user_id=user.id,
            token=token,
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=8),
            last_activity=datetime.now(timezone.utc),
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        self.database.store_session(session)
        self.sessions[token] = session
        
        return token
    
    def validate_session(self, token: str) -> Optional[ConsoleUser]:
        """Mock validate session."""
        session = self.database.get_session_by_token(token)
        if not session or not session.is_valid():
            return None
        
        # Find user by ID
        for user in self.database.users.values():
            if user.id == session.user_id:
                return user
        
        return None
    
    async def logout_user(self, token: str) -> bool:
        """Mock logout user."""
        self.logout_calls.append(token)
        session = self.database.get_session_by_token(token)
        if session:
            session.is_active = False
            self.database.store_session(session)
            self.sessions.pop(token, None)
            return True
        return False
    
    def create_user(self, username: str, email: str, password: str,
                   role: UserRole, tenant_id: Optional[str] = None,
                   permissions: List[PermissionLevel] = None) -> Optional[ConsoleUser]:
        """Mock create user."""
        self.create_calls.append({
            'username': username,
            'email': email,
            'role': role,
            'tenant_id': tenant_id,
            'permissions': permissions
        })
        
        # Check if user exists
        if self.database.get_user_by_username(username):
            return None
        
        user = ConsoleUser(
            id=str(uuid.uuid4()),
            username=username,
            email=email,
            password_hash="$2b$12$mock_hash",
            role=role,
            permissions=permissions or [PermissionLevel.READ],
            tenant_id=tenant_id
        )
        
        if self.database.store_user(user):
            return user
        
        return None


class MockConfigurationManager:
    """Mock configuration manager for testing."""
    
    def __init__(self, database):
        self.database = database
        self.config_cache = {}
        self.set_calls = []
        self.get_calls = []
        self.backup_calls = []
    
    def set_configuration(self, scope: ConfigurationScope, component: str,
                         key: str, value: Any, tenant_id: Optional[str] = None,
                         created_by: str = "system", encrypt: bool = False) -> bool:
        """Mock set configuration."""
        self.set_calls.append({
            'scope': scope,
            'component': component,
            'key': key,
            'value': value,
            'tenant_id': tenant_id,
            'created_by': created_by,
            'encrypt': encrypt
        })
        
        config_id = f"{scope.value}:{component}:{key}:{tenant_id or 'global'}"
        self.config_cache[config_id] = {
            'scope': scope,
            'component': component,
            'key': key,
            'value': value,
            'tenant_id': tenant_id,
            'created_by': created_by,
            'is_encrypted': encrypt
        }
        
        return True
    
    def get_configuration(self, scope: ConfigurationScope, component: str,
                         key: str, tenant_id: Optional[str] = None,
                         default: Any = None) -> Any:
        """Mock get configuration."""
        self.get_calls.append({
            'scope': scope,
            'component': component,
            'key': key,
            'tenant_id': tenant_id,
            'default': default
        })
        
        config_id = f"{scope.value}:{component}:{key}:{tenant_id or 'global'}"
        config = self.config_cache.get(config_id)
        
        return config['value'] if config else default
    
    def get_component_configuration(self, component: str,
                                  tenant_id: Optional[str] = None) -> Dict[str, Any]:
        """Mock get component configuration."""
        config = {}
        for config_id, data in self.config_cache.items():
            if data['component'] == component:
                # Check tenant match (include global configs and specific tenant configs)
                if data['tenant_id'] is None or data['tenant_id'] == tenant_id:
                    config[data['key']] = data['value']
        
        return config
    
    def backup_configuration(self, tenant_id: Optional[str] = None) -> Dict[str, Any]:
        """Mock backup configuration."""
        self.backup_calls.append(tenant_id)
        
        configurations = []
        for config_id, data in self.config_cache.items():
            if tenant_id is None or data['tenant_id'] == tenant_id:
                configurations.append(data)
        
        return {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'tenant_id': tenant_id,
            'configurations': configurations
        }


class MockPolicyManager:
    """Mock policy manager for testing."""
    
    def __init__(self, database):
        self.database = database
        self.policies = {}
        self.create_calls = []
        self.get_calls = []
    
    def create_policy(self, name: str, description: str, policy_type: str,
                     rules: List[Dict[str, Any]], conditions: Dict[str, Any],
                     actions: List[Dict[str, Any]], tenant_id: Optional[str] = None,
                     created_by: str = "system") -> Optional[SecurityPolicy]:
        """Mock create policy."""
        self.create_calls.append({
            'name': name,
            'description': description,
            'policy_type': policy_type,
            'rules': rules,
            'conditions': conditions,
            'actions': actions,
            'tenant_id': tenant_id,
            'created_by': created_by
        })
        
        policy = SecurityPolicy(
            id=str(uuid.uuid4()),
            name=name,
            description=description,
            policy_type=policy_type,
            rules=rules,
            conditions=conditions,
            actions=actions,
            tenant_id=tenant_id,
            created_by=created_by
        )
        
        self.policies[policy.id] = policy
        return policy
    
    def get_policies(self, tenant_id: Optional[str] = None,
                    policy_type: Optional[str] = None) -> List[SecurityPolicy]:
        """Mock get policies."""
        self.get_calls.append({
            'tenant_id': tenant_id,
            'policy_type': policy_type
        })
        
        results = []
        for policy in self.policies.values():
            # Check tenant filter
            if tenant_id and policy.tenant_id != tenant_id:
                continue
            
            # Check policy type filter
            if policy_type and policy.policy_type != policy_type:
                continue
            
            results.append(policy)
        
        return sorted(results, key=lambda p: p.priority, reverse=True)


class MockNotificationManager:
    """Mock notification manager for testing."""
    
    def __init__(self, database):
        self.database = database
        self.subscribers = defaultdict(list)
        self.notifications = {}
        self.send_calls = []
        self.broadcast_calls = []
    
    def add_subscriber(self, websocket, user_id: str, tenant_id: Optional[str] = None):
        """Mock add subscriber."""
        key = f"{user_id}:{tenant_id or 'global'}"
        self.subscribers[key].append(websocket)
    
    def remove_subscriber(self, websocket, user_id: str, tenant_id: Optional[str] = None):
        """Mock remove subscriber."""
        key = f"{user_id}:{tenant_id or 'global'}"
        if websocket in self.subscribers[key]:
            self.subscribers[key].remove(websocket)
    
    async def send_notification(self, title: str, message: str,
                              severity: NotificationSeverity, category: str,
                              user_id: Optional[str] = None, tenant_id: Optional[str] = None,
                              expires_at: Optional[datetime] = None) -> str:
        """Mock send notification."""
        self.send_calls.append({
            'title': title,
            'message': message,
            'severity': severity,
            'category': category,
            'user_id': user_id,
            'tenant_id': tenant_id,
            'expires_at': expires_at
        })
        
        notification = ConsoleNotification(
            id=str(uuid.uuid4()),
            title=title,
            message=message,
            severity=severity,
            category=category,
            user_id=user_id,
            tenant_id=tenant_id,
            expires_at=expires_at
        )
        
        self.notifications[notification.id] = notification
        self.broadcast_calls.append(notification.id)
        
        return notification.id


class MockWebConsoleManager:
    """Mock web console manager for testing."""
    
    def __init__(self):
        self.database = MockConsoleDatabase()
        self.user_manager = MockUserManager(self.database)
        self.config_manager = MockConfigurationManager(self.database)
        self.policy_manager = MockPolicyManager(self.database)
        self.notification_manager = MockNotificationManager(self.database)
        self.soar_orchestrator = None
        
        self.metrics = {
            'requests_handled': 0,
            'users_online': 0,
            'notifications_sent': 0,
            'configurations_changed': 0,
            'start_time': datetime.now(timezone.utc)
        }
        
        self.auth_calls = []
        self.audit_calls = []
    
    async def authenticate_request(self, request) -> Optional[ConsoleUser]:
        """Mock authenticate request."""
        self.auth_calls.append({
            'headers': getattr(request, 'headers', {}),
            'client': getattr(request, 'client', None),
            'timestamp': datetime.now(timezone.utc).isoformat()
        })
        
        # Mock authentication logic
        auth_header = getattr(request, 'headers', {}).get('Authorization', '')
        if not auth_header or not auth_header.startswith('Bearer '):
            return None
        
        token = auth_header[7:]
        return self.user_manager.validate_session(token)
    
    def get_dashboard_data(self, user: ConsoleUser) -> Dict[str, Any]:
        """Mock get dashboard data."""
        return {
            'user_info': user.to_dict(),
            'system_metrics': {
                'uptime': int((datetime.now(timezone.utc) - self.metrics['start_time']).total_seconds()),
                'requests_handled': self.metrics['requests_handled'],
                'users_online': self.metrics['users_online'],
                'notifications_sent': self.metrics['notifications_sent']
            },
            'security_overview': {
                'active_incidents': 0,
                'threats_blocked': 0,
                'policies_active': len(self.policy_manager.get_policies(user.tenant_id))
            },
            'recent_activity': []
        }


class MockRequest:
    """Mock FastAPI Request object."""
    
    def __init__(self, headers: Dict[str, str] = None, client_host: str = "127.0.0.1"):
        self.headers = headers or {}
        self.client = Mock()
        self.client.host = client_host
    
    def __getattr__(self, name):
        return Mock()


class MockWebSocket:
    """Mock WebSocket for testing."""
    
    def __init__(self):
        self.messages = []
        self.closed = False
        self.accept_called = False
        
    async def accept(self):
        """Mock accept connection."""
        self.accept_called = True
    
    async def send_text(self, message: str):
        """Mock send text message."""
        if not self.closed:
            self.messages.append(message)
        else:
            raise Exception("WebSocket connection closed")
    
    async def receive_text(self) -> str:
        """Mock receive text message."""
        if self.closed:
            raise Exception("WebSocket connection closed")
        return "ping"  # Mock message
    
    def close(self):
        """Mock close connection."""
        self.closed = True


class MockEnterpriseConsoleTestEnvironment:
    """Comprehensive mock environment for Enterprise Console testing."""
    
    def __init__(self):
        self.console_manager = MockWebConsoleManager()
        
        # Test data
        self.test_users = self._generate_test_users()
        self.test_configurations = self._generate_test_configurations()
        self.test_policies = self._generate_test_policies()
        
        # Performance tracking
        self.performance_metrics = {
            'api_calls': [],
            'response_times': [],
            'websocket_connections': []
        }
    
    def _generate_test_users(self) -> List[ConsoleUser]:
        """Generate test users."""
        users = []
        
        roles = [UserRole.ADMIN, UserRole.SECURITY_ANALYST, UserRole.VIEWER, UserRole.AUDITOR]
        permissions_map = {
            UserRole.ADMIN: [PermissionLevel.READ, PermissionLevel.WRITE, PermissionLevel.EXECUTE],
            UserRole.SECURITY_ANALYST: [PermissionLevel.READ, PermissionLevel.WRITE],
            UserRole.VIEWER: [PermissionLevel.READ],
            UserRole.AUDITOR: [PermissionLevel.READ]
        }
        
        for i, role in enumerate(roles):
            user = ConsoleUser(
                id=f"test-user-{i}",
                username=f"user_{role.value}_{i}",
                email=f"user_{i}@test.com",
                password_hash="$2b$12$mock_hash",
                role=role,
                permissions=permissions_map[role],
                tenant_id=f"tenant_{i % 2}" if i % 2 == 0 else None
            )
            users.append(user)
        
        return users
    
    def _generate_test_configurations(self) -> List[Dict[str, Any]]:
        """Generate test configurations."""
        configs = []
        
        components = ['rate_limiting', 'bot_detection', 'input_validation', 'threat_intelligence']
        scopes = [ConfigurationScope.GLOBAL, ConfigurationScope.TENANT, ConfigurationScope.SHIELD]
        
        for i, component in enumerate(components):
            for j, scope in enumerate(scopes):
                config = {
                    'scope': scope,
                    'component': component,
                    'key': f'config_key_{i}_{j}',
                    'value': f'config_value_{i}_{j}',
                    'tenant_id': f'tenant_{i}' if scope == ConfigurationScope.TENANT else None
                }
                configs.append(config)
        
        return configs
    
    def _generate_test_policies(self) -> List[Dict[str, Any]]:
        """Generate test security policies."""
        policies = []
        
        policy_types = ['access_control', 'rate_limiting', 'data_protection', 'threat_response']
        
        for i, policy_type in enumerate(policy_types):
            policy = {
                'name': f'Test Policy {i+1}',
                'description': f'Test security policy for {policy_type}',
                'policy_type': policy_type,
                'rules': [
                    {'condition': f'condition_{i}', 'action': f'action_{i}'}
                ],
                'conditions': {'severity': ['high', 'critical']},
                'actions': [
                    {'type': 'block', 'parameters': {'duration': '1h'}}
                ],
                'tenant_id': f'tenant_{i % 2}' if i % 2 == 0 else None
            }
            policies.append(policy)
        
        return policies
    
    def setup_test_data(self):
        """Setup test data in the console manager."""
        # Add test users
        for user in self.test_users:
            self.console_manager.database.store_user(user)
        
        # Add test configurations
        for config in self.test_configurations:
            self.console_manager.config_manager.set_configuration(
                scope=config['scope'],
                component=config['component'],
                key=config['key'],
                value=config['value'],
                tenant_id=config['tenant_id']
            )
        
        # Add test policies
        for policy in self.test_policies:
            self.console_manager.policy_manager.create_policy(
                name=policy['name'],
                description=policy['description'],
                policy_type=policy['policy_type'],
                rules=policy['rules'],
                conditions=policy['conditions'],
                actions=policy['actions'],
                tenant_id=policy['tenant_id']
            )
    
    def track_performance(self, operation: str, duration: float):
        """Track performance metrics."""
        self.performance_metrics['api_calls'].append({
            'operation': operation,
            'timestamp': time.time(),
            'duration': duration
        })
    
    def simulate_user_session(self, username: str = "admin") -> str:
        """Simulate user login and return session token."""
        # Use asyncio to run the async method
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            token = loop.run_until_complete(
                self.console_manager.user_manager.authenticate_user(username, "password")
            )
            return token
        finally:
            loop.close()
    
    def create_mock_request(self, token: str = None, headers: Dict[str, str] = None) -> MockRequest:
        """Create mock request with authentication."""
        request_headers = headers or {}
        
        if token:
            request_headers['Authorization'] = f'Bearer {token}'
        
        return MockRequest(headers=request_headers)
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get performance statistics."""
        api_calls = self.performance_metrics['api_calls']
        
        if not api_calls:
            return {'status': 'no_data'}
        
        response_times = [call['duration'] for call in api_calls]
        
        return {
            'total_operations': len(api_calls),
            'avg_response_time': sum(response_times) / len(response_times),
            'max_response_time': max(response_times),
            'min_response_time': min(response_times),
            'websocket_connections': len(self.performance_metrics['websocket_connections'])
        }
    
    def reset(self):
        """Reset all mock services."""
        self.console_manager = MockWebConsoleManager()
        self.performance_metrics = {
            'api_calls': [],
            'response_times': [],
            'websocket_connections': []
        }


# Export all mock classes
__all__ = [
    'MockConsoleDatabase',
    'MockUserManager',
    'MockConfigurationManager',
    'MockPolicyManager',
    'MockNotificationManager',
    'MockWebConsoleManager',
    'MockRequest',
    'MockWebSocket',
    'MockEnterpriseConsoleTestEnvironment'
]