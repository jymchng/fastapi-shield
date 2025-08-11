"""Mock infrastructure for Quantum-Resistant Cryptographic Security Engine testing."""

import asyncio
import json
import secrets
import time
import numpy as np
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Tuple
from unittest.mock import Mock, AsyncMock
import uuid
import hashlib
import struct

from src.fastapi_shield.quantum_crypto import (
    QuantumKeyPair, QuantumSignature, QuantumEncryptedData, QKDSession,
    QuantumAlgorithm, SecurityLevel, CryptoOperation, HybridMode
)


class MockQuantumCryptoDatabase:
    """Mock quantum crypto database for testing."""
    
    def __init__(self):
        self.keypairs = {}
        self.signatures = {}
        self.encrypted_data = {}
        self.qkd_sessions = {}
        self.performance_metrics = []
        self.storage_calls = []
        self.query_calls = []
        
    def store_keypair(self, keypair: QuantumKeyPair) -> bool:
        """Mock store keypair."""
        self.storage_calls.append(('keypair', keypair.key_id))
        self.keypairs[keypair.key_id] = keypair
        return True
    
    def get_keypair(self, key_id: str) -> Optional[QuantumKeyPair]:
        """Mock get keypair."""
        self.query_calls.append(('keypair', key_id))
        return self.keypairs.get(key_id)
    
    def store_performance_metric(self, algorithm: str, operation: str, duration_ms: float,
                                key_size: Optional[int] = None, data_size: Optional[int] = None) -> bool:
        """Mock store performance metric."""
        metric = {
            'algorithm': algorithm,
            'operation': operation,
            'duration_ms': duration_ms,
            'key_size': key_size,
            'data_size': data_size,
            'timestamp': datetime.now(timezone.utc)
        }
        self.performance_metrics.append(metric)
        return True


class MockLatticeBasedCrypto:
    """Mock lattice-based cryptography for testing."""
    
    def __init__(self, security_level: SecurityLevel = SecurityLevel.LEVEL_3):
        self.security_level = security_level
        self.keygen_calls = []
        self.encap_calls = []
        self.decap_calls = []
        self.sign_calls = []
        self.verify_calls = []
        
        # Mock parameters
        self.parameters = {
            SecurityLevel.LEVEL_1: {'n': 256, 'q': 3329, 'k': 2},
            SecurityLevel.LEVEL_3: {'n': 256, 'q': 3329, 'k': 3},
            SecurityLevel.LEVEL_5: {'n': 256, 'q': 3329, 'k': 4}
        }
        
    def generate_kyber_keypair(self) -> QuantumKeyPair:
        """Mock Kyber keypair generation."""
        self.keygen_calls.append(('kyber', self.security_level))
        
        # Generate mock keys with realistic sizes
        public_key_size = 800 + self.security_level.value * 100
        private_key_size = 1600 + self.security_level.value * 200
        
        public_key = secrets.token_bytes(public_key_size)
        private_key = secrets.token_bytes(private_key_size)
        
        return QuantumKeyPair(
            algorithm=QuantumAlgorithm.KYBER,
            security_level=self.security_level,
            public_key=public_key,
            private_key=private_key,
            created_at=datetime.now(timezone.utc)
        )
    
    def kyber_encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """Mock Kyber key encapsulation."""
        self.encap_calls.append(len(public_key))
        
        # Generate mock ciphertext and shared secret
        ciphertext_size = 768 + self.security_level.value * 100
        ciphertext = secrets.token_bytes(ciphertext_size)
        shared_secret = secrets.token_bytes(32)  # Standard 256-bit key
        
        return ciphertext, shared_secret
    
    def kyber_decapsulate(self, ciphertext: bytes, private_key: bytes) -> bytes:
        """Mock Kyber key decapsulation."""
        self.decap_calls.append((len(ciphertext), len(private_key)))
        
        # Return deterministic shared secret based on inputs
        combined = ciphertext[:32] + private_key[:32]
        shared_secret = hashlib.sha256(combined).digest()
        
        return shared_secret
    
    def generate_dilithium_keypair(self) -> QuantumKeyPair:
        """Mock Dilithium keypair generation."""
        self.keygen_calls.append(('dilithium', self.security_level))
        
        # Dilithium key sizes based on security level
        if self.security_level == SecurityLevel.LEVEL_1:
            pk_size, sk_size = 1312, 2528
        elif self.security_level == SecurityLevel.LEVEL_3:
            pk_size, sk_size = 1952, 4000
        else:  # LEVEL_5
            pk_size, sk_size = 2592, 4864
            
        public_key = secrets.token_bytes(pk_size)
        private_key = secrets.token_bytes(sk_size)
        
        return QuantumKeyPair(
            algorithm=QuantumAlgorithm.DILITHIUM,
            security_level=self.security_level,
            public_key=public_key,
            private_key=private_key,
            created_at=datetime.now(timezone.utc)
        )
    
    def dilithium_sign(self, message: bytes, private_key: bytes) -> bytes:
        """Mock Dilithium signature generation."""
        self.sign_calls.append((len(message), len(private_key)))
        
        # Generate deterministic signature based on message and key
        signature_input = message + private_key[:32]
        signature_hash = hashlib.sha256(signature_input).digest()
        
        # Dilithium signature sizes
        if self.security_level == SecurityLevel.LEVEL_1:
            sig_size = 2420
        elif self.security_level == SecurityLevel.LEVEL_3:
            sig_size = 3293
        else:  # LEVEL_5
            sig_size = 4595
        
        # Generate signature with first 32 bytes being the hash
        signature = signature_hash + secrets.token_bytes(sig_size - 32)
        
        return signature
    
    def dilithium_verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Mock Dilithium signature verification."""
        self.verify_calls.append((len(message), len(signature), len(public_key)))
        
        if len(signature) < 32:
            return False
            
        # Extract signature hash and verify
        signature_hash = signature[:32]
        expected_hash = hashlib.sha256(message + b'mock_key').digest()
        
        # Simple verification - in reality would be much more complex
        # Accept if signature contains expected pattern
        verification_pattern = hashlib.sha256(message).digest()[:8]
        return verification_pattern in signature


class MockHashBasedSignatures:
    """Mock hash-based signatures for testing."""
    
    def __init__(self, security_level: SecurityLevel = SecurityLevel.LEVEL_3):
        self.security_level = security_level
        self.keygen_calls = []
        self.sign_calls = []
        self.verify_calls = []
        
        # SPHINCS+ parameters
        if security_level == SecurityLevel.LEVEL_1:
            self.n, self.sig_size = 16, 17088
        elif security_level == SecurityLevel.LEVEL_3:
            self.n, self.sig_size = 24, 35664
        else:  # LEVEL_5
            self.n, self.sig_size = 32, 49856
    
    def generate_sphincs_keypair(self) -> QuantumKeyPair:
        """Mock SPHINCS+ keypair generation."""
        self.keygen_calls.append(('sphincs', self.security_level))
        
        public_key = secrets.token_bytes(self.n * 2)  # pub_seed + root
        private_key = secrets.token_bytes(self.n * 4)  # sk_seed + sk_prf + pub_seed + root
        
        return QuantumKeyPair(
            algorithm=QuantumAlgorithm.SPHINCS_PLUS,
            security_level=self.security_level,
            public_key=public_key,
            private_key=private_key,
            created_at=datetime.now(timezone.utc)
        )
    
    def sphincs_sign(self, message: bytes, private_key: bytes) -> bytes:
        """Mock SPHINCS+ signature generation."""
        self.sign_calls.append((len(message), len(private_key)))
        
        # Generate deterministic signature
        signature_input = message + private_key[:self.n]
        signature_hash = hashlib.sha256(signature_input).digest()
        
        # SPHINCS+ signature with randomizer + FORS sig + HT sig
        opt_rand = secrets.token_bytes(self.n)
        remaining_size = self.sig_size - self.n
        signature_body = signature_hash[:min(32, remaining_size)] + secrets.token_bytes(max(0, remaining_size - 32))
        
        return opt_rand + signature_body
    
    def sphincs_verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Mock SPHINCS+ signature verification."""
        self.verify_calls.append((len(message), len(signature), len(public_key)))
        
        if len(signature) < self.n + 32:
            return False
        
        # Extract components
        opt_rand = signature[:self.n]
        sig_body = signature[self.n:]
        
        # Simple verification check
        verification_hash = hashlib.sha256(message + opt_rand).digest()
        return verification_hash[:16] in sig_body
    
    def generate_xmss_keypair(self, tree_height: int = 10) -> QuantumKeyPair:
        """Mock XMSS keypair generation."""
        self.keygen_calls.append(('xmss', self.security_level, tree_height))
        
        # Generate mock Merkle tree structure
        num_leaves = 2 ** tree_height
        
        # Generate WOTS+ keypairs (simplified)
        wots_keys = []
        for i in range(min(num_leaves, 16)):  # Limit for testing
            wots_sk = secrets.token_bytes(32)
            wots_pk = hashlib.sha256(wots_sk).digest()
            wots_keys.append((wots_sk.hex(), wots_pk.hex()))
        
        # Generate mock tree
        tree_levels = []
        current_level = [hashlib.sha256(secrets.token_bytes(32)).digest() for _ in range(num_leaves)]
        tree_levels.append([node.hex() for node in current_level])
        
        # Build tree levels (simplified)
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                parent = hashlib.sha256(left + right).digest()
                next_level.append(parent)
            tree_levels.insert(0, [node.hex() for node in next_level])
            current_level = next_level
        
        root = current_level[0]
        
        # Pack keys
        private_key = secrets.token_bytes(32) + struct.pack('<I', 0)  # seed + state
        public_key = root + struct.pack('<I', tree_height)
        
        keypair = QuantumKeyPair(
            algorithm=QuantumAlgorithm.XMSS,
            security_level=self.security_level,
            public_key=public_key,
            private_key=private_key,
            created_at=datetime.now(timezone.utc)
        )
        
        # Store tree data in metadata
        keypair.metadata = {
            'wots_keys': wots_keys,
            'tree': tree_levels,
            'tree_height': tree_height
        }
        
        return keypair
    
    def xmss_sign(self, message: bytes, private_key: bytes, keypair_metadata: Dict[str, Any]) -> bytes:
        """Mock XMSS signature generation."""
        self.sign_calls.append((len(message), len(private_key)))
        
        # Extract state
        state = struct.unpack('<I', private_key[32:36])[0]
        tree_height = keypair_metadata.get('tree_height', 10)
        
        # Generate mock WOTS+ signature
        msg_hash = hashlib.sha256(message).digest()
        wots_sig = secrets.token_bytes(32 * 67)  # Simplified WOTS+ signature
        
        # Generate mock authentication path
        auth_path = []
        for i in range(tree_height):
            auth_path.append(secrets.token_bytes(32))
        
        # Pack signature
        signature = struct.pack('<I', state) + wots_sig
        for node in auth_path:
            signature += node
            
        return signature
    
    def xmss_verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Mock XMSS signature verification."""
        self.verify_calls.append((len(message), len(signature), len(public_key)))
        
        if len(signature) < 4:
            return False
        
        try:
            # Extract leaf index
            leaf_idx = struct.unpack('<I', signature[:4])[0]
            
            # Simple verification - check if message hash appears in signature
            msg_hash = hashlib.sha256(message).digest()
            return msg_hash[:8] in signature or leaf_idx < 2**20  # Reasonable leaf index
            
        except:
            return False


class MockQuantumKeyDistribution:
    """Mock quantum key distribution for testing."""
    
    def __init__(self):
        self.sessions = {}
        self.bb84_calls = []
        self.e91_calls = []
        
    def bb84_protocol(self, alice_id: str, bob_id: str, key_length: int = 256) -> QKDSession:
        """Mock BB84 protocol."""
        self.bb84_calls.append((alice_id, bob_id, key_length))
        
        session_id = str(uuid.uuid4())
        
        # Generate shared key
        shared_key = secrets.token_bytes(key_length // 8)
        
        # Simulate realistic QKD parameters
        error_rate = np.random.uniform(0.02, 0.08)  # 2-8% error rate
        security_parameter = max(0.0, 1.0 - 2 * error_rate)
        
        session = QKDSession(
            session_id=session_id,
            alice_id=alice_id,
            bob_id=bob_id,
            shared_key=shared_key,
            key_length=len(shared_key),
            error_rate=error_rate,
            security_parameter=security_parameter,
            protocol='BB84',
            created_at=datetime.now(timezone.utc)
        )
        
        self.sessions[session_id] = session
        return session
    
    def e91_protocol(self, alice_id: str, bob_id: str, key_length: int = 256) -> QKDSession:
        """Mock E91 protocol."""
        self.e91_calls.append((alice_id, bob_id, key_length))
        
        session_id = str(uuid.uuid4())
        
        # Generate shared key
        shared_key = secrets.token_bytes(key_length // 8)
        
        # Simulate Bell violation
        bell_violation = np.random.uniform(0.6, 0.85)  # Strong violation
        error_rate = max(0.01, 0.15 - bell_violation)
        security_parameter = min(bell_violation, 0.95)
        
        session = QKDSession(
            session_id=session_id,
            alice_id=alice_id,
            bob_id=bob_id,
            shared_key=shared_key,
            key_length=len(shared_key),
            error_rate=error_rate,
            security_parameter=security_parameter,
            protocol='E91',
            created_at=datetime.now(timezone.utc)
        )
        
        session.metadata = {'bell_violation': bell_violation}
        self.sessions[session_id] = session
        return session
    
    def get_qkd_session(self, session_id: str) -> Optional[QKDSession]:
        """Mock get QKD session."""
        return self.sessions.get(session_id)
    
    def list_active_sessions(self) -> List[QKDSession]:
        """Mock list active sessions."""
        return [session for session in self.sessions.values() if session.status == 'active']


class MockHybridCryptoSystem:
    """Mock hybrid cryptographic system for testing."""
    
    def __init__(self, lattice_crypto, hash_crypto):
        self.lattice_crypto = lattice_crypto
        self.hash_crypto = hash_crypto
        self.encap_calls = []
        self.sign_calls = []
        self.verify_calls = []
        
    def hybrid_key_encapsulation(self, classical_pubkey: bytes, quantum_pubkey: bytes,
                                mode: HybridMode = HybridMode.PARALLEL_HYBRID) -> Tuple[bytes, bytes]:
        """Mock hybrid key encapsulation."""
        self.encap_calls.append((len(classical_pubkey), len(quantum_pubkey), mode))
        
        # Generate appropriate ciphertext and key based on mode
        if mode == HybridMode.CLASSICAL_ONLY:
            ciphertext = secrets.token_bytes(256)  # Classical ciphertext
            shared_key = secrets.token_bytes(32)
        elif mode == HybridMode.QUANTUM_ONLY:
            ciphertext, shared_key = self.lattice_crypto.kyber_encapsulate(quantum_pubkey)
        elif mode == HybridMode.PARALLEL_HYBRID:
            classical_ct = secrets.token_bytes(256)
            quantum_ct, quantum_key = self.lattice_crypto.kyber_encapsulate(quantum_pubkey)
            ciphertext = classical_ct + quantum_ct
            # Combine keys using XOR for simplicity
            classical_key = secrets.token_bytes(32)
            shared_key = bytes(a ^ b for a, b in zip(classical_key, quantum_key))
        else:
            # Other hybrid modes
            classical_ct = secrets.token_bytes(256)
            quantum_ct, quantum_key = self.lattice_crypto.kyber_encapsulate(quantum_pubkey)
            ciphertext = classical_ct + quantum_ct
            shared_key = quantum_key
        
        return ciphertext, shared_key
    
    def hybrid_signature(self, message: bytes, classical_privkey: bytes, quantum_privkey: bytes,
                        mode: HybridMode = HybridMode.PARALLEL_HYBRID) -> bytes:
        """Mock hybrid signature generation."""
        self.sign_calls.append((len(message), len(classical_privkey), len(quantum_privkey), mode))
        
        if mode == HybridMode.CLASSICAL_ONLY:
            # Classical signature (HMAC)
            import hmac
            return hmac.new(classical_privkey[:32], message, hashlib.sha256).digest()
        elif mode == HybridMode.QUANTUM_ONLY:
            return self.hash_crypto.sphincs_sign(message, quantum_privkey)
        elif mode == HybridMode.PARALLEL_HYBRID:
            # Both signatures
            import hmac
            classical_sig = hmac.new(classical_privkey[:32], message, hashlib.sha256).digest()
            quantum_sig = self.hash_crypto.sphincs_sign(message, quantum_privkey)
            return struct.pack('<I', len(classical_sig)) + classical_sig + quantum_sig
        else:
            # Sequential modes
            import hmac
            classical_sig = hmac.new(classical_privkey[:32], message, hashlib.sha256).digest()
            quantum_sig = self.hash_crypto.sphincs_sign(message if mode == HybridMode.QUANTUM_THEN_CLASSICAL else classical_sig, quantum_privkey)
            return struct.pack('<I', len(classical_sig)) + classical_sig + quantum_sig
    
    def hybrid_verify_signature(self, message: bytes, signature: bytes,
                               classical_pubkey: bytes, quantum_pubkey: bytes,
                               mode: HybridMode = HybridMode.PARALLEL_HYBRID) -> bool:
        """Mock hybrid signature verification."""
        self.verify_calls.append((len(message), len(signature), len(classical_pubkey), len(quantum_pubkey), mode))
        
        try:
            if mode == HybridMode.CLASSICAL_ONLY:
                # Classical verification (HMAC)
                import hmac
                expected = hmac.new(classical_pubkey[:32], message, hashlib.sha256).digest()
                return hmac.compare_digest(signature, expected)
            elif mode == HybridMode.QUANTUM_ONLY:
                return self.hash_crypto.sphincs_verify(message, signature, quantum_pubkey)
            elif mode == HybridMode.PARALLEL_HYBRID:
                # Both signatures
                if len(signature) < 4:
                    return False
                classical_sig_len = struct.unpack('<I', signature[:4])[0]
                classical_sig = signature[4:4 + classical_sig_len]
                quantum_sig = signature[4 + classical_sig_len:]
                
                # Verify both
                import hmac
                classical_ok = hmac.compare_digest(
                    classical_sig,
                    hmac.new(classical_pubkey[:32], message, hashlib.sha256).digest()
                )
                quantum_ok = self.hash_crypto.sphincs_verify(message, quantum_sig, quantum_pubkey)
                return classical_ok and quantum_ok
            else:
                # Sequential modes - simplified verification
                return len(signature) > 36 and hashlib.sha256(message).digest()[:8] in signature
                
        except Exception:
            return False


class MockQuantumCryptoEngine:
    """Mock quantum cryptographic engine for testing."""
    
    def __init__(self, db_path: str = "mock_quantum_crypto.db",
                 security_level: SecurityLevel = SecurityLevel.LEVEL_3):
        self.database = MockQuantumCryptoDatabase()
        self.security_level = security_level
        
        # Initialize mock components
        self.lattice_crypto = MockLatticeBasedCrypto(security_level)
        self.hash_crypto = MockHashBasedSignatures(security_level)
        self.qkd = MockQuantumKeyDistribution()
        self.hybrid_crypto = MockHybridCryptoSystem(self.lattice_crypto, self.hash_crypto)
        
        # Key management
        self.active_keypairs = {}
        
        # Track method calls
        self.keygen_calls = []
        self.sign_calls = []
        self.verify_calls = []
        self.encrypt_calls = []
        self.decrypt_calls = []
        
    def generate_keypair(self, algorithm: QuantumAlgorithm) -> QuantumKeyPair:
        """Mock generate keypair."""
        self.keygen_calls.append(algorithm)
        
        if algorithm == QuantumAlgorithm.KYBER:
            keypair = self.lattice_crypto.generate_kyber_keypair()
        elif algorithm == QuantumAlgorithm.DILITHIUM:
            keypair = self.lattice_crypto.generate_dilithium_keypair()
        elif algorithm == QuantumAlgorithm.SPHINCS_PLUS:
            keypair = self.hash_crypto.generate_sphincs_keypair()
        elif algorithm == QuantumAlgorithm.XMSS:
            keypair = self.hash_crypto.generate_xmss_keypair()
        else:
            # Generate generic keypair for other algorithms
            keypair = QuantumKeyPair(
                algorithm=algorithm,
                security_level=self.security_level,
                public_key=secrets.token_bytes(1000),
                private_key=secrets.token_bytes(2000),
                created_at=datetime.now(timezone.utc)
            )
        
        # Store keypair
        self.database.store_keypair(keypair)
        self.active_keypairs[keypair.key_id] = keypair
        
        return keypair
    
    def sign_message(self, message: bytes, key_id: str) -> QuantumSignature:
        """Mock sign message."""
        self.sign_calls.append((len(message), key_id))
        
        keypair = self.active_keypairs.get(key_id)
        if not keypair:
            raise ValueError(f"Keypair {key_id} not found")
        
        # Generate signature based on algorithm
        if keypair.algorithm == QuantumAlgorithm.DILITHIUM:
            signature_bytes = self.lattice_crypto.dilithium_sign(message, keypair.private_key)
        elif keypair.algorithm == QuantumAlgorithm.SPHINCS_PLUS:
            signature_bytes = self.hash_crypto.sphincs_sign(message, keypair.private_key)
        elif keypair.algorithm == QuantumAlgorithm.XMSS:
            signature_bytes = self.hash_crypto.xmss_sign(message, keypair.private_key, keypair.metadata)
        else:
            # Generic signature
            signature_bytes = hashlib.sha256(message + keypair.private_key[:32]).digest() + secrets.token_bytes(64)
        
        return QuantumSignature(
            algorithm=keypair.algorithm,
            signature=signature_bytes,
            message_hash=hashlib.sha256(message).digest(),
            signer_key_id=key_id,
            timestamp=datetime.now(timezone.utc),
            security_level=keypair.security_level
        )
    
    def verify_signature(self, message: bytes, signature: QuantumSignature, public_key: bytes) -> bool:
        """Mock verify signature."""
        self.verify_calls.append((len(message), signature.algorithm, len(public_key)))
        
        # Verify message hash
        expected_hash = hashlib.sha256(message).digest()
        if signature.message_hash != expected_hash:
            return False
        
        # Verify based on algorithm
        if signature.algorithm == QuantumAlgorithm.DILITHIUM:
            return self.lattice_crypto.dilithium_verify(message, signature.signature, public_key)
        elif signature.algorithm == QuantumAlgorithm.SPHINCS_PLUS:
            return self.hash_crypto.sphincs_verify(message, signature.signature, public_key)
        elif signature.algorithm == QuantumAlgorithm.XMSS:
            return self.hash_crypto.xmss_verify(message, signature.signature, public_key)
        else:
            # Generic verification - check if signature contains message hash
            return signature.message_hash[:16] in signature.signature
    
    def encrypt_data(self, data: bytes, public_key: bytes,
                    algorithm: QuantumAlgorithm = QuantumAlgorithm.KYBER) -> QuantumEncryptedData:
        """Mock encrypt data."""
        self.encrypt_calls.append((len(data), len(public_key), algorithm))
        
        if algorithm == QuantumAlgorithm.KYBER:
            # Use Kyber for key encapsulation
            encapsulated_key, shared_secret = self.lattice_crypto.kyber_encapsulate(public_key)
            
            # Mock encryption with shared secret
            nonce = secrets.token_bytes(12)
            
            # Simple XOR encryption for testing
            ciphertext = bytes(a ^ b for a, b in zip(data, shared_secret * (len(data) // 32 + 1)))
            tag = hashlib.sha256(ciphertext + shared_secret).digest()[:16]
            
            return QuantumEncryptedData(
                algorithm=algorithm,
                ciphertext=ciphertext,
                encapsulated_key=encapsulated_key,
                nonce=nonce,
                tag=tag,
                security_level=self.security_level,
                encryption_timestamp=datetime.now(timezone.utc)
            )
        else:
            raise ValueError(f"Algorithm {algorithm} not supported for encryption")
    
    def decrypt_data(self, encrypted_data: QuantumEncryptedData, private_key: bytes) -> bytes:
        """Mock decrypt data."""
        self.decrypt_calls.append((encrypted_data.algorithm, len(private_key)))
        
        if encrypted_data.algorithm == QuantumAlgorithm.KYBER:
            # Decapsulate shared secret
            shared_secret = self.lattice_crypto.kyber_decapsulate(
                encrypted_data.encapsulated_key, private_key
            )
            
            # Simple XOR decryption
            plaintext = bytes(
                a ^ b for a, b in zip(
                    encrypted_data.ciphertext,
                    shared_secret * (len(encrypted_data.ciphertext) // 32 + 1)
                )
            )
            
            return plaintext
        else:
            raise ValueError(f"Algorithm {encrypted_data.algorithm} not supported for decryption")
    
    def establish_qkd_session(self, alice_id: str, bob_id: str,
                             protocol: str = 'BB84', key_length: int = 256) -> QKDSession:
        """Mock establish QKD session."""
        if protocol == 'BB84':
            return self.qkd.bb84_protocol(alice_id, bob_id, key_length)
        elif protocol == 'E91':
            return self.qkd.e91_protocol(alice_id, bob_id, key_length)
        else:
            raise ValueError(f"Unsupported QKD protocol: {protocol}")
    
    def hybrid_sign(self, message: bytes, classical_key_id: str, quantum_key_id: str,
                   mode: HybridMode = HybridMode.PARALLEL_HYBRID) -> bytes:
        """Mock hybrid signature."""
        classical_keypair = self.active_keypairs.get(classical_key_id)
        quantum_keypair = self.active_keypairs.get(quantum_key_id)
        
        if not classical_keypair or not quantum_keypair:
            raise ValueError("Required keypairs not found")
        
        return self.hybrid_crypto.hybrid_signature(
            message, classical_keypair.private_key, quantum_keypair.private_key, mode
        )
    
    def hybrid_verify(self, message: bytes, signature: bytes,
                     classical_key_id: str, quantum_key_id: str,
                     mode: HybridMode = HybridMode.PARALLEL_HYBRID) -> bool:
        """Mock hybrid signature verification."""
        classical_keypair = self.active_keypairs.get(classical_key_id)
        quantum_keypair = self.active_keypairs.get(quantum_key_id)
        
        if not classical_keypair or not quantum_keypair:
            raise ValueError("Required keypairs not found")
        
        return self.hybrid_crypto.hybrid_verify_signature(
            message, signature, classical_keypair.public_key,
            quantum_keypair.public_key, mode
        )
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Mock get performance metrics."""
        return {
            'active_keypairs': len(self.active_keypairs),
            'security_level': self.security_level.value,
            'supported_algorithms': [alg.value for alg in QuantumAlgorithm],
            'qkd_sessions': len(self.qkd.sessions),
            'operations_performed': {
                'keygen': len(self.keygen_calls),
                'sign': len(self.sign_calls),
                'verify': len(self.verify_calls),
                'encrypt': len(self.encrypt_calls),
                'decrypt': len(self.decrypt_calls)
            }
        }


class MockQuantumCryptoTestEnvironment:
    """Comprehensive mock environment for quantum crypto testing."""
    
    def __init__(self):
        self.engine = MockQuantumCryptoEngine()
        
        # Test data
        self.test_messages = self._generate_test_messages()
        self.test_keypairs = {}
        
        # Performance tracking
        self.performance_metrics = {
            'operations': [],
            'timing_data': []
        }
        
    def _generate_test_messages(self) -> List[bytes]:
        """Generate test messages of various sizes."""
        messages = [
            b"Hello, quantum world!",
            b"The quick brown fox jumps over the lazy dog",
            secrets.token_bytes(100),  # Random small data
            secrets.token_bytes(1024),  # 1KB
            secrets.token_bytes(10240),  # 10KB
            b"A" * 50000,  # Large repetitive data
            b"",  # Empty message
            b"\x00\x01\x02\x03" * 256,  # Binary pattern
        ]
        return messages
    
    def setup_test_keypairs(self):
        """Setup test keypairs for all algorithms."""
        algorithms = [
            QuantumAlgorithm.KYBER,
            QuantumAlgorithm.DILITHIUM,
            QuantumAlgorithm.SPHINCS_PLUS,
            QuantumAlgorithm.XMSS,
            QuantumAlgorithm.FALCON
        ]
        
        for algorithm in algorithms:
            try:
                keypair = self.engine.generate_keypair(algorithm)
                self.test_keypairs[algorithm] = keypair
            except Exception as e:
                print(f"Warning: Could not generate {algorithm.value} keypair: {e}")
    
    def run_performance_test(self, algorithm: QuantumAlgorithm, num_iterations: int = 100) -> Dict[str, Any]:
        """Run performance test for specific algorithm."""
        if algorithm not in self.test_keypairs:
            self.test_keypairs[algorithm] = self.engine.generate_keypair(algorithm)
        
        keypair = self.test_keypairs[algorithm]
        test_message = b"Performance test message for quantum cryptography"
        
        # Time signature operations
        sign_times = []
        verify_times = []
        
        for _ in range(num_iterations):
            # Sign
            start_time = time.time()
            signature = self.engine.sign_message(test_message, keypair.key_id)
            sign_times.append((time.time() - start_time) * 1000)  # Convert to ms
            
            # Verify
            start_time = time.time()
            result = self.engine.verify_signature(test_message, signature, keypair.public_key)
            verify_times.append((time.time() - start_time) * 1000)
            
            if not result:
                print(f"Warning: Verification failed for {algorithm.value}")
        
        return {
            'algorithm': algorithm.value,
            'iterations': num_iterations,
            'sign_times': {
                'avg': np.mean(sign_times),
                'min': np.min(sign_times),
                'max': np.max(sign_times),
                'std': np.std(sign_times)
            },
            'verify_times': {
                'avg': np.mean(verify_times),
                'min': np.min(verify_times),
                'max': np.max(verify_times),
                'std': np.std(verify_times)
            },
            'key_sizes': {
                'public_key': len(keypair.public_key),
                'private_key': len(keypair.private_key)
            }
        }
    
    def test_algorithm_interoperability(self) -> Dict[str, Any]:
        """Test interoperability between different algorithms."""
        results = {}
        
        # Test hybrid combinations
        hybrid_tests = [
            (QuantumAlgorithm.DILITHIUM, QuantumAlgorithm.SPHINCS_PLUS),
            (QuantumAlgorithm.KYBER, QuantumAlgorithm.XMSS),
        ]
        
        for classical_alg, quantum_alg in hybrid_tests:
            try:
                if classical_alg not in self.test_keypairs:
                    self.test_keypairs[classical_alg] = self.engine.generate_keypair(classical_alg)
                if quantum_alg not in self.test_keypairs:
                    self.test_keypairs[quantum_alg] = self.engine.generate_keypair(quantum_alg)
                
                classical_kp = self.test_keypairs[classical_alg]
                quantum_kp = self.test_keypairs[quantum_alg]
                
                test_message = b"Hybrid signature test message"
                
                # Test all hybrid modes
                for mode in HybridMode:
                    try:
                        signature = self.engine.hybrid_sign(
                            test_message, classical_kp.key_id, quantum_kp.key_id, mode
                        )
                        
                        verification = self.engine.hybrid_verify(
                            test_message, signature, classical_kp.key_id, quantum_kp.key_id, mode
                        )
                        
                        results[f"{classical_alg.value}+{quantum_alg.value}_{mode.value}"] = {
                            'success': True,
                            'signature_size': len(signature),
                            'verification_result': verification
                        }
                        
                    except Exception as e:
                        results[f"{classical_alg.value}+{quantum_alg.value}_{mode.value}"] = {
                            'success': False,
                            'error': str(e)
                        }
                        
            except Exception as e:
                results[f"{classical_alg.value}+{quantum_alg.value}"] = {
                    'success': False,
                    'error': str(e)
                }
        
        return results
    
    def simulate_quantum_attacks(self) -> Dict[str, Any]:
        """Simulate quantum attacks on different algorithms."""
        attack_results = {}
        
        # Simulate Shor's algorithm effectiveness
        shor_vulnerable = [
            ('RSA-2048', 'completely_broken'),
            ('ECDSA-P256', 'completely_broken'),
            ('DH-2048', 'completely_broken')
        ]
        
        # Post-quantum algorithm resistance
        pq_resistant = [
            (QuantumAlgorithm.KYBER, 'resistant'),
            (QuantumAlgorithm.DILITHIUM, 'resistant'),
            (QuantumAlgorithm.SPHINCS_PLUS, 'resistant'),
            (QuantumAlgorithm.XMSS, 'resistant'),
            (QuantumAlgorithm.FALCON, 'resistant')
        ]
        
        attack_results['shors_algorithm'] = {
            'vulnerable': shor_vulnerable,
            'resistant': [(alg.value, status) for alg, status in pq_resistant]
        }
        
        # Simulate Grover's algorithm impact (halves effective security level)
        grover_impact = {}
        for algorithm in [QuantumAlgorithm.KYBER, QuantumAlgorithm.DILITHIUM, QuantumAlgorithm.SPHINCS_PLUS]:
            if algorithm in self.test_keypairs:
                original_level = self.test_keypairs[algorithm].security_level
                effective_level = SecurityLevel(max(1, original_level.value - 1))  # Reduce by one level
                grover_impact[algorithm.value] = {
                    'original_security_level': original_level.value,
                    'post_grover_effective_level': effective_level.value,
                    'security_reduction_bits': 64 * (original_level.value - effective_level.value)
                }
        
        attack_results['grovers_algorithm'] = grover_impact
        
        return attack_results
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get comprehensive performance summary."""
        return {
            'algorithms_tested': list(self.test_keypairs.keys()),
            'total_operations': len(self.performance_metrics['operations']),
            'engine_metrics': self.engine.get_performance_metrics(),
            'qkd_sessions': len(self.engine.qkd.sessions),
            'hybrid_operations': {
                'signatures': len(self.engine.hybrid_crypto.sign_calls),
                'verifications': len(self.engine.hybrid_crypto.verify_calls),
                'encapsulations': len(self.engine.hybrid_crypto.encap_calls)
            }
        }
    
    def cleanup(self):
        """Cleanup test environment."""
        self.test_keypairs.clear()
        self.performance_metrics = {'operations': [], 'timing_data': []}
        self.engine.active_keypairs.clear()


# Export all mock classes
__all__ = [
    'MockQuantumCryptoDatabase',
    'MockLatticeBasedCrypto',
    'MockHashBasedSignatures',
    'MockQuantumKeyDistribution',
    'MockHybridCryptoSystem',
    'MockQuantumCryptoEngine',
    'MockQuantumCryptoTestEnvironment'
]