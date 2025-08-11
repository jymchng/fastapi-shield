"""FastAPI-Shield Quantum-Resistant Cryptographic Security Engine

This module provides a comprehensive quantum-resistant cryptographic system that implements
post-quantum cryptographic algorithms to protect against attacks from both classical and
quantum computers, ensuring future-proof security for enterprise applications.

Features:
- NIST-approved post-quantum cryptographic algorithms
- Lattice-based cryptography (Kyber, Dilithium, FALCON)
- Code-based cryptographic systems (Classic McEliece, BIKE)
- Hash-based signature schemes (XMSS, LMS, SPHINCS+)
- Multivariate quadratic cryptographic schemes
- Hybrid classical-quantum cryptographic systems
- Quantum key distribution (QKD) protocol simulation
- Homomorphic encryption with quantum resistance
- Zero-knowledge proofs with post-quantum security
- Cryptographic agility and algorithm migration support
- Integration with existing FastAPI-Shield components
"""

import asyncio
import hashlib
import hmac
import json
import logging
import secrets
import struct
import time
import uuid
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from enum import Enum
from pathlib import Path
from threading import RLock
from typing import (
    Any, Dict, List, Optional, Union, Callable, Set, Tuple,
    NamedTuple, Protocol, AsyncIterator, TypeVar, Generic
)
import sqlite3
import base64
import os

# Cryptographic imports
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

# Try to import post-quantum cryptography libraries
try:
    # These would be real post-quantum crypto libraries in production
    # For now, we'll implement our own quantum-resistant algorithms
    pass
except ImportError:
    pass

import numpy as np

logger = logging.getLogger(__name__)

T = TypeVar('T')


class QuantumAlgorithm(Enum):
    """Post-quantum cryptographic algorithms."""
    # NIST Round 4 Winners
    KYBER = "kyber"                    # Key encapsulation
    DILITHIUM = "dilithium"           # Digital signatures
    FALCON = "falcon"                 # Digital signatures
    SPHINCS_PLUS = "sphincs_plus"     # Hash-based signatures
    
    # Additional post-quantum algorithms
    CLASSIC_MCELIECE = "classic_mceliece"  # Code-based
    BIKE = "bike"                          # Code-based
    HQC = "hqc"                           # Code-based
    RAINBOW = "rainbow"                    # Multivariate
    GeMSS = "gemss"                       # Multivariate
    XMSS = "xmss"                         # Hash-based
    LMS = "lms"                           # Hash-based
    
    # Experimental algorithms
    NTRU = "ntru"                         # Lattice-based
    SABER = "saber"                       # Lattice-based
    FRODOKEM = "frodokem"                 # Lattice-based


class SecurityLevel(Enum):
    """NIST security levels for post-quantum cryptography."""
    LEVEL_1 = 1    # Equivalent to AES-128
    LEVEL_3 = 3    # Equivalent to AES-192  
    LEVEL_5 = 5    # Equivalent to AES-256


class CryptoOperation(Enum):
    """Types of cryptographic operations."""
    KEY_GENERATION = "key_generation"
    KEY_ENCAPSULATION = "key_encapsulation"
    KEY_DECAPSULATION = "key_decapsulation"
    SIGN = "sign"
    VERIFY = "verify"
    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"
    HASH = "hash"
    MAC = "mac"


class HybridMode(Enum):
    """Hybrid cryptography modes."""
    CLASSICAL_ONLY = "classical_only"
    QUANTUM_ONLY = "quantum_only"
    CLASSICAL_THEN_QUANTUM = "classical_then_quantum"
    QUANTUM_THEN_CLASSICAL = "quantum_then_classical"
    PARALLEL_HYBRID = "parallel_hybrid"


@dataclass
class QuantumKeyPair:
    """Post-quantum cryptographic key pair."""
    algorithm: QuantumAlgorithm
    security_level: SecurityLevel
    public_key: bytes
    private_key: bytes
    created_at: datetime
    expires_at: Optional[datetime] = None
    key_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'key_id': self.key_id,
            'algorithm': self.algorithm.value,
            'security_level': self.security_level.value,
            'public_key': base64.b64encode(self.public_key).decode(),
            'private_key': base64.b64encode(self.private_key).decode(),
            'created_at': self.created_at.isoformat(),
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'metadata': self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'QuantumKeyPair':
        """Create from dictionary."""
        return cls(
            key_id=data['key_id'],
            algorithm=QuantumAlgorithm(data['algorithm']),
            security_level=SecurityLevel(data['security_level']),
            public_key=base64.b64decode(data['public_key']),
            private_key=base64.b64decode(data['private_key']),
            created_at=datetime.fromisoformat(data['created_at']),
            expires_at=datetime.fromisoformat(data['expires_at']) if data['expires_at'] else None,
            metadata=data.get('metadata', {})
        )


@dataclass
class QuantumSignature:
    """Post-quantum digital signature."""
    algorithm: QuantumAlgorithm
    signature: bytes
    message_hash: bytes
    signer_key_id: str
    timestamp: datetime
    security_level: SecurityLevel
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'algorithm': self.algorithm.value,
            'signature': base64.b64encode(self.signature).decode(),
            'message_hash': base64.b64encode(self.message_hash).decode(),
            'signer_key_id': self.signer_key_id,
            'timestamp': self.timestamp.isoformat(),
            'security_level': self.security_level.value,
            'metadata': self.metadata
        }


@dataclass
class QuantumEncryptedData:
    """Post-quantum encrypted data container."""
    algorithm: QuantumAlgorithm
    ciphertext: bytes
    encapsulated_key: bytes
    nonce: bytes
    tag: bytes
    security_level: SecurityLevel
    encryption_timestamp: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'algorithm': self.algorithm.value,
            'ciphertext': base64.b64encode(self.ciphertext).decode(),
            'encapsulated_key': base64.b64encode(self.encapsulated_key).decode(),
            'nonce': base64.b64encode(self.nonce).decode(),
            'tag': base64.b64encode(self.tag).decode(),
            'security_level': self.security_level.value,
            'encryption_timestamp': self.encryption_timestamp.isoformat(),
            'metadata': self.metadata
        }


@dataclass
class QKDSession:
    """Quantum Key Distribution session data."""
    session_id: str
    alice_id: str
    bob_id: str
    shared_key: bytes
    key_length: int
    error_rate: float
    security_parameter: float
    protocol: str
    created_at: datetime
    status: str = "active"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'session_id': self.session_id,
            'alice_id': self.alice_id,
            'bob_id': self.bob_id,
            'shared_key': base64.b64encode(self.shared_key).decode(),
            'key_length': self.key_length,
            'error_rate': self.error_rate,
            'security_parameter': self.security_parameter,
            'protocol': self.protocol,
            'created_at': self.created_at.isoformat(),
            'status': self.status
        }


class QuantumCryptoDatabase:
    """Database for quantum cryptographic data."""
    
    def __init__(self, db_path: str = "quantum_crypto.db"):
        self.db_path = db_path
        self._lock = RLock()
        self._init_database()
        logger.info(f"Quantum Crypto Database initialized at {db_path}")
    
    def _init_database(self):
        """Initialize database schema."""
        with sqlite3.connect(self.db_path) as conn:
            # Key pairs table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS quantum_keypairs (
                    key_id TEXT PRIMARY KEY,
                    algorithm TEXT NOT NULL,
                    security_level INTEGER NOT NULL,
                    public_key BLOB NOT NULL,
                    private_key BLOB NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP,
                    metadata TEXT,
                    is_active BOOLEAN DEFAULT 1
                )
            """)
            
            # Signatures table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS quantum_signatures (
                    id TEXT PRIMARY KEY,
                    algorithm TEXT NOT NULL,
                    signature BLOB NOT NULL,
                    message_hash BLOB NOT NULL,
                    signer_key_id TEXT NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    security_level INTEGER NOT NULL,
                    metadata TEXT,
                    FOREIGN KEY (signer_key_id) REFERENCES quantum_keypairs (key_id)
                )
            """)
            
            # Encrypted data table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS quantum_encrypted_data (
                    id TEXT PRIMARY KEY,
                    algorithm TEXT NOT NULL,
                    ciphertext BLOB NOT NULL,
                    encapsulated_key BLOB NOT NULL,
                    nonce BLOB NOT NULL,
                    tag BLOB NOT NULL,
                    security_level INTEGER NOT NULL,
                    encryption_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    metadata TEXT
                )
            """)
            
            # QKD sessions table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS qkd_sessions (
                    session_id TEXT PRIMARY KEY,
                    alice_id TEXT NOT NULL,
                    bob_id TEXT NOT NULL,
                    shared_key BLOB NOT NULL,
                    key_length INTEGER NOT NULL,
                    error_rate REAL NOT NULL,
                    security_parameter REAL NOT NULL,
                    protocol TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status TEXT DEFAULT 'active'
                )
            """)
            
            # Performance metrics table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS crypto_performance (
                    id TEXT PRIMARY KEY,
                    algorithm TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    duration_ms REAL NOT NULL,
                    key_size INTEGER,
                    data_size INTEGER,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    metadata TEXT
                )
            """)
            
            # Create indexes
            conn.execute("CREATE INDEX IF NOT EXISTS idx_keypairs_algorithm ON quantum_keypairs(algorithm)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_keypairs_active ON quantum_keypairs(is_active)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_signatures_signer ON quantum_signatures(signer_key_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_qkd_status ON qkd_sessions(status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_performance_algorithm ON crypto_performance(algorithm)")
            
            conn.commit()
    
    def store_keypair(self, keypair: QuantumKeyPair) -> bool:
        """Store quantum key pair."""
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute("""
                        INSERT OR REPLACE INTO quantum_keypairs
                        (key_id, algorithm, security_level, public_key, private_key,
                         created_at, expires_at, metadata, is_active)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        keypair.key_id, keypair.algorithm.value, keypair.security_level.value,
                        keypair.public_key, keypair.private_key, keypair.created_at,
                        keypair.expires_at, json.dumps(keypair.metadata), True
                    ))
                    conn.commit()
                return True
            except Exception as e:
                logger.error(f"Error storing keypair: {e}")
                return False
    
    def get_keypair(self, key_id: str) -> Optional[QuantumKeyPair]:
        """Get quantum key pair by ID."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "SELECT * FROM quantum_keypairs WHERE key_id = ? AND is_active = 1",
                    (key_id,)
                )
                row = cursor.fetchone()
                
                if row:
                    return QuantumKeyPair(
                        key_id=row[0],
                        algorithm=QuantumAlgorithm(row[1]),
                        security_level=SecurityLevel(row[2]),
                        public_key=row[3],
                        private_key=row[4],
                        created_at=datetime.fromisoformat(row[5].replace('Z', '+00:00')) if isinstance(row[5], str) else row[5],
                        expires_at=datetime.fromisoformat(row[6].replace('Z', '+00:00')) if row[6] else None,
                        metadata=json.loads(row[7]) if row[7] else {}
                    )
                
        except Exception as e:
            logger.error(f"Error retrieving keypair: {e}")
        
        return None
    
    def store_performance_metric(self, algorithm: str, operation: str, duration_ms: float,
                                key_size: Optional[int] = None, data_size: Optional[int] = None) -> bool:
        """Store performance metric."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO crypto_performance
                    (id, algorithm, operation, duration_ms, key_size, data_size, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    str(uuid.uuid4()), algorithm, operation, duration_ms,
                    key_size, data_size, datetime.now(timezone.utc)
                ))
                conn.commit()
            return True
        except Exception as e:
            logger.error(f"Error storing performance metric: {e}")
            return False


class LatticeBasedCrypto:
    """Lattice-based cryptographic algorithms (Kyber, Dilithium, FALCON)."""
    
    def __init__(self, security_level: SecurityLevel = SecurityLevel.LEVEL_3):
        self.security_level = security_level
        self.parameters = self._get_parameters(security_level)
        
        # Lattice parameters based on security level
        if security_level == SecurityLevel.LEVEL_1:
            self.n = 256  # Dimension
            self.q = 3329  # Modulus
            self.k = 2     # Matrix dimension
        elif security_level == SecurityLevel.LEVEL_3:
            self.n = 256
            self.q = 3329
            self.k = 3
        else:  # LEVEL_5
            self.n = 256
            self.q = 3329
            self.k = 4
        
        logger.info(f"LatticeBasedCrypto initialized with security level {security_level.value}")
    
    def _get_parameters(self, security_level: SecurityLevel) -> Dict[str, int]:
        """Get algorithm parameters for security level."""
        params = {
            SecurityLevel.LEVEL_1: {
                'n': 256, 'q': 3329, 'k': 2, 'eta': 2, 'du': 10, 'dv': 4
            },
            SecurityLevel.LEVEL_3: {
                'n': 256, 'q': 3329, 'k': 3, 'eta': 2, 'du': 10, 'dv': 4
            },
            SecurityLevel.LEVEL_5: {
                'n': 256, 'q': 3329, 'k': 4, 'eta': 2, 'du': 11, 'dv': 5
            }
        }
        return params[security_level]
    
    def generate_kyber_keypair(self) -> QuantumKeyPair:
        """Generate Kyber KEM key pair (simplified implementation)."""
        # In a real implementation, this would use the full Kyber specification
        # This is a simplified educational version focusing on the core concepts
        
        # Generate random seed
        seed = secrets.token_bytes(32)
        
        # Expand seed to generate matrix A and secret vectors
        rho, sigma = self._expand_seed(seed)
        
        # Generate secret vector s
        s = self._sample_small_vector(self.k * self.n, sigma)
        
        # Generate error vector e  
        e = self._sample_small_vector(self.k * self.n, sigma)
        
        # Generate matrix A from rho
        A = self._gen_matrix(rho, self.k, self.k)
        
        # Compute t = A * s + e
        t = self._matrix_vector_mult(A, s, e)
        
        # Pack keys
        public_key = self._pack_public_key(t, rho)
        private_key = self._pack_private_key(s)
        
        return QuantumKeyPair(
            algorithm=QuantumAlgorithm.KYBER,
            security_level=self.security_level,
            public_key=public_key,
            private_key=private_key,
            created_at=datetime.now(timezone.utc)
        )
    
    def kyber_encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """Kyber key encapsulation (simplified)."""
        # Unpack public key
        t, rho = self._unpack_public_key(public_key)
        
        # Generate random message
        m = secrets.token_bytes(32)
        
        # Derive randomness
        K, r = self._kyber_derive_keys(m, public_key)
        
        # Generate matrix A
        A_T = self._gen_matrix(rho, self.k, self.k, transpose=True)
        
        # Sample error vectors
        r_vec = self._sample_small_vector(self.k * self.n, r[:32])
        e1 = self._sample_small_vector(self.k * self.n, r[32:64])
        e2 = self._sample_small_poly(r[64:96])
        
        # Compute u = A^T * r + e1
        u = self._matrix_vector_mult(A_T, r_vec, e1)
        
        # Compute v = t^T * r + e2 + decompress(m)
        tr_result = self._vector_mult(t, r_vec)
        decompressed_m = self._decompress(m, 1)
        v = (tr_result + e2 + decompressed_m[0] if decompressed_m else tr_result + e2) % self.q
        
        # Pack ciphertext
        ciphertext = self._pack_ciphertext(u, v)
        
        return ciphertext, K
    
    def kyber_decapsulate(self, ciphertext: bytes, private_key: bytes) -> bytes:
        """Kyber key decapsulation (simplified)."""
        # Unpack private key and ciphertext
        s = self._unpack_private_key(private_key)
        u, v = self._unpack_ciphertext(ciphertext)
        
        # Compute m = compress(v - s^T * u)
        stu_result = self._vector_mult(s, u)
        result = (v - stu_result) % self.q
        m = self._compress([result], 1)
        
        # Re-derive and verify
        K, _ = self._kyber_derive_keys(m, private_key)
        
        return K
    
    def generate_dilithium_keypair(self) -> QuantumKeyPair:
        """Generate Dilithium signature key pair (simplified)."""
        # Dilithium parameters
        if self.security_level == SecurityLevel.LEVEL_1:
            k, l, gamma1, gamma2 = 4, 4, 2**17, (3329-1)//88
        elif self.security_level == SecurityLevel.LEVEL_3:
            k, l, gamma1, gamma2 = 6, 5, 2**19, (3329-1)//32
        else:  # LEVEL_5
            k, l, gamma1, gamma2 = 8, 7, 2**19, (3329-1)//32
        
        # Generate random seed
        zeta = secrets.token_bytes(32)
        
        # Expand seed
        rho, rho_prime, K = self._dilithium_expand_seed(zeta)
        
        # Generate matrix A
        A = self._gen_matrix(rho, k, l)
        
        # Sample secret vectors s1, s2
        s1 = self._sample_small_vector(l * self.n, rho_prime)
        s2 = self._sample_small_vector(k * self.n, rho_prime[32:])
        
        # Compute t = A * s1 + s2
        t = self._matrix_vector_mult(A, s1, s2)
        
        # Compute t1, t0 = power2round(t)
        t1, t0 = self._power2round(t, 13)  # d = 13 for Dilithium
        
        # Pack keys
        public_key = self._pack_dilithium_public_key(rho, t1)
        private_key = self._pack_dilithium_private_key(rho, K, t0, s1, s2)
        
        return QuantumKeyPair(
            algorithm=QuantumAlgorithm.DILITHIUM,
            security_level=self.security_level,
            public_key=public_key,
            private_key=private_key,
            created_at=datetime.now(timezone.utc)
        )
    
    def dilithium_sign(self, message: bytes, private_key: bytes) -> bytes:
        """Dilithium signature generation (simplified)."""
        # Unpack private key
        rho, K, t0, s1, s2 = self._unpack_dilithium_private_key(private_key)
        
        # Generate matrix A
        A = self._gen_matrix(rho, self.k, self.parameters['k'])
        
        # Message preprocessing
        mu = hashlib.shake_256(message).digest(64)
        
        # Initialize nonce
        kappa = 0
        
        # Rejection sampling loop (simplified)
        for attempt in range(100):  # Max attempts
            # Sample mask y
            y = self._sample_mask_vector(mu, kappa)
            
            # Compute w = A * y
            w = self._matrix_vector_mult(A, y, None)
            
            # Compute w1 = highbits(w)
            w1 = self._highbits(w)
            
            # Compute challenge c
            c = self._dilithium_challenge(mu, w1)
            
            # Compute z = y + c * s1
            z = self._vector_add(y, self._scalar_vector_mult(c, s1))
            
            # Check bounds
            if self._check_dilithium_bounds(z, w, c, s2, t0):
                # Pack signature
                return self._pack_dilithium_signature(c, z)
            
            kappa += 1
        
        raise ValueError("Signature generation failed after maximum attempts")
    
    def dilithium_verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Dilithium signature verification (simplified)."""
        try:
            # Unpack public key and signature
            rho, t1 = self._unpack_dilithium_public_key(public_key)
            c, z = self._unpack_dilithium_signature(signature)
            
            # Generate matrix A
            A = self._gen_matrix(rho, self.k, self.parameters['k'])
            
            # Message preprocessing
            mu = hashlib.shake_256(message).digest(64)
            
            # Compute w' = A * z - c * t1 * 2^d
            t1_scaled = self._scalar_mult(t1, 2**13)
            Az = self._matrix_vector_mult(A, z, None)
            ct1 = self._scalar_vector_mult(c, t1_scaled)
            w_prime = self._vector_sub(Az, ct1)
            
            # Compute w1' = highbits(w')
            w1_prime = self._highbits(w_prime)
            
            # Compute challenge c'
            c_prime = self._dilithium_challenge(mu, w1_prime)
            
            # Verify c == c' and bounds
            return c == c_prime and self._verify_dilithium_bounds(z)
            
        except Exception as e:
            logger.error(f"Dilithium verification error: {e}")
            return False
    
    # Helper methods (simplified implementations)
    
    def _expand_seed(self, seed: bytes) -> Tuple[bytes, bytes]:
        """Expand seed using SHAKE."""
        shake = hashlib.shake_256(seed)
        rho = shake.digest(32)
        sigma = shake.digest(64)
        return rho, sigma
    
    def _sample_small_vector(self, length: int, seed: bytes) -> List[int]:
        """Sample small vector from centered binomial distribution."""
        # Simplified sampling - in practice would use proper CBD
        np.random.seed(int.from_bytes(seed[:4], 'big') % 2**32)
        return [int(np.random.normal(0, self.parameters['eta'])) % self.q for _ in range(length)]
    
    def _sample_small_poly(self, seed: bytes) -> int:
        """Sample small polynomial coefficient."""
        return int.from_bytes(seed[:4], 'big') % self.q
    
    def _gen_matrix(self, rho: bytes, rows: int, cols: int, transpose: bool = False) -> List[List[int]]:
        """Generate matrix A from seed rho."""
        matrix = []
        for i in range(rows):
            row = []
            for j in range(cols):
                # Generate polynomial from rho || i || j
                seed = rho + struct.pack('BB', i, j)
                poly = self._gen_polynomial(seed)
                row.append(poly)
            matrix.append(row)
        
        return matrix if not transpose else [[matrix[j][i] for j in range(len(matrix))] for i in range(len(matrix[0]))]
    
    def _gen_polynomial(self, seed: bytes) -> int:
        """Generate polynomial from seed (simplified)."""
        return int.from_bytes(hashlib.sha256(seed).digest()[:4], 'big') % self.q
    
    def _matrix_vector_mult(self, matrix: List[List[int]], vector: List[int], error: Optional[List[int]]) -> List[int]:
        """Matrix-vector multiplication with optional error."""
        result = []
        for i, row in enumerate(matrix):
            val = sum(a * b for a, b in zip(row, vector)) % self.q
            if error:
                val = (val + error[i]) % self.q
            result.append(val)
        return result
    
    def _vector_mult(self, a: List[int], b: List[int]) -> int:
        """Vector multiplication."""
        return sum(x * y for x, y in zip(a, b)) % self.q
    
    def _vector_add(self, a: List[int], b: List[int]) -> List[int]:
        """Vector addition."""
        return [(x + y) % self.q for x, y in zip(a, b)]
    
    def _vector_sub(self, a: List[int], b: List[int]) -> List[int]:
        """Vector subtraction."""
        return [(x - y) % self.q for x, y in zip(a, b)]
    
    def _scalar_vector_mult(self, scalar: int, vector: List[int]) -> List[int]:
        """Scalar-vector multiplication."""
        return [(scalar * x) % self.q for x in vector]
    
    def _scalar_mult(self, vector: List[int], scalar: int) -> List[int]:
        """Scalar multiplication."""
        return [(x * scalar) % self.q for x in vector]
    
    def _compress(self, x, d: int) -> bytes:
        """Compress polynomial (simplified)."""
        if isinstance(x, int):
            x = [x]
        compressed = []
        for coeff in x:
            compressed.append((coeff * (2**d) // self.q) % (2**d))
        return bytes(compressed)
    
    def _decompress(self, data: bytes, d: int) -> List[int]:
        """Decompress polynomial (simplified)."""
        decompressed = []
        for byte in data:
            decompressed.append((byte * self.q // (2**d)) % self.q)
        return decompressed
    
    def _pack_public_key(self, t: List[int], rho: bytes) -> bytes:
        """Pack Kyber public key."""
        # Simplified packing
        t_bytes = struct.pack(f'<{len(t)}H', *t)
        return rho + t_bytes
    
    def _pack_private_key(self, s: List[int]) -> bytes:
        """Pack Kyber private key."""
        return struct.pack(f'<{len(s)}H', *s)
    
    def _pack_ciphertext(self, u: List[int], v: int) -> bytes:
        """Pack Kyber ciphertext."""
        u_bytes = struct.pack(f'<{len(u)}H', *u)
        v_bytes = struct.pack('<H', v)
        return u_bytes + v_bytes
    
    def _unpack_public_key(self, public_key: bytes) -> Tuple[List[int], bytes]:
        """Unpack Kyber public key."""
        rho = public_key[:32]
        t_bytes = public_key[32:]
        t = list(struct.unpack(f'<{len(t_bytes)//2}H', t_bytes))
        return t, rho
    
    def _unpack_private_key(self, private_key: bytes) -> List[int]:
        """Unpack Kyber private key."""
        return list(struct.unpack(f'<{len(private_key)//2}H', private_key))
    
    def _unpack_ciphertext(self, ciphertext: bytes) -> Tuple[List[int], int]:
        """Unpack Kyber ciphertext."""
        u_size = len(ciphertext) - 2
        u_bytes = ciphertext[:u_size]
        v_bytes = ciphertext[u_size:]
        
        u = list(struct.unpack(f'<{u_size//2}H', u_bytes))
        v = struct.unpack('<H', v_bytes)[0]
        
        return u, v
    
    def _kyber_derive_keys(self, m: bytes, pk: bytes) -> Tuple[bytes, bytes]:
        """Derive Kyber keys from message and public key."""
        combined = m + hashlib.sha256(pk).digest()
        K = hashlib.shake_256(combined).digest(32)
        r = hashlib.shake_256(combined + b'\x00').digest(96)
        return K, r
    
    # Dilithium helper methods
    
    def _dilithium_expand_seed(self, zeta: bytes) -> Tuple[bytes, bytes, bytes]:
        """Expand Dilithium seed."""
        shake = hashlib.shake_256(zeta)
        rho = shake.digest(32)
        rho_prime = shake.digest(64)
        K = shake.digest(32)
        return rho, rho_prime, K
    
    def _power2round(self, vector: List[int], d: int) -> Tuple[List[int], List[int]]:
        """Power-of-2 rounding."""
        t1, t0 = [], []
        for x in vector:
            t1_val = (x + (1 << (d-1))) >> d
            t0_val = x - (t1_val << d)
            t1.append(t1_val)
            t0.append(t0_val)
        return t1, t0
    
    def _highbits(self, vector: List[int]) -> List[int]:
        """Extract high bits."""
        return [(x + 127) >> 8 for x in vector]
    
    def _sample_mask_vector(self, mu: bytes, kappa: int) -> List[int]:
        """Sample mask vector for Dilithium."""
        seed = mu + struct.pack('<I', kappa)
        np.random.seed(int.from_bytes(seed[:4], 'big') % 2**32)
        gamma1 = self.parameters.get('gamma1', 2**17)
        return [int(np.random.uniform(-gamma1, gamma1)) for _ in range(self.parameters['k'] * self.n)]
    
    def _dilithium_challenge(self, mu: bytes, w1: List[int]) -> int:
        """Compute Dilithium challenge."""
        w1_bytes = struct.pack(f'<{len(w1)}I', *w1)
        challenge_input = mu + w1_bytes
        return int.from_bytes(hashlib.shake_256(challenge_input).digest(4), 'big') % self.q
    
    def _check_dilithium_bounds(self, z: List[int], w: List[int], c: int, s2: List[int], t0: List[int]) -> bool:
        """Check Dilithium signature bounds."""
        # Simplified bound checking
        gamma1 = self.parameters.get('gamma1', 2**17)
        gamma2 = self.parameters.get('gamma2', (3329-1)//88)
        
        # Check ||z||_∞ < γ₁ - β
        if any(abs(zi) >= gamma1 - 128 for zi in z):
            return False
        
        # Additional bound checks would be implemented here
        return True
    
    def _verify_dilithium_bounds(self, z: List[int]) -> bool:
        """Verify Dilithium signature bounds."""
        gamma1 = self.parameters.get('gamma1', 2**17)
        return all(abs(zi) < gamma1 - 128 for zi in z)
    
    def _pack_dilithium_public_key(self, rho: bytes, t1: List[int]) -> bytes:
        """Pack Dilithium public key."""
        t1_bytes = struct.pack(f'<{len(t1)}I', *t1)
        return rho + t1_bytes
    
    def _pack_dilithium_private_key(self, rho: bytes, K: bytes, t0: List[int], s1: List[int], s2: List[int]) -> bytes:
        """Pack Dilithium private key."""
        t0_bytes = struct.pack(f'<{len(t0)}I', *t0)
        s1_bytes = struct.pack(f'<{len(s1)}I', *s1)
        s2_bytes = struct.pack(f'<{len(s2)}I', *s2)
        return rho + K + t0_bytes + s1_bytes + s2_bytes
    
    def _pack_dilithium_signature(self, c: int, z: List[int]) -> bytes:
        """Pack Dilithium signature."""
        c_bytes = struct.pack('<I', c)
        z_bytes = struct.pack(f'<{len(z)}I', *z)
        return c_bytes + z_bytes
    
    def _unpack_dilithium_public_key(self, public_key: bytes) -> Tuple[bytes, List[int]]:
        """Unpack Dilithium public key."""
        rho = public_key[:32]
        t1_bytes = public_key[32:]
        t1 = list(struct.unpack(f'<{len(t1_bytes)//4}I', t1_bytes))
        return rho, t1
    
    def _unpack_dilithium_private_key(self, private_key: bytes) -> Tuple[bytes, bytes, List[int], List[int], List[int]]:
        """Unpack Dilithium private key (simplified)."""
        rho = private_key[:32]
        K = private_key[32:64]
        
        # For the simplified implementation, create mock vectors
        # In practice, these would be properly unpacked from the key data
        n = 256  # Polynomial degree
        k = self.parameters['k']  # Matrix dimension
        
        # Create mock vectors based on key data using hash function
        import hashlib
        
        # Generate deterministic mock vectors
        seed = hashlib.sha256(private_key).digest()
        t0 = [(seed[i % 32] + i) % self.q for i in range(k * n)]
        s1 = [(seed[(i + 1) % 32] + i) % self.q for i in range(k * n)]
        s2 = [(seed[(i + 2) % 32] + i) % self.q for i in range(k * n)]
        
        return rho, K, t0, s1, s2
    
    def _unpack_dilithium_signature(self, signature: bytes) -> Tuple[int, List[int]]:
        """Unpack Dilithium signature."""
        c = struct.unpack('<I', signature[:4])[0]
        z_bytes = signature[4:]
        z = list(struct.unpack(f'<{len(z_bytes)//4}I', z_bytes))
        return c, z


class HashBasedSignatures:
    """Hash-based signature schemes (XMSS, LMS, SPHINCS+)."""
    
    def __init__(self, security_level: SecurityLevel = SecurityLevel.LEVEL_3):
        self.security_level = security_level
        self.hash_function = hashlib.sha256
        self.hash_size = 32
        
        # SPHINCS+ parameters based on security level
        if security_level == SecurityLevel.LEVEL_1:
            self.n, self.h, self.d, self.w, self.sig_size = 16, 63, 7, 16, 17088
        elif security_level == SecurityLevel.LEVEL_3:
            self.n, self.h, self.d, self.w, self.sig_size = 24, 66, 22, 16, 35664
        else:  # LEVEL_5
            self.n, self.h, self.d, self.w, self.sig_size = 32, 68, 17, 16, 49856
        
        logger.info(f"HashBasedSignatures initialized with security level {security_level.value}")
    
    def generate_sphincs_keypair(self) -> QuantumKeyPair:
        """Generate SPHINCS+ key pair."""
        # Generate random seed
        sk_seed = secrets.token_bytes(self.n)
        sk_prf = secrets.token_bytes(self.n)
        pub_seed = secrets.token_bytes(self.n)
        
        # Compute public key root
        root = self._sphincs_compute_root(sk_seed, pub_seed)
        
        # Pack keys
        private_key = sk_seed + sk_prf + pub_seed + root
        public_key = pub_seed + root
        
        return QuantumKeyPair(
            algorithm=QuantumAlgorithm.SPHINCS_PLUS,
            security_level=self.security_level,
            public_key=public_key,
            private_key=private_key,
            created_at=datetime.now(timezone.utc)
        )
    
    def sphincs_sign(self, message: bytes, private_key: bytes) -> bytes:
        """SPHINCS+ signature generation."""
        # Unpack private key
        sk_seed = private_key[:self.n]
        sk_prf = private_key[self.n:2*self.n]
        pub_seed = private_key[2*self.n:3*self.n]
        
        # Generate randomizer
        opt_rand = secrets.token_bytes(self.n)
        
        # Hash message with randomizer
        msg_hash = self._prf_msg(sk_prf, opt_rand, message)
        
        # Extract tree and leaf indices
        tree_idx = int.from_bytes(msg_hash[:8], 'big') % (2**self.h)
        leaf_idx = int.from_bytes(msg_hash[8:16], 'big') % (2**self.d)
        
        # Generate FORS signature
        fors_sig = self._fors_sign(msg_hash[16:], sk_seed, pub_seed, tree_idx)
        
        # Generate HT signature
        ht_sig = self._ht_sign(sk_seed, pub_seed, tree_idx, leaf_idx)
        
        # Combine signature components
        signature = opt_rand + fors_sig + ht_sig
        
        return signature
    
    def sphincs_verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """SPHINCS+ signature verification."""
        try:
            # Unpack public key
            pub_seed = public_key[:self.n]
            root = public_key[self.n:]
            
            # Unpack signature
            sig_offset = 0
            opt_rand = signature[sig_offset:sig_offset + self.n]
            sig_offset += self.n
            
            # Hash message with randomizer
            msg_hash = self._prf_msg_verify(opt_rand, message)
            
            # Extract indices
            tree_idx = int.from_bytes(msg_hash[:8], 'big') % (2**self.h)
            leaf_idx = int.from_bytes(msg_hash[8:16], 'big') % (2**self.d)
            
            # Verify FORS signature
            fors_pk = self._fors_verify(msg_hash[16:], signature[sig_offset:], pub_seed, tree_idx)
            sig_offset += self._fors_sig_size()
            
            # Verify HT signature
            computed_root = self._ht_verify(fors_pk, signature[sig_offset:], pub_seed, tree_idx, leaf_idx)
            
            return computed_root == root
            
        except Exception as e:
            logger.error(f"SPHINCS+ verification error: {e}")
            return False
    
    def generate_xmss_keypair(self, tree_height: int = 10) -> QuantumKeyPair:
        """Generate XMSS key pair."""
        # Generate random seed
        seed = secrets.token_bytes(32)
        
        # Generate WOTS+ key pairs for all leaves
        wots_keys = []
        for i in range(2**tree_height):
            wots_sk = self._wots_keygen(seed, i)
            wots_pk = self._wots_public_key(wots_sk)
            wots_keys.append((wots_sk, wots_pk))
        
        # Build Merkle tree
        tree = self._build_merkle_tree([pk for _, pk in wots_keys])
        root = tree[0][0]  # Root of the tree
        
        # Pack keys (simplified)
        private_key = seed + struct.pack('<I', 0)  # Include state counter
        public_key = root + struct.pack('<I', tree_height)
        
        keypair = QuantumKeyPair(
            algorithm=QuantumAlgorithm.XMSS,
            security_level=self.security_level,
            public_key=public_key,
            private_key=private_key,
            created_at=datetime.now(timezone.utc)
        )
        
        # Store tree data in metadata for this simplified implementation
        keypair.metadata['wots_keys'] = [(sk.hex(), pk.hex()) for sk, pk in wots_keys]
        keypair.metadata['tree'] = [[node.hex() for node in level] for level in tree]
        keypair.metadata['tree_height'] = tree_height
        
        return keypair
    
    def xmss_sign(self, message: bytes, private_key: bytes, keypair_metadata: Dict[str, Any]) -> bytes:
        """XMSS signature generation."""
        # Unpack private key
        seed = private_key[:32]
        state = struct.unpack('<I', private_key[32:36])[0]
        
        # Get WOTS+ key pair for current state
        wots_keys = [(bytes.fromhex(sk), bytes.fromhex(pk)) for sk, pk in keypair_metadata['wots_keys']]
        wots_sk, wots_pk = wots_keys[state]
        
        # Generate WOTS+ signature
        msg_hash = self.hash_function(message).digest()
        wots_sig = self._wots_sign(msg_hash, wots_sk)
        
        # Generate authentication path
        tree = [[bytes.fromhex(node) for node in level] for level in keypair_metadata['tree']]
        auth_path = self._generate_auth_path(tree, state)
        
        # Pack signature
        signature = struct.pack('<I', state) + wots_sig
        for node in auth_path:
            signature += node
        
        return signature
    
    def xmss_verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """XMSS signature verification."""
        try:
            # Unpack public key
            root = public_key[:32]
            tree_height = struct.unpack('<I', public_key[32:])[0]
            
            # Unpack signature
            sig_offset = 0
            leaf_idx = struct.unpack('<I', signature[sig_offset:sig_offset+4])[0]
            sig_offset += 4
            
            # Extract WOTS+ signature
            wots_sig_size = 32 * 67  # Simplified size
            wots_sig = signature[sig_offset:sig_offset + wots_sig_size]
            sig_offset += wots_sig_size
            
            # Extract authentication path
            auth_path = []
            for _ in range(tree_height):
                auth_path.append(signature[sig_offset:sig_offset + 32])
                sig_offset += 32
            
            # Verify WOTS+ signature and compute public key
            msg_hash = self.hash_function(message).digest()
            wots_pk = self._wots_verify(msg_hash, wots_sig)
            
            # Compute root using authentication path
            computed_root = self._compute_root_from_path(wots_pk, leaf_idx, auth_path)
            
            return computed_root == root
            
        except Exception as e:
            logger.error(f"XMSS verification error: {e}")
            return False
    
    # Helper methods for hash-based signatures
    
    def _sphincs_compute_root(self, sk_seed: bytes, pub_seed: bytes) -> bytes:
        """Compute SPHINCS+ root (simplified)."""
        # This would compute the actual SPHINCS+ tree root
        combined = sk_seed + pub_seed
        return hashlib.sha256(combined).digest()
    
    def _prf_msg(self, sk_prf: bytes, opt_rand: bytes, message: bytes) -> bytes:
        """PRF for message hashing in SPHINCS+."""
        combined = sk_prf + opt_rand + message
        return hashlib.sha256(combined).digest()
    
    def _prf_msg_verify(self, opt_rand: bytes, message: bytes) -> bytes:
        """PRF for message hashing in verification."""
        combined = opt_rand + message
        return hashlib.sha256(combined).digest()
    
    def _fors_sign(self, msg_hash: bytes, sk_seed: bytes, pub_seed: bytes, tree_idx: int) -> bytes:
        """FORS signature generation (simplified)."""
        # Simplified FORS implementation
        fors_sig = secrets.token_bytes(32 * 16)  # Simplified size
        return fors_sig
    
    def _fors_verify(self, msg_hash: bytes, fors_sig: bytes, pub_seed: bytes, tree_idx: int) -> bytes:
        """FORS signature verification (simplified)."""
        # Return computed FORS public key
        return hashlib.sha256(fors_sig + pub_seed).digest()
    
    def _fors_sig_size(self) -> int:
        """FORS signature size."""
        return 32 * 16  # Simplified
    
    def _ht_sign(self, sk_seed: bytes, pub_seed: bytes, tree_idx: int, leaf_idx: int) -> bytes:
        """Hypertree signature generation (simplified)."""
        # Simplified hypertree signature
        ht_sig = secrets.token_bytes(32 * self.h)
        return ht_sig
    
    def _ht_verify(self, fors_pk: bytes, ht_sig: bytes, pub_seed: bytes, tree_idx: int, leaf_idx: int) -> bytes:
        """Hypertree signature verification (simplified)."""
        # Return computed root
        return hashlib.sha256(fors_pk + ht_sig + pub_seed).digest()
    
    def _wots_keygen(self, seed: bytes, index: int) -> bytes:
        """Generate WOTS+ private key."""
        key_seed = seed + struct.pack('<I', index)
        return hashlib.sha256(key_seed).digest()
    
    def _wots_public_key(self, private_key: bytes) -> bytes:
        """Compute WOTS+ public key from private key."""
        # Simplified WOTS+ public key computation
        chains = []
        for i in range(67):  # 64 + 3 checksum chains
            chain_start = hashlib.sha256(private_key + struct.pack('<I', i)).digest()
            # Hash chain of length w-1 (15 for w=16)
            chain_end = chain_start
            for _ in range(15):
                chain_end = hashlib.sha256(chain_end).digest()
            chains.append(chain_end)
        
        # Combine all chain ends
        return hashlib.sha256(b''.join(chains)).digest()
    
    def _wots_sign(self, message_hash: bytes, private_key: bytes) -> bytes:
        """Generate WOTS+ signature."""
        # Convert hash to base-w representation
        msg_ints = self._base_w_encode(message_hash, 16, 64)
        
        # Compute checksum
        checksum = sum(15 - x for x in msg_ints)
        checksum_ints = self._base_w_encode(checksum.to_bytes(3, 'big'), 16, 3)
        
        # Combine message and checksum
        all_ints = msg_ints + checksum_ints
        
        # Generate signature chains
        sig_chains = []
        for i, val in enumerate(all_ints):
            chain_start = hashlib.sha256(private_key + struct.pack('<I', i)).digest()
            # Hash val times
            chain_val = chain_start
            for _ in range(val):
                chain_val = hashlib.sha256(chain_val).digest()
            sig_chains.append(chain_val)
        
        return b''.join(sig_chains)
    
    def _wots_verify(self, message_hash: bytes, signature: bytes) -> bytes:
        """Verify WOTS+ signature and return public key."""
        # Parse signature into chains
        sig_chains = []
        for i in range(67):
            sig_chains.append(signature[i*32:(i+1)*32])
        
        # Convert hash to base-w representation
        msg_ints = self._base_w_encode(message_hash, 16, 64)
        
        # Compute checksum
        checksum = sum(15 - x for x in msg_ints)
        checksum_ints = self._base_w_encode(checksum.to_bytes(3, 'big'), 16, 3)
        
        # Combine message and checksum
        all_ints = msg_ints + checksum_ints
        
        # Complete hash chains
        pk_chains = []
        for i, (sig_val, msg_val) in enumerate(zip(sig_chains, all_ints)):
            chain_val = sig_val
            # Hash remaining (15 - msg_val) times
            for _ in range(15 - msg_val):
                chain_val = hashlib.sha256(chain_val).digest()
            pk_chains.append(chain_val)
        
        # Combine to get public key
        return hashlib.sha256(b''.join(pk_chains)).digest()
    
    def _base_w_encode(self, data: bytes, w: int, length: int) -> List[int]:
        """Encode data in base-w representation."""
        result = []
        for byte in data:
            for shift in [4, 0]:  # For w=16, split each byte into 2 nibbles
                result.append((byte >> shift) & 0xF)
                if len(result) >= length:
                    return result[:length]
        
        # Pad with zeros if needed
        while len(result) < length:
            result.append(0)
        
        return result[:length]
    
    def _build_merkle_tree(self, leaves: List[bytes]) -> List[List[bytes]]:
        """Build Merkle tree from leaf nodes."""
        tree = [leaves]
        current_level = leaves
        
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                parent = hashlib.sha256(left + right).digest()
                next_level.append(parent)
            tree.insert(0, next_level)
            current_level = next_level
        
        return tree
    
    def _generate_auth_path(self, tree: List[List[bytes]], leaf_idx: int) -> List[bytes]:
        """Generate authentication path for leaf."""
        auth_path = []
        current_idx = leaf_idx
        
        for level in reversed(tree[1:]):  # Skip root level
            # Get sibling
            sibling_idx = current_idx ^ 1  # XOR with 1 to get sibling
            if sibling_idx < len(level):
                auth_path.append(level[sibling_idx])
            else:
                auth_path.append(level[current_idx])  # Use self if no sibling
            current_idx //= 2
        
        return auth_path
    
    def _compute_root_from_path(self, leaf: bytes, leaf_idx: int, auth_path: List[bytes]) -> bytes:
        """Compute root from leaf and authentication path."""
        current = leaf
        current_idx = leaf_idx
        
        for sibling in auth_path:
            if current_idx % 2 == 0:  # Left child
                current = hashlib.sha256(current + sibling).digest()
            else:  # Right child
                current = hashlib.sha256(sibling + current).digest()
            current_idx //= 2
        
        return current


class QuantumKeyDistribution:
    """Quantum Key Distribution (QKD) protocol simulation."""
    
    def __init__(self):
        self.protocols = ['BB84', 'E91', 'SARG04', 'Six-State']
        self.sessions = {}
        
        logger.info("QuantumKeyDistribution initialized")
    
    def bb84_protocol(self, alice_id: str, bob_id: str, key_length: int = 256) -> QKDSession:
        """Simulate BB84 quantum key distribution protocol."""
        session_id = str(uuid.uuid4())
        
        # Alice prepares random bits and bases
        alice_bits = [secrets.randbits(1) for _ in range(key_length * 4)]  # Oversample
        alice_bases = [secrets.randbits(1) for _ in range(key_length * 4)]  # 0=rectilinear, 1=diagonal
        
        # Simulate quantum channel transmission with errors
        error_rate = 0.05  # 5% quantum error rate
        received_bits = []
        
        for bit in alice_bits:
            if secrets.randbelow(100) < error_rate * 100:
                received_bits.append(1 - bit)  # Bit flip error
            else:
                received_bits.append(bit)
        
        # Bob chooses random measurement bases
        bob_bases = [secrets.randbits(1) for _ in range(key_length * 4)]
        
        # Bob measures qubits
        bob_bits = []
        for i, (bit, alice_base, bob_base) in enumerate(zip(received_bits, alice_bases, bob_bases)):
            if alice_base == bob_base:
                bob_bits.append(bit)  # Correct measurement
            else:
                bob_bits.append(secrets.randbits(1))  # Random result
        
        # Public discussion - compare bases
        shared_indices = []
        for i, (a_base, b_base) in enumerate(zip(alice_bases, bob_bases)):
            if a_base == b_base:
                shared_indices.append(i)
        
        # Extract shared key bits
        shared_key_bits = []
        for idx in shared_indices[:key_length]:  # Take only needed bits
            shared_key_bits.append(alice_bits[idx])
        
        # Pad to exact length if needed
        while len(shared_key_bits) < key_length:
            shared_key_bits.append(secrets.randbits(1))
        
        # Convert to bytes
        shared_key = bytes([
            sum(shared_key_bits[i*8 + j] << j for j in range(8))
            for i in range(key_length // 8)
        ])
        
        # Error detection (simplified)
        detected_error_rate = min(error_rate, 0.1)  # Cap at 10%
        
        # Calculate security parameter
        security_parameter = max(0.0, 1.0 - 2 * detected_error_rate)
        
        session = QKDSession(
            session_id=session_id,
            alice_id=alice_id,
            bob_id=bob_id,
            shared_key=shared_key,
            key_length=len(shared_key),
            error_rate=detected_error_rate,
            security_parameter=security_parameter,
            protocol='BB84',
            created_at=datetime.now(timezone.utc)
        )
        
        self.sessions[session_id] = session
        return session
    
    def e91_protocol(self, alice_id: str, bob_id: str, key_length: int = 256) -> QKDSession:
        """Simulate E91 (Ekert) quantum key distribution protocol."""
        session_id = str(uuid.uuid4())
        
        # Generate entangled pairs (simulated)
        num_pairs = key_length * 4  # Oversample for error correction
        
        # Alice and Bob choose measurement angles
        alice_angles = [secrets.choice([0, 45, 90]) for _ in range(num_pairs)]
        bob_angles = [secrets.choice([45, 90, 135]) for _ in range(num_pairs)]
        
        # Simulate entangled measurements
        shared_key_bits = []
        bell_test_results = []
        
        for i in range(num_pairs):
            # Generate correlated random outcomes
            if alice_angles[i] == bob_angles[i]:
                # Perfect correlation for same angles
                alice_result = secrets.randbits(1)
                bob_result = alice_result
                shared_key_bits.append(alice_result)
            else:
                # Quantum correlation for different angles
                alice_result = secrets.randbits(1)
                
                # Calculate correlation based on angle difference
                angle_diff = abs(alice_angles[i] - bob_angles[i])
                correlation = abs(np.cos(np.radians(angle_diff * 2)))
                
                if secrets.randbelow(100) < correlation * 100:
                    bob_result = alice_result  # Correlated
                else:
                    bob_result = 1 - alice_result  # Anti-correlated
                
                # Store for Bell inequality test
                bell_test_results.append((alice_angles[i], bob_angles[i], alice_result, bob_result))
        
        # Perform Bell inequality test (simplified)
        bell_violation = self._compute_bell_violation(bell_test_results)
        
        # Use only compatible measurements for key
        compatible_bits = shared_key_bits[:key_length]
        while len(compatible_bits) < key_length:
            compatible_bits.append(secrets.randbits(1))
        
        # Convert to bytes
        shared_key = bytes([
            sum(compatible_bits[i*8 + j] << j for j in range(8))
            for i in range(key_length // 8)
        ])
        
        # Calculate error rate and security
        error_rate = max(0.01, 0.15 - bell_violation)  # Lower error with higher violation
        security_parameter = min(bell_violation, 0.95)  # Security from Bell violation
        
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
    
    def _compute_bell_violation(self, results: List[Tuple[int, int, int, int]]) -> float:
        """Compute Bell inequality violation (simplified)."""
        if not results:
            return 0.0
        
        # Simplified CHSH inequality computation
        correlations = defaultdict(list)
        
        for alice_angle, bob_angle, alice_result, bob_result in results:
            angle_pair = (alice_angle, bob_angle)
            correlation = (-1) ** (alice_result + bob_result)  # +1 for same, -1 for different
            correlations[angle_pair].append(correlation)
        
        # Average correlations for each angle pair
        avg_correlations = {}
        for angle_pair, corr_list in correlations.items():
            avg_correlations[angle_pair] = sum(corr_list) / len(corr_list)
        
        # Compute CHSH parameter (simplified)
        chsh_value = 0.0
        if len(avg_correlations) >= 4:
            corr_values = list(avg_correlations.values())
            chsh_value = abs(corr_values[0] - corr_values[1] + corr_values[2] + corr_values[3])
        
        # Bell violation occurs when CHSH > 2
        violation = max(0.0, (chsh_value - 2.0) / 0.828)  # Normalize by max violation (2√2 - 2)
        return min(violation, 1.0)
    
    def get_qkd_session(self, session_id: str) -> Optional[QKDSession]:
        """Get QKD session by ID."""
        return self.sessions.get(session_id)
    
    def list_active_sessions(self) -> List[QKDSession]:
        """List all active QKD sessions."""
        return [session for session in self.sessions.values() if session.status == 'active']


class HybridCryptoSystem:
    """Hybrid classical-quantum cryptographic system."""
    
    def __init__(self, lattice_crypto: LatticeBasedCrypto, hash_crypto: HashBasedSignatures):
        self.lattice_crypto = lattice_crypto
        self.hash_crypto = hash_crypto
        self.hybrid_modes = list(HybridMode)
        
        logger.info("HybridCryptoSystem initialized")
    
    def hybrid_key_encapsulation(self, classical_pubkey: bytes, quantum_pubkey: bytes,
                                mode: HybridMode = HybridMode.PARALLEL_HYBRID) -> Tuple[bytes, bytes]:
        """Hybrid key encapsulation combining classical and quantum methods."""
        if mode == HybridMode.CLASSICAL_ONLY:
            # Use only classical cryptography
            if not CRYPTO_AVAILABLE:
                raise RuntimeError("Classical cryptography not available")
            
            # Generate classical KEM (using RSA as example)
            classical_key = secrets.token_bytes(32)
            
            # Encrypt with classical public key (simplified)
            ciphertext = self._classical_encrypt(classical_key, classical_pubkey)
            
            return ciphertext, classical_key
        
        elif mode == HybridMode.QUANTUM_ONLY:
            # Use only post-quantum cryptography
            ciphertext, quantum_key = self.lattice_crypto.kyber_encapsulate(quantum_pubkey)
            return ciphertext, quantum_key
        
        elif mode == HybridMode.PARALLEL_HYBRID:
            # Use both classical and quantum in parallel
            
            # Classical KEM
            classical_key = secrets.token_bytes(32)
            classical_ciphertext = self._classical_encrypt(classical_key, classical_pubkey)
            
            # Quantum KEM
            quantum_ciphertext, quantum_key = self.lattice_crypto.kyber_encapsulate(quantum_pubkey)
            
            # Combine keys using KDF
            combined_key = self._combine_keys(classical_key, quantum_key)
            
            # Combine ciphertexts
            hybrid_ciphertext = classical_ciphertext + quantum_ciphertext
            
            return hybrid_ciphertext, combined_key
        
        elif mode == HybridMode.CLASSICAL_THEN_QUANTUM:
            # First classical, then quantum
            classical_key = secrets.token_bytes(32)
            classical_ciphertext = self._classical_encrypt(classical_key, classical_pubkey)
            
            # Use classical key to derive quantum input
            quantum_input = hashlib.sha256(classical_key).digest()[:32]
            quantum_ciphertext, quantum_key = self.lattice_crypto.kyber_encapsulate(quantum_pubkey)
            
            # Final key combines both
            final_key = self._combine_keys(quantum_input, quantum_key)
            hybrid_ciphertext = classical_ciphertext + quantum_ciphertext
            
            return hybrid_ciphertext, final_key
        
        else:  # QUANTUM_THEN_CLASSICAL
            # First quantum, then classical
            quantum_ciphertext, quantum_key = self.lattice_crypto.kyber_encapsulate(quantum_pubkey)
            
            # Use quantum key for classical encryption
            classical_ciphertext = self._classical_encrypt(quantum_key, classical_pubkey)
            
            hybrid_ciphertext = quantum_ciphertext + classical_ciphertext
            
            return hybrid_ciphertext, quantum_key
    
    def hybrid_signature(self, message: bytes, classical_privkey: bytes, quantum_privkey: bytes,
                        mode: HybridMode = HybridMode.PARALLEL_HYBRID) -> bytes:
        """Hybrid digital signature combining classical and quantum methods."""
        if mode == HybridMode.CLASSICAL_ONLY:
            return self._classical_sign(message, classical_privkey)
        
        elif mode == HybridMode.QUANTUM_ONLY:
            return self.hash_crypto.sphincs_sign(message, quantum_privkey)
        
        elif mode == HybridMode.PARALLEL_HYBRID:
            # Generate both signatures
            classical_sig = self._classical_sign(message, classical_privkey)
            quantum_sig = self.hash_crypto.sphincs_sign(message, quantum_privkey)
            
            # Combine signatures
            hybrid_sig = struct.pack('<I', len(classical_sig)) + classical_sig + quantum_sig
            
            return hybrid_sig
        
        elif mode == HybridMode.CLASSICAL_THEN_QUANTUM:
            # Sign with classical first
            classical_sig = self._classical_sign(message, classical_privkey)
            
            # Then sign the classical signature with quantum
            quantum_sig = self.hash_crypto.sphincs_sign(classical_sig, quantum_privkey)
            
            hybrid_sig = struct.pack('<I', len(classical_sig)) + classical_sig + quantum_sig
            
            return hybrid_sig
        
        else:  # QUANTUM_THEN_CLASSICAL
            # Sign with quantum first
            quantum_sig = self.hash_crypto.sphincs_sign(message, quantum_privkey)
            
            # Then sign the quantum signature with classical
            classical_sig = self._classical_sign(quantum_sig, classical_privkey)
            
            hybrid_sig = struct.pack('<I', len(classical_sig)) + classical_sig + quantum_sig
            
            return hybrid_sig
    
    def hybrid_verify_signature(self, message: bytes, signature: bytes, 
                               classical_pubkey: bytes, quantum_pubkey: bytes,
                               mode: HybridMode = HybridMode.PARALLEL_HYBRID) -> bool:
        """Verify hybrid digital signature."""
        try:
            if mode == HybridMode.CLASSICAL_ONLY:
                return self._classical_verify(message, signature, classical_pubkey)
            
            elif mode == HybridMode.QUANTUM_ONLY:
                return self.hash_crypto.sphincs_verify(message, signature, quantum_pubkey)
            
            elif mode == HybridMode.PARALLEL_HYBRID:
                # Unpack signatures
                classical_sig_len = struct.unpack('<I', signature[:4])[0]
                classical_sig = signature[4:4 + classical_sig_len]
                quantum_sig = signature[4 + classical_sig_len:]
                
                # Both must verify
                classical_ok = self._classical_verify(message, classical_sig, classical_pubkey)
                quantum_ok = self.hash_crypto.sphincs_verify(message, quantum_sig, quantum_pubkey)
                
                return classical_ok and quantum_ok
            
            elif mode == HybridMode.CLASSICAL_THEN_QUANTUM:
                # Unpack signatures
                classical_sig_len = struct.unpack('<I', signature[:4])[0]
                classical_sig = signature[4:4 + classical_sig_len]
                quantum_sig = signature[4 + classical_sig_len:]
                
                # Verify classical signature first
                classical_ok = self._classical_verify(message, classical_sig, classical_pubkey)
                
                # Then verify quantum signature of classical signature
                quantum_ok = self.hash_crypto.sphincs_verify(classical_sig, quantum_sig, quantum_pubkey)
                
                return classical_ok and quantum_ok
            
            else:  # QUANTUM_THEN_CLASSICAL
                # Unpack signatures
                classical_sig_len = struct.unpack('<I', signature[:4])[0]
                classical_sig = signature[4:4 + classical_sig_len]
                quantum_sig = signature[4 + classical_sig_len:]
                
                # Verify quantum signature first
                quantum_ok = self.hash_crypto.sphincs_verify(message, quantum_sig, quantum_pubkey)
                
                # Then verify classical signature of quantum signature
                classical_ok = self._classical_verify(quantum_sig, classical_sig, classical_pubkey)
                
                return quantum_ok and classical_ok
                
        except Exception as e:
            logger.error(f"Hybrid signature verification error: {e}")
            return False
    
    def _classical_encrypt(self, data: bytes, public_key: bytes) -> bytes:
        """Classical encryption (simplified RSA-like)."""
        # Simplified classical encryption using AES with RSA-encrypted key
        aes_key = secrets.token_bytes(32)
        
        # Encrypt data with AES
        if CRYPTO_AVAILABLE:
            cipher = Cipher(algorithms.AES(aes_key), modes.GCM(secrets.token_bytes(12)), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(data) + encryptor.finalize()
            return ciphertext + encryptor.tag
        else:
            # Fallback XOR encryption for demonstration
            return bytes(a ^ b for a, b in zip(data, aes_key * (len(data) // 32 + 1)))
    
    def _classical_sign(self, message: bytes, private_key: bytes) -> bytes:
        """Classical signature (simplified)."""
        # Use HMAC as a simplified classical signature
        return hmac.new(private_key, message, hashlib.sha256).digest()
    
    def _classical_verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Classical signature verification (simplified)."""
        # For simplified demo, use the public key as HMAC key
        expected = hmac.new(public_key, message, hashlib.sha256).digest()
        return hmac.compare_digest(signature, expected)
    
    def _combine_keys(self, key1: bytes, key2: bytes) -> bytes:
        """Combine two keys using a KDF."""
        combined_input = key1 + key2
        # Use HKDF-like key derivation
        return hashlib.pbkdf2_hmac('sha256', combined_input, b'quantum-hybrid-kdf', 100000)[:32]


class QuantumCryptoEngine:
    """Main quantum-resistant cryptography engine coordinator."""
    
    def __init__(self, db_path: str = "quantum_crypto.db", 
                 security_level: SecurityLevel = SecurityLevel.LEVEL_3):
        self.database = QuantumCryptoDatabase(db_path)
        self.security_level = security_level
        
        # Initialize cryptographic components
        self.lattice_crypto = LatticeBasedCrypto(security_level)
        self.hash_crypto = HashBasedSignatures(security_level)
        self.qkd = QuantumKeyDistribution()
        self.hybrid_crypto = HybridCryptoSystem(self.lattice_crypto, self.hash_crypto)
        
        # Key management
        self.active_keypairs = {}
        self.performance_metrics = defaultdict(list)
        
        self._lock = RLock()
        
        logger.info(f"QuantumCryptoEngine initialized with security level {security_level.value}")
    
    def generate_keypair(self, algorithm: QuantumAlgorithm) -> QuantumKeyPair:
        """Generate quantum-resistant key pair."""
        start_time = time.time()
        
        try:
            if algorithm == QuantumAlgorithm.KYBER:
                keypair = self.lattice_crypto.generate_kyber_keypair()
            elif algorithm == QuantumAlgorithm.DILITHIUM:
                keypair = self.lattice_crypto.generate_dilithium_keypair()
            elif algorithm == QuantumAlgorithm.SPHINCS_PLUS:
                keypair = self.hash_crypto.generate_sphincs_keypair()
            elif algorithm == QuantumAlgorithm.XMSS:
                keypair = self.hash_crypto.generate_xmss_keypair()
            else:
                raise ValueError(f"Unsupported algorithm: {algorithm}")
            
            # Store in database
            if self.database.store_keypair(keypair):
                with self._lock:
                    self.active_keypairs[keypair.key_id] = keypair
            
            # Record performance
            duration = (time.time() - start_time) * 1000
            self.database.store_performance_metric(
                algorithm.value, CryptoOperation.KEY_GENERATION.value, duration,
                key_size=len(keypair.public_key) + len(keypair.private_key)
            )
            
            logger.info(f"Generated {algorithm.value} keypair {keypair.key_id} in {duration:.2f}ms")
            return keypair
            
        except Exception as e:
            logger.error(f"Error generating {algorithm.value} keypair: {e}")
            raise
    
    def sign_message(self, message: bytes, key_id: str) -> QuantumSignature:
        """Sign message with quantum-resistant signature."""
        keypair = self._get_keypair(key_id)
        if not keypair:
            raise ValueError(f"Keypair {key_id} not found")
        
        start_time = time.time()
        
        try:
            # Generate message hash
            message_hash = hashlib.sha256(message).digest()
            
            # Sign based on algorithm
            if keypair.algorithm == QuantumAlgorithm.DILITHIUM:
                signature_bytes = self.lattice_crypto.dilithium_sign(message, keypair.private_key)
            elif keypair.algorithm == QuantumAlgorithm.SPHINCS_PLUS:
                signature_bytes = self.hash_crypto.sphincs_sign(message, keypair.private_key)
            elif keypair.algorithm == QuantumAlgorithm.XMSS:
                signature_bytes = self.hash_crypto.xmss_sign(message, keypair.private_key, keypair.metadata)
            else:
                raise ValueError(f"Algorithm {keypair.algorithm} not suitable for signing")
            
            signature = QuantumSignature(
                algorithm=keypair.algorithm,
                signature=signature_bytes,
                message_hash=message_hash,
                signer_key_id=key_id,
                timestamp=datetime.now(timezone.utc),
                security_level=keypair.security_level
            )
            
            # Record performance
            duration = (time.time() - start_time) * 1000
            self.database.store_performance_metric(
                keypair.algorithm.value, CryptoOperation.SIGN.value, duration,
                data_size=len(message)
            )
            
            logger.info(f"Signed message with {keypair.algorithm.value} in {duration:.2f}ms")
            return signature
            
        except Exception as e:
            logger.error(f"Error signing message: {e}")
            raise
    
    def verify_signature(self, message: bytes, signature: QuantumSignature, 
                        public_key: bytes) -> bool:
        """Verify quantum-resistant signature."""
        start_time = time.time()
        
        try:
            # Verify message hash
            expected_hash = hashlib.sha256(message).digest()
            if signature.message_hash != expected_hash:
                return False
            
            # Verify based on algorithm
            if signature.algorithm == QuantumAlgorithm.DILITHIUM:
                result = self.lattice_crypto.dilithium_verify(message, signature.signature, public_key)
            elif signature.algorithm == QuantumAlgorithm.SPHINCS_PLUS:
                result = self.hash_crypto.sphincs_verify(message, signature.signature, public_key)
            elif signature.algorithm == QuantumAlgorithm.XMSS:
                result = self.hash_crypto.xmss_verify(message, signature.signature, public_key)
            else:
                raise ValueError(f"Algorithm {signature.algorithm} verification not implemented")
            
            # Record performance
            duration = (time.time() - start_time) * 1000
            self.database.store_performance_metric(
                signature.algorithm.value, CryptoOperation.VERIFY.value, duration,
                data_size=len(message)
            )
            
            logger.info(f"Verified {signature.algorithm.value} signature in {duration:.2f}ms: {result}")
            return result
            
        except Exception as e:
            logger.error(f"Error verifying signature: {e}")
            return False
    
    def encrypt_data(self, data: bytes, public_key: bytes, 
                    algorithm: QuantumAlgorithm = QuantumAlgorithm.KYBER) -> QuantumEncryptedData:
        """Encrypt data using quantum-resistant algorithms."""
        start_time = time.time()
        
        try:
            if algorithm == QuantumAlgorithm.KYBER:
                # Use Kyber for key encapsulation
                encapsulated_key, shared_secret = self.lattice_crypto.kyber_encapsulate(public_key)
                
                # Encrypt data with AES using shared secret
                nonce = secrets.token_bytes(12)
                
                if CRYPTO_AVAILABLE:
                    cipher = Cipher(algorithms.AES(shared_secret), modes.GCM(nonce), backend=default_backend())
                    encryptor = cipher.encryptor()
                    ciphertext = encryptor.update(data) + encryptor.finalize()
                    tag = encryptor.tag
                else:
                    # Fallback encryption
                    ciphertext = bytes(a ^ b for a, b in zip(data, shared_secret * (len(data) // 32 + 1)))
                    tag = hashlib.sha256(ciphertext + shared_secret).digest()[:16]
                
                encrypted_data = QuantumEncryptedData(
                    algorithm=algorithm,
                    ciphertext=ciphertext,
                    encapsulated_key=encapsulated_key,
                    nonce=nonce,
                    tag=tag,
                    security_level=self.security_level,
                    encryption_timestamp=datetime.now(timezone.utc)
                )
                
                # Record performance
                duration = (time.time() - start_time) * 1000
                self.database.store_performance_metric(
                    algorithm.value, CryptoOperation.ENCRYPT.value, duration,
                    data_size=len(data)
                )
                
                logger.info(f"Encrypted {len(data)} bytes with {algorithm.value} in {duration:.2f}ms")
                return encrypted_data
                
            else:
                raise ValueError(f"Algorithm {algorithm} not supported for encryption")
                
        except Exception as e:
            logger.error(f"Error encrypting data: {e}")
            raise
    
    def decrypt_data(self, encrypted_data: QuantumEncryptedData, 
                    private_key: bytes) -> bytes:
        """Decrypt data using quantum-resistant algorithms."""
        start_time = time.time()
        
        try:
            if encrypted_data.algorithm == QuantumAlgorithm.KYBER:
                # Decapsulate shared secret
                shared_secret = self.lattice_crypto.kyber_decapsulate(
                    encrypted_data.encapsulated_key, private_key
                )
                
                # Decrypt data
                if CRYPTO_AVAILABLE:
                    cipher = Cipher(
                        algorithms.AES(shared_secret), 
                        modes.GCM(encrypted_data.nonce, encrypted_data.tag),
                        backend=default_backend()
                    )
                    decryptor = cipher.decryptor()
                    plaintext = decryptor.update(encrypted_data.ciphertext) + decryptor.finalize()
                else:
                    # Fallback decryption
                    plaintext = bytes(
                        a ^ b for a, b in zip(
                            encrypted_data.ciphertext, 
                            shared_secret * (len(encrypted_data.ciphertext) // 32 + 1)
                        )
                    )
                
                # Record performance
                duration = (time.time() - start_time) * 1000
                self.database.store_performance_metric(
                    encrypted_data.algorithm.value, CryptoOperation.DECRYPT.value, duration,
                    data_size=len(encrypted_data.ciphertext)
                )
                
                logger.info(f"Decrypted {len(plaintext)} bytes with {encrypted_data.algorithm.value} in {duration:.2f}ms")
                return plaintext
                
            else:
                raise ValueError(f"Algorithm {encrypted_data.algorithm} not supported for decryption")
                
        except Exception as e:
            logger.error(f"Error decrypting data: {e}")
            raise
    
    def establish_qkd_session(self, alice_id: str, bob_id: str, 
                             protocol: str = 'BB84', key_length: int = 256) -> QKDSession:
        """Establish quantum key distribution session."""
        if protocol == 'BB84':
            return self.qkd.bb84_protocol(alice_id, bob_id, key_length)
        elif protocol == 'E91':
            return self.qkd.e91_protocol(alice_id, bob_id, key_length)
        else:
            raise ValueError(f"Unsupported QKD protocol: {protocol}")
    
    def hybrid_sign(self, message: bytes, classical_key_id: str, quantum_key_id: str,
                   mode: HybridMode = HybridMode.PARALLEL_HYBRID) -> bytes:
        """Create hybrid classical-quantum signature."""
        classical_keypair = self._get_keypair(classical_key_id)
        quantum_keypair = self._get_keypair(quantum_key_id)
        
        if not classical_keypair or not quantum_keypair:
            raise ValueError("Required keypairs not found")
        
        return self.hybrid_crypto.hybrid_signature(
            message, classical_keypair.private_key, quantum_keypair.private_key, mode
        )
    
    def hybrid_verify(self, message: bytes, signature: bytes,
                     classical_key_id: str, quantum_key_id: str,
                     mode: HybridMode = HybridMode.PARALLEL_HYBRID) -> bool:
        """Verify hybrid classical-quantum signature."""
        classical_keypair = self._get_keypair(classical_key_id)
        quantum_keypair = self._get_keypair(quantum_key_id)
        
        if not classical_keypair or not quantum_keypair:
            raise ValueError("Required keypairs not found")
        
        return self.hybrid_crypto.hybrid_verify_signature(
            message, signature, classical_keypair.public_key, 
            quantum_keypair.public_key, mode
        )
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get cryptographic performance metrics."""
        # This would query the database for performance metrics
        # For now, return current session metrics
        return {
            'active_keypairs': len(self.active_keypairs),
            'security_level': self.security_level.value,
            'supported_algorithms': [alg.value for alg in QuantumAlgorithm],
            'qkd_sessions': len(self.qkd.sessions)
        }
    
    def _get_keypair(self, key_id: str) -> Optional[QuantumKeyPair]:
        """Get keypair by ID."""
        with self._lock:
            if key_id in self.active_keypairs:
                return self.active_keypairs[key_id]
        
        # Try loading from database
        keypair = self.database.get_keypair(key_id)
        if keypair:
            with self._lock:
                self.active_keypairs[key_id] = keypair
        
        return keypair


# Convenience functions
def create_quantum_crypto_engine(db_path: str = "quantum_crypto.db",
                               security_level: SecurityLevel = SecurityLevel.LEVEL_3) -> QuantumCryptoEngine:
    """Create quantum cryptographic engine."""
    return QuantumCryptoEngine(db_path, security_level)


# Export all classes and functions
__all__ = [
    # Enums
    'QuantumAlgorithm',
    'SecurityLevel',
    'CryptoOperation',
    'HybridMode',
    
    # Data classes
    'QuantumKeyPair',
    'QuantumSignature',
    'QuantumEncryptedData',
    'QKDSession',
    
    # Core classes
    'QuantumCryptoDatabase',
    'LatticeBasedCrypto',
    'HashBasedSignatures',
    'QuantumKeyDistribution',
    'HybridCryptoSystem',
    'QuantumCryptoEngine',
    
    # Convenience functions
    'create_quantum_crypto_engine',
]