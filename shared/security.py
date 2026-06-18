import hmac
import hashlib
import time
import base64
import json
from typing import Dict, Tuple, Optional
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# In-memory store for nonces to prevent replay attacks (simple set, clean for local run)
# In production, this would be backed by Redis with TTL
_used_nonces = set()
NONCE_VALIDITY_SECONDS = 300  # 5 minutes

def generate_hmac_signature(secret_key: str, method: str, path: str, timestamp: str, nonce: str, body: str) -> str:
    """
    Generates an HMAC-SHA256 signature for a request.
    Message format: METHOD|PATH|TIMESTAMP|NONCE|BODY
    """
    message = f"{method.upper()}|{path}|{timestamp}|{nonce}|{body}"
    sig = hmac.new(
        secret_key.encode('utf-8'),
        message.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    return sig

def verify_hmac_signature(secret_key: str, signature: str, method: str, path: str, timestamp: str, nonce: str, body: str) -> Tuple[bool, str]:
    """
    Verifies the HMAC-SHA256 signature of an incoming request and checks for replay attacks.
    """
    # 1. Check timestamp freshness
    try:
        req_time = float(timestamp)
    except ValueError:
        return False, "Invalid timestamp format"
        
    current_time = time.time()
    if abs(current_time - req_time) > NONCE_VALIDITY_SECONDS:
        return False, f"Request timestamp expired (skew: {current_time - req_time:.1f}s)"

    # 2. Check for duplicate nonce
    if nonce in _used_nonces:
        return False, "Replay attack detected: Nonce already used"
    
    # Record nonce (in local lab scenario, keep simple)
    _used_nonces.add(nonce)
    # Simple cleanup to prevent unbounded memory growth
    if len(_used_nonces) > 10000:
        _used_nonces.clear()

    # 3. Verify signature matching
    expected_sig = generate_hmac_signature(secret_key, method, path, timestamp, nonce, body)
    if not hmac.compare_digest(expected_sig, signature):
        return False, "Signature mismatch"
        
    return True, "Valid signature"


# --- JWS Helper Functions (Base64url + Cryptography Asymmetric Signatures) ---

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode('utf-8').replace('=', '')

def _b64url_decode(s: str) -> bytes:
    # Add padding back if necessary
    padding_len = 4 - (len(s) % 4)
    if padding_len < 4:
        s += '=' * padding_len
    return base64.urlsafe_b64decode(s.encode('utf-8'))

def create_jws(payload: dict, private_key_pem: bytes) -> str:
    """
    Creates an RFC 7515 compliant JWS (compact serialization) signed with RSA-SHA256 (RS256).
    JWS format: UTF8(Header) || '.' || UTF8(Payload) || '.' || Signature
    """
    header = {"alg": "RS256", "typ": "JWS"}
    
    # 1. Encode header and payload
    header_b64 = _b64url_encode(json.dumps(header).encode('utf-8'))
    payload_b64 = _b64url_encode(json.dumps(payload).encode('utf-8'))
    
    signing_input = f"{header_b64}.{payload_b64}".encode('utf-8')
    
    # 2. Load private key and sign
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    signature = private_key.sign(
        signing_input,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    
    signature_b64 = _b64url_encode(signature)
    return f"{header_b64}.{payload_b64}.{signature_b64}"

def verify_jws(jws_str: str, public_key_pem: bytes) -> Tuple[bool, Optional[dict], str]:
    """
    Verifies a compact JWS signature and returns the parsed payload.
    """
    parts = jws_str.split('.')
    if len(parts) != 3:
        return False, None, "Invalid JWS structure"
        
    header_b64, payload_b64, signature_b64 = parts
    
    signing_input = f"{header_b64}.{payload_b64}".encode('utf-8')
    signature = _b64url_decode(signature_b64)
    
    try:
        # Load public key and verify signature
        public_key = serialization.load_pem_public_key(public_key_pem)
        public_key.verify(
            signature,
            signing_input,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        
        payload_bytes = _b64url_decode(payload_b64)
        payload = json.loads(payload_bytes.decode('utf-8'))
        return True, payload, "Valid signature"
    except Exception as e:
        return False, None, f"Verification failed: {str(e)}"


# --- Envelope Encryption Tools ---

def encrypt_data_aes_gcm(plaintext: str, key: bytes) -> Tuple[str, str]:
    """
    Encrypts plaintext using AES-GCM. Returns (ciphertext_hex, iv_hex).
    """
    aesgcm = AESGCM(key)
    iv = AESGCM.generate_nonce()
    ciphertext = aesgcm.encrypt(iv, plaintext.encode('utf-8'), None)
    return ciphertext.hex(), iv.hex()

def decrypt_data_aes_gcm(ciphertext_hex: str, iv_hex: str, key: bytes) -> str:
    """
    Decrypts AES-GCM encrypted ciphertext.
    """
    aesgcm = AESGCM(key)
    ciphertext = bytes.fromhex(ciphertext_hex)
    iv = bytes.fromhex(iv_hex)
    decrypted = aesgcm.decrypt(iv, ciphertext, None)
    return decrypted.decode('utf-8')
