import os
import time
import json
import uuid
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from shared.security import verify_hmac_signature, create_jws

app = FastAPI(title="KMS / SoftHSM Simulator Service", version="1.0.0")

# Enable CORS for local testing dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# KMS Secret Key for HMAC request verification of S2S calls
KMS_HMAC_SECRET = "kms_internal_secret_key_98765"

# Directory to store our keys simulating an HSM boundary
KEYS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.hsm_keys"))
os.makedirs(KEYS_DIR, exist_ok=True)

# File paths for keys
MASTER_PRIV_KEY_PATH = os.path.join(KEYS_DIR, "master_priv_kek.pem")
MASTER_PUB_KEY_PATH = os.path.join(KEYS_DIR, "master_pub_kek.pem")
SIGNING_PRIV_KEY_PATH = os.path.join(KEYS_DIR, "signing_priv_key.pem")
SIGNING_PUB_KEY_PATH = os.path.join(KEYS_DIR, "signing_pub_key.pem")
ROTATION_LOG_PATH = os.path.join(KEYS_DIR, "rotation_log.json")

# --- Key Generation / Initialization ---

def generate_and_save_rsa_keypair(priv_path: str, pub_path: str):
    """Generates an RSA-2048 keypair and saves them in PEM format."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Save private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(priv_path, "wb") as f:
        f.write(private_pem)
        
    # Save public key
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicEncoding.SubjectPublicKeyInfo
    )
    with open(pub_path, "wb") as f:
        f.write(public_pem)

def initialize_keys():
    """Initializes Master Wrapping KEK and Signing Keypair if they don't exist."""
    if not os.path.exists(MASTER_PRIV_KEY_PATH):
        print("[KMS] Generating Master Key Encryption Key (KEK)...")
        generate_and_save_rsa_keypair(MASTER_PRIV_KEY_PATH, MASTER_PUB_KEY_PATH)
        
    if not os.path.exists(SIGNING_PRIV_KEY_PATH):
        print("[KMS] Generating Active JWS Receipt Signing Key...")
        generate_and_save_rsa_keypair(SIGNING_PRIV_KEY_PATH, SIGNING_PUB_KEY_PATH)

# Initialize on module import
initialize_keys()


# --- Security Middleware ---

@app.middleware("http")
async def verify_s2s_signature(request: Request, call_next):
    """
    Middleware verifying the HMAC request signature for all non-public endpoints.
    Allows GET /kms/public-key for easy sharing of the verification public key.
    """
    if request.url.path in ["/kms/public-key", "/docs", "/openapi.json", "/kms/hsm-status"]:
        return await call_next(request)
        
    # Read headers
    sig = request.headers.get("X-Signature")
    timestamp = request.headers.get("X-Timestamp")
    nonce = request.headers.get("X-Nonce")
    
    if not all([sig, timestamp, nonce]):
        return JSONResponse(
            status_code=401,
            content={"detail": "Missing security headers for S2S request"}
        )
        
    # Read body
    body = await request.body()
    body_str = body.decode("utf-8")
    
    # Verify signature
    is_valid, msg = verify_hmac_signature(
        secret_key=KMS_HMAC_SECRET,
        signature=sig,
        method=request.method,
        path=request.url.path,
        timestamp=timestamp,
        nonce=nonce,
        body=body_str
    )
    
    if not is_valid:
        return JSONResponse(
            status_code=401,
            content={"detail": f"Unauthorized S2S request: {msg}"}
        )
        
    # Restore body for endpoint handler to consume
    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}
    request._receive = receive
    
    return await call_next(request)


# --- Endpoints ---

@app.get("/kms/public-key")
async def get_public_key():
    """Returns the current public signing key to verify JWS receipts."""
    try:
        with open(SIGNING_PUB_KEY_PATH, "r") as f:
            pub_pem = f.read()
        return {"public_key": pub_pem}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read public key: {str(e)}")

@app.get("/kms/hsm-status")
async def get_hsm_status():
    """Returns status metrics of the simulated HSM partition."""
    rotations = []
    if os.path.exists(ROTATION_LOG_PATH):
        try:
            with open(ROTATION_LOG_PATH, "r") as f:
                rotations = json.load(f)
        except Exception:
            pass
            
    # Check if files exist
    hsm_ready = os.path.exists(MASTER_PRIV_KEY_PATH) and os.path.exists(SIGNING_PRIV_KEY_PATH)
    
    return {
        "status": "OPERATIONAL" if hsm_ready else "ERROR",
        "key_storage": "HSM_PARTITION_MOCK",
        "master_key_bits": 2048,
        "signing_algorithm": "RS256",
        "rotation_count": len(rotations),
        "last_rotation": rotations[-1]["timestamp"] if rotations else "NEVER",
        "keys_dir": KEYS_DIR
    }

@app.post("/kms/sign")
async def sign_receipt(payload: dict):
    """Signs a receipt payload returning a compact JWS signature."""
    try:
        with open(SIGNING_PRIV_KEY_PATH, "rb") as f:
            priv_pem = f.read()
        jws_token = create_jws(payload, priv_pem)
        return {"jws_receipt": jws_token}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"KMS signing failed: {str(e)}")

@app.post("/kms/envelope/wrap")
async def wrap_key(payload: dict):
    """
    Encrypts (wraps) a Data Encryption Key (DEK) using the KMS Master Public Key (KEK).
    Payload: {"dek_hex": "..."}
    """
    dek_hex = payload.get("dek_hex")
    if not dek_hex:
        raise HTTPException(status_code=400, detail="Missing dek_hex")
        
    try:
        # Load Master Public Key
        with open(MASTER_PUB_KEY_PATH, "rb") as f:
            pub_pem = f.read()
        pub_key = serialization.load_pem_public_key(pub_pem)
        
        # Encrypt the DEK bytes using RSA-OAEP
        dek_bytes = bytes.fromhex(dek_hex)
        wrapped_bytes = pub_key.encrypt(
            dek_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return {"wrapped_dek_hex": wrapped_bytes.hex()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"KMS key wrap failed: {str(e)}")

@app.post("/kms/envelope/unwrap")
async def unwrap_key(payload: dict):
    """
    Decrypts (unwraps) a wrapped DEK using the KMS Master Private Key (KEK).
    Payload: {"wrapped_dek_hex": "..."}
    """
    wrapped_dek_hex = payload.get("wrapped_dek_hex")
    if not wrapped_dek_hex:
        raise HTTPException(status_code=400, detail="Missing wrapped_dek_hex")
        
    try:
        # Load Master Private Key
        with open(MASTER_PRIV_KEY_PATH, "rb") as f:
            priv_pem = f.read()
        priv_key = serialization.load_pem_private_key(priv_pem, password=None)
        
        # Decrypt wrapped DEK
        wrapped_bytes = bytes.fromhex(wrapped_dek_hex)
        unwrapped_bytes = priv_key.decrypt(
            wrapped_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return {"dek_hex": unwrapped_bytes.hex()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"KMS key unwrap failed: {str(e)}")

@app.post("/kms/keys/rotate")
async def rotate_keys():
    """
    Rotates the active JWS Receipt Signing Key.
    Archives the old key by renaming it and logging the event.
    """
    try:
        timestamp_str = str(int(time.time()))
        rotation_id = str(uuid.uuid4())
        
        # Archive old keys if they exist
        if os.path.exists(SIGNING_PRIV_KEY_PATH):
            archive_priv = os.path.join(KEYS_DIR, f"signing_priv_key_{timestamp_str}.pem")
            os.rename(SIGNING_PRIV_KEY_PATH, archive_priv)
        if os.path.exists(SIGNING_PUB_KEY_PATH):
            archive_pub = os.path.join(KEYS_DIR, f"signing_pub_key_{timestamp_str}.pem")
            os.rename(SIGNING_PUB_KEY_PATH, archive_pub)
            
        # Generate new keys
        generate_and_save_rsa_keypair(SIGNING_PRIV_KEY_PATH, SIGNING_PUB_KEY_PATH)
        
        # Record rotation in log
        log_entry = {
            "rotation_id": rotation_id,
            "timestamp": timestamp_str,
            "event": "SIGNING_KEY_ROTATION",
            "archived_priv": f"signing_priv_key_{timestamp_str}.pem",
            "archived_pub": f"signing_pub_key_{timestamp_str}.pem"
        }
        
        rotations = []
        if os.path.exists(ROTATION_LOG_PATH):
            try:
                with open(ROTATION_LOG_PATH, "r") as f:
                    rotations = json.load(f)
            except Exception:
                pass
                
        rotations.append(log_entry)
        with open(ROTATION_LOG_PATH, "w") as f:
            json.dump(rotations, f, indent=2)
            
        return {
            "message": "Key rotation completed successfully",
            "rotation_id": rotation_id,
            "timestamp": timestamp_str
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"KMS key rotation failed: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8004)
