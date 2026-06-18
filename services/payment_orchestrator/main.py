import os
import json
import time
import sqlite3
import uuid
import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from shared.security import generate_hmac_signature, encrypt_data_aes_gcm, decrypt_data_aes_gcm

app = FastAPI(title="Payment Orchestrator / Gateway", version="1.0.0")

# Enable CORS for frontend dashboard interactions
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "payments.db"))

# S2S Shared Secrets for HMAC Request Signing
ORDER_PAYMENT_SHARED_SECRET = "order_payment_gateway_hmac_secret_445566"
FRAUD_HMAC_SECRET = "fraud_internal_secret_key_12345"
KMS_HMAC_SECRET = "kms_internal_secret_key_98765"

# Internal Microservices URL config
ORDER_SERVICE_URL = "http://127.0.0.1:8001"
FRAUD_ENGINE_URL = "http://127.0.0.1:8003"
KMS_SERVICE_URL = "http://127.0.0.1:8004"

# In-memory store for client-side payment tokens (PCI Scope Reduction Simulation)
# Structure: token_id -> { encrypted_card, iv, wrapped_dek, created_at, used }
_token_vault = {}
TOKEN_TTL_SECONDS = 600  # 10 minutes

# In-memory store for pending 3DS challenges
# Structure: txn_id -> { order_id, client_ip, token_id, amount, device_fingerprint, billing_country }
_3ds_vault = {}

# --- Database Initialization ---

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id TEXT PRIMARY KEY,
            order_id TEXT NOT NULL,
            amount REAL NOT NULL,
            token TEXT NOT NULL,
            status TEXT NOT NULL,
            risk_score REAL,
            encrypted_card TEXT,
            iv TEXT,
            wrapped_dek TEXT,
            signed_receipt TEXT,
            created_at REAL NOT NULL
        )
    """)
    conn.commit()
    conn.close()

init_db()


# --- Secure S2S Request Helper ---

async def signed_s2s_request(method: str, url: str, secret_key: str, payload: dict = None) -> httpx.Response:
    """Sends an HMAC-signed request to another microservice."""
    timestamp = str(time.time())
    nonce = str(uuid.uuid4().hex)
    body_str = json.dumps(payload) if payload is not None else ""
    path = httpx.URL(url).path
    
    sig = generate_hmac_signature(secret_key, method, path, timestamp, nonce, body_str)
    
    headers = {
        "X-Signature": sig,
        "X-Timestamp": timestamp,
        "X-Nonce": nonce,
        "Content-Type": "application/json"
    }
    
    async with httpx.AsyncClient() as client:
        if method.upper() == "GET":
            return await client.get(url, headers=headers)
        elif method.upper() == "POST":
            return await client.post(url, headers=headers, content=body_str)
        else:
            raise ValueError(f"Unsupported HTTP method: {method}")


# --- Endpoints ---

@app.get("/payments/status-check")
async def get_status():
    return {
        "status": "ACTIVE",
        "vaulted_tokens": len(_token_vault),
        "database": "SQLITE",
        "db_path": DB_PATH
    }

@app.get("/payments/transactions")
async def get_transactions():
    """Returns all transaction records (used for showing the ledger dashboard)."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM transactions ORDER BY created_at DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.post("/payments/tokenize")
async def tokenize_card(payload: dict):
    """
    Client-side tokenization simulating Hosted Fields.
    Sends raw card directly to gateway endpoint to generate token, reducing merchant server PCI scope.
    Payload: {
        "card_number": str,
        "exp_month": str,
        "exp_year": str,
        "cvc": str
    }
    """
    card_number = payload.get("card_number", "")
    exp_month = payload.get("exp_month", "")
    exp_year = payload.get("exp_year", "")
    cvc = payload.get("cvc", "")
    
    if not all([card_number, exp_month, exp_year, cvc]):
        raise HTTPException(status_code=400, detail="Missing card details")
        
    try:
        # 1. Generate local AES Data Encryption Key (DEK)
        dek = os.urandom(32)
        
        # 2. Encrypt card data with DEK using AES-GCM
        card_raw = f"{card_number}|{exp_month}/{exp_year}|{cvc}"
        encrypted_card, iv = encrypt_data_aes_gcm(card_raw, dek)
        
        # 3. Call KMS (Port 8004) to wrap the DEK (Envelope Encryption)
        kms_url = f"{KMS_SERVICE_URL}/kms/envelope/wrap"
        kms_res = await signed_s2s_request("POST", kms_url, KMS_HMAC_SECRET, {"dek_hex": dek.hex()})
        
        if kms_res.status_code != 200:
            raise HTTPException(status_code=500, detail=f"KMS key wrapping failed: {kms_res.text}")
            
        wrapped_dek = kms_res.json()["wrapped_dek_hex"]
        
        # 4. Save to vault mapped to token
        token_id = f"tok_{uuid.uuid4().hex[:16]}"
        _token_vault[token_id] = {
            "encrypted_card": encrypted_card,
            "iv": iv,
            "wrapped_dek": wrapped_dek,
            "created_at": time.time(),
            "used": False
        }
        
        # Return only the token to the client
        return {"card_token": token_id}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Tokenization failed: {str(e)}")

@app.post("/payments/charge")
async def process_charge(payload: dict):
    """
    Core Payment Processing.
    Payload: {
        "order_id": str,
        "card_token": str,
        "client_ip": str,
        "device_fingerprint": str,
        "billing_country": str
    }
    """
    order_id = payload.get("order_id")
    token_id = payload.get("card_token")
    client_ip = payload.get("client_ip", "127.0.0.1")
    device = payload.get("device_fingerprint", "unknown")
    country = payload.get("billing_country", "US")
    
    if not order_id or not token_id:
        raise HTTPException(status_code=400, detail="Missing order_id or card_token")
        
    # --- SECURITY DRILL: Token Replay Attack Verification ---
    token_entry = _token_vault.get(token_id)
    if not token_entry:
        raise HTTPException(status_code=400, detail="Invalid or expired card token")
        
    if token_entry["used"]:
        raise HTTPException(
            status_code=403,
            detail="SECURITY ALERT: Token Replay Attack Detected! This single-use card token has already been processed."
        )
        
    # Mark token as used immediately to prevent race conditions
    token_entry["used"] = True

    # --- S2S ORDER VERIFICATION (Amount Tampering Defense) ---
    order_url = f"{ORDER_SERVICE_URL}/orders/{order_id}"
    order_res = await signed_s2s_request("GET", order_url, ORDER_PAYMENT_SHARED_SECRET)
    
    if order_res.status_code != 200:
        raise HTTPException(status_code=400, detail=f"Order verification failed: {order_res.text}")
        
    order_data = order_res.json()
    amount = float(order_data["amount"])
    
    if order_data["status"] != "PENDING":
        raise HTTPException(status_code=400, detail=f"Order is already in status: {order_data['status']}")

    # --- S2S FRAUD DETECTION ASSESSMENT ---
    fraud_url = f"{FRAUD_ENGINE_URL}/fraud/evaluate"
    fraud_payload = {
        "amount": amount,
        "card_token": token_id,
        "client_ip": client_ip,
        "device_fingerprint": device,
        "billing_country": country
    }
    fraud_res = await signed_s2s_request("POST", fraud_url, FRAUD_HMAC_SECRET, fraud_payload)
    
    if fraud_res.status_code != 200:
        raise HTTPException(status_code=500, detail=f"Fraud Engine verification failed: {fraud_res.text}")
        
    fraud_data = fraud_res.json()
    risk_score = fraud_data["score"]
    action = fraud_data["action"]
    
    # Handle Fraud Verdicts
    if action == "BLOCK":
        # Call Order Service S2S to fail order
        await signed_s2s_request("POST", f"{ORDER_SERVICE_URL}/orders/{order_id}/fail", ORDER_PAYMENT_SHARED_SECRET)
        
        # Save blocked transaction
        txn_id = f"txn_blk_{uuid.uuid4().hex[:12]}"
        save_transaction(
            txn_id, order_id, amount, token_id, "BLOCKED", risk_score,
            token_entry["encrypted_card"], token_entry["iv"], token_entry["wrapped_dek"], None
        )
        return {
            "status": "BLOCKED",
            "reason": f"Fraud prevention engine blocked transaction. Reason: {fraud_data['reason']}",
            "risk_score": risk_score
        }
        
    elif action == "CHALLENGE_3DS":
        # Suspend transaction and request 3DS Customer Authentication
        txn_id = f"txn_3ds_{uuid.uuid4().hex[:12]}"
        _3ds_vault[txn_id] = {
            "order_id": order_id,
            "amount": amount,
            "card_token": token_id,
            "client_ip": client_ip,
            "device_fingerprint": device,
            "billing_country": country,
            "risk_score": risk_score,
            "token_entry": token_entry,
            "otp_code": "123456"  # Mock OTP
        }
        return {
            "status": "PENDING_3DS",
            "transaction_id": txn_id,
            "message": "3-D Secure Authentication required",
            "risk_score": risk_score,
            "reason": fraud_data["reason"]
        }

    # If ALLOWED, execute standard approval path
    return await execute_payment_approval(order_id, amount, token_id, token_entry, risk_score)


@app.post("/payments/3ds-verify")
async def verify_3ds(payload: dict):
    """
    Resolves the 3-D Secure OTP code.
    Payload: {"transaction_id": str, "otp_code": str}
    """
    txn_id = payload.get("transaction_id")
    otp_code = payload.get("otp_code")
    
    challenge = _3ds_vault.get(txn_id)
    if not challenge:
        raise HTTPException(status_code=400, detail="Invalid or expired 3-D Secure challenge")
        
    if otp_code != challenge["otp_code"]:
        # Failed OTP -> Mark transaction & order as FAILED
        order_id = challenge["order_id"]
        await signed_s2s_request("POST", f"{ORDER_SERVICE_URL}/orders/{order_id}/fail", ORDER_PAYMENT_SHARED_SECRET)
        
        token_entry = challenge["token_entry"]
        save_transaction(
            txn_id, order_id, challenge["amount"], challenge["card_token"], "FAILED_3DS", challenge["risk_score"],
            token_entry["encrypted_card"], token_entry["iv"], token_entry["wrapped_dek"], None
        )
        del _3ds_vault[txn_id]
        raise HTTPException(status_code=401, detail="Invalid OTP code. Authentication failed.")
        
    # Passed OTP -> Approve transaction
    order_id = challenge["order_id"]
    amount = challenge["amount"]
    token_id = challenge["card_token"]
    token_entry = challenge["token_entry"]
    risk_score = challenge["risk_score"]
    
    # Execute approval
    res = await execute_payment_approval(order_id, amount, token_id, token_entry, risk_score, txn_id=txn_id)
    
    # Remove from 3DS vault
    del _3ds_vault[txn_id]
    return res

@app.post("/payments/{txn_id}/decrypt")
async def decrypt_transaction_card(txn_id: str):
    """Secure Auditor Endpoint: Decrypts transaction card details using KMS unwrapping."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT encrypted_card, iv, wrapped_dek FROM transactions WHERE id = ?", (txn_id,))
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        raise HTTPException(status_code=404, detail="Transaction not found")
        
    tx = dict(row)
    if not tx["encrypted_card"] or not tx["wrapped_dek"]:
        raise HTTPException(status_code=400, detail="No encrypted card data for this transaction")
        
    try:
        # Call KMS to unwrap the DEK (requires signed S2S request)
        kms_url = f"{KMS_SERVICE_URL}/kms/envelope/unwrap"
        kms_res = await signed_s2s_request("POST", kms_url, KMS_HMAC_SECRET, {"wrapped_dek_hex": tx["wrapped_dek"]})
        if kms_res.status_code != 200:
            raise HTTPException(status_code=500, detail=f"KMS unwrap failed: {kms_res.text}")
            
        dek_hex = kms_res.json()["dek_hex"]
        dek = bytes.fromhex(dek_hex)
        
        # Decrypt the card data using AES-GCM
        decrypted_card = decrypt_data_aes_gcm(tx["encrypted_card"], tx["iv"], dek)
        return {"decrypted_card": decrypted_card}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Decryption failed: {str(e)}")

@app.post("/payments/kms-rotate-trigger")
async def trigger_kms_key_rotation():
    """Admin Proxy: Triggers key rotation in the KMS using a signed S2S request."""
    try:
        kms_url = f"{KMS_SERVICE_URL}/kms/keys/rotate"
        kms_res = await signed_s2s_request("POST", kms_url, KMS_HMAC_SECRET, {})
        if kms_res.status_code != 200:
            raise HTTPException(status_code=500, detail=f"KMS rotation failed: {kms_res.text}")
        return kms_res.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to proxy key rotation: {str(e)}")


# --- Inner Helpers ---

async def execute_payment_approval(order_id: str, amount: float, token_id: str, token_entry: dict, risk_score: float, txn_id: str = None) -> dict:
    """Executes the standard approved transaction path with JWS signed receipts."""
    if not txn_id:
        txn_id = f"txn_app_{uuid.uuid4().hex[:12]}"
        
    # 1. Complete order on Order Service (HMAC callback)
    order_complete_res = await signed_s2s_request(
        "POST", f"{ORDER_SERVICE_URL}/orders/{order_id}/complete", ORDER_PAYMENT_SHARED_SECRET
    )
    if order_complete_res.status_code != 200:
        raise HTTPException(status_code=500, detail="Failed to finalize order status")
        
    # 2. Get cryptographically signed JWS receipt from KMS
    receipt_payload = {
        "transaction_id": txn_id,
        "order_id": order_id,
        "amount": amount,
        "status": "APPROVED",
        "timestamp": time.time(),
        "gateway_signature_party": "SECURE_GATEWAY_v4"
    }
    
    kms_sign_url = f"{KMS_SERVICE_URL}/kms/sign"
    kms_res = await signed_s2s_request("POST", kms_sign_url, KMS_HMAC_SECRET, receipt_payload)
    
    if kms_res.status_code != 200:
        raise HTTPException(status_code=500, detail=f"KMS receipt signing failed: {kms_res.text}")
        
    jws_receipt = kms_res.json()["jws_receipt"]
    
    # 3. Store payment record in database (including JWS receipt and envelope data)
    save_transaction(
        txn_id, order_id, amount, token_id, "APPROVED", risk_score,
        token_entry["encrypted_card"], token_entry["iv"], token_entry["wrapped_dek"], jws_receipt
    )
    
    return {
        "status": "APPROVED",
        "transaction_id": txn_id,
        "amount": amount,
        "receipt": jws_receipt,
        "risk_score": risk_score
    }

def save_transaction(txn_id: str, order_id: str, amount: float, token_id: str, status: str, risk_score: float, encrypted_card: str, iv: str, wrapped_dek: str, signed_receipt: str):
    """Inserts a transaction record into SQLite database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO transactions (id, order_id, amount, token, status, risk_score, encrypted_card, iv, wrapped_dek, signed_receipt, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (txn_id, order_id, amount, token_id, status, risk_score, encrypted_card, iv, wrapped_dek, signed_receipt, time.time())
    )
    conn.commit()
    conn.close()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8002)
