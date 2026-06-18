import time
from typing import Dict, List
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
try:
    import numpy as np
    from sklearn.linear_model import LogisticRegression
    HAS_ML = True
except ImportError:
    HAS_ML = False

from shared.security import verify_hmac_signature

app = FastAPI(title="Fraud Detection Engine", version="1.0.0")

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

FRAUD_HMAC_SECRET = "fraud_internal_secret_key_12345"

# In-memory database of transactions for velocity checks (timestamp, ip, token)
transaction_history: List[Dict] = []
HISTORY_WINDOW_SECONDS = 60  # 1 minute

# --- Machine Learning Model Setup ---
# We will train a simple Logistic Regression model on startup using synthetic data
# Features: [Amount, HourOfDay/24, RecentTransactionsCount, DeviceFingerprintRisk]
# Labels: 0 (Genuine), 1 (Fraudulent)
ml_model = None

def train_mock_model():
    global ml_model
    if not HAS_ML:
        print("[Fraud Engine] scikit-learn/numpy missing. Running in Heuristic Emulation Mode.")
        return
        
    try:
        ml_model = LogisticRegression()
        np.random.seed(42)
        n_samples = 200
        
        # Generate genuine features
        genuine_amounts = np.random.uniform(5.0, 300.0, n_samples // 2)
        genuine_hours = np.random.uniform(8.0, 22.0, n_samples // 2) / 24.0
        genuine_velocity = np.random.poisson(1, n_samples // 2)
        genuine_device = np.random.uniform(0.0, 0.2, n_samples // 2)
        
        genuine_features = np.column_stack((genuine_amounts, genuine_hours, genuine_velocity, genuine_device))
        genuine_labels = np.zeros(n_samples // 2)
        
        # Generate fraudulent features
        fraud_amounts = np.random.uniform(800.0, 5000.0, n_samples // 2)
        fraud_hours = np.concatenate([np.random.uniform(0.0, 5.0, n_samples // 4), np.random.uniform(22.0, 24.0, n_samples // 4)]) / 24.0
        fraud_velocity = np.random.poisson(5, n_samples // 2)
        fraud_device = np.random.uniform(0.6, 1.0, n_samples // 2)
        
        fraud_features = np.column_stack((fraud_amounts, fraud_hours, fraud_velocity, fraud_device))
        fraud_labels = np.ones(n_samples // 2)
        
        # Combine
        X = np.vstack((genuine_features, fraud_features))
        y = np.concatenate((genuine_labels, fraud_labels))
        
        # Shuffle
        indices = np.arange(n_samples)
        np.random.shuffle(indices)
        X = X[indices]
        y = y[indices]
        
        ml_model.fit(X, y)
        print("[Fraud Engine] Machine Learning model trained and operational.")
    except Exception as e:
        print(f"[Fraud Engine] ML Training failed: {str(e)}. Falling back to Heuristic Mode.")
        ml_model = None

# Train on start
train_mock_model()


# --- Security Middleware ---

@app.middleware("http")
async def verify_s2s_signature(request: Request, call_next):
    if request.url.path in ["/docs", "/openapi.json", "/fraud/status"]:
        return await call_next(request)
        
    sig = request.headers.get("X-Signature")
    timestamp = request.headers.get("X-Timestamp")
    nonce = request.headers.get("X-Nonce")
    
    if not all([sig, timestamp, nonce]):
        return JSONResponse(
            status_code=401,
            content={"detail": "Missing security headers for S2S request"}
        )
        
    body = await request.body()
    body_str = body.decode("utf-8")
    
    is_valid, msg = verify_hmac_signature(
        secret_key=FRAUD_HMAC_SECRET,
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
        
    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}
    request._receive = receive
    
    return await call_next(request)


# --- API Helper Functions ---

def clean_history():
    """Removes historical data outside the velocity time window."""
    now = time.time()
    global transaction_history
    transaction_history = [tx for tx in transaction_history if now - tx["timestamp"] < HISTORY_WINDOW_SECONDS]

def get_velocity_count(ip: str, token: str) -> int:
    """Gets number of transactions from this IP or token in the last window."""
    clean_history()
    count = 0
    for tx in transaction_history:
        if tx["ip"] == ip or tx["token"] == token:
            count += 1
    return count


# --- Endpoints ---

@app.get("/fraud/status")
async def get_status():
    """Returns status metrics of the Fraud Detection Engine."""
    clean_history()
    return {
        "status": "ACTIVE",
        "engine_type": "Hybrid (Rules + Logistic Regression)" if HAS_ML and ml_model else "Hybrid (Rules + Heuristic Emulation)",
        "model_trained": HAS_ML and ml_model is not None,
        "velocity_window_seconds": HISTORY_WINDOW_SECONDS,
        "logged_transactions_in_window": len(transaction_history)
    }

@app.post("/fraud/evaluate")
async def evaluate_transaction(payload: dict):
    """
    Evaluates transaction risk.
    Payload: {
        "amount": float,
        "card_token": str,
        "client_ip": str,
        "device_fingerprint": str,
        "billing_country": str
    }
    """
    amount = float(payload.get("amount", 0.0))
    token = payload.get("card_token", "")
    ip = payload.get("client_ip", "127.0.0.1")
    device = payload.get("device_fingerprint", "unknown")
    country = payload.get("billing_country", "US")
    
    # 1. Run Velocity Check (Rule Engine)
    velocity_count = get_velocity_count(ip, token)
    
    # Update history with this attempt
    transaction_history.append({
        "timestamp": time.time(),
        "ip": ip,
        "token": token
    })
    
    # --- RULE ENGINE RULES ---
    
    # Rule A: Extreme velocity threshold
    if velocity_count >= 5:
        return {
            "score": 1.0,
            "action": "BLOCK",
            "reason": f"Velocity check failed: Too many requests ({velocity_count + 1} attempts/min)"
        }
        
    # Rule B: High amount hard limit
    if amount >= 10000.0:
        return {
            "score": 0.99,
            "action": "BLOCK",
            "reason": "Transaction amount exceeds hard limit ($10,000)"
        }
        
    # Rule C: Suspicious testing country
    if country == "XX":
        return {
            "score": 0.95,
            "action": "BLOCK",
            "reason": "Blocked country code (XX)"
        }

    # --- MACHINE LEARNING SCORING ---
    # Extract ML Features
    # Time of day (mock as current hour)
    current_hour = time.localtime().tm_hour
    hour_feature = current_hour / 24.0
    
    # Device risk heuristic: if device contains 'unknown' or is empty -> high risk
    device_risk = 0.8 if device in ["unknown", "", "compromised"] else 0.05
    
    # Predict Probability of Fraud
    if HAS_ML and ml_model is not None:
        try:
            # Vector format: [Amount, Hour, Velocity, DeviceRisk]
            feature_vector = np.array([[amount, hour_feature, velocity_count, device_risk]])
            probs = ml_model.predict_proba(feature_vector)
            ml_fraud_score = float(probs[0][1])  # Class 1 (fraud) probability
        except Exception as e:
            ml_fraud_score = 0.5  # Fallback
            print(f"[Fraud Engine] ML Inference failed: {str(e)}")
    else:
        # Heuristic Emulation Model
        score = 0.05
        # Higher amounts increase risk linearly up to 0.45 at $5000
        score += min(amount / 5000.0, 1.0) * 0.45
        # Night hours (10pm - 6am) add risk
        if current_hour >= 22 or current_hour < 6:
            score += 0.20
        # Velocity adds risk
        score += min(velocity_count * 0.15, 0.45)
        # Device risk adds risk
        score += device_risk * 0.40
        # Cap score between 0.01 and 0.99
        ml_fraud_score = min(max(score, 0.01), 0.99)

    # Overrides based on ML score combined with rule check
    action = "ALLOW"
    reason = "Transaction deemed safe"
    
    if ml_fraud_score >= 0.85:
        action = "BLOCK"
        reason = f"ML Fraud Score ({ml_fraud_score:.2f}) exceeds critical threshold"
    elif ml_fraud_score >= 0.40 or amount >= 2000.0 or velocity_count >= 2:
        action = "CHALLENGE_3DS"
        reason = f"ML Fraud Score ({ml_fraud_score:.2f}) indicates elevated risk"
        if amount >= 2000.0:
            reason = "Amount triggers mandatory 3DS review ($2,000+)"
        elif velocity_count >= 2:
            reason = "Velocity check triggers 3DS review"
            
    return {
        "score": ml_fraud_score,
        "action": action,
        "reason": reason,
        "features": {
            "amount": amount,
            "hour": current_hour,
            "velocity": velocity_count,
            "device_risk": device_risk
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8003)
