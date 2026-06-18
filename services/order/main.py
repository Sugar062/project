import os
import json
import time
import sqlite3
import uuid
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from shared.security import verify_hmac_signature

app = FastAPI(title="Order Service", version="1.0.0")

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ORDER_PAYMENT_SHARED_SECRET = "order_payment_gateway_hmac_secret_445566"
DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "orders.db"))

# --- Database Initialization ---

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS orders (
            id TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            amount REAL NOT NULL,
            status TEXT NOT NULL,
            items TEXT NOT NULL,
            created_at REAL NOT NULL
        )
    """)
    conn.commit()
    conn.close()

init_db()


# --- Security Middleware ---

@app.middleware("http")
async def verify_s2s_signature(request: Request, call_next):
    # Exclude order creation and docs from signature verification (public endpoints)
    if request.method == "POST" and request.url.path == "/orders":
        return await call_next(request)
    if request.url.path in ["/docs", "/openapi.json", "/orders/status-check"]:
        return await call_next(request)

    # Read HMAC headers
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
    
    # Verify S2S HMAC
    is_valid, msg = verify_hmac_signature(
        secret_key=ORDER_PAYMENT_SHARED_SECRET,
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
        
    # Restore body for request handlers
    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}
    request._receive = receive
    
    return await call_next(request)


# --- Helper Database Functions ---

def get_order_by_id(order_id: str) -> dict:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM orders WHERE id = ?", (order_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        order = dict(row)
        order["items"] = json.loads(order["items"])
        return order
    return None

def update_order_status(order_id: str, status: str) -> bool:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE orders SET status = ? WHERE id = ?", (status, order_id))
    conn.commit()
    rows_affected = cursor.rowcount
    conn.close()
    return rows_affected > 0


# --- Endpoints ---

@app.get("/orders/status-check")
async def get_status():
    return {"status": "ACTIVE", "database": "SQLITE", "db_path": DB_PATH}

@app.post("/orders")
async def create_order(payload: dict):
    """
    Public Endpoint: Create a new checkout order.
    Payload: {
        "client_id": str,
        "items": [
            {"id": "item1", "name": "Crypto Shield Pro", "price": 49.99, "quantity": 1}
        ]
    }
    """
    client_id = payload.get("client_id")
    items = payload.get("items")
    
    if not client_id or not items:
        raise HTTPException(status_code=400, detail="Missing client_id or items")
        
    # Calculate amount
    total_amount = 0.0
    for item in items:
        try:
            total_amount += float(item["price"]) * int(item["quantity"])
        except (ValueError, KeyError):
            raise HTTPException(status_code=400, detail="Invalid item structure or pricing")
            
    order_id = f"ord_{uuid.uuid4().hex[:12]}"
    
    # Store order in SQLite
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO orders (id, client_id, amount, status, items, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (order_id, client_id, total_amount, "PENDING", json.dumps(items), time.time())
    )
    conn.commit()
    conn.close()
    
    return {
        "order_id": order_id,
        "amount": round(total_amount, 2),
        "status": "PENDING"
    }

@app.get("/orders/{order_id}")
async def get_order(order_id: str):
    """Secure S2S Endpoint: Fetch order details for verification."""
    order = get_order_by_id(order_id)
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    return order

@app.post("/orders/{order_id}/complete")
async def complete_order(order_id: str, payload: dict = None):
    """Secure S2S Endpoint: Gateway updates order status to PAID."""
    order = get_order_by_id(order_id)
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    if order["status"] == "PAID":
        return {"status": "PAID", "message": "Order already completed"}
        
    success = update_order_status(order_id, "PAID")
    if not success:
        raise HTTPException(status_code=500, detail="Failed to update order status")
        
    return {"status": "PAID", "message": "Order status updated to PAID"}

@app.post("/orders/{order_id}/fail")
async def fail_order(order_id: str, payload: dict = None):
    """Secure S2S Endpoint: Gateway updates order status to FAILED."""
    order = get_order_by_id(order_id)
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
        
    success = update_order_status(order_id, "FAILED")
    if not success:
        raise HTTPException(status_code=500, detail="Failed to update order status")
        
    return {"status": "FAILED", "message": "Order status updated to FAILED"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8001)
