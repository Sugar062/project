import os
import time
import json
import sqlite3
import httpx
from shared.security import generate_hmac_signature

ORDER_DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../order/orders.db"))
PAYMENT_DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../payment_orchestrator/payments.db"))
KMS_SERVICE_URL = "http://127.0.0.1:8004"
KMS_HMAC_SECRET = "kms_internal_secret_key_98765"
REPORT_OUTPUT_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../reconciliation_report.jws"))

print("[Reconciler] Background worker started. Monitoring databases...")

async def sign_report_with_kms(report: dict) -> str:
    """Sends the report payload to KMS to get a signed JWS receipt."""
    timestamp = str(time.time())
    nonce = os.urandom(8).hex()
    body_str = json.dumps(report)
    path = "/kms/sign"
    url = f"{KMS_SERVICE_URL}{path}"
    
    sig = generate_hmac_signature(KMS_HMAC_SECRET, "POST", path, timestamp, nonce, body_str)
    
    headers = {
        "X-Signature": sig,
        "X-Timestamp": timestamp,
        "X-Nonce": nonce,
        "Content-Type": "application/json"
    }
    
    async with httpx.AsyncClient() as client:
        try:
            res = await client.post(url, headers=headers, content=body_str, timeout=5.0)
            if res.status_code == 200:
                return res.json().get("jws_receipt", "")
            else:
                print(f"[Reconciler] KMS signing failed: HTTP {res.status_code} - {res.text}")
        except Exception as e:
            print(f"[Reconciler] Error connecting to KMS for signing: {str(e)}")
    return ""

def reconcile_databases():
    """Compares Order database and Payment database, finding mismatch disputes."""
    if not os.path.exists(ORDER_DB_PATH) or not os.path.exists(PAYMENT_DB_PATH):
        # Databases might not be initialized yet
        return None
        
    conn_order = sqlite3.connect(ORDER_DB_PATH)
    conn_order.row_factory = sqlite3.Row
    cursor_o = conn_order.cursor()
    cursor_o.execute("SELECT id, amount, status FROM orders")
    orders = {row["id"]: dict(row) for row in cursor_o.fetchall()}
    conn_order.close()
    
    conn_payment = sqlite3.connect(PAYMENT_DB_PATH)
    conn_payment.row_factory = sqlite3.Row
    cursor_p = conn_payment.cursor()
    cursor_p.execute("SELECT id, order_id, amount, status FROM transactions")
    payments = [dict(row) for row in cursor_p.fetchall()]
    conn_payment.close()
    
    discrepancies = []
    matched_count = 0
    
    # Track which payment order IDs we process
    processed_orders_in_payments = set()
    
    for pay in payments:
        order_id = pay["order_id"]
        pay_id = pay["id"]
        
        # Only audit APPROVED transactions for reconciliation
        if pay["status"] != "APPROVED":
            continue
            
        processed_orders_in_payments.add(order_id)
        
        if order_id not in orders:
            discrepancies.append({
                "type": "ORPHAN_PAYMENT",
                "payment_id": pay_id,
                "order_id": order_id,
                "detail": f"Approved payment {pay_id} exists but order {order_id} does not exist in order service database."
            })
            continue
            
        order = orders[order_id]
        
        # Check amount mismatch
        if abs(pay["amount"] - order["amount"]) > 0.01:
            discrepancies.append({
                "type": "AMOUNT_MISMATCH",
                "payment_id": pay_id,
                "order_id": order_id,
                "detail": f"Payment amount ${pay['amount']:.2f} does not match order amount ${order['amount']:.2f}."
            })
            
        # Check status mismatch
        if order["status"] != "PAID":
            discrepancies.append({
                "type": "STATUS_MISMATCH",
                "payment_id": pay_id,
                "order_id": order_id,
                "detail": f"Payment is approved, but order status is '{order['status']}' instead of 'PAID'."
            })
            
        if abs(pay["amount"] - order["amount"]) <= 0.01 and order["status"] == "PAID":
            matched_count += 1
            
    # Check for PAID orders that do not have APPROVED payments
    for ord_id, ord_data in orders.items():
        if ord_data["status"] == "PAID" and ord_id not in processed_orders_in_payments:
            discrepancies.append({
                "type": "UNPAID_ORDER_COMPLETED",
                "order_id": ord_id,
                "detail": f"Order {ord_id} is marked PAID, but no approved gateway transaction was found."
            })
            
    report = {
        "timestamp": int(time.time()),
        "total_orders_evaluated": len(orders),
        "total_payments_evaluated": len(payments),
        "reconciled_matches": matched_count,
        "discrepancies_found": len(discrepancies),
        "discrepancies": discrepancies,
        "status": "HEALTHY" if len(discrepancies) == 0 else "DISPUTES_FOUND"
    }
    
    return report

async def main():
    while True:
        try:
            report = reconcile_databases()
            if report:
                print(f"\n[Reconciler] Running audit... status: {report['status']}")
                print(f"  - Orders: {report['total_orders_evaluated']}, Approved Payments: {report['total_payments_evaluated']}")
                print(f"  - Matches: {report['reconciled_matches']}, Discrepancies: {report['discrepancies_found']}")
                
                if report['discrepancies_found'] > 0:
                    for disc in report['discrepancies']:
                        print(f"    ⚠️ WARNING: [{disc['type']}] {disc['detail']}")
                        
                # Sign report with KMS RSA key material
                jws_sig = await sign_report_with_kms(report)
                if jws_sig:
                    with open(REPORT_OUTPUT_PATH, "w") as f:
                        f.write(jws_sig)
                    print(f"  - Signed audit statement written to: {os.path.basename(REPORT_OUTPUT_PATH)}")
                else:
                    print("  - Signed audit skipped (KMS Service offline)")
            else:
                print("[Reconciler] Waiting for databases to initialize...")
        except Exception as e:
            print(f"[Reconciler] Audit loop error: {str(e)}")
            
        time.sleep(15)

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
