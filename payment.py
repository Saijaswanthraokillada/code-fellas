"""
GuardFi v2 - Payment Simulation Engine
Sandbox payment processing with multi-bank support
"""

import hashlib
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from database import get_db

# Supported banks
SUPPORTED_BANKS = {
    "HDFC": {"name": "HDFC Bank", "ifsc_prefix": "HDFC", "color": "#004B87"},
    "SBI": {"name": "State Bank of India", "ifsc_prefix": "SBIN", "color": "#22B573"},
    "ICICI": {"name": "ICICI Bank", "ifsc_prefix": "ICIC", "color": "#F58220"},
    "Axis": {"name": "Axis Bank", "ifsc_prefix": "UTIB", "color": "#97144D"},
    "Kotak": {"name": "Kotak Mahindra Bank", "ifsc_prefix": "KKBK", "color": "#ED1C24"},
    "Yes": {"name": "Yes Bank", "ifsc_prefix": "YESB", "color": "#1C1C6B"},
}

class PaymentEngine:
    """Sandbox payment processing engine"""
    
    def __init__(self):
        self.sandbox_mode = True  # No real money transfers
    
    def validate_bank_details(self, bank_name: str, account: str, ifsc: str) -> Dict[str, Any]:
        """Validate bank account details"""
        errors = []
        
        if not bank_name or bank_name not in SUPPORTED_BANKS:
            errors.append(f"Unsupported bank. Supported: {', '.join(SUPPORTED_BANKS.keys())}")
        
        if not account or len(account) < 10 or not account.isdigit():
            errors.append("Invalid account number (must be 10-16 digits)")
        
        if not ifsc or len(ifsc) != 11:
            errors.append("Invalid IFSC code (must be 11 characters)")
        elif ifsc[:4] not in [b["ifsc_prefix"] for b in SUPPORTED_BANKS.values()]:
            errors.append("IFSC prefix doesn't match bank name")
        
        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "bank_info": SUPPORTED_BANKS.get(bank_name, {})
        }
    
    def calculate_transfer_fee(self, amount: float, bank_name: str) -> Dict[str, Any]:
        """Calculate transfer fees based on amount and bank"""
        # Sandbox fee calculation
        if amount <= 10000:
            fee = 0  # Free for small amounts
        elif amount <= 100000:
            fee = amount * 0.001  # 0.1%
        else:
            fee = amount * 0.0005  # 0.05% for large amounts
        
        return {
            "amount": amount,
            "fee": round(fee, 2),
            "total": round(amount + fee, 2),
            "fee_percentage": round((fee / amount * 100) if amount > 0 else 0, 3)
        }
    
    def execute_payment(self, tx_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a sandbox payment"""
        tx_id = f"TX-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        
        # Validate bank details
        validation = self.validate_bank_details(
            tx_data.get("bank_name", ""),
            tx_data.get("account_number", ""),
            tx_data.get("ifsc_code", "")
        )
        
        if not validation["valid"]:
            return {
                "status": "failed",
                "error": "Validation failed",
                "details": validation["errors"]
            }
        
        # Calculate fees
        fee_info = self.calculate_transfer_fee(tx_data["amount"], tx_data["bank_name"])
        
        # Generate proof
        proof_data = f"{tx_id}:{tx_data['amount']}:{tx_data.get('sender', '')}:{tx_data.get('receiver', '')}:{datetime.now().isoformat()}"
        proof_hash = hashlib.sha256(proof_data.encode()).hexdigest()[:16]
        
        # Create transaction record
        rollback_deadline = datetime.now() + timedelta(seconds=30)
        
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("""
            INSERT INTO transactions 
            (tx_id, document_id, amount, currency, sender, receiver, bank_name,
             account_number, ifsc_code, status, risk_score, approval_required,
             rollback_deadline, proof_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'completed', ?, 1, ?, ?)
        """, (
            tx_id,
            tx_data.get("document_id"),
            fee_info["total"],
            "INR",
            tx_data.get("sender", "Unknown"),
            tx_data.get("receiver", "Unknown"),
            tx_data["bank_name"],
            tx_data["account_number"],
            tx_data["ifsc_code"],
            tx_data.get("risk_score", 0.0),
            rollback_deadline.isoformat(),
            proof_hash
        ))
        
        db.commit()
        db.close()
        
        return {
            "status": "completed",
            "tx_id": tx_id,
            "amount": fee_info["amount"],
            "fee": fee_info["fee"],
            "total_debited": fee_info["total"],
            "sender": tx_data.get("sender", "Unknown"),
            "receiver": tx_data.get("receiver", "Unknown"),
            "bank": tx_data["bank_name"],
            "proof_hash": proof_hash,
            "rollback_deadline": rollback_deadline.isoformat(),
            "rollback_available": True,
            "sandbox_mode": True,
            "message": f"✅ Payment of ₹{fee_info['amount']:,.2f} completed successfully (sandbox mode)"
        }
    
    def rollback_payment(self, tx_id: str) -> Dict[str, Any]:
        """Rollback a payment within 30-second window"""
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("SELECT * FROM transactions WHERE tx_id = ?", (tx_id,))
        tx = cursor.fetchone()
        
        if not tx:
            db.close()
            return {"status": "failed", "error": "Transaction not found"}
        
        if tx["rolled_back"]:
            db.close()
            return {"status": "failed", "error": "Transaction already rolled back"}
        
        # Check rollback window
        rollback_deadline = datetime.fromisoformat(tx["rollback_deadline"])
        if datetime.now() > rollback_deadline:
            db.close()
            return {"status": "failed", "error": "Rollback window expired (30 seconds)"}
        
        # Execute rollback
        cursor.execute("""
            UPDATE transactions 
            SET status = 'rolled_back', rolled_back = 1 
            WHERE tx_id = ?
        """, (tx_id,))
        
        # Create alert
        cursor.execute("""
            INSERT INTO alerts (alert_type, severity, title, message, transaction_id)
            VALUES ('rollback', 'warning', '🔄 Payment Rolled Back', 
                    ?, ?)
        """, (f"Transaction {tx_id} has been rolled back. Amount ₹{tx['amount']:,.2f} refunded.", tx["id"]))
        
        db.commit()
        db.close()
        
        return {
            "status": "rolled_back",
            "tx_id": tx_id,
            "amount_refunded": tx["amount"],
            "message": f"🔄 Payment {tx_id} rolled back. ₹{tx['amount']:,.2f} refunded."
        }
    
    def get_transaction_history(self, limit: int = 50, user_id: int = None) -> list:
        """Get transaction history filtered by user_id"""
        db = get_db()
        cursor = db.cursor()
        
        if user_id:
            cursor.execute("""
                SELECT t.*, sd.filename as document_name
                FROM transactions t
                LEFT JOIN scanned_documents sd ON t.document_id = sd.id
                WHERE t.user_id = ?
                ORDER BY t.created_at DESC
                LIMIT ?
            """, (user_id, limit))
        else:
            cursor.execute("""
                SELECT t.*, sd.filename as document_name
                FROM transactions t
                LEFT JOIN scanned_documents sd ON t.document_id = sd.id
                ORDER BY t.created_at DESC
                LIMIT ?
            """, (limit,))
        
        transactions = [dict(row) for row in cursor.fetchall()]
        db.close()
        
        return transactions

# Global instance
payment_engine = PaymentEngine()
