"""
GuardFi v2 - Device Recovery System
Cloud sync and data recovery when device is lost
"""

import uuid
import hashlib
import json
from datetime import datetime
from typing import Dict, Any, List
from database import get_db

class RecoverySystem:
    """Device recovery and cloud sync"""
    
    def __init__(self):
        self.sync_interval_minutes = 5
    
    def generate_recovery_token(self, user_id: int, device_info: str = "") -> Dict[str, Any]:
        """Generate a recovery token for a device"""
        token = f"REC-{uuid.uuid4().hex.upper()}"
        
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("""
            INSERT INTO recovery_tokens (user_id, token, device_info, last_sync)
            VALUES (?, ?, ?, ?)
        """, (user_id, token, device_info, datetime.now().isoformat()))
        
        db.commit()
        db.close()
        
        return {
            "status": "generated",
            "token": token,
            "device_info": device_info,
            "message": f"Recovery token generated: {token}"
        }
    
    def sync_device(self, token: str, device_info: str = "") -> Dict[str, Any]:
        """Sync device data from cloud"""
        db = get_db()
        cursor = db.cursor()
        
        # Verify token
        cursor.execute("SELECT * FROM recovery_tokens WHERE token = ? AND status = 'active'", (token,))
        recovery = cursor.fetchone()
        
        if not recovery:
            db.close()
            return {"status": "failed", "error": "Invalid or inactive recovery token"}
        
        # Update last sync
        cursor.execute("""
            UPDATE recovery_tokens 
            SET last_sync = ?, device_info = ?
            WHERE token = ?
        """, (datetime.now().isoformat(), device_info, token))
        
        # Get all user data for sync
        cursor.execute("SELECT * FROM scanned_documents ORDER BY scanned_at DESC LIMIT 100")
        documents = [dict(row) for row in cursor.fetchall()]
        
        cursor.execute("SELECT * FROM transactions ORDER BY created_at DESC LIMIT 100")
        transactions = [dict(row) for row in cursor.fetchall()]
        
        cursor.execute("SELECT * FROM alerts ORDER BY created_at DESC LIMIT 100")
        alerts = [dict(row) for row in cursor.fetchall()]
        
        # Generate sync hash
        sync_data = json.dumps({
            "documents": len(documents),
            "transactions": len(transactions),
            "alerts": len(alerts),
            "timestamp": datetime.now().isoformat()
        })
        sync_hash = hashlib.sha256(sync_data.encode()).hexdigest()[:16]
        
        db.commit()
        db.close()
        
        return {
            "status": "synced",
            "sync_hash": sync_hash,
            "documents_synced": len(documents),
            "transactions_synced": len(transactions),
            "alerts_synced": len(alerts),
            "last_sync": datetime.now().isoformat(),
            "device_info": device_info,
            "message": f"✅ Device synced successfully. {len(documents)} documents, {len(transactions)} transactions, {len(alerts)} alerts restored."
        }
    
    def get_recovery_tokens(self, user_id: int) -> List[Dict]:
        """Get all recovery tokens for a user"""
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("""
            SELECT * FROM recovery_tokens 
            WHERE user_id = ?
            ORDER BY created_at DESC
        """, (user_id,))
        
        tokens = [dict(row) for row in cursor.fetchall()]
        db.close()
        
        return tokens
    
    def revoke_token(self, token: str) -> Dict[str, Any]:
        """Revoke a recovery token"""
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("""
            UPDATE recovery_tokens SET status = 'revoked' WHERE token = ?
        """, (token,))
        
        db.commit()
        db.close()
        
        return {"status": "revoked", "token": token, "message": "Token revoked successfully"}

# Global instance
recovery_system = RecoverySystem()
