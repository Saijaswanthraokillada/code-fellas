"""
GuardFi v2 - Email Monitor
Auto-forwarding and scanning of incoming emails/invoices
"""

import uuid
import re
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from database import get_db

class EmailMonitor:
    """Email monitoring and auto-scanning system"""
    
    def __init__(self):
        self.scan_interval_minutes = 5
        self.auto_forward_enabled = True
    
    def simulate_incoming_email(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate receiving an email (for demo)"""
        email_id = f"EMAIL-{uuid.uuid4().hex[:8].upper()}"
        
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("""
            INSERT INTO email_queue 
            (email_id, sender, subject, received_at, has_attachment, attachment_name, scan_status)
            VALUES (?, ?, ?, ?, ?, ?, 'pending')
        """, (
            email_id,
            email_data.get("sender", "unknown@domain.com"),
            email_data.get("subject", "No Subject"),
            datetime.now().isoformat(),
            1 if email_data.get("has_attachment") else 0,
            email_data.get("attachment_name")
        ))
        
        db.commit()
        db.close()
        
        return {
            "status": "received",
            "email_id": email_id,
            "message": f"Email received from {email_data.get('sender', 'unknown')}. Queued for scanning."
        }
    
    def get_pending_emails(self) -> List[Dict]:
        """Get emails waiting to be scanned"""
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("""
            SELECT * FROM email_queue 
            WHERE scan_status = 'pending' 
            ORDER BY received_at ASC
        """)
        
        emails = [dict(row) for row in cursor.fetchall()]
        db.close()
        
        return emails
    
    def get_all_emails(self, limit: int = 100) -> List[Dict]:
        """Get all scanned emails"""
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("""
            SELECT eq.*, sd.injection_verdict, sd.risk_score
            FROM email_queue eq
            LEFT JOIN scanned_documents sd ON eq.document_id = sd.id
            ORDER BY eq.received_at DESC
            LIMIT ?
        """, (limit,))
        
        emails = [dict(row) for row in cursor.fetchall()]
        db.close()
        
        return emails
    
    def update_email_status(self, email_id: str, status: str, document_id: int = None):
        """Update email scan status"""
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("""
            UPDATE email_queue 
            SET scan_status = ?, document_id = ?
            WHERE email_id = ?
        """, (status, document_id, email_id))
        
        db.commit()
        db.close()
    
    def get_email_stats(self) -> Dict[str, Any]:
        """Get email monitoring statistics"""
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("SELECT COUNT(*) as total FROM email_queue")
        total = cursor.fetchone()["total"]
        
        cursor.execute("SELECT COUNT(*) as blocked FROM email_queue WHERE scan_status = 'blocked'")
        blocked = cursor.fetchone()["blocked"]
        
        cursor.execute("SELECT COUNT(*) as completed FROM email_queue WHERE scan_status = 'completed'")
        completed = cursor.fetchone()["completed"]
        
        cursor.execute("SELECT COUNT(*) as pending FROM email_queue WHERE scan_status = 'pending'")
        pending = cursor.fetchone()["pending"]
        
        db.close()
        
        return {
            "total_emails": total,
            "scanned": completed + blocked,
            "blocked": blocked,
            "completed": completed,
            "pending": pending,
            "auto_forward_enabled": self.auto_forward_enabled,
            "scan_interval_minutes": self.scan_interval_minutes
        }

# Global instance
email_monitor = EmailMonitor()
