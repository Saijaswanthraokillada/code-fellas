"""
GuardFi v2 - Smart Alert System
Real-time notifications for threats, payments, and system events
"""

import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from database import get_db

class AlertSystem:
    """Smart notification system"""
    
    def __init__(self):
        self.severity_levels = {
            "critical": {"color": "#ff4545", "icon": "🚨", "sound": True},
            "warning": {"color": "#ffd700", "icon": "⚠️", "sound": True},
            "info": {"color": "#00d4aa", "icon": "ℹ️", "sound": False},
            "success": {"color": "#00d4aa", "icon": "✅", "sound": False}
        }
    
    def create_alert(self, alert_type: str, severity: str, title: str, 
                     message: str, document_id: int = None, 
                     transaction_id: int = None) -> Dict[str, Any]:
        """Create a new alert"""
        alert_id = f"ALERT-{uuid.uuid4().hex[:8].upper()}"
        
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("""
            INSERT INTO alerts (alert_type, severity, title, message, document_id, transaction_id)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (alert_type, severity, title, message, document_id, transaction_id))
        
        alert_db_id = cursor.lastrowid
        db.commit()
        db.close()
        
        return {
            "alert_id": alert_id,
            "db_id": alert_db_id,
            "type": alert_type,
            "severity": severity,
            "title": title,
            "message": message,
            "created_at": datetime.now().isoformat(),
            "info": self.severity_levels.get(severity, self.severity_levels["info"])
        }
    
    def get_alerts(self, limit: int = 50, unread_only: bool = False, user_id: int = None) -> List[Dict]:
        """Get recent alerts filtered by user_id"""
        db = get_db()
        cursor = db.cursor()
        
        conditions = []
        params = []
        
        if user_id:
            conditions.append("a.user_id = ?")
            params.append(user_id)
        
        if unread_only:
            conditions.append("a.is_read = 0")
        
        where_clause = " WHERE " + " AND ".join(conditions) if conditions else ""
        
        query = f"""
            SELECT a.*, t.tx_id, t.amount as tx_amount
            FROM alerts a
            LEFT JOIN transactions t ON a.transaction_id = t.id
            {where_clause}
            ORDER BY a.created_at DESC
            LIMIT ?
        """
        
        params.append(limit)
        cursor.execute(query, params)
        alerts = [dict(row) for row in cursor.fetchall()]
        db.close()
        
        return alerts
    
    def mark_alert_read(self, alert_id: int):
        """Mark an alert as read"""
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("UPDATE alerts SET is_read = 1 WHERE id = ?", (alert_id,))
        db.commit()
        db.close()
    
    def mark_all_read(self):
        """Mark all alerts as read"""
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("UPDATE alerts SET is_read = 1 WHERE is_read = 0")
        db.commit()
        db.close()
    
    def get_alert_stats(self) -> Dict[str, Any]:
        """Get alert statistics"""
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("SELECT COUNT(*) as total FROM alerts")
        total = cursor.fetchone()["total"]
        
        cursor.execute("SELECT COUNT(*) as unread FROM alerts WHERE is_read = 0")
        unread = cursor.fetchone()["unread"]
        
        cursor.execute("SELECT COUNT(*) as critical FROM alerts WHERE severity = 'critical' AND is_read = 0")
        critical = cursor.fetchone()["critical"]
        
        cursor.execute("SELECT COUNT(*) as warnings FROM alerts WHERE severity = 'warning' AND is_read = 0")
        warnings = cursor.fetchone()["warnings"]
        
        db.close()
        
        return {
            "total_alerts": total,
            "unread": unread,
            "critical": critical,
            "warnings": warnings,
            "has_critical": critical > 0
        }

# Global instance
alert_system = AlertSystem()
