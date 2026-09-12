"""
GuardFi v2 - User Authentication System
Registration, login, session management
"""

import hashlib
import uuid
import secrets
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from database import get_db

class AuthSystem:
    """User authentication and session management"""
    
    def __init__(self):
        self.session_duration_hours = 24
    
    def hash_password(self, password: str) -> str:
        """Hash password with salt"""
        salt = "guardfi_salt_2026"
        return hashlib.sha256(f"{salt}{password}".encode()).hexdigest()
    
    def register(self, username: str, password: str, email: str, 
                 company: str = "", role: str = "user") -> Dict[str, Any]:
        """Register a new user"""
        if len(username) < 3:
            return {"status": "failed", "error": "Username must be at least 3 characters"}
        
        if len(password) < 6:
            return {"status": "failed", "error": "Password must be at least 6 characters"}
        
        db = get_db()
        cursor = db.cursor()
        
        # Check if username exists
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            db.close()
            return {"status": "failed", "error": "Username already exists"}
        
        # Create user
        password_hash = self.hash_password(password)
        session_token = secrets.token_hex(32)
        
        # Admin is auto-approved, others need verification
        verification_status = 'approved' if role == 'admin' else 'pending'
        
        cursor.execute("""
            INSERT INTO users (username, password_hash, role, email, company, session_token, session_expires, verification_status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            username, password_hash, role, email, company, session_token,
            (datetime.now() + timedelta(hours=self.session_duration_hours)).isoformat(),
            verification_status
        ))
        
        user_id = cursor.lastrowid
        db.commit()
        db.close()
        
        return {
            "status": "success",
            "user_id": user_id,
            "username": username,
            "role": role,
            "session_token": session_token,
            "message": f"User {username} registered successfully"
        }
    
    def login(self, username: str, password: str) -> Dict[str, Any]:
        """Login user and return session token"""
        db = get_db()
        cursor = db.cursor()
        
        password_hash = self.hash_password(password)
        
        cursor.execute("""
            SELECT id, username, role, email, company, verification_status 
            FROM users 
            WHERE username = ? AND password_hash = ?
        """, (username, password_hash))
        
        user = cursor.fetchone()
        
        if not user:
            db.close()
            return {"status": "failed", "error": "Invalid username or password"}
        
        # Check verification status
        if user["verification_status"] == "pending" and user["role"] != "admin":
            db.close()
            return {"status": "failed", "error": "Account pending admin approval. Please wait for verification.", "pending": True}
        
        if user["verification_status"] == "rejected":
            db.close()
            return {"status": "failed", "error": "Account rejected by admin. Please contact support."}
        
        # Generate new session token
        session_token = secrets.token_hex(32)
        session_expires = (datetime.now() + timedelta(hours=self.session_duration_hours)).isoformat()
        
        cursor.execute("""
            UPDATE users SET session_token = ?, session_expires = ?
            WHERE id = ?
        """, (session_token, session_expires, user["id"]))
        
        db.commit()
        db.close()
        
        return {
            "status": "success",
            "user_id": user["id"],
            "username": user["username"],
            "role": user["role"],
            "email": user["email"],
            "company": user["company"],
            "verification_status": user["verification_status"],
            "session_token": session_token,
            "message": f"Welcome back, {user['username']}!"
        }
    
    def verify_session(self, session_token: str) -> Optional[Dict[str, Any]]:
        """Verify session token and return user info"""
        if not session_token:
            return None
        
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("""
            SELECT id, username, role, email, company, session_expires
            FROM users 
            WHERE session_token = ?
        """, (session_token,))
        
        user = cursor.fetchone()
        db.close()
        
        if not user:
            return None
        
        # Check if session expired
        if user["session_expires"]:
            expires = datetime.fromisoformat(user["session_expires"])
            if datetime.now() > expires:
                return None
        
        return {
            "user_id": user["id"],
            "username": user["username"],
            "role": user["role"],
            "email": user["email"],
            "company": user["company"]
        }
    
    def logout(self, session_token: str) -> Dict[str, Any]:
        """Logout user by invalidating session"""
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("""
            UPDATE users SET session_token = NULL, session_expires = NULL
            WHERE session_token = ?
        """, (session_token,))
        
        db.commit()
        db.close()
        
        return {"status": "success", "message": "Logged out successfully"}
    
    def get_user_by_id(self, user_id: int) -> Optional[Dict]:
        """Get user details by ID"""
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("""
            SELECT id, username, role, email, company, created_at
            FROM users WHERE id = ?
        """, (user_id,))
        
        user = cursor.fetchone()
        db.close()
        
        return dict(user) if user else None
    
    def approve_user(self, user_id: int, approved_by: str) -> Dict[str, Any]:
        """Admin approves a user"""
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("""
            UPDATE users SET verification_status = 'approved', approved_by = ?, approved_at = ?
            WHERE id = ?
        """, (approved_by, datetime.now().isoformat(), user_id))
        
        db.commit()
        db.close()
        
        return {"status": "success", "message": f"User {user_id} approved by {approved_by}"}
    
    def reject_user(self, user_id: int, rejected_by: str) -> Dict[str, Any]:
        """Admin rejects a user"""
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("""
            UPDATE users SET verification_status = 'rejected', approved_by = ?
            WHERE id = ?
        """, (rejected_by, user_id))
        
        db.commit()
        db.close()
        
        return {"status": "success", "message": f"User {user_id} rejected by {rejected_by}"}
    
    def get_pending_users(self) -> List[Dict]:
        """Get users pending approval"""
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("""
            SELECT id, username, email, company, role, created_at
            FROM users WHERE verification_status = 'pending'
            ORDER BY created_at DESC
        """)
        
        users = [dict(row) for row in cursor.fetchall()]
        db.close()
        
        return users
    
    def get_all_users(self) -> List[Dict]:
        """Get all users (admin only)"""
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("""
            SELECT id, username, role, email, company, verification_status, approved_by, created_at
            FROM users ORDER BY created_at DESC
        """)
        
        users = [dict(row) for row in cursor.fetchall()]
        db.close()
        
        return users

# Global instance
auth_system = AuthSystem()
