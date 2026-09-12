"""
GuardFi v2 - Complete Database Layer
SQLite database for transactions, alerts, emails, and device recovery
"""

import sqlite3
import hashlib
import json
from datetime import datetime
from typing import Optional, List, Dict, Any

DB_PATH = "guardfi.db"

def get_db():
    """Get database connection"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def init_db():
    """Initialize all database tables"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'officer',
            email TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Scanned documents
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scanned_documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id TEXT UNIQUE NOT NULL,
            filename TEXT,
            source_type TEXT,
            raw_text TEXT,
            visible_text TEXT,
            injection_verdict TEXT,
            risk_score REAL,
            reasons TEXT,
            ai_intent TEXT,
            ai_confidence REAL,
            is_grounded INTEGER,
            total_latency_ms INTEGER,
            status TEXT DEFAULT 'completed',
            scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Transactions (payment ledger)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tx_id TEXT UNIQUE NOT NULL,
            document_id INTEGER,
            amount REAL,
            currency TEXT DEFAULT 'INR',
            sender TEXT,
            receiver TEXT,
            bank_name TEXT,
            account_number TEXT,
            ifsc_code TEXT,
            status TEXT DEFAULT 'pending',
            risk_score REAL,
            approval_required INTEGER DEFAULT 1,
            approved_by TEXT,
            approved_at TIMESTAMP,
            rolled_back INTEGER DEFAULT 0,
            rollback_deadline TIMESTAMP,
            proof_hash TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (document_id) REFERENCES scanned_documents(id)
        )
    """)
    
    # Email monitor queue
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS email_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email_id TEXT UNIQUE NOT NULL,
            sender TEXT,
            subject TEXT,
            received_at TIMESTAMP,
            has_attachment INTEGER DEFAULT 0,
            attachment_name TEXT,
            attachment_path TEXT,
            scan_status TEXT DEFAULT 'pending',
            document_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (document_id) REFERENCES scanned_documents(id)
        )
    """)
    
    # Alerts
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type TEXT NOT NULL,
            severity TEXT DEFAULT 'info',
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            document_id INTEGER,
            transaction_id INTEGER,
            is_read INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (document_id) REFERENCES scanned_documents(id),
            FOREIGN KEY (transaction_id) REFERENCES transactions(id)
        )
    """)
    
    # Device recovery tokens
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS recovery_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            token TEXT UNIQUE NOT NULL,
            device_info TEXT,
            last_sync TIMESTAMP,
            status TEXT DEFAULT 'active',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    
    # Risk trends (for charts)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS risk_trends (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT NOT NULL,
            total_scans INTEGER DEFAULT 0,
            attacks_blocked INTEGER DEFAULT 0,
            payments_approved INTEGER DEFAULT 0,
            total_amount REAL DEFAULT 0,
            avg_risk_score REAL DEFAULT 0
        )
    """)
    
    # Seed default user
    password_hash = hashlib.sha256("guardfi_salt_2026".encode() + b"admin123").hexdigest()
    cursor.execute("""
        INSERT OR IGNORE INTO users (username, password_hash, role, email, company)
        VALUES ('admin', ?, 'admin', 'admin@guardfi.com', 'GuardFi Systems')
    """, [password_hash])
    
    # No seed data - clean start for production
    # Users register themselves, data comes from real usage
    
    conn.commit()
    conn.close()
    print("Database initialized successfully")

def _seed_sample_data(cursor):
    """Seed sample data for demo"""
    import random
    
    # Sample scanned documents
    docs = [
        ("INV-2026-001", "Clean invoice from Samsung", "text", "approved", 0.15, "payment_request", 0.95, 1, 120),
        ("INV-2026-002", "Attack blocked - injection detected", "text", "blocked", 0.95, "system_override", 0.0, 0, 15),
        ("INV-2026-003", "Legitimate utility bill", "text", "approved", 0.10, "payment_request", 0.98, 1, 95),
        ("INV-2026-004", "Hidden transfer attack", "email", "blocked", 0.88, "hidden_instruction", 0.0, 0, 12),
        ("INV-2026-005", "Monthly salary invoice", "text", "approved", 0.08, "payment_request", 0.99, 1, 110),
        ("INV-2026-006", "Override attempt blocked", "pdf", "blocked", 0.92, "system_override", 0.0, 0, 18),
        ("INV-2026-007", "Office supplies invoice", "text", "approved", 0.12, "payment_request", 0.96, 1, 88),
        ("INV-2026-008", "Cloud hosting payment", "email", "approved", 0.11, "payment_request", 0.97, 1, 105),
        ("INV-2026-009", "SQL injection attempt", "text", "blocked", 0.89, "code_injection", 0.0, 0, 14),
        ("INV-2026-010", "Marketing agency invoice", "text", "approved", 0.09, "payment_request", 0.99, 1, 92),
    ]
    
    for doc in docs:
        cursor.execute("""
            INSERT OR IGNORE INTO scanned_documents 
            (request_id, filename, source_type, injection_verdict, risk_score, 
             ai_intent, ai_confidence, is_grounded, total_latency_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, doc)
    
    # Sample transactions
    txns = [
        ("TX-2026-001", 1, 168150.00, "INR", "XYZ Trading Co.", "Samsung India", "HDFC Bank", "50100123456789", "HDFC0001234", "completed", 0.15, 1, "admin", "2026-09-12 10:30:00", 0, None, "a1b2c3d4e5f6"),
        ("TX-2026-002", 3, 5500.00, "INR", "MyHome Apartments", "BESCOM Electricity", "SBI", "12345678901234", "SBIN0001234", "completed", 0.10, 1, "admin", "2026-09-12 11:15:00", 0, None, "b2c3d4e5f6a7"),
        ("TX-2026-003", 5, 450000.00, "INR", "TechCorp India", "Employee Salaries", "ICICI", "98765432101234", "ICIC0005678", "pending", 0.08, 1, None, None, 0, "2026-09-12 12:00:00", "c3d4e5f6a7b8"),
        ("TX-2026-004", 7, 28000.00, "INR", "Office Complex", "CleanGreen Supplies", "Axis", "55556666777788", "UTIB0007890", "completed", 0.12, 1, "admin", "2026-09-12 13:45:00", 0, None, "d4e5f6a7b8c9"),
        ("TX-2026-005", 8, 85000.00, "INR", "TechStartup Inc", "AWS Cloud Services", "HDFC", "33334444555566", "HDFC0009012", "completed", 0.11, 1, "admin", "2026-09-12 14:30:00", 0, None, "e5f6a7b8c9d0"),
    ]
    
    for txn in txns:
        cursor.execute("""
            INSERT OR IGNORE INTO transactions 
            (tx_id, document_id, amount, currency, sender, receiver, bank_name, 
             account_number, ifsc_code, status, risk_score, approval_required, 
             approved_by, approved_at, rolled_back, rollback_deadline, proof_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, txn)
    
    # Sample alerts
    alerts = [
        ("attack_blocked", "critical", "🚨 Injection Attack Blocked", "Hidden transfer指令 detected in invoice INV-2026-002. Attack prevented.", 2, None),
        ("attack_blocked", "critical", "🚨 Override Attempt Blocked", "System override指令 detected in document INV-2026-006. Action blocked.", 6, None),
        ("payment_approved", "info", "✅ Payment Completed", "₹1,68,150.00 paid to Samsung India via HDFC Bank", None, 1),
        ("payment_approved", "info", "✅ Payment Completed", "₹5,500.00 paid to BESCOM Electricity via SBI", None, 2),
        ("payment_pending", "warning", "⏳ Payment Awaiting Approval", "₹4,50,000.00 to Employee Salaries - requires officer approval", None, 3),
        ("attack_blocked", "critical", "🚨 SQL Injection Detected", "SQL injection attempt in document INV-2026-009. Blocked immediately.", 9, None),
        ("system_info", "info", "📊 Daily Scan Summary", "10 documents scanned today. 3 attacks blocked. 7 payments processed.", None, None),
        ("risk_warning", "warning", "⚠️ High Risk Score Detected", "Document INV-2026-002 has risk score 0.95 - extremely high threat level.", 2, None),
    ]
    
    for alert in alerts:
        cursor.execute("""
            INSERT OR IGNORE INTO alerts (alert_type, severity, title, message, document_id, transaction_id)
            VALUES (?, ?, ?, ?, ?, ?)
        """, alert)
    
    # Sample email queue
    emails = [
        ("EMAIL-001", "accounts@samsung.co.in", "Invoice for Galaxy S26 Ultra", "2026-09-12 09:00:00", 1, "INV-2026-001.pdf", None, "completed", 1),
        ("EMAIL-002", "billing@techsolutions.com", "Monthly Services Bill", "2026-09-12 09:30:00", 1, "bill_sept2026.pdf", None, "blocked", 2),
        ("EMAIL-003", "bescom@karnataka.gov.in", "Electricity Bill - September", "2026-09-12 10:00:00", 1, "bill_092026.pdf", None, "completed", 3),
        ("EMAIL-004", "invoices@malicious-domain.com", "Payment Request - URGENT", "2026-09-12 10:15:00", 1, "invoice.pdf", None, "blocked", 4),
        ("EMAIL-005", "hr@techcorp.in", "Salary Disbursement List", "2026-09-12 11:00:00", 1, "salaries_sep.xlsx", None, "completed", 5),
    ]
    
    for email in emails:
        cursor.execute("""
            INSERT OR IGNORE INTO email_queue 
            (email_id, sender, subject, received_at, has_attachment, attachment_name, 
             attachment_path, scan_status, document_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, email)
    
    # Risk trends for the last 7 days
    for i in range(7):
        date = f"2026-09-{5+i:02d}"
        scans = random.randint(8, 25)
        attacks = random.randint(1, 4)
        payments = random.randint(5, 15)
        amount = random.uniform(50000, 500000)
        avg_risk = random.uniform(0.1, 0.3)
        
        cursor.execute("""
            INSERT OR IGNORE INTO risk_trends 
            (date, total_scans, attacks_blocked, payments_approved, total_amount, avg_risk_score)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (date, scans, attacks, payments, amount, avg_risk))

# Initialize database on import
init_db()
