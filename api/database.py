#!/usr/bin/env python3
"""
BOFA Extended Systems v2.5.1 - Database Models and Connection
SQLAlchemy models and database management
"""

import os
from datetime import datetime, timedelta
from typing import List, Optional
import sqlite3
from pathlib import Path
import json
import logging

# Simple SQLite database manager for BOFA
logger = logging.getLogger(__name__)

class DatabaseManager:
    def __init__(self, db_path: str = "/app/data/bofa.db"):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.init_database()
    
    def get_connection(self):
        """Get database connection"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row  # Enable dict-like access
        return conn
    
    def init_database(self):
        """Initialize database tables"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                is_active BOOLEAN DEFAULT 1
            )
        ''')
        
        # Script executions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS script_executions (
                id TEXT PRIMARY KEY,
                user_id INTEGER,
                module TEXT NOT NULL,
                script_name TEXT NOT NULL,
                parameters TEXT,
                status TEXT DEFAULT 'running',
                output TEXT,
                error_message TEXT,
                execution_time REAL,
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Lab instances table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS lab_instances (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                lab_id TEXT NOT NULL,
                user_id INTEGER,
                container_id TEXT,
                status TEXT DEFAULT 'stopped',
                port INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                started_at TIMESTAMP,
                stopped_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # System metrics table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                metric_type TEXT NOT NULL,
                metric_value REAL NOT NULL,
                metadata TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # API keys table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                service_name TEXT NOT NULL,
                api_key TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Learning progress table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS learning_progress (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                lesson_id TEXT NOT NULL,
                progress REAL DEFAULT 0,
                completed BOOLEAN DEFAULT 0,
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        conn.commit()
        conn.close()
        
        # Create default admin user
        self.create_default_admin()
        logger.info("✅ Database initialized successfully")
    
    def create_default_admin(self):
        """Create default admin user"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Check if admin exists
        cursor.execute("SELECT id FROM users WHERE username = ?", ("admin",))
        if cursor.fetchone():
            conn.close()
            return
        
        # Create admin user (password: admin123)
        import hashlib
        password_hash = hashlib.sha256("admin123".encode()).hexdigest()
        
        cursor.execute('''
            INSERT INTO users (username, email, password_hash, role)
            VALUES (?, ?, ?, ?)
        ''', ("admin", "admin@bofa.local", password_hash, "admin"))
        
        conn.commit()
        conn.close()
        logger.info("👤 Default admin user created (admin/admin123)")
    
    # User management
    def create_user(self, username: str, email: str, password_hash: str, role: str = "user"):
        """Create new user"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO users (username, email, password_hash, role)
                VALUES (?, ?, ?, ?)
            ''', (username, email, password_hash, role))
            user_id = cursor.lastrowid
            conn.commit()
            return user_id
        except sqlite3.IntegrityError:
            return None
        finally:
            conn.close()
    
    def get_user_by_username(self, username: str):
        """Get user by username"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM users WHERE username = ? AND is_active = 1", (username,))
        user = cursor.fetchone()
        conn.close()
        
        return dict(user) if user else None
    
    def update_last_login(self, user_id: int):
        """Update user last login"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?
        ''', (user_id,))
        
        conn.commit()
        conn.close()
    
    # Script execution management
    def create_execution(self, execution_id: str, user_id: int, module: str, 
                        script_name: str, parameters: dict):
        """Create script execution record"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO script_executions 
            (id, user_id, module, script_name, parameters, status)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (execution_id, user_id, module, script_name, json.dumps(parameters), "running"))
        
        conn.commit()
        conn.close()
    
    def update_execution(self, execution_id: str, status: str, output: str = None, 
                        error_message: str = None, execution_time: float = None):
        """Update script execution"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE script_executions 
            SET status = ?, output = ?, error_message = ?, execution_time = ?, 
                completed_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (status, output, error_message, execution_time, execution_id))
        
        conn.commit()
        conn.close()
    
    def get_execution_history(self, user_id: int = None, limit: int = 50):
        """Get execution history"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        if user_id:
            cursor.execute('''
                SELECT * FROM script_executions 
                WHERE user_id = ? 
                ORDER BY started_at DESC LIMIT ?
            ''', (user_id, limit))
        else:
            cursor.execute('''
                SELECT * FROM script_executions 
                ORDER BY started_at DESC LIMIT ?
            ''', (limit,))
        
        executions = cursor.fetchall()
        conn.close()
        
        return [dict(execution) for execution in executions]
    
    # Lab management
    def create_lab_instance(self, lab_id: str, user_id: int, container_id: str = None, port: int = None):
        """Create lab instance"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO lab_instances (lab_id, user_id, container_id, port, status)
            VALUES (?, ?, ?, ?, ?)
        ''', (lab_id, user_id, container_id, port, "starting"))
        
        instance_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return instance_id
    
    def update_lab_status(self, lab_id: str, user_id: int, status: str):
        """Update lab status"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        if status == "running":
            cursor.execute('''
                UPDATE lab_instances 
                SET status = ?, started_at = CURRENT_TIMESTAMP
                WHERE lab_id = ? AND user_id = ?
            ''', (status, lab_id, user_id))
        elif status == "stopped":
            cursor.execute('''
                UPDATE lab_instances 
                SET status = ?, stopped_at = CURRENT_TIMESTAMP
                WHERE lab_id = ? AND user_id = ?
            ''', (status, lab_id, user_id))
        else:
            cursor.execute('''
                UPDATE lab_instances 
                SET status = ?
                WHERE lab_id = ? AND user_id = ?
            ''', (status, lab_id, user_id))
        
        conn.commit()
        conn.close()
    
    def get_user_labs(self, user_id: int):
        """Get user's lab instances"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM lab_instances 
            WHERE user_id = ? 
            ORDER BY created_at DESC
        ''', (user_id,))
        
        labs = cursor.fetchall()
        conn.close()
        
        return [dict(lab) for lab in labs]
    
    # Metrics and analytics
    def add_metric(self, metric_type: str, value: float, metadata: dict = None):
        """Add system metric"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO system_metrics (metric_type, metric_value, metadata)
            VALUES (?, ?, ?)
        ''', (metric_type, value, json.dumps(metadata) if metadata else None))
        
        conn.commit()
        conn.close()
    
    def get_metrics(self, metric_type: str = None, hours: int = 24):
        """Get system metrics"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        since = datetime.now() - timedelta(hours=hours)
        
        if metric_type:
            cursor.execute('''
                SELECT * FROM system_metrics 
                WHERE metric_type = ? AND timestamp > ?
                ORDER BY timestamp DESC
            ''', (metric_type, since))
        else:
            cursor.execute('''
                SELECT * FROM system_metrics 
                WHERE timestamp > ?
                ORDER BY timestamp DESC
            ''', (since,))
        
        metrics = cursor.fetchall()
        conn.close()
        
        return [dict(metric) for metric in metrics]
    
    # API key management
    def store_api_key(self, user_id: int, service_name: str, api_key: str):
        """Store API key"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Deactivate old keys for same service
        cursor.execute('''
            UPDATE api_keys SET is_active = 0 
            WHERE user_id = ? AND service_name = ?
        ''', (user_id, service_name))
        
        # Insert new key
        cursor.execute('''
            INSERT INTO api_keys (user_id, service_name, api_key)
            VALUES (?, ?, ?)
        ''', (user_id, service_name, api_key))
        
        conn.commit()
        conn.close()
    
    def get_api_key(self, user_id: int, service_name: str):
        """Get API key"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT api_key FROM api_keys 
            WHERE user_id = ? AND service_name = ? AND is_active = 1
        ''', (user_id, service_name))
        
        result = cursor.fetchone()
        conn.close()
        
        return result['api_key'] if result else None
    
    # Learning progress
    def update_lesson_progress(self, user_id: int, lesson_id: str, progress: float):
        """Update lesson progress"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Check if record exists
        cursor.execute('''
            SELECT id FROM learning_progress 
            WHERE user_id = ? AND lesson_id = ?
        ''', (user_id, lesson_id))
        
        if cursor.fetchone():
            # Update existing
            cursor.execute('''
                UPDATE learning_progress 
                SET progress = ?, completed = ?, completed_at = ?
                WHERE user_id = ? AND lesson_id = ?
            ''', (progress, progress >= 100, 
                  datetime.now() if progress >= 100 else None,
                  user_id, lesson_id))
        else:
            # Insert new
            cursor.execute('''
                INSERT INTO learning_progress (user_id, lesson_id, progress, completed, completed_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (user_id, lesson_id, progress, progress >= 100,
                  datetime.now() if progress >= 100 else None))
        
        conn.commit()
        conn.close()
    
    def get_learning_progress(self, user_id: int):
        """Get user learning progress"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM learning_progress WHERE user_id = ?
        ''', (user_id,))
        
        progress = cursor.fetchall()
        conn.close()
        
        return [dict(p) for p in progress]

# Global database instance
db = DatabaseManager()