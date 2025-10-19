#!/usr/bin/env python3
"""
API Key Manager - BOFA v2.5.1
Manages API keys for external services with encryption and caching
Author: @descambiado
"""

import hashlib
import secrets
from typing import Optional, Dict, Any
from cryptography.fernet import Fernet
import base64
import os


class APIKeyManager:
    """Manages API keys for external services"""
    
    def __init__(self, database_manager):
        self.db = database_manager
        self.cache: Dict[str, str] = {}
        # Generate or load encryption key (in production, use env variable)
        self.encryption_key = self._get_encryption_key()
        self.cipher = Fernet(self.encryption_key)
    
    def _get_encryption_key(self) -> bytes:
        """Get or generate encryption key"""
        key = os.getenv('API_KEY_ENCRYPTION_KEY')
        if key:
            return base64.urlsafe_b64decode(key)
        # Generate new key (should be saved to env in production)
        return Fernet.generate_key()
    
    def store_key(self, user_id: int, service: str, api_key: str) -> bool:
        """Store encrypted API key for a user"""
        try:
            encrypted_key = self.cipher.encrypt(api_key.encode()).decode()
            
            cursor = self.db.conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO api_keys (user_id, service, encrypted_key)
                VALUES (?, ?, ?)
            """, (user_id, service, encrypted_key))
            self.db.conn.commit()
            
            # Update cache
            cache_key = f"{user_id}:{service}"
            self.cache[cache_key] = api_key
            
            return True
        except Exception as e:
            print(f"Error storing API key: {e}")
            return False
    
    def get_key(self, user_id: int, service: str) -> Optional[str]:
        """Get decrypted API key with caching"""
        cache_key = f"{user_id}:{service}"
        
        # Check cache first
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        try:
            cursor = self.db.conn.cursor()
            cursor.execute("""
                SELECT encrypted_key FROM api_keys
                WHERE user_id = ? AND service = ?
            """, (user_id, service))
            
            row = cursor.fetchone()
            if row:
                decrypted_key = self.cipher.decrypt(row[0].encode()).decode()
                self.cache[cache_key] = decrypted_key
                return decrypted_key
            
            return None
        except Exception as e:
            print(f"Error retrieving API key: {e}")
            return None
    
    def delete_key(self, user_id: int, service: str) -> bool:
        """Delete API key"""
        try:
            cursor = self.db.conn.cursor()
            cursor.execute("""
                DELETE FROM api_keys
                WHERE user_id = ? AND service = ?
            """, (user_id, service))
            self.db.conn.commit()
            
            # Clear cache
            cache_key = f"{user_id}:{service}"
            self.cache.pop(cache_key, None)
            
            return True
        except Exception as e:
            print(f"Error deleting API key: {e}")
            return False
    
    def list_keys(self, user_id: int) -> list:
        """List all services with API keys for a user"""
        try:
            cursor = self.db.conn.cursor()
            cursor.execute("""
                SELECT service, created_at FROM api_keys
                WHERE user_id = ?
            """, (user_id,))
            
            return [{"service": row[0], "created_at": row[1]} for row in cursor.fetchall()]
        except Exception as e:
            print(f"Error listing API keys: {e}")
            return []
    
    def test_key(self, service: str, api_key: str) -> Dict[str, Any]:
        """Test if API key is valid"""
        import requests
        
        test_endpoints = {
            "shodan": "https://api.shodan.io/api-info?key=",
            "virustotal": "https://www.virustotal.com/api/v3/users/current",
            "github": "https://api.github.com/user",
        }
        
        if service not in test_endpoints:
            return {"valid": False, "error": "Service not supported"}
        
        try:
            if service == "shodan":
                response = requests.get(f"{test_endpoints[service]}{api_key}", timeout=10)
            elif service == "virustotal":
                response = requests.get(
                    test_endpoints[service],
                    headers={"x-apikey": api_key},
                    timeout=10
                )
            elif service == "github":
                response = requests.get(
                    test_endpoints[service],
                    headers={"Authorization": f"token {api_key}"},
                    timeout=10
                )
            
            if response.status_code == 200:
                return {"valid": True, "message": "API key is valid"}
            else:
                return {"valid": False, "error": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"valid": False, "error": str(e)}
