#!/usr/bin/env python3
"""
BOFA authentication and authorization
JWT-based authentication for the local runtime and API.
"""

import logging
import os
from pathlib import Path
import secrets
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

import jwt
from fastapi import HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

try:
    from .passwords import hash_password, needs_rehash, verify_password
except ImportError:
    from passwords import hash_password, needs_rehash, verify_password

logger = logging.getLogger(__name__)

def _load_jwt_secret() -> str:
    configured = os.getenv("JWT_SECRET")
    if configured:
        return configured

    app_root = Path(os.getenv("BOFA_APP_ROOT", Path(__file__).resolve().parents[1]))
    secret_path = Path(os.getenv("BOFA_JWT_SECRET_FILE", app_root / "data" / "jwt_secret"))
    secret_path.parent.mkdir(parents=True, exist_ok=True)
    if secret_path.exists():
        return secret_path.read_text(encoding="utf-8").strip()

    generated = secrets.token_urlsafe(48)
    secret_path.write_text(generated, encoding="utf-8")
    try:
        secret_path.chmod(0o600)
    except OSError:
        pass
    return generated


JWT_SECRET = _load_jwt_secret()
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = int(os.getenv("JWT_EXPIRATION_HOURS", "24"))

security = HTTPBearer()

class AuthManager:
    def __init__(self, database_manager):
        self.db = database_manager
    
    def hash_password(self, password: str) -> str:
        """Hash a password using a salted, adaptive KDF."""
        return hash_password(password)
    
    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against hash"""
        return verify_password(password, hashed)
    
    def create_access_token(self, user_data: Dict[str, Any]) -> str:
        """Create JWT access token"""
        to_encode = user_data.copy()
        expire = datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS)
        to_encode.update({"exp": expire, "iat": datetime.utcnow()})
        
        encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
        return encoded_jwt
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify JWT token"""
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            return payload
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token has expired")
        except jwt.PyJWTError:
            raise HTTPException(status_code=401, detail="Could not validate credentials")
    
    def authenticate_user(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """Authenticate user credentials"""
        user = self.db.get_user_by_username(username)
        if not user:
            return None
        
        if not self.verify_password(password, user['password_hash']):
            return None

        if needs_rehash(user["password_hash"]):
            self.db.update_password_hash(user["id"], self.hash_password(password))
        
        # Update last login
        self.db.update_last_login(user['id'])
        
        # Remove sensitive data
        user_data = {
            "user_id": user['id'],
            "username": user['username'],
            "email": user['email'],
            "role": user['role']
        }
        
        return user_data

    def bootstrap_admin(self, username: str, email: str, password: str) -> Optional[int]:
        user_id = self.db.create_initial_admin(username, email, self.hash_password(password))
        if user_id:
            logger.info("Initial administrator registered: %s", username)
        return user_id
    
    def register_user(self, username: str, email: str, password: str, role: str = "user") -> Optional[int]:
        """Register new user"""
        password_hash = self.hash_password(password)
        user_id = self.db.create_user(username, email, password_hash, role)
        
        if user_id:
            logger.info("User registered: %s (%s)", username, role)
        
        return user_id
    
    def get_current_user(self, credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
        """Get current authenticated user"""
        token = credentials.credentials
        payload = self.verify_token(token)
        
        # Verify user still exists and is active
        user = self.db.get_user_by_username(payload['username'])
        if not user:
            raise HTTPException(status_code=401, detail="User no longer exists")
        
        return {
            "user_id": user['id'],
            "username": user['username'],
            "email": user['email'],
            "role": user['role']
        }
    
    def require_role(self, required_role: str):
        """Decorator to require specific role"""
        def role_checker(current_user: Dict[str, Any] = Depends(self.get_current_user)):
            if current_user['role'] != required_role and current_user['role'] != 'admin':
                raise HTTPException(
                    status_code=403, 
                    detail=f"Access denied. Required role: {required_role}"
                )
            return current_user
        return role_checker
    
    def get_optional_user(self, credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)):
        """Get user if authenticated, else return None"""
        if not credentials:
            return None
        
        try:
            return self.get_current_user(credentials)
        except HTTPException:
            return None

# Role-based permissions
class Roles:
    ADMIN = "admin"
    RED_TEAM = "red_team"
    BLUE_TEAM = "blue_team"
    PURPLE_TEAM = "purple_team"
    ANALYST = "analyst"
    USER = "user"
    
    @classmethod
    def get_permissions(cls, role: str) -> Dict[str, bool]:
        """Get permissions for role"""
        permissions = {
            "execute_scripts": False,
            "manage_labs": False,
            "view_all_history": False,
            "manage_users": False,
            "access_red_tools": False,
            "access_blue_tools": False,
            "access_purple_tools": False,
            "manage_api_keys": False
        }
        
        if role == cls.ADMIN:
            return {key: True for key in permissions}
        elif role == cls.RED_TEAM:
            permissions.update({
                "execute_scripts": True,
                "manage_labs": True,
                "access_red_tools": True,
                "access_purple_tools": True,
                "manage_api_keys": True
            })
        elif role == cls.BLUE_TEAM:
            permissions.update({
                "execute_scripts": True,
                "manage_labs": True,
                "access_blue_tools": True,
                "access_purple_tools": True,
                "manage_api_keys": True
            })
        elif role == cls.PURPLE_TEAM:
            permissions.update({
                "execute_scripts": True,
                "manage_labs": True,
                "access_red_tools": True,
                "access_blue_tools": True,
                "access_purple_tools": True,
                "manage_api_keys": True
            })
        elif role == cls.ANALYST:
            permissions.update({
                "execute_scripts": True,
                "access_blue_tools": True,
                "manage_api_keys": True
            })
        elif role == cls.USER:
            permissions.update({
                "execute_scripts": True
            })
        
        return permissions

def check_permission(user: Dict[str, Any], permission: str) -> bool:
    """Check if user has specific permission"""
    permissions = Roles.get_permissions(user['role'])
    return permissions.get(permission, False)
