#!/usr/bin/env python3
"""
BOFA Extended Systems v2.8.0 - Authentication and Authorization
JWT-based authentication system
"""

import os
import hashlib
import hmac
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from fastapi import HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import ExpiredSignatureError, JWTError, jwt
import logging

logger = logging.getLogger(__name__)

# JWT Configuration. The legacy BOFA token and the SotyHub gateway token use
# separate secrets. A gateway token is short lived and constrained to one HTTP
# method and path, so it cannot be replayed against a different BOFA route.
JWT_SECRET = os.getenv("JWT_SECRET", "").strip()
SOTYHUB_PROXY_JWT_SECRET = os.getenv("SOTYHUB_PROXY_JWT_SECRET", "").strip()
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24
SOTYHUB_PROXY_ISSUER = "sotyhub-proxy"
SOTYHUB_PROXY_AUDIENCE = "bofa-api"

security = HTTPBearer()

class AuthManager:
    def __init__(self, database_manager):
        self.db = database_manager
    
    def hash_password(self, password: str) -> str:
        """Hash password using SHA256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against hash"""
        return self.hash_password(password) == hashed
    
    def create_access_token(self, user_data: Dict[str, Any]) -> str:
        """Create JWT access token"""
        if not JWT_SECRET:
            raise RuntimeError("JWT_SECRET must be configured")
        to_encode = user_data.copy()
        expire = datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS)
        to_encode.update({"exp": expire, "iat": datetime.utcnow()})
        
        encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
        return encoded_jwt
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify either a legacy BOFA token or a bounded SotyHub proxy token."""
        if not JWT_SECRET:
            logger.error("JWT_SECRET is not configured")
            raise HTTPException(status_code=503, detail="Authentication is not configured")

        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            payload["_auth_source"] = "bofa_local"
            return payload
        except ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token has expired")
        except JWTError:
            pass

        if not SOTYHUB_PROXY_JWT_SECRET:
            raise HTTPException(status_code=401, detail="Could not validate credentials")

        try:
            payload = jwt.decode(
                token,
                SOTYHUB_PROXY_JWT_SECRET,
                algorithms=[JWT_ALGORITHM],
                audience=SOTYHUB_PROXY_AUDIENCE,
                issuer=SOTYHUB_PROXY_ISSUER,
            )
        except ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token has expired")
        except JWTError:
            raise HTTPException(status_code=401, detail="Could not validate credentials")

        uid = payload.get("sub")
        allowed_path = payload.get("bofa_path")
        allowed_method = payload.get("bofa_method")
        if (
            payload.get("token_use") != "sotyhub_proxy"
            or not isinstance(uid, str)
            or not uid
            or not isinstance(allowed_path, str)
            or not allowed_path.startswith("/")
            or not isinstance(allowed_method, str)
            or allowed_method.upper() not in {"GET", "POST"}
        ):
            raise HTTPException(status_code=401, detail="Could not validate credentials")

        return {
            "user_id": uid,
            "username": f"sotyhub:{uid}",
            "email": payload.get("email") if isinstance(payload.get("email"), str) else None,
            "role": "user",
            "_auth_source": "sotyhub_proxy",
            "_allowed_path": allowed_path,
            "_allowed_method": allowed_method.upper(),
        }
    
    def authenticate_user(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """Authenticate user credentials"""
        user = self.db.get_user_by_username(username)
        if not user:
            return None
        
        if not self.verify_password(password, user['password_hash']):
            return None
        
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
    
    def register_user(self, username: str, email: str, password: str, role: str = "user") -> Optional[int]:
        """Register new user"""
        password_hash = self.hash_password(password)
        user_id = self.db.create_user(username, email, password_hash, role)
        
        if user_id:
            logger.info(f"👤 User registered: {username} ({role})")
        
        return user_id
    
    def get_current_user(
        self,
        request: Request,
        credentials: HTTPAuthorizationCredentials = Depends(security),
    ) -> Dict[str, Any]:
        """Get current authenticated user"""
        token = credentials.credentials
        payload = self.verify_token(token)

        if payload.get("_auth_source") == "sotyhub_proxy":
            if (
                not hmac.compare_digest(payload["_allowed_path"], request.url.path)
                or not hmac.compare_digest(payload["_allowed_method"], request.method.upper())
            ):
                raise HTTPException(status_code=403, detail="BOFA proxy token scope mismatch")
            return {
                "user_id": payload["user_id"],
                "username": payload["username"],
                "email": payload.get("email"),
                "role": payload["role"],
            }
        
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
