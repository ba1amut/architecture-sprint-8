import os
import time
from functools import lru_cache

import requests
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt
from jose.jwk import construct
from starlette import status


KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://localhost:8080")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "reports-realm")
REQUIRED_ROLE = os.getenv("REQUIRED_ROLE", "prothetic_user")
ALLOWED_ALGORITHMS = os.getenv("ALLOWED_ALGORITHMS", "HS256,RS256").split(",")
CACHE_TTL = int(os.getenv("KEY_CACHE_TTL", 3600)) 
security = HTTPBearer()
app = FastAPI()


app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("ALLOWED_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@lru_cache(maxsize=1)
def get_public_key():
    """Get and cache the public key from Keycloak with TTL"""
    try:
        url = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/certs"
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        jwks = response.json()
        return jwks['keys'][0]
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Unable to fetch public key from Keycloak"
        )

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        key_data = get_public_key()
        public_key = construct(key_data)
        

        token_payload = jwt.decode(
            token,
            key=public_key,
            algorithms=ALLOWED_ALGORITHMS,
            options={"verify_aud": False}  
        )
        

        if token_payload.get("exp", 0) < time.time():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token expired",
            )
            

        if REQUIRED_ROLE not in token_payload.get('realm_access', {}).get('roles', []):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="The required role is missing"
            )
            
        return token_payload
        
    except jwt.JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during authentication"
        )

@app.get("/reports")
def get_all_reports(user=Depends(verify_token)):
    return {"user": user.get('name'), "reports": "report.zip"}