"""Autenticación basada en JWT.

NOTA (defecto sembrado - SAST): la clave secreta está embebida en el código
(hardcoded secret). SonarQube lo reporta como vulnerabilidad de seguridad.
En un entorno real debería leerse de una variable de entorno o de un gestor
de secretos. Se mantiene así de forma intencionada para demostrar el control
SAST y el Quality Gate del modelo DevSecPerOps.
"""

from datetime import datetime, timedelta
from typing import Optional

from jose import JWTError, jwt
from passlib.context import CryptContext

# DEFECTO SEMBRADO: secreto embebido en el código fuente
SECRET_KEY = "supersecretkey1234567890"  # noqa: S105
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(subject: str, expires_minutes: Optional[int] = None) -> str:
    expire = datetime.utcnow() + timedelta(
        minutes=expires_minutes or ACCESS_TOKEN_EXPIRE_MINUTES
    )
    payload = {"sub": subject, "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> Optional[str]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")
    except JWTError:
        return None
