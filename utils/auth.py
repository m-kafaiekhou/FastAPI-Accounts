import datetime
from uuid import uuid4
import bcrypt
import jwt
from config.settings import get_settings
from services.redis import get_redis


settings = get_settings()


async def hash_password(password) -> str:
    """Transforms password from it's raw textual form to 
    cryptographic hashes
    """
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())


async def check_password(password: str, hashed_password: str) -> bool:
    """Checks if a password matches a hashed password"""
    return bcrypt.checkpw(password.encode(), hashed_password)


async def gen_jti():
    return uuid4().hex


async def get_token_exp(mins=60*24*7):
    now = datetime.datetime.utcnow()
    expire_time = now + datetime.timedelta(minutes=mins)
    return expire_time


async def generate_token(user_id) -> dict:
    """Generate access token for user"""

    jti = await gen_jti()

    access_exp = await get_token_exp(settings.jwt_access_lifetime_min)
    refresh_exp = await get_token_exp(settings.jwt_refresh_lifetime_min)

    get_redis().set(jti, user_id, ex=refresh_exp)

    tokens = {
        "access_token": jwt.encode(
            {'type': 'access', 'exp': access_exp, "user_identifier": user_id, 'jti': jti},
            settings.secret_key
        ),
        "refresh_token": jwt.encode(
            {'type': 'refresh', 'exp': refresh_exp, "user_identifier": user_id, 'jti': jti},
            settings.secret_key
        )
    }
    return tokens


async def decode(token):
    decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=settings.JWT_ALGORITHM)
    return decoded_token


async def encode(token):
    encoded_token = jwt.encode(token, settings.SECRET_KEY, algorithms=settings.JWT_ALGORITHM)
    return encoded_token
