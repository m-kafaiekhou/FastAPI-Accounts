from config.settings import get_settings
from fastapi import Request, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from utils.auth import decode
from services.redis import get_redis
from fastapi.exceptions import HTTPException
import jwt


settings = get_settings()


class JWTBearer(HTTPBearer):
    def __init__(self, auto_error: bool = True):
        super(JWTBearer, self).__init__(auto_error=auto_error)

    async def __call__(self, request: Request):
        credentials: HTTPAuthorizationCredentials = await super(JWTBearer, self).__call__(request)
        if credentials:
            if not credentials.scheme == settings.jwt_token_prefix:
                raise HTTPException(status_code=403, detail="Invalid authentication scheme.")
            if not self.verify_jwt(credentials.credentials):
                raise HTTPException(status_code=403, detail="Invalid token or expired token.")
            return await decode(credentials.credentials)
        else:
            raise HTTPException(status_code=403, detail="Invalid authorization code.")

    async def verify_jwt(self, jwtoken: str) -> bool:
        isTokenValid: bool = False

        try:
            payload = await decode(jwtoken)

        except jwt.InvalidSignatureError:
            raise HTTPException(status_code=403 ,detail='Invalid signature')
        
        except Exception as e:
            print(e)
            raise HTTPException(status_code=401 ,detail='Token Expired')

        jti = payload['jti']
        token = get_redis().get(jti)

        if token:
            return payload
        raise HTTPException(status_code=403, detail='token not in white list')
    
    async def get_the_token_from_header(self, token):
        token = token.replace(settings.jwt_token_prefix, '').replace(' ', '')
        return token
    
    async def validate_token(self, token):
        cleaned_token = self.get_the_token_from_header(token)
        payload = self.verify_jwt(cleaned_token)
        return payload
    