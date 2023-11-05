from typing import Dict
from fastapi import Body, Depends, HTTPException, Header, APIRouter

from schemas.authorization_schemas import *
from services.authentications import JWTBearer
from services.accounts import AccountsRequests
from utils.auth import generate_token
from services.redis import get_redis


router = APIRouter(prefix='/auth')


@router.post('/login', response_model=Dict)
async def login(
        payload: UserLoginSchema,
    ):
    adapter = AccountsRequests()

    response = await adapter.login(payload.model_dump())

    if response.status_code == 200:
        token = await generate_token(response.json().get('user'))
        return token
    
    else:
        return response
    


@router.post('/register', response_model=Dict)
async def register(
        payload: CreateUserSchema = Body(),
    ):

    adapter = AccountsRequests()

    response = await adapter.register(payload.model_dump())

    return response


@router.post('/logout', response_model=Dict)
async def logout(
        token: bool = Depends(JWTBearer())
    ):

    jti = token['jti']
    get_redis().delete(jti)

    return {'message': 'Logged out'}


@router.get('/refresh')
async def refresh(token: TokenSchema = Body()):
    try:
        payload = JWTBearer().validate_token(token)
    except:
        raise HTTPException(403, detail='Invalid or expired token')
    else:
        new_token = await generate_token(payload['user_identifier'])
        return new_token


@router.get('/testauth')
async def testauth(token: bool = Depends(JWTBearer())):
    return {'message': 'Authenticated Ahmad Mohsen'}


# @router.post('/reset-password', response_model=Dict)
# async def reset_password(
#         payload: CreateUserSchema = Body(),
#     ):

#     pass


# @router.post('/forgot-password', response_model=Dict)
# async def forgot_password(
#         payload: CreateUserSchema = Body(),
#     ):

#     pass


# @router.post('/forgot-password-reset', response_model=Dict)
# async def forgot_password_reset(
#         payload: CreateUserSchema = Body(),
#     ):

#     pass


