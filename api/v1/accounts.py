from typing import Dict
from fastapi import Body, Depends, HTTPException, Header, APIRouter, Response

from schemas.authorization_schemas import *
from services.authentications import JWTBearer
from services.accounts import AccountsRequests
from utils.auth import generate_token, check_password
from services.redis import get_redis
from services.mongo import get_mongo


router = APIRouter(prefix='/auth')

user_collection = get_mongo()['user']


@router.post('/login', response_model=Dict)
async def login(
        payload: UserLoginSchema,
    ):
    
    user = await user_collection.find_one({'$or': [{'username': payload.username}, {'email': payload.username}]})
    
    if not user:
        raise HTTPException(status_code=403, detail="Invalid username or password")
    
    valid_cred = await check_password(payload.password, user.password) 

    if not valid_cred:
        raise HTTPException(status_code=403, detail="Invalid username or password")
        
    return Response()
    



@router.post('/register', response_model=Dict)
async def register(
        payload: UserSchema = Body(),
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


