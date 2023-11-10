from typing import Dict
from fastapi import Body, Depends, HTTPException, Header, APIRouter, Response

from schemas.authorization_schemas import *
from services.authentications import JWTBearer       
from utils.auth import check_password, hash_password
from services.mongo import get_mongo
from bson.objectid import ObjectId


router = APIRouter(prefix='/accounts')

user_collection = get_mongo()['user']


@router.post('/login', response_model=Dict)
async def login(
        payload: UserLoginSchema,
    ):
    
    user = await user_collection.find_one({'$or': [{'username': payload.username}, {'email': payload.username}]})
    
    if not user:
        raise HTTPException(status_code=403, detail="Invalid username or password")
    
    valid_cred = await check_password(payload.password, user['password']) 

    if not valid_cred:
        raise HTTPException(status_code=403, detail="Invalid username or password")
    print('check'*10)
    return {'user_id': str(user['_id']), 'username': user['username']}
    



@router.post('/register', response_model=Dict)
async def register(
        payload: CreateUserSchema = Body(),
    ):
    print('acc 1'* 20)

    existing_user = await user_collection.find_one({'$or': [{'username': payload.username}, {'email': payload.email}]})
    print('')
    if existing_user:
        raise HTTPException(status_code=422, detail="User already exists")
    
    new_user = payload.model_dump()

    hashed_pass = await hash_password(new_user['password'])
    new_user['password'] = hashed_pass

    await user_collection.insert_one(new_user)

    new_user['_id'] = str(new_user['_id'])
    print('acc 2'* 20)

    return Response(content=new_user, status_code=201)


@router.get('/profile')
async def profile(
        token: str = Depends(JWTBearer())
    ):
    print(token['user_identifier'])
    document_id = ObjectId(token['user_identifier'])
    print(document_id)
    user = await user_collection.find_one({'_id': document_id})
    user['_id'] = str(user['_id'])
    del user['password']
    return user


@router.post('/reset-password', response_model=Dict)
async def reset_password(
        payload: CreateUserSchema = Body(),
    ):

    pass
