import re
from pydantic import BaseModel, Field, EmailStr, validator


class CreateUserSchema(BaseModel):
    username: str 
    email: EmailStr
    password: str

    @validator('password')
    def password_validator(cls, v):
        if not re.search(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s]).{8,}$', v):
            raise ValueError('Password must be at least 8 characters long, one upper, one lower, one digit, and one symbol')
        return v

    @validator('username')
    def username_validator(cls, v):
        if not re.search(r'^[a-zA-Z0-9_-]{3,16}$', v):
            raise ValueError('Username should contain only Alphanumeric characters, and -_ ')
        return v
    

class UserSchema(CreateUserSchema):
    full_name: str | None = None 
    address: str | None = None
    _id: str | None = None

    @validator('full_name')
    def fullname_validator(cls, v):
        if not re.search(r'^[a-zA-Z ]{4,100}$', v):
            raise ValueError('Name must contain only alphabets and space.')
        return v
    
    @validator('address')
    def address_validator(cls, v):
        if not re.search(r'^[a-zA-Z0-9_- ]{10,254}$', v):
            raise ValueError('address should contain only Alphanumeric characters, and -_ ')
        return v


class UserLoginSchema(BaseModel):
    username: str
    password: str 

    @validator('password')
    def password_validator(cls, v):
        if not re.search(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s]).{8,}$', v):
            raise ValueError('Password must be at least 8 characters long, one upper, one lower, one digit, and one symbol')
        return v


class TokenSchema(BaseModel):
    refresh: str

