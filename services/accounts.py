import httpx
from utils.singleton import Singleton
# import asyncio


class AccountsRequests(metaclass=Singleton):
    REGISTER_URL = 'localhost:8005/api/accounts/register/'
    LOGIN_URL = 'localhost:8005/api/accounts/login/'

    async def register(self, data: dict):
        response = await self.apost(self.REGISTER_URL, data)
        return response
    
    async def login(self, data: dict):
        response = await self.apost(self.LOGIN_URL, data)
        return response

    async def apost(self, url: str, data: dict):
        async with httpx.AsyncClient() as client:
            return await client.post(url=url, json=data)
        

adapter = AccountsRequests()

def get_adapter():
    return adapter
