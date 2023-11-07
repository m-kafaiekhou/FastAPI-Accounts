import motor.motor_asyncio

from config.settings import get_settings

settings = get_settings()
mongo_url = f"mongodb://{settings.MONGO_HOST}:{settings.MONGO_PORT}"
client = motor.motor_asyncio.AsyncIOMotorClient(mongo_url)
database = client["users"]


def get_mongo():
    return database