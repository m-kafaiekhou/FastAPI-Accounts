from functools import lru_cache
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_name: str = "Authorization Service"
    secret_key: str
    jwt_algorithm: str

    redis_host: str
    redis_port: str

    MONGO_HOST: str
    MONGO_PORT: str

    class Config:
        env_file = '.env'


settings = Settings()


@lru_cache
def get_settings():
    return settings