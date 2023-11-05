from functools import lru_cache
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_name: str = "Authorization Service"
    secret_key: str
    jwt_algorithm: str

    jwt_access_lifetime_min: int = 60 * 24 * 7
    jwt_refresh_lifetime_min: int = jwt_access_lifetime_min * 10
    jwt_token_prefix: str

    redis_host: str
    redis_port: str

    class Config:
        env_file = '.env'


settings = Settings()


@lru_cache
def get_settings():
    return settings