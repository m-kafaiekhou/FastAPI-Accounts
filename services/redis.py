import redis.asyncio as aredis

from config.settings import get_settings


settings = get_settings()

redis = aredis.from_url(f"redis://{settings.redis_host}:{settings.redis_port}",
                       encoding="utf-8", decode_responses=True, db=0)


def get_redis():
    return redis