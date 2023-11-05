from functools import lru_cache
from fastapi import FastAPI
import uvicorn
from api.v1 import authorization

from config.settings import settings


app = FastAPI()

app.include_router(authorization.router, prefix='/api')


if __name__ == "__main__":
    uvicorn.run("__main__:app", host="0.0.0.0", port=8001, log_level="debug", reload=True)
