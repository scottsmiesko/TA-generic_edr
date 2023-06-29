from fastapi import FastAPI
from datetime import datetime

app = FastAPI()


@app.head("/")
async def root():
    pass


@app.post("/api/v1/authenticate/simple")
async def auth():
    return {"secret": "1f10d113-e9e7-4174-b6e1-f8de66da7d1c", "expiry": str(datetime.utcnow())}
