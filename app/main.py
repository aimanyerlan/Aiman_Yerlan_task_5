from fastapi import FastAPI
from app.routers import auth
from app import models, database

app = FastAPI()
app.include_router(auth.router)

models.Base.metadata.create_all(bind=database.engine)

