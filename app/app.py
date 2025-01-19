from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, jwt_required, create_access_token
import boto3
from botocore.exceptions import NoCredentialsError
import os
from werkzeug.utils import secure_filename
from fastapi import FastAPI, Depends, UploadFile, File, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from minio import Minio
from pydantic_settings import BaseSettings
import uuid
import requests
from typing import Optional

app = Flask(__name__)
app.config.from_object("config.Config")
jwt = JWTManager(app)

s3 = boto3.client(
    "s3",
    endpoint_url=app.config["S3_ENDPOINT"],
    aws_access_key_id=app.config["S3_ACCESS_KEY"],
    aws_secret_access_key=app.config["S3_SECRET_KEY"],
)

class Settings(BaseSettings):
    MINIO_ROOT_USER: str = "minioadmin"
    MINIO_ROOT_PASSWORD: str = "minioadmin"
    MINIO_ENDPOINT: str = "minio:9000"
    MINIO_BUCKET: str = "files"
    
    KEYCLOAK_URL: str = "http://keycloak:8080"
    KEYCLOAK_REALM: str = "myrealm"
    KEYCLOAK_CLIENT_ID: str = "myclient"
    KEYCLOAK_CLIENT_SECRET: str = "your-client-secret"

    class Config:
        env_file = ".env"

settings = Settings()


app = FastAPI(title="File Management API")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

minio_client = Minio(
    settings.MINIO_ENDPOINT,
    access_key=settings.MINIO_ROOT_USER,
    secret_key=settings.MINIO_ROOT_PASSWORD,
    secure=False
)


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Невалидни credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        response = requests.get(
            f"{settings.KEYCLOAK_URL}/realms/{settings.KEYCLOAK_REALM}/protocol/openid-connect/userinfo",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        if response.status_code != 200:
            raise credentials_exception
            
        return response.json()
    except Exception:
        raise credentials_exception


@app.on_event("startup")
async def startup_event():
    if not minio_client.bucket_exists(settings.MINIO_BUCKET):
        minio_client.make_bucket(settings.MINIO_BUCKET)

@app.route("/upload", methods=["POST"])
@jwt_required()
def upload_file():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400
    file = request.files["file"]
    filename = secure_filename(file.filename)

    try:
        s3.upload_fileobj(file, app.config["S3_BUCKET"], filename)
        return jsonify({"message": "File uploaded", "file_id": filename}), 201
    except NoCredentialsError:
        return jsonify({"error": "S3 credentials error"}), 500


@app.route("/download/<file_id>", methods=["GET"])
@jwt_required()
def download_file(file_id):
    try:
        file_obj = s3.get_object(Bucket=app.config["S3_BUCKET"], Key=file_id)
        return file_obj["Body"].read(), 200
    except s3.exceptions.NoSuchKey:
        return jsonify({"error": "File not found"}), 404


@app.route("/update/<file_id>", methods=["PUT"])
@jwt_required()
def update_file(file_id):
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400
    file = request.files["file"]

    try:
        s3.upload_fileobj(file, app.config["S3_BUCKET"], file_id)
        return jsonify({"message": "File updated"}), 200
    except NoCredentialsError:
        return jsonify({"error": "S3 credentials error"}), 500


@app.route("/delete/<file_id>", methods=["DELETE"])
@jwt_required()
def delete_file(file_id):
    try:
        s3.delete_object(Bucket=app.config["S3_BUCKET"], Key=file_id)
        return jsonify({"message": "File deleted"}), 200
    except s3.exceptions.NoSuchKey:
        return jsonify({"error": "File not found"}), 404


@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")


    if username == "test" and password == "test":
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token), 200

    return jsonify({"error": "Invalid credentials"}), 401


@app.post("/api/upload")
async def upload_file(
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user)
):
    file_id = str(uuid.uuid4())
    try:
        minio_client.put_object(
            settings.MINIO_BUCKET,
            file_id,
            file.file,
            file.size
        )
        return {"file_id": file_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/download/{file_id}")
async def download_file(
    file_id: str,
    current_user: dict = Depends(get_current_user)
):
    try:
        response = minio_client.get_object(settings.MINIO_BUCKET, file_id)
        return response.read()
    except Exception as e:
        raise HTTPException(status_code=404, detail="Файлът не е намерен")

@app.put("/api/update/{file_id}")
async def update_file(
    file_id: str,
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user)
):
    try:
        minio_client.remove_object(settings.MINIO_BUCKET, file_id)
        minio_client.put_object(
            settings.MINIO_BUCKET,
            file_id,
            file.file,
            file.size
        )
        return {"message": "Файлът е обновен успешно"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/delete/{file_id}")
async def delete_file(
    file_id: str,
    current_user: dict = Depends(get_current_user)
):
    try:
        minio_client.remove_object(settings.MINIO_BUCKET, file_id)
        return {"message": "Файлът е изтрит успешно"}
    except Exception as e:
        raise HTTPException(status_code=404, detail="Файлът не е намерен")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
