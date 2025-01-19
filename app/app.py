from flask import Flask, request, send_file, jsonify
from werkzeug.utils import secure_filename
from functools import wraps
from minio import Minio
import requests
import json
import os
import uuid
import io
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

MINIO_ENDPOINT = "minio:9000"
MINIO_ACCESS_KEY = "minioadmin"
MINIO_SECRET_KEY = "minioadmin"
BUCKET_NAME = "files"
KEYCLOAK_URL = "http://keycloak:8080"
REALM_NAME = "my-realm"
CLIENT_ID = "my-app"
CLIENT_SECRET = "client-secret"


minio_client = Minio(
    MINIO_ENDPOINT,
    access_key=MINIO_ACCESS_KEY,
    secret_key=MINIO_SECRET_KEY,
    secure=False
)

try:
    if not minio_client.bucket_exists(BUCKET_NAME):
        minio_client.make_bucket(BUCKET_NAME)
        logger.info(f"Created bucket: {BUCKET_NAME}")
except Exception as e:
    logger.error(f"Error with bucket creation: {str(e)}")
    raise

def verify_token(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = None

        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1]
            except IndexError:
                return jsonify({'message': 'Invalid token format'}), 401
        
        if not token:
            return jsonify({'message': 'Token is missing'}), 401

        try:
            r = requests.get(f"{KEYCLOAK_URL}/realms/{REALM_NAME}/.well-known/openid-configuration")
            config = r.json()
            jwks_uri = config['jwks_uri']
            r = requests.get(jwks_uri)
            public_key = r.json()['keys'][0]
            
            from jose import jwt
            decoded_token = jwt.decode(
                token,
                public_key,
                algorithms=['RS256'],
                audience=CLIENT_ID
            )
            logger.info(f"Token verified successfully for user: {decoded_token.get('preferred_username')}")

            return f(*args, **kwargs)
        except Exception as e:
            logger.error(f"Token verification failed: {str(e)}")
            return jsonify({'message': 'Invalid token'}), 401
        
    return decorated_function

@app.route('/')
def home():
    return jsonify({"message": "File Storage API is running"}), 200

@app.route('/api/upload', methods=['POST'])
@verify_token
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        file_id = secure_filename(file.filename)

        file_content = file.read()
        file_size = len(file_content)

        minio_client.put_object(
            BUCKET_NAME,
            file_id,
            io.BytesIO(file_content),
            file_size
        )
        
        logger.info(f"File uploaded successfully: {file_id}")
        return jsonify({'message': 'File uploaded successfully', 'file_id': file_id})
        
    except Exception as e:
        logger.error(f"Upload failed: {str(e)}")
        return jsonify({'error': 'File upload failed'}), 500

@app.route('/api/download/<file_id>', methods=['GET'])
@verify_token
def download_file(file_id):
    try:
        file_object = minio_client.get_object(BUCKET_NAME, file_id)
        return send_file(io.BytesIO(file_object.read()), as_attachment=True, download_name=file_id)
    except Exception as e:
        logger.error(f"Download failed: {str(e)}")
        return jsonify({'error': 'File not found or download failed'}), 404

@app.route('/api/update/<file_id>', methods=['PUT'])
@verify_token
def update_file(file_id):
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        file_content = file.read()
        file_size = len(file_content)

        try:
            minio_client.stat_object(BUCKET_NAME, file_id)
        except Exception:
            return jsonify({'error': 'File not found'}), 404

        minio_client.put_object(
            BUCKET_NAME,
            file_id,
            io.BytesIO(file_content),
            file_size
        )
        
        logger.info(f"File updated successfully: {file_id}")
        return jsonify({'message': 'File updated successfully'})
        
    except Exception as e:
        logger.error(f"Update failed: {str(e)}")
        return jsonify({'error': 'File update failed'}), 500

@app.route('/api/delete/<file_id>', methods=['DELETE'])
@verify_token
def delete_file(file_id):
    try:
        try:
            minio_client.stat_object(BUCKET_NAME, file_id)
        except Exception:
            return jsonify({'error': 'File not found'}), 404
        
        minio_client.remove_object(BUCKET_NAME, file_id)
        
        logger.info(f"File deleted successfully: {file_id}")
        return jsonify({'message': 'File deleted successfully'})
        
    except Exception as e:
        logger.error(f"Delete failed: {str(e)}")
        return jsonify({'error': 'File deletion failed'}), 500

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Not found'}), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
