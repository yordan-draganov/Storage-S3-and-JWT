# Storage-S3-and-JWT


This project implements a secure file storage service using MinIO as the storage backend and Keycloak for authentication. The service provides REST API endpoints for file operations (upload, download, update, delete) with JWT-based authentication.

#Setup and Installation

##Clone the repository:

git clone <repository-url>
cd <project-directory>

##Start the services:

docker-compose up --build

#Authentication
##First, obtain an access token from Keycloak:

curl -X POST \
  http://localhost:8080/realms/my-realm/protocol/openid-connect/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=password' \
  -d 'client_id=my-app' \
  -d 'client_secret=client-secret' \
  -d 'username=test-user' \
  -d 'password=password'

##Upload File
curl -X POST \
  http://localhost:5000/api/upload \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -F "file=@/path/to/your/file"

##Download File
curl -X GET \
  http://localhost:5000/api/download/FILE_ID \
  -H "Authorization: Bearer YOUR_TOKEN"
##Update File
curl -X PUT \
  http://localhost:5000/api/update/FILE_ID \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -F "file=@/path/to/your/new/file"
##Delete File
curl -X DELETE \
  http://localhost:5000/api/delete/FILE_ID \
  -H "Authorization: Bearer YOUR_TOKEN"
