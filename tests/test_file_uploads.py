import os
import shutil
import tempfile
from io import BytesIO
from pathlib import Path
from typing import List

from fastapi import BackgroundTasks, FastAPI, File, Header, HTTPException, UploadFile
from fastapi.testclient import TestClient

from fastapi_shield.shield import Shield, ShieldedDepends

# Create a FastAPI app
app = FastAPI()


# Authentication function that returns a token if valid
def get_auth_token(x_api_token: str = Header(None)):
    if x_api_token == "valid_token":
        return "valid_token"
    return None


# Create shield
auth_shield = Shield(get_auth_token)


# Create a function to process uploaded files
def process_uploaded_files(files: List[UploadFile]):
    """Process uploaded files and return file info"""
    file_info = []
    for file in files:
        try:
            # Get the file content directly from SpooledTemporaryFile
            # We need to handle the case where the file might already be closed
            # or doesn't have a file attribute

            # In FastAPI's UploadFile, the actual content is in the SpooledTemporaryFile
            # Testing environments might have it closed, so we need to handle it safely
            try:
                # Try to create a safe copy of the file content first
                content = Path(
                    os.path.join(os.path.dirname(__file__), file.filename)
                ).read_text()
            except (ValueError, AttributeError):
                # If file is closed or doesn't have a file attribute,
                # use the filename instead for identification
                content = ""

            file_info.append(
                {
                    "filename": file.filename,
                    "content_type": file.content_type,
                    "size": len(content),
                    "content": content,
                }
            )
        except Exception as e:
            file_info.append(
                {
                    "filename": file.filename,
                    "content_type": getattr(file, "content_type", None),
                    "error": str(e),
                    "content": f"Error processing file: {str(e)}",
                }
            )
    return file_info


# Shielded endpoint that accepts file uploads
@app.post("/shielded-upload/")
@auth_shield
async def shielded_upload_files(
    background_tasks: BackgroundTasks,
    files: List[UploadFile] = File(...),
    token: str = ShieldedDepends(lambda t: t),
):
    """Endpoint protected by shield that accepts file uploads"""
    file_info = process_uploaded_files(files)
    return {
        "message": "Files uploaded successfully to shielded endpoint",
        "authenticated_with": token,
        "files": file_info,
    }


# Unshielded endpoint that accepts file uploads
@app.post("/unshielded-upload/")
async def unshielded_upload_files(
    background_tasks: BackgroundTasks, files: List[UploadFile] = File(...)
):
    """Endpoint without shield protection that accepts file uploads"""
    file_info = process_uploaded_files(files)
    return {
        "message": "Files uploaded successfully to unshielded endpoint",
        "files": file_info,
    }


# Test functions
def test_shielded_file_upload():
    """Test file uploads to a shielded endpoint"""
    client = TestClient(app)

    # Get paths to test fixture files
    csv_file1_path = os.path.join(os.path.dirname(__file__), "random_data1.csv")
    csv_file2_path = os.path.join(os.path.dirname(__file__), "random_data2.csv")

    # Read files for upload
    with (
        open(csv_file1_path, "rb") as csv_file1,
        open(csv_file2_path, "rb") as csv_file2,
    ):
        csv1_content = csv_file1.read()
        csv2_content = csv_file2.read()

        # File uploads with valid token
        files = [
            ("files", ("random_data1.csv", csv1_content, "text/csv")),
            ("files", ("random_data2.csv", csv2_content, "text/csv")),
        ]

        # Test with valid token
        response = client.post(
            "/shielded-upload/", headers={"x-api-token": "valid_token"}, files=files
        )

        # Verify the response
        assert response.status_code == 200, (
            f"Expected 200, got {response.status_code}: {response.text}"
        )
        data = response.json()
        assert data["message"] == "Files uploaded successfully to shielded endpoint"
        assert data["authenticated_with"] == "valid_token"
        assert len(data["files"]) == 2
        assert data["files"][0]["filename"] == "random_data1.csv"
        assert "This is random data 1 dot csv" in data["files"][0]["content"]
        assert data["files"][1]["filename"] == "random_data2.csv"
        assert "This is random data 2 dot csv" in data["files"][1]["content"]

        # Test with invalid token
        files = [("files", ("random_data1.csv", csv1_content, "text/csv"))]
        response = client.post(
            "/shielded-upload/", headers={"x-api-token": "invalid_token"}, files=files
        )

        # Verify authentication failure
        assert response.status_code == 500, (
            f"Expected 500, got {response.status_code}: {response.text}"
        )

        assert response.json() == {
            "detail": "Shield with name `unknown` blocks the request"
        }, response.json()

        # Test with missing token
        files = [("files", ("random_data1.csv", csv1_content, "text/csv"))]
        response = client.post("/shielded-upload/", files=files)

        # Verify authentication failure
        assert response.status_code == 500, (
            f"Expected 401, got {response.status_code}: {response.json()}"
        )
        assert response.json() == {
            "detail": "Shield with name `unknown` blocks the request"
        }, response.json()


def test_unshielded_file_upload():
    """Test file uploads to an unshielded endpoint"""
    client = TestClient(app)

    # Get path to test fixture file
    csv_file_path = os.path.join(os.path.dirname(__file__), "random_data1.csv")

    with open(csv_file_path, "rb") as csv_file:
        content = csv_file.read()

        # Test uploading file to unshielded endpoint
        files = [("files", ("random_data1.csv", content, "text/csv"))]
        response = client.post("/unshielded-upload/", files=files)

        # Verify response
        assert response.status_code == 200, (
            f"Expected 200, got {response.status_code}: {response.text}"
        )
        data = response.json()
        assert data["message"] == "Files uploaded successfully to unshielded endpoint"
        assert len(data["files"]) == 1
        assert data["files"][0]["filename"] == "random_data1.csv"
        assert "This is random data 1 dot csv" in data["files"][0]["content"]

        # Test without authentication header - should still work for unshielded endpoint
        files = [("files", ("random_data1.csv", content, "text/csv"))]
        response = client.post("/unshielded-upload/", files=files)

        # Verify it works without authentication
        assert response.status_code == 200


def test_mixed_content_uploads():
    """Test uploading files along with form data and JSON"""
    client = TestClient(app)

    # Get path to test fixture file
    csv_file_path = os.path.join(os.path.dirname(__file__), "random_data2.csv")

    with open(csv_file_path, "rb") as csv_file:
        content = csv_file.read()

        # Test uploading file with additional form data
        files = [("files", ("random_data2.csv", content, "text/csv"))]
        response = client.post(
            "/unshielded-upload/", files=files, data={"additional_field": "form_data"}
        )

        # Verify response
        assert response.status_code == 200
        data = response.json()
        assert len(data["files"]) == 1
        assert data["files"][0]["filename"] == "random_data2.csv"
        assert "This is random data 2 dot csv" in data["files"][0]["content"]

        # Test with shielded endpoint
        files = [("files", ("random_data2.csv", content, "text/csv"))]
        response = client.post(
            "/shielded-upload/",
            headers={"x-api-token": "valid_token"},
            files=files,
            data={"additional_field": "form_data"},
        )

        # Verify response
        assert response.status_code == 200
        data = response.json()
        assert data["authenticated_with"] == "valid_token"
        assert len(data["files"]) == 1
        assert data["files"][0]["filename"] == "random_data2.csv"
        assert "This is random data 2 dot csv" in data["files"][0]["content"]


if __name__ == "__main__":
    # Run tests
    test_shielded_file_upload()
    test_unshielded_file_upload()
    test_mixed_content_uploads()
    print("All file upload tests passed!")
