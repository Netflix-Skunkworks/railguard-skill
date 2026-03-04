import requests
import json
import base64
from typing import Dict, Any
import os
import sys

# Add the parent directory to the path so we can import the crypto module
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import our crypto module to verify functionality
try:
    from fastapi_app.crypto import encrypt_aes, decrypt_aes, sign_data_rsa, verify_signature_rsa
except ImportError:
    print("Warning: Could not import crypto module. Some tests may fail.")

# Base URL for the API
BASE_URL = "http://localhost:8000"

# Hardcoded credentials for testing - DO NOT USE IN PRODUCTION
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"
USER_USERNAME = "user"
USER_PASSWORD = "user123"

# Store the JWT token for authenticated requests
JWT_TOKEN = None

def print_response(response: requests.Response) -> None:
    """Print the response in a formatted way"""
    print(f"Status Code: {response.status_code}")
    print("Response:")
    try:
        print(json.dumps(response.json(), indent=2))
    except:
        print(response.text)
    print("-" * 50)

def test_root() -> None:
    """Test the root endpoint"""
    print("\nTesting GET / endpoint...")
    response = requests.get(f"{BASE_URL}/")
    print_response(response)

def test_search_user(username: str) -> None:
    """Test the user search endpoint"""
    print(f"\nTesting GET /users/search endpoint with username={username}...")
    response = requests.get(f"{BASE_URL}/users/search", params={"username": username})
    print_response(response)

def test_search_products(name: str, category: str = None) -> None:
    """Test the product search endpoint"""
    print(f"\nTesting GET /products/search endpoint with name={name}, category={category}...")
    params = {"name": name}
    if category:
        params["category"] = category
    response = requests.get(f"{BASE_URL}/products/search", params=params)
    print_response(response)

def test_get_weather(city: str, country: str) -> None:
    """Test the weather endpoint"""
    print(f"\nTesting GET /weather endpoint with city={city}, country={country}...")
    response = requests.get(f"{BASE_URL}/weather", params={"city": city, "country": country})
    print_response(response)

def test_register_user(user_data: Dict[str, Any]) -> None:
    """Test the user registration endpoint"""
    print("\nTesting POST /users/register endpoint...")
    response = requests.post(f"{BASE_URL}/users/register", json=user_data)
    print_response(response)

def test_create_product(product_data: Dict[str, Any]) -> None:
    """Test the product creation endpoint"""
    print("\nTesting POST /products/create endpoint...")
    response = requests.post(f"{BASE_URL}/products/create", json=product_data)
    print_response(response)

def test_submit_feedback(feedback_data: Dict[str, Any]) -> None:
    """Test the feedback submission endpoint"""
    print("\nTesting POST /feedback/submit endpoint...")
    response = requests.post(f"{BASE_URL}/feedback/submit", json=feedback_data)
    print_response(response)

def test_create_order(order_data: Dict[str, Any]) -> None:
    """Test the order creation endpoint"""
    print("\nTesting POST /orders/create endpoint...")
    response = requests.post(f"{BASE_URL}/orders/create", json=order_data)
    print_response(response)

def run_tests() -> None:
    """Run all tests"""
    # Test GET endpoints
    test_root()
    test_search_user("johndoe")
    test_search_products("smartphone", "electronics")
    test_get_weather("London", "GB")
    
    # Test POST endpoints
    user_data = {
        "username": "johndoe",
        "email": "john@example.com",
        "full_name": "John Doe",
        "password": "securepassword"
    }
    test_register_user(user_data)
    
    product_data = {
        "name": "Smartphone",
        "description": "A high-end smartphone with great features",
        "price": 999.99,
        "category": "electronics",
        "in_stock": True,
        "tags": ["tech", "mobile", "5G"]
    }
    test_create_product(product_data)
    
    feedback_data = {
        "user_id": 1,
        "feedback_type": "feature",
        "subject": "New Feature Request",
        "message": "I would like to see this new feature implemented...",
        "rating": 4
    }
    test_submit_feedback(feedback_data)
    
    order_data = {
        "user_id": 1,
        "items": [
            {
                "product_id": 1,
                "quantity": 2,
                "unit_price": 999.99
            },
            {
                "product_id": 2,
                "quantity": 1,
                "unit_price": 49.99
            }
        ],
        "shipping_address": "123 Main St, Anytown, AN 12345",
        "payment_method": "credit_card"
    }
    test_create_order(order_data)

def test_login(username: str, password: str) -> None:
    """Test the login endpoint to get a JWT token"""
    global JWT_TOKEN
    print(f"\nTesting POST /token endpoint with username={username}...")
    response = requests.post(
        f"{BASE_URL}/token",
        json={"username": username, "password": password}
    )
    print_response(response)
    
    if response.status_code == 200:
        JWT_TOKEN = response.json().get("access_token")
        print(f"JWT Token received: {JWT_TOKEN[:10]}...")
    
    return response

def test_user_profile() -> None:
    """Test the user profile endpoint"""
    print("\nTesting GET /user/profile endpoint...")
    headers = {"Authorization": f"Bearer {JWT_TOKEN}"} if JWT_TOKEN else {}
    response = requests.get(f"{BASE_URL}/user/profile", headers=headers)
    print_response(response)
    return response

def test_encrypt_decrypt() -> None:
    """Test the encryption and decryption endpoints"""
    # Test encryption
    print("\nTesting POST /crypto/encrypt endpoint...")
    plaintext = "This is a secret message that should be encrypted"
    response = requests.post(
        f"{BASE_URL}/crypto/encrypt",
        json={"text": plaintext}
    )
    print_response(response)
    
    if response.status_code == 200:
        encrypted_text = response.json().get("encrypted_text")
        
        # Test decryption
        print("\nTesting POST /crypto/decrypt endpoint...")
        response = requests.post(
            f"{BASE_URL}/crypto/decrypt",
            json={"encrypted_text": encrypted_text}
        )
        print_response(response)
        
        # Verify the decrypted text matches the original
        if response.status_code == 200:
            decrypted_text = response.json().get("decrypted_text")
            if decrypted_text == plaintext:
                print("SUCCESS: Encryption/Decryption test passed: Original text matches decrypted text")
            else:
                print("ERROR: Encryption/Decryption test failed: Original text does not match decrypted text")

def test_sign_verify() -> None:
    """Test the signing and verification endpoints"""
    # Test signing
    print("\nTesting POST /crypto/sign endpoint...")
    data = {"id": 123, "message": "This data needs to be signed for integrity"}
    response = requests.post(
        f"{BASE_URL}/crypto/sign",
        json={"data": data}
    )
    print_response(response)
    
    if response.status_code == 200:
        signature = response.json().get("signature")
        
        # Test verification with correct data
        print("\nTesting POST /crypto/verify endpoint with correct data...")
        response = requests.post(
            f"{BASE_URL}/crypto/verify",
            json={"data": data, "signature": signature}
        )
        print_response(response)
        
        # Test verification with tampered data
        print("\nTesting POST /crypto/verify endpoint with tampered data...")
        tampered_data = dict(data)
        tampered_data["message"] = "This data has been tampered with"
        response = requests.post(
            f"{BASE_URL}/crypto/verify",
            json={"data": tampered_data, "signature": signature}
        )
        print_response(response)

def test_secure_anime_creation() -> None:
    """Test the secure anime creation endpoint"""
    print("\nTesting POST /anime/secure/create endpoint...")
    
    if not JWT_TOKEN:
        print("ERROR: JWT Token not available. Please run test_login first.")
        return
    
    headers = {"Authorization": f"Bearer {JWT_TOKEN}"}
    anime_data = {
        "title": "Secure Anime Title",
        "description": "This description will be encrypted in the database",
        "genres": ["action", "adventure"],
        "episodes": 24,
        "rating": "pg_13",
        "year": 2025,
        "studio": "Security Studios"
    }
    
    response = requests.post(
        f"{BASE_URL}/anime/secure/create",
        json=anime_data,
        headers=headers
    )
    print_response(response)
    
    if response.status_code == 201:
        anime_id = response.json().get("anime_id")
        
        # Test retrieving the secure anime
        print(f"\nTesting GET /anime/secure/{anime_id} endpoint...")
        response = requests.get(
            f"{BASE_URL}/anime/secure/{anime_id}",
            headers=headers
        )
        print_response(response)
        
        # Test retrieving and decrypting the secure anime
        print(f"\nTesting GET /anime/secure/{anime_id}?decrypt=true endpoint...")
        response = requests.get(
            f"{BASE_URL}/anime/secure/{anime_id}?decrypt=true",
            headers=headers
        )
        print_response(response)

def test_aws_s3_operations() -> None:
    """Test the AWS S3 operations endpoints"""
    print("\nTesting AWS S3 operations...")
    
    if not JWT_TOKEN:
        print("ERROR: JWT Token not available. Please run test_login first.")
        return
    
    headers = {"Authorization": f"Bearer {JWT_TOKEN}"}
    
    # Test uploading to S3
    print("\nTesting POST /aws/s3/upload endpoint...")
    data = {
        "key": "test-data.json",
        "data": {
            "name": "Test Data",
            "value": "This is test data for S3",
            "timestamp": "2025-06-20T22:00:00Z"
        }
    }
    
    response = requests.post(
        f"{BASE_URL}/aws/s3/upload",
        json=data,
        headers=headers
    )
    print_response(response)
    
    # Test listing S3 objects
    print("\nTesting GET /aws/s3/list endpoint...")
    response = requests.get(
        f"{BASE_URL}/aws/s3/list",
        headers=headers
    )
    print_response(response)
    
    # Test downloading from S3
    print("\nTesting POST /aws/s3/download endpoint...")
    response = requests.post(
        f"{BASE_URL}/aws/s3/download",
        json={"key": "test-data.json"},
        headers=headers
    )
    print_response(response)
    
    # Test deleting from S3
    print("\nTesting DELETE /aws/s3/delete endpoint...")
    response = requests.delete(
        f"{BASE_URL}/aws/s3/delete?key=test-data.json",
        headers=headers
    )
    print_response(response)

def run_crypto_tests() -> None:
    """Run all crypto and AWS related tests"""
    # First login to get JWT token
    test_login(ADMIN_USERNAME, ADMIN_PASSWORD)
    
    # Test user profile
    test_user_profile()
    
    # Test crypto operations
    test_encrypt_decrypt()
    test_sign_verify()
    
    # Test secure anime creation
    test_secure_anime_creation()
    
    # Test AWS S3 operations
    test_aws_s3_operations()

if __name__ == "__main__":
    print("Starting API tests...")
    print("Make sure the FastAPI server is running at http://localhost:8000")
    print("=" * 50)
    
    try:
        # Choose which tests to run
        test_type = input("Run standard tests (1) or crypto/AWS tests (2)? ")
        
        if test_type == "1":
            run_tests()
        elif test_type == "2":
            run_crypto_tests()
        else:
            print("Invalid choice. Running all tests...")
            run_tests()
            print("\n" + "=" * 50)
            run_crypto_tests()
        
        print("\nAll tests completed successfully!")
    except requests.exceptions.ConnectionError:
        print("\nError: Could not connect to the API server.")
        print("Make sure the server is running with: uvicorn main:app --reload")
    except Exception as e:
        print(f"\nError during testing: {e}")