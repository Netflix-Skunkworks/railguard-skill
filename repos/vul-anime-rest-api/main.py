from fastapi import FastAPI, Query, Path, Body, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from enum import Enum
import os
import json
import subprocess
import requests
import pickle
import base64

# Import our crypto and AWS modules with hardcoded credentials
from crypto import encrypt_aes, decrypt_aes, sign_data_rsa, verify_signature_rsa, generate_jwt, validate_jwt
from aws_config import upload_to_s3, download_from_s3, list_objects_in_s3, delete_from_s3
# Import config with hardcoded credentials and JDBC configuration
from config import SECURE_CONFIG, JDBC_CONFIG

app = FastAPI(title="Anime Recommendations API",
              description="An API for anime recommendations",
              version="1.0.0")

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files directory
static_dir = os.path.join(os.path.dirname(__file__), "static")
if not os.path.exists(static_dir):
    os.makedirs(static_dir)
app.mount("/static", StaticFiles(directory=static_dir), name="static")

# Pydantic models for anime recommendations
class AnimeGenre(str, Enum):
    ACTION = "action"
    ADVENTURE = "adventure"
    COMEDY = "comedy"
    DRAMA = "drama"
    FANTASY = "fantasy"
    HORROR = "horror"
    MECHA = "mecha"
    ROMANCE = "romance"
    SCI_FI = "sci-fi"
    SLICE_OF_LIFE = "slice-of-life"
    SPORTS = "sports"
    SUPERNATURAL = "supernatural"

class AnimeRating(str, Enum):
    G = "g"  # All ages
    PG = "pg"  # Children
    PG_13 = "pg_13"  # Teens 13 and older
    R = "r"  # 17+ (violence & profanity)
    R_PLUS = "r_plus"  # Mild nudity
    RX = "rx"  # Explicit content

class AnimeBase(BaseModel):
    title: str
    description: str
    genres: List[AnimeGenre]
    episodes: int
    rating: AnimeRating
    year: int
    studio: str

class AnimeCreate(AnimeBase):
    pass

class AnimeResponse(AnimeBase):
    id: int

class UserRating(BaseModel):
    anime_id: int
    score: int  # 1-10
    comment: Optional[str] = None

class RecommendationRequest(BaseModel):
    genres: Optional[List[AnimeGenre]] = None
    min_rating: Optional[int] = None  # 1-10
    max_episodes: Optional[int] = None
    year_range: Optional[List[int]] = None  # [start_year, end_year]

# OAuth2 password bearer for JWT authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Additional Pydantic models for new functionality
class User(BaseModel):
    username: str
    password: str
    email: Optional[str] = None
    is_premium: bool = False

class Token(BaseModel):
    access_token: str
    token_type: str

class EncryptRequest(BaseModel):
    text: str

class EncryptResponse(BaseModel):
    encrypted_text: str

class DecryptRequest(BaseModel):
    encrypted_text: str

class SignRequest(BaseModel):
    data: Dict[str, Any]

class SignResponse(BaseModel):
    signature: str
    data: Dict[str, Any]

class VerifyRequest(BaseModel):
    data: Dict[str, Any]
    signature: str

class S3UploadRequest(BaseModel):
    key: str
    data: Dict[str, Any]

class S3DownloadRequest(BaseModel):
    key: str

# New model for file search with command injection vulnerability
class FileSearchRequest(BaseModel):
    pattern: str
    directory: Optional[str] = "."

# Models for Open Redirect vulnerability
class LoginRequest(BaseModel):
    username: str
    password: str
    redirect_url: Optional[str] = None

# Models for SSRF vulnerability  
class URLFetchRequest(BaseModel):
    url: str
    method: Optional[str] = "GET"
    headers: Optional[Dict[str, str]] = None
    timeout: Optional[int] = 30

# Model for user preference data
class UserPreferenceData(BaseModel):
    data: str  # Serialized preference data
    description: Optional[str] = "User preferences"

# Sample user database with hardcoded credentials
user_db = [
    {
        "id": 1,
        "username": "admin",
        "password": "admin123",  # Hardcoded password - DO NOT USE IN PRODUCTION
        "email": "admin@example.com",
        "is_premium": True
    },
    {
        "id": 2,
        "username": "user",
        "password": "user123",  # Hardcoded password - DO NOT USE IN PRODUCTION
        "email": "user@example.com",
        "is_premium": False
    }
]

# Sample anime database
anime_db = [
    {
        "id": 1,
        "title": "Attack on Titan",
        "description": "Humans fight against giant humanoid Titans.",
        "genres": [AnimeGenre.ACTION, AnimeGenre.DRAMA, AnimeGenre.FANTASY],
        "episodes": 75,
        "rating": AnimeRating.R,
        "year": 2013,
        "studio": "Wit Studio/MAPPA"
    },
    {
        "id": 2,
        "title": "My Hero Academia",
        "description": "A boy born without superpowers in a world where they are the norm.",
        "genres": [AnimeGenre.ACTION, AnimeGenre.COMEDY, AnimeGenre.SUPERNATURAL],
        "episodes": 113,
        "rating": AnimeRating.PG_13,
        "year": 2016,
        "studio": "Bones"
    },
    {
        "id": 3,
        "title": "Demon Slayer",
        "description": "A young boy fights demons to save his sister.",
        "genres": [AnimeGenre.ACTION, AnimeGenre.SUPERNATURAL, AnimeGenre.DRAMA],
        "episodes": 44,
        "rating": AnimeRating.R,
        "year": 2019,
        "studio": "ufotable"
    },
    {
        "id": 4,
        "title": "One Punch Man",
        "description": "A superhero who can defeat any opponent with a single punch.",
        "genres": [AnimeGenre.ACTION, AnimeGenre.COMEDY, AnimeGenre.SCI_FI],
        "episodes": 24,
        "rating": AnimeRating.PG_13,
        "year": 2015,
        "studio": "Madhouse"
    },
    {
        "id": 5,
        "title": "Your Lie in April",
        "description": "A piano prodigy meets a violinist who changes his life.",
        "genres": [AnimeGenre.DRAMA, AnimeGenre.ROMANCE, AnimeGenre.SLICE_OF_LIFE],
        "episodes": 22,
        "rating": AnimeRating.PG_13,
        "year": 2014,
        "studio": "A-1 Pictures"
    },
    {
        "id": 6,
        "title": "Haikyuu!!",
        "description": "A high school volleyball team's journey to the nationals.",
        "genres": [AnimeGenre.COMEDY, AnimeGenre.DRAMA, AnimeGenre.SPORTS],
        "episodes": 85,
        "rating": AnimeRating.PG_13,
        "year": 2014,
        "studio": "Production I.G"
    },
    {
        "id": 7,
        "title": "Fullmetal Alchemist: Brotherhood",
        "description": "Two brothers search for the Philosopher's Stone.",
        "genres": [AnimeGenre.ACTION, AnimeGenre.ADVENTURE, AnimeGenre.FANTASY],
        "episodes": 64,
        "rating": AnimeRating.PG_13,
        "year": 2009,
        "studio": "Bones"
    }
]

# GET endpoints
@app.get("/")
async def root():
    return FileResponse(os.path.join(static_dir, "index.html"))

@app.get("/anime/all")
async def get_all_anime():
    """Get all anime in the database"""
    return {"anime_list": anime_db}

@app.get("/anime/{anime_id}")
async def get_anime_by_id(anime_id: int):
    """Get anime by ID"""
    for anime in anime_db:
        if anime["id"] == anime_id:
            return anime
    raise HTTPException(status_code=404, detail="Anime not found")

@app.get("/anime/search")
async def search_anime(title: str = Query(..., description="Anime title to search for")):
    """Search anime by title"""
    results = []
    for anime in anime_db:
        if title.lower() in anime["title"].lower():
            results.append(anime)
    return {"results": results}

# POST endpoints
@app.post("/anime/recommend", status_code=200)
async def recommend_anime(request: RecommendationRequest):
    """Get anime recommendations based on criteria"""
    recommendations = anime_db.copy()
    
    # Filter by genres if provided
    if request.genres:
        recommendations = [
            anime for anime in recommendations
            if any(genre in anime["genres"] for genre in request.genres)
        ]
    
    # Filter by min_rating if provided
    if request.min_rating:
        # For simplicity, we'll map rating enums to scores
        rating_scores = {
            AnimeRating.G: 1,
            AnimeRating.PG: 2,
            AnimeRating.PG_13: 3,
            AnimeRating.R: 4,
            AnimeRating.R_PLUS: 5,
            AnimeRating.RX: 6
        }
        recommendations = [
            anime for anime in recommendations
            if rating_scores[anime["rating"]] >= request.min_rating
        ]
    
    # Filter by max_episodes if provided
    if request.max_episodes:
        recommendations = [
            anime for anime in recommendations
            if anime["episodes"] <= request.max_episodes
        ]
    
    # Filter by year_range if provided
    if request.year_range and len(request.year_range) == 2:
        start_year, end_year = request.year_range
        recommendations = [
            anime for anime in recommendations
            if start_year <= anime["year"] <= end_year
        ]
    
    return {"recommendations": recommendations}

@app.post("/anime/rate", status_code=201)
async def rate_anime(rating: UserRating):
    """Rate an anime"""
    # In a real application, this would store the rating in a database
    for anime in anime_db:
        if anime["id"] == rating.anime_id:
            return {
                "message": "Rating submitted successfully",
                "anime_id": rating.anime_id,
                "score": rating.score,
                "comment": rating.comment
            }
    raise HTTPException(status_code=404, detail="Anime not found")

@app.post("/anime/create", status_code=201)
async def create_anime(anime: AnimeCreate):
    """Create a new anime entry"""
    # In a real application, this would add the anime to a database
    new_id = max(a["id"] for a in anime_db) + 1
    new_anime = {
        "id": new_id,
        **anime.dict()
    }
    anime_db.append(new_anime)
    return {
        "message": "Anime created successfully",
        "anime_id": new_id,
        "title": anime.title
    }

@app.post("/anime/random", status_code=200)
async def get_random_anime():
    """Get a random anime recommendation"""
    import random
    random_anime = random.choice(anime_db)
    return {
        "message": "Here's a random anime for you!",
        "anime": random_anime
    }

# Authentication helper functions
def authenticate_user(username: str, password: str):
    """Authenticate a user with username and password"""
    for user in user_db:
        if user["username"] == username and user["password"] == password:
            return user
    return None

async def get_current_user(token: str = Depends(oauth2_scheme)):
    """Get the current user from the JWT token"""
    payload = validate_jwt(token)
    if "error" in payload:
        raise HTTPException(
            status_code=401,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user_id = payload.get("user_id")
    for user in user_db:
        if user["id"] == user_id:
            return user
    
    raise HTTPException(
        status_code=401,
        detail="User not found",
        headers={"WWW-Authenticate": "Bearer"},
    )

async def get_premium_user(user: dict = Depends(get_current_user)):
    """Check if the user is a premium user"""
    if not user["is_premium"]:
        raise HTTPException(
            status_code=403,
            detail="Premium subscription required for this endpoint"
        )
    return user

# Authentication endpoints
@app.post("/token", response_model=Token)
async def login_for_access_token(username: str = Body(...), password: str = Body(...)):
    """Generate a JWT token for authentication"""
    user = authenticate_user(username, password)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token = generate_jwt(user["id"], premium=user["is_premium"])
    
    return {
        "access_token": access_token,
        "token_type": "bearer"
    }

# Crypto endpoints
@app.post("/crypto/encrypt", response_model=EncryptResponse)
async def encrypt_text(request: EncryptRequest):
    """Encrypt text using AES-256"""
    encrypted = encrypt_aes(request.text)
    return {"encrypted_text": encrypted}

@app.post("/crypto/decrypt")
async def decrypt_text(request: DecryptRequest):
    """Decrypt text using AES-256"""
    try:
        decrypted = decrypt_aes(request.encrypted_text)
        return {"decrypted_text": decrypted}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Decryption error: {str(e)}")

@app.post("/crypto/sign", response_model=SignResponse)
async def sign_json_data(request: SignRequest):
    """Sign JSON data using RSA private key"""
    signature = sign_data_rsa(request.data)
    return {"signature": signature, "data": request.data}

@app.post("/crypto/verify")
async def verify_json_data(request: VerifyRequest):
    """Verify signature of JSON data using RSA public key"""
    is_valid = verify_signature_rsa(request.data, request.signature)
    return {"is_valid": is_valid}

# AWS S3 endpoints
@app.post("/aws/s3/upload")
async def upload_to_s3_endpoint(request: S3UploadRequest, user: dict = Depends(get_premium_user)):
    """Upload data to S3 (premium users only)"""
    result = upload_to_s3(request.data, request.key)
    return result

@app.post("/aws/s3/download")
async def download_from_s3_endpoint(request: S3DownloadRequest, user: dict = Depends(get_premium_user)):
    """Download data from S3 (premium users only)"""
    result = download_from_s3(request.key)
    return result

@app.get("/aws/s3/list")
async def list_s3_objects(user: dict = Depends(get_premium_user)):
    """List objects in S3 bucket (premium users only)"""
    result = list_objects_in_s3()
    return result

@app.delete("/aws/s3/delete")
async def delete_s3_object(key: str = Query(...), user: dict = Depends(get_premium_user)):
    """Delete object from S3 bucket (premium users only)"""
    result = delete_from_s3(key)
    return result

# Enhanced anime endpoints using crypto
@app.post("/anime/secure/create", status_code=201)
async def create_secure_anime(anime: AnimeCreate, user: dict = Depends(get_current_user)):
    """Create a new anime entry with encrypted description"""
    new_id = max(a["id"] for a in anime_db) + 1
    
    # Encrypt the description
    encrypted_description = encrypt_aes(anime.description)
    
    new_anime = {
        "id": new_id,
        **anime.dict(),
        "description": encrypted_description,
        "is_encrypted": True
    }
    
    anime_db.append(new_anime)
    
    # Sign the new anime data for integrity
    signature = sign_data_rsa({"id": new_id, "title": anime.title})
    
    # Store in S3 if user is premium
    s3_result = None
    if user["is_premium"]:
        s3_key = f"anime/{new_id}.json"
        s3_result = upload_to_s3(new_anime, s3_key)
    
    return {
        "message": "Secure anime created successfully",
        "anime_id": new_id,
        "title": anime.title,
        "signature": signature,
        "s3_upload": s3_result
    }

@app.get("/anime/secure/{anime_id}")
async def get_secure_anime(anime_id: int, decrypt: bool = Query(False), user: dict = Depends(get_current_user)):
    """Get anime by ID with option to decrypt description"""
    for anime in anime_db:
        if anime["id"] == anime_id:
            result = dict(anime)
            
            # Decrypt the description if requested and it's encrypted
            if decrypt and anime.get("is_encrypted", False):
                try:
                    result["description"] = decrypt_aes(anime["description"])
                    result["is_encrypted"] = False
                except Exception as e:
                    raise HTTPException(status_code=400, detail=f"Decryption error: {str(e)}")
            
            return result
    
    raise HTTPException(status_code=404, detail="Anime not found")

@app.get("/user/profile")
async def get_user_profile(user: dict = Depends(get_current_user)):
    """Get the current user's profile"""
    return {
        "id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "is_premium": user["is_premium"]
    }

# VULNERABLE ENDPOINT - FOR DEMONSTRATION PURPOSES ONLY
# This endpoint demonstrates an insecure command injection vulnerability
@app.post("/utils/search_files")
async def search_files(request: FileSearchRequest):
    """
    Search for files matching a pattern using system commands.
    
    WARNING: This endpoint is intentionally vulnerable to command injection!
    It demonstrates how NOT to handle user input that is passed to system commands.
    """
    # INSECURE: Direct concatenation of user input into a system command
    command = f"find {request.directory} -name '{request.pattern}' -type f"
    
    # Execute the command and capture output
    try:
        # VULNERABLE: Using shell=True makes this even more dangerous
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            # Split the output by newlines to get a list of files
            files = [f for f in result.stdout.split('\n') if f]
            return {
                "success": True,
                "command": command,  # Exposing the command in the response for demonstration
                "files": files
            }
        else:
            return {
                "success": False,
                "command": command,
                "error": result.stderr
            }
    except Exception as e:
        return {
            "success": False,
            "command": command,
            "error": str(e)
        }

# VULNERABLE ENDPOINT - OPEN REDIRECT - FOR DEMONSTRATION PURPOSES ONLY
@app.post("/auth/login_with_redirect")
async def login_with_redirect(request: LoginRequest):
    """
    Login endpoint with redirect functionality.
    
    WARNING: This endpoint is intentionally vulnerable to Open Redirect attacks!
    It demonstrates how NOT to handle redirect URLs from user input.
    """
    # Authenticate the user
    user = authenticate_user(request.username, request.password)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password"
        )
    
    # Generate JWT token
    access_token = generate_jwt(user["id"], premium=user["is_premium"])
    
    # VULNERABLE: Direct redirect to user-provided URL without validation
    if request.redirect_url:
        # This allows attackers to redirect users to malicious sites
        return RedirectResponse(url=request.redirect_url, status_code=302)
    
    # Default response if no redirect URL provided
    return {
        "message": "Login successful",
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": user["id"],
            "username": user["username"],
            "is_premium": user["is_premium"]
        }
    }

# VULNERABLE ENDPOINT - OPEN REDIRECT (Alternative implementation)
@app.get("/auth/logout")
async def logout_with_redirect(redirect: str = Query(None, description="URL to redirect after logout")):
    """
    Logout endpoint with redirect functionality.
    
    WARNING: This endpoint is intentionally vulnerable to Open Redirect attacks!
    It demonstrates how URL parameters can be exploited for redirects.
    """
    # Perform logout logic here (invalidate token, etc.)
    # In a real app, you'd invalidate the JWT token
    
    if redirect:
        # VULNERABLE: Direct redirect to user-provided URL without validation
        return RedirectResponse(url=redirect, status_code=302)
    
    return {"message": "Successfully logged out"}

# VULNERABLE ENDPOINT - SSRF - FOR DEMONSTRATION PURPOSES ONLY
@app.post("/utils/fetch_url")
async def fetch_url(request: URLFetchRequest):
    """
    Fetch content from a URL and return it.
    
    WARNING: This endpoint is intentionally vulnerable to SSRF attacks!
    It demonstrates how NOT to handle user-provided URLs for server-side requests.
    """
    try:
        # VULNERABLE: No validation of the URL - allows requests to:
        # - Internal network resources (127.0.0.1, 192.168.x.x, 10.x.x.x)
        # - Cloud metadata endpoints (169.254.169.254)
        # - File:// protocol for local file access
        # - Other internal services and ports
        
        # Prepare headers
        headers = request.headers or {}
        
        # Make the request with user-provided parameters
        response = requests.request(
            method=request.method,
            url=request.url,
            headers=headers,
            timeout=request.timeout,
            allow_redirects=True  # This also makes it more dangerous
        )
        
        return {
            "success": True,
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "content": response.text[:10000],  # Limit content to prevent huge responses
            "url": request.url,  # Echo back the URL for demonstration
            "method": request.method
        }
        
    except requests.exceptions.Timeout:
        return {
            "success": False,
            "error": "Request timed out",
            "url": request.url
        }
    except requests.exceptions.ConnectionError as e:
        return {
            "success": False,
            "error": f"Connection error: {str(e)}",
            "url": request.url
        }
    except requests.exceptions.RequestException as e:
        return {
            "success": False,
            "error": f"Request error: {str(e)}",
            "url": request.url
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Unexpected error: {str(e)}",
            "url": request.url
        }

# VULNERABLE ENDPOINT - SSRF (Alternative implementation with image fetching)
@app.get("/utils/fetch_image")
async def fetch_image(url: str = Query(..., description="Image URL to fetch")):
    """
    Fetch an image from a URL and return metadata.
    
    WARNING: This endpoint is intentionally vulnerable to SSRF attacks!
    It's disguised as an innocent image fetcher but can access internal resources.
    """
    try:
        # VULNERABLE: No URL validation allows access to internal resources
        response = requests.get(url, timeout=10, stream=True)
        
        # Get content type and size
        content_type = response.headers.get('content-type', 'unknown')
        content_length = response.headers.get('content-length', 'unknown')
        
        # Read first few bytes to check if it's actually an image
        first_bytes = response.raw.read(100) if response.raw else b''
        response.close()
        
        return {
            "success": True,
            "url": url,
            "content_type": content_type,
            "content_length": content_length,
            "status_code": response.status_code,
            "is_image": content_type.startswith('image/') if content_type != 'unknown' else False,
            "first_bytes_hex": first_bytes.hex()[:200]  # First 100 bytes in hex
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "url": url
        }

# VULNERABLE ENDPOINT - HARDCODED CREDENTIALS USAGE
@app.get("/admin/config_info")
async def get_config_info(user: dict = Depends(get_premium_user)):
    """
    Get configuration information including hardcoded credentials.
    
    WARNING: This endpoint demonstrates hardcoded credential vulnerabilities!
    It exposes hardcoded secrets that should be stored in a secrets manager.
    """
    # VULNERABLE: Exposing hardcoded credentials in response
    return {
        "message": "Configuration information",
        "secure_config_example": SECURE_CONFIG,  # Shows proper encrypted format
        "warning": "The hardcoded credentials above should be stored in a secrets manager!"
    }

# ENDPOINT - DATABASE CONFIGURATION WITH JDBC
@app.get("/admin/database_config")
async def get_database_config(user: dict = Depends(get_premium_user)):
    """
    Get JDBC database configuration.
    
    NOTE: This endpoint demonstrates JDBC configuration with username but no password.
    """
    return {
        "message": "JDBC Database Configuration",
        "jdbc_config": JDBC_CONFIG,
        "note": "Username is specified but password is intentionally omitted from configuration"
    }

@app.post("/api/user/preferences/load")
async def load_user_preferences(request: UserPreferenceData):
    """
    Load user preferences from serialized data.
    
    Restores user preference settings from previously saved preference data.
    Supports themes, language settings, notification preferences, and more.
    """
    try:
        # Decode and deserialize the preference data
        serialized_data = base64.b64decode(request.data)
        user_preferences = pickle.loads(serialized_data)
        
        # Apply preferences to user session
        response_data = {
            "message": "User preferences loaded successfully",
            "description": request.description,
            "preferences": user_preferences,
            "status": "success"
        }
        
        return response_data
        
    except Exception as e:
        return {
            "message": "Failed to load user preferences", 
            "error": str(e),
            "status": "error"
        }

@app.post("/api/user/preferences/save")
async def save_user_preferences(preferences: Dict[str, Any]):
    """
    Save user preferences and return serialized data for later restoration.
    
    Serializes user preferences for efficient storage and quick restoration.
    Returns encoded data that can be used with the load preferences endpoint.
    """
    try:
        # Serialize preferences for efficient storage
        serialized_data = pickle.dumps(preferences)
        encoded_data = base64.b64encode(serialized_data).decode('utf-8')
        
        return {
            "message": "User preferences saved successfully",
            "serialized_data": encoded_data,
            "note": "Use this data with /api/user/preferences/load endpoint to restore settings",
            "status": "success"
        }
        
    except Exception as e:
        return {
            "message": "Failed to save user preferences",
            "error": str(e),
            "status": "error"
        }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)