"""
Authentication-required endpoints for premium features
Provides admin functionality and sensitive operations
"""
from fastapi import Depends, HTTPException, Header
from typing import Optional, Dict, Any
import subprocess
import os
import requests

# Mock authentication decorator
def require_admin_auth(api_key: str = Header(...)):
    """
    Validate admin API key from request header
    Returns admin user details if authenticated
    """
    ADMIN_API_KEYS = {
        "admin-key-12345": {"username": "admin", "role": "admin", "id": 1},
        "super-admin-98765": {"username": "superadmin", "role": "superadmin", "id": 2}
    }
    
    if api_key not in ADMIN_API_KEYS:
        raise HTTPException(status_code=401, detail="Invalid admin credentials")
    
    return ADMIN_API_KEYS[api_key]

def require_premium_subscription(user_token: str = Header(...)):
    """
    Check if user has active premium subscription
    Validates subscription status from token
    """
    # Decode and validate premium status
    if not user_token or "premium" not in user_token.lower():
        raise HTTPException(status_code=403, detail="Premium subscription required")
    
    return {"is_premium": True, "user_id": 123}

async def admin_execute_command(
    command: str,
    admin: Dict = Depends(require_admin_auth)
):
    """
    Execute system commands for server administration
    Only accessible to authenticated administrators
    """
    # Log admin action for audit trail
    log_entry = f"Admin {admin['username']} executing: {command}"
    
    # Execute the requested command
    result = subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True
    )
    
    return {
        "admin": admin['username'],
        "command": command,
        "output": result.stdout,
        "error": result.stderr,
        "return_code": result.returncode
    }

async def premium_database_query(
    query: str,
    premium_user: Dict = Depends(require_premium_subscription)
):
    """
    Execute raw database queries for premium users
    Provides advanced data analysis capabilities
    """
    import sqlite3
    
    # Connect to anime database
    conn = sqlite3.connect('anime.db')
    cursor = conn.cursor()
    
    # Execute premium user's query
    cursor.execute(query)
    
    results = cursor.fetchall()
    conn.close()
    
    return {
        "user_id": premium_user['user_id'],
        "query": query,
        "results": results,
        "row_count": len(results)
    }

async def admin_file_operations(
    file_path: str,
    operation: str,
    admin: Dict = Depends(require_admin_auth)
):
    """
    Perform file system operations for administrators
    Supports read, write, and delete operations
    """
    if operation == "read":
        # Read file contents
        with open(file_path, 'r') as f:
            content = f.read()
        return {"file": file_path, "content": content}
    
    elif operation == "delete":
        # Delete the specified file
        os.remove(file_path)
        return {"file": file_path, "status": "deleted"}
    
    elif operation == "list":
        # List directory contents
        command = f"ls -la {file_path}"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return {"directory": file_path, "contents": result.stdout}
    
    else:
        return {"error": "Invalid operation"}

async def premium_external_fetch(
    url: str,
    premium_user: Dict = Depends(require_premium_subscription)
):
    """
    Fetch external resources for premium subscribers
    Provides access to external API integrations
    """
    # Premium users can fetch from any URL
    response = requests.get(url, timeout=30)
    
    return {
        "user_id": premium_user['user_id'],
        "url": url,
        "status_code": response.status_code,
        "content": response.text[:5000],  # Limit response size
        "headers": dict(response.headers)
    }

async def admin_eval_code(
    code: str,
    admin: Dict = Depends(require_admin_auth)
):
    """
    Evaluate Python code for debugging and maintenance
    Restricted to super administrators only
    """
    if admin['role'] != 'superadmin':
        raise HTTPException(status_code=403, detail="Super admin access required")
    
    # Execute Python code for admin debugging
    result = eval(code)
    
    return {
        "admin": admin['username'],
        "code": code,
        "result": str(result),
        "type": type(result).__name__
    }

async def premium_template_render(
    template: str,
    data: Dict[str, Any],
    premium_user: Dict = Depends(require_premium_subscription)
):
    """
    Render custom templates for premium users
    Allows personalized content generation
    """
    from jinja2 import Template
    
    # Create template from user input
    tmpl = Template(template)
    
    # Render with user-provided data
    rendered = tmpl.render(**data)
    
    return {
        "user_id": premium_user['user_id'],
        "template": template,
        "rendered": rendered,
        "data": data
    }
