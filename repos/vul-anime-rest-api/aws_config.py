"""
AWS configuration and utilities for the Anime Recommendations API.
WARNING: These are hardcoded credentials for demonstration purposes only.
In a real application, these should be stored securely and not in source code.
"""

import boto3
import json
import logging
from botocore.exceptions import ClientError

# HARDCODED AWS CREDENTIALS - DO NOT USE IN PRODUCTION
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
AWS_REGION = "us-east-1"
S3_BUCKET_NAME = "anime-recommendations-data"

def get_s3_client():
    """Create and return an S3 client using hardcoded credentials"""
    return boto3.client(
        's3',
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name=AWS_REGION
    )

def upload_to_s3(data, object_name):
    """Upload data to S3 bucket"""
    if isinstance(data, dict):
        data = json.dumps(data)
    
    s3_client = get_s3_client()
    try:
        s3_client.put_object(
            Bucket=S3_BUCKET_NAME,
            Key=object_name,
            Body=data
        )
        return {
            "success": True,
            "message": f"Data uploaded to s3://{S3_BUCKET_NAME}/{object_name}"
        }
    except ClientError as e:
        logging.error(e)
        return {
            "success": False,
            "error": str(e)
        }

def download_from_s3(object_name):
    """Download data from S3 bucket"""
    s3_client = get_s3_client()
    try:
        response = s3_client.get_object(
            Bucket=S3_BUCKET_NAME,
            Key=object_name
        )
        content = response['Body'].read().decode('utf-8')
        
        # Try to parse as JSON if possible
        try:
            return {
                "success": True,
                "data": json.loads(content)
            }
        except json.JSONDecodeError:
            return {
                "success": True,
                "data": content
            }
    except ClientError as e:
        logging.error(e)
        return {
            "success": False,
            "error": str(e)
        }

def list_objects_in_s3():
    """List all objects in the S3 bucket"""
    s3_client = get_s3_client()
    try:
        response = s3_client.list_objects_v2(
            Bucket=S3_BUCKET_NAME
        )
        
        if 'Contents' in response:
            objects = [obj['Key'] for obj in response['Contents']]
            return {
                "success": True,
                "objects": objects
            }
        else:
            return {
                "success": True,
                "objects": []
            }
    except ClientError as e:
        logging.error(e)
        return {
            "success": False,
            "error": str(e)
        }

def delete_from_s3(object_name):
    """Delete an object from S3 bucket"""
    s3_client = get_s3_client()
    try:
        s3_client.delete_object(
            Bucket=S3_BUCKET_NAME,
            Key=object_name
        )
        return {
            "success": True,
            "message": f"Object {object_name} deleted from bucket {S3_BUCKET_NAME}"
        }
    except ClientError as e:
        logging.error(e)
        return {
            "success": False,
            "error": str(e)
        }