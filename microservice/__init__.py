import logging
from passlib.hash import bcrypt
from supabase import create_client
import os
from dotenv import load_dotenv
import json
import jwt
from datetime import datetime, timedelta
import azure.functions as func
load_dotenv()

def main(req: func.HttpRequest) -> func.HttpResponse:
    route_params = req.route_params
    if "action" in route_params:
        if route_params["action"] == "register":
            return register(req)
        elif route_params["action"] == "login":
            return login(req)
        elif route_params["action"] == "logout":
            return logout(req)
    
    return func.HttpResponse("Invalid action", status_code=400)

# Initialize Supabase client
url = os.environ["supabase_url"]
key = os.environ["supabase_key"]
supabase = create_client(url, key)

SECRET_KEY = os.environ.get('token_key')

def generate_token(username):
    payload = {
        'sub': username,
        'exp': datetime.utcnow() + timedelta(days=1),  # Token expiration time
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    return token

def register(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')
    username = req.params.get("username")
    password = req.params.get("password")

    if not username or not password:
        return func.HttpResponse("Username and password are required", status_code=400)

    # Check if the username already exists
    data, count = supabase.table("users").select("*").eq("username", username).execute()

    user_data = data[1] if isinstance(data, tuple) and len(data) == 2 else []

    if user_data != []:
        return func.HttpResponse("Username already taken", status_code=400)
    else:
        hashed_password = bcrypt.hash(password)
        new_user, count = supabase.table("users").insert([{"username": username, "password": hashed_password}]).execute()
        return func.HttpResponse("Account created successfully!", status_code=200)


def login(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')
    username = req.params.get("username")
    password = req.params.get("password")

    if not username or not password:
        return func.HttpResponse("Username and password are required", status_code=400)

    data, count = supabase.table("users").select("*").eq("username", username).execute()

    user_data = data[1] if isinstance(data, tuple) and len(data) == 2 else []

    if user_data == []:
        return func.HttpResponse("Username not found", status_code=400)
    elif user_data != []:
        stored_password = user_data[0].get("password")
        if bcrypt.verify(password, stored_password):
            token = generate_token(username)
            supabase.table("users").update({"session_token": token}).eq("username", username).execute()

            response_data = {"message": "Login successful!"}
            response = func.HttpResponse(json.dumps(response_data), status_code=200)
            response.headers["Authorization"] = f"Bearer {token}"
            return response
        else:
            return func.HttpResponse("Incorrect password", status_code=400)
    else:
        return func.HttpResponse("Oops, something went wrong!", status_code=400)


def logout(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')
    
    # Assuming the token is provided in the request headers
    token = req.headers.get("Authorization")

    if not token:
        return func.HttpResponse("Authorization token is required for logout", status_code=400)

    try:
        # Decode the token to get the username or user identifier
        decoded_token = jwt.decode(token.split(" ")[1], SECRET_KEY, algorithms=["HS256"])
        username = decoded_token["sub"]

        # Perform any additional logout logic, such as updating the database or invalidating the token
        supabase.table("users").update({"session_token": None}).eq("username", username).execute()

        return func.HttpResponse("Logout successful!", status_code=200)

    except jwt.ExpiredSignatureError:
        return func.HttpResponse("Token has expired", status_code=401)
    except jwt.InvalidTokenError:
        return func.HttpResponse("Invalid token", status_code=401)
    except Exception as e:
        logging.error(f"Error during logout: {str(e)}")
        return func.HttpResponse("An error occurred during logout", status_code=500)
