import json
import jwt
import bcrypt
import os
from datetime import datetime, timedelta
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Database setup (RDS connection)
DATABASE_URL = os.getenv("DATABASE_URL")  # e.g., "mysql+pymysql://user:pass@host/dbname"
engine = create_engine(DATABASE_URL)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    name = Column(String(30))
    email = Column(String, unique=True)
    password = Column(String(30))

Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)

SECRET_KEY = os.getenv("SECRET_KEY")

def token_required(event):
    auth_header = event.get("headers", {}).get("Authorization", "")
    if not auth_header or not auth_header.startswith("Bearer "):
        return False, {"statusCode": 401, "body": json.dumps({"error": "Unauthorized"})}
    token = auth_header.split(" ")[1]
    try:
        jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return True, None
    except jwt.ExpiredSignatureError:
        return False, {"statusCode": 401, "body": json.dumps({"error": "Token expired"})}
    except jwt.InvalidTokenError:
        return False, {"statusCode": 401, "body": json.dumps({"error": "Invalid token"})}

def lambda_handler(event, context):
    path = event["path"]
    method = event["httpMethod"]
    body = json.loads(event.get("body", "{}") or "{}")
    db_session = Session()

    try:
        if path == "/api/register" and method == "POST":
            name = body.get("name")
            email = body.get("email")
            password = body.get("password")
            user_exists = db_session.query(User).filter_by(email=email).first() is not None
            if user_exists:
                return {"statusCode": 409, "body": json.dumps({"error": "User already exists"})}
            hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
            new_user = User(name=name, email=email, password=hashed_password)
            db_session.add(new_user)
            db_session.commit()
            token = jwt.encode(
                {"user_id": new_user.id, "exp": datetime.utcnow() + timedelta(hours=24)},
                SECRET_KEY,
                algorithm="HS256",
            )
            return {
                "statusCode": 200,
                "body": json.dumps({
                    "user": {"id": new_user.id, "name": new_user.name, "email": new_user.email},
                    "token": token
                })
            }

        elif path == "/api/login" and method == "POST":
            email = body.get("email")
            password = body.get("password")
            user = db_session.query(User).filter_by(email=email).first()
            if not user or not bcrypt.checkpw(password.encode(), user.password.encode()):
                return {"statusCode": 401, "body": json.dumps({"error": "Invalid email or password"})}
            token = jwt.encode(
                {"user_id": user.id, "exp": datetime.utcnow() + timedelta(hours=24)},
                SECRET_KEY,
                algorithm="HS256",
            )
            return {
                "statusCode": 200,
                "body": json.dumps({
                    "user": {"id": user.id, "name": user.name, "email": user.email},
                    "token": token
                })
            }

        elif path == "/api/@me" and method == "GET":
            is_valid, error = token_required(event)
            if not is_valid:
                return error
            token = event["headers"]["Authorization"].split(" ")[1]
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            user = db_session.query(User).filter_by(id=payload["user_id"]).first()
            return {
                "statusCode": 200,
                "body": json.dumps({
                    "user": {"id": user.id, "name": user.name, "email": user.email},
                    "token": token
                })
            }

        else:
            return {"statusCode": 405, "body": json.dumps({"error": "Method not allowed"})}

    except Exception as e:
        db_session.rollback()
        return {"statusCode": 500, "body": json.dumps({"error": str(e)})}
    finally:
        db_session.close()
