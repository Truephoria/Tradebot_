# telegram_auth.py
import os
import asyncio
import logging
from flask import Flask, request, jsonify
from telethon import TelegramClient, errors
from telethon.sessions import StringSession

import boto3
from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# -----------------------------------------------------------------------------
# ENVIRONMENT VARIABLES
# -----------------------------------------------------------------------------
API_ID = os.getenv("API_ID")
API_HASH = os.getenv("API_HASH")

if not API_ID or not API_HASH:
    raise RuntimeError("Missing API_ID or API_HASH environment variables. Set them and restart.")

DYNAMODB_TABLE_NAME = os.getenv("DYNAMODB_TABLE_NAME", "UserSessions")

# -----------------------------------------------------------------------------
# INIT DYNAMODB
# -----------------------------------------------------------------------------
dynamodb = boto3.resource("dynamodb")
try:
    user_sessions_table = dynamodb.Table(DYNAMODB_TABLE_NAME)
    # You might optionally confirm the table exists by calling user_sessions_table.table_status
except ClientError as e:
    logger.error(f"Error initializing DynamoDB table: {e}")
    raise

# -----------------------------------------------------------------------------
# HELPER FUNCTIONS FOR DYNAMODB
# -----------------------------------------------------------------------------
def get_session_string_from_db(user_id: str) -> str:
    """
    Fetches the Telethon session string from DynamoDB for the given user_id.
    Returns None if not found.
    """
    try:
        response = user_sessions_table.get_item(Key={"user_id": user_id})
        item = response.get("Item")
        if item:
            return item.get("session_string")  # The attribute in the DB
        else:
            return None
    except ClientError as e:
        logger.error(f"DynamoDB get_item error: {e}")
        return None

def store_session_string_in_db(user_id: str, session_string: str):
    """
    Stores (or updates) the Telethon session string in DynamoDB for user_id.
    """
    try:
        user_sessions_table.put_item(
            Item={
                "user_id": user_id,
                "session_string": session_string,
            }
        )
        logger.info(f"Stored session for user {user_id} in DynamoDB.")
    except ClientError as e:
        logger.error(f"DynamoDB put_item error: {e}")

# -----------------------------------------------------------------------------
# HELPER: GET TELEGRAM CLIENT FOR A GIVEN USER
# -----------------------------------------------------------------------------
def get_client_for_user(user_id: str) -> TelegramClient:
    """
    Retrieves or creates a Telethon client for the given user_id, storing session in DynamoDB.
    1) Attempt to load existing session string from DB
    2) If none, create a blank session (user not authorized yet).
    """
    session_string = get_session_string_from_db(user_id)
    if session_string:
        logger.debug(f"Using existing session for user {user_id}")
        return TelegramClient(StringSession(session_string), API_ID, API_HASH)
    else:
        logger.debug(f"Creating new session for user {user_id}")
        return TelegramClient(StringSession(None), API_ID, API_HASH)

# -----------------------------------------------------------------------------
# 1) SEND CODE (POST /telegram/send_code)
# -----------------------------------------------------------------------------
@app.route("/telegram/send_code", methods=["POST"])
def send_code():
    """
    Expects JSON: { "user_id": "...", "phone_number": "..." }
    1) Creates or retrieves a Telethon client for this user.
    2) Calls client.send_code_request(phone_number).
    3) The user later calls /verify_code with the code they received.
    """
    data = request.json or {}
    user_id = data.get("user_id")
    phone_number = data.get("phone_number")

    if not user_id or not phone_number:
        return jsonify({"status": "error", "message": "user_id and phone_number required"}), 400

    async def _send_code():
        client = get_client_for_user(user_id)
        await client.connect()
        try:
            await client.send_code_request(phone_number)
            logger.info(f"Sent code request to phone {phone_number} for user {user_id}")
            return "ok"
        except Exception as e:
            logger.error(f"Error sending code: {e}")
            return str(e)
        finally:
            await client.disconnect()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    result = loop.run_until_complete(_send_code())

    if result == "ok":
        return jsonify({"status": "success", "message": "Code sent successfully"})
    else:
        return jsonify({"status": "error", "message": result}), 400

# -----------------------------------------------------------------------------
# 2) VERIFY CODE (POST /telegram/verify_code)
# -----------------------------------------------------------------------------
@app.route("/telegram/verify_code", methods=["POST"])
def verify_code():
    """
    Expects JSON: { "user_id": "...", "phone_number": "...", "code": "12345" }
    1) sign_in(phone_number, code)
    2) If success, store updated session_string in DB.
    """
    data = request.json or {}
    user_id = data.get("user_id")
    phone_number = data.get("phone_number")
    code = data.get("code")

    if not user_id or not phone_number or not code:
        return jsonify({"status": "error", "message": "user_id, phone_number, and code are required"}), 400

    async def _verify_code():
        client = get_client_for_user(user_id)
        await client.connect()
        try:
            await client.sign_in(phone_number, code)
        except errors.SessionPasswordNeededError:
            msg = "2FA password needed (use a separate endpoint to provide password)."
            logger.warning(msg)
            return msg
        except Exception as e:
            logger.error(f"Login error for user {user_id}: {e}")
            return f"Login error: {e}"

        if not await client.is_user_authorized():
            msg = "Not authorized after sign_in"
            logger.warning(msg)
            return msg

        # Save updated session
        session_string = client.session.save()
        store_session_string_in_db(user_id, session_string)
        logger.info(f"User {user_id} is now authorized. Session stored.")
        return "ok"

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    result = loop.run_until_complete(_verify_code())

    if result == "ok":
        return jsonify({"status": "success", "message": "User is now authorized"})
    else:
        return jsonify({"status": "error", "message": result}), 400

# -----------------------------------------------------------------------------
# 3) (Optional) 2FA PASSWORD ENDPOINT
# -----------------------------------------------------------------------------
@app.route("/telegram/verify_password", methods=["POST"])
def verify_password():
    """
    If user has 2FA, you catch SessionPasswordNeededError above and ask them
    to call this endpoint with their password.
    Expects JSON: { "user_id": "...", "password": "..." }
    """
    data = request.json or {}
    user_id = data.get("user_id")
    password = data.get("password")

    if not user_id or not password:
        return jsonify({"status": "error", "message": "user_id and password required"}), 400

    async def _verify_password():
        client = get_client_for_user(user_id)
        await client.connect()
        try:
            await client.sign_in(password=password)
        except Exception as e:
            logger.error(f"2FA password error for user {user_id}: {e}")
            return f"2FA password error: {e}"

        if not await client.is_user_authorized():
            return "Still not authorized after 2FA password"

        # Save the updated session
        session_string = client.session.save()
        store_session_string_in_db(user_id, session_string)
        logger.info(f"User {user_id} authorized after 2FA password.")
        return "ok"
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    result = loop.run_until_complete(_verify_password())

    if result == "ok":
        return jsonify({"status": "success", "message": "Authorized after 2FA password"})
    else:
        return jsonify({"status": "error", "message": result}), 400

# -----------------------------------------------------------------------------
# 4) EXAMPLE ENDPOINT: /telegram/test
# -----------------------------------------------------------------------------
@app.route("/telegram/test", methods=["POST"])
def test_telegram():
    """
    Example: Expects JSON: { "user_id": "..." }
    We'll load the user's session from DynamoDB, connect, and do something (get_me()).
    """
    data = request.json or {}
    user_id = data.get("user_id")
    if not user_id:
        return jsonify({"status": "error", "message": "user_id required"}), 400

    async def _do_something():
        client = get_client_for_user(user_id)
        await client.connect()
        if not await client.is_user_authorized():
            return "User not authorized!"
        me = await client.get_me()
        await client.disconnect()
        return f"Hello, {me.first_name or 'Unknown'}!"

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    result = loop.run_until_complete(_do_something())

    if result.startswith("User not authorized"):
        return jsonify({"status": "error", "message": result}), 401
    return jsonify({"status": "success", "message": result})

# -----------------------------------------------------------------------------
# FLASK ENTRYPOINT
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
