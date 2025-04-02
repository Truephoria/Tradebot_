import os
import json
import uuid
import re
import logging
import asyncio
import eventlet

eventlet.monkey_patch()

from flask import Flask, jsonify, request, g
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from dotenv import load_dotenv
from datetime import datetime, timedelta
from functools import wraps
from enum import Enum

import jwt
import boto3
from botocore.exceptions import ClientError

# Telethon
from telethon import TelegramClient, events, errors
from telethon.sessions import StringSession
from threading import Thread

# Load environment variables on startup
load_dotenv()

# -------------------------------------------------------------------------
# Flask App + Logging
# -------------------------------------------------------------------------
app = Flask(__name__)
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# -------------------------------------------------------------------------
# CORS + SocketIO Config
# -------------------------------------------------------------------------
CORS(
    app,
    origins=["https://main.d1bpy75hw1zntc.amplifyapp.com"],
    supports_credentials=True
)

socketio = SocketIO(
    app,
    cors_allowed_origins=["https://main.d1bpy75hw1zntc.amplifyapp.com"],
    async_mode="eventlet"
)

# -------------------------------------------------------------------------
# SECRET_KEY + JWT
# -------------------------------------------------------------------------
secret_key_value = os.getenv("SECRET_KEY", "fallback-secret")
app.config['SECRET_KEY'] = secret_key_value
SECRET_KEY = secret_key_value

# -------------------------------------------------------------------------
# Bcrypt for password hashing
# -------------------------------------------------------------------------
bcrypt = Bcrypt(app)

# -------------------------------------------------------------------------
# DynamoDB Setup (Users, Channels, etc.)
# -------------------------------------------------------------------------
dynamodb = boto3.resource('dynamodb')
users_table = dynamodb.Table('Users')
channels_table = dynamodb.Table('Channels')
signals_table = dynamodb.Table('Signals')
take_profits_table = dynamodb.Table('TakeProfits')
settings_table = dynamodb.Table('Settings')
trades_table = dynamodb.Table('Trades')

# -------------------------------------------------------------------------
# SINGLE_TELEGRAM_CREDS:
#   A global dictionary storing API_ID, API_HASH, PHONE_NUMBER
#   initialized from .env, but can be overwritten at runtime
# -------------------------------------------------------------------------
SINGLE_TELEGRAM_CREDS = {
    "api_id": os.getenv("API_ID", ""),
    "api_hash": os.getenv("API_HASH", ""),
    "phone_number": os.getenv("PHONE_NUMBER", ""),
}

logger.info(f"Initial single-user Telegram creds: {SINGLE_TELEGRAM_CREDS}")

# -------------------------------------------------------------------------
# If you ALSO have multi-user logic in the same file, keep or remove it
# (Left in for demonstration)
# -------------------------------------------------------------------------
DYNAMODB_TELEGRAM_SESSIONS = os.getenv("DYNAMODB_TABLE_NAME", "UserSessions")
try:
    user_sessions_table = dynamodb.Table(DYNAMODB_TELEGRAM_SESSIONS)
except ClientError as e:
    logger.error(f"Error initializing DynamoDB UserSessions table: {e}")
    user_sessions_table = None

def get_session_string_from_db(user_id: str) -> str:
    if not user_sessions_table:
        return None
    try:
        resp = user_sessions_table.get_item(Key={"user_id": user_id})
        item = resp.get("Item")
        return item.get("session_string") if item else None
    except ClientError as e:
        logger.error(f"Error get_session_string_from_db user {user_id}: {e}")
        return None

def store_session_string_in_db(user_id: str, session_string: str):
    if not user_sessions_table:
        return
    try:
        user_sessions_table.put_item(
            Item={"user_id": user_id, "session_string": session_string}
        )
        logger.info(f"Stored session for user {user_id}")
    except ClientError as e:
        logger.error(f"Error store_session_string_in_db user {user_id}: {e}")

def get_client_for_user(user_id: str) -> TelegramClient:
    session_str = get_session_string_from_db(user_id)
    if session_str:
        logger.debug(f"Using existing multi-user session for user {user_id}")
        return TelegramClient(StringSession(session_str), SINGLE_TELEGRAM_CREDS["api_id"], SINGLE_TELEGRAM_CREDS["api_hash"])
    else:
        logger.debug(f"Creating new multi-user session for user {user_id}")
        return TelegramClient(StringSession(None), SINGLE_TELEGRAM_CREDS["api_id"], SINGLE_TELEGRAM_CREDS["api_hash"])

# -------------------------------------------------------------------------
# Single-User Enums / Global States
# -------------------------------------------------------------------------
class SignalStatus(Enum):
    IDLE = 0
    UPDATED = 1

signalStatus = SignalStatus.IDLE

class SettingStatus(Enum):
    IDLE = 0
    UPDATED = 1

settingStatus = SettingStatus.IDLE

# -------------------------------------------------------------------------
# DB Init (Settings, etc.)
# -------------------------------------------------------------------------
def init_db():
    default_settings = [
        ('allowedSymbols', 'EURUSD,GBPUSD,XAUUSD,USDJPY,US30'),
        ('botEnabled', 'True'),
        ('enableTrailingStop', 'True'),
        ('maxDailyLoss', '3'),
        ('maxTradesPerDay', '10'),
        ('minimumRRR', '1.5'),
        ('riskType', 'PERCENTAGE'),
        ('riskValue', '1.5'),
        ('tradingHoursStart', '08:00'),
        ('tradingHoursEnd', '16:00')
    ]
    for key, value in default_settings:
        try:
            resp = settings_table.get_item(Key={'key': key})
            if 'Item' not in resp:
                settings_table.put_item(Item={'key': key, 'value': value})
        except ClientError as e:
            logger.error(f"Error initializing setting {key}: {str(e)}")
            raise e
    logger.info("DynamoDB initialized with default settings")

def add_channels(channels):
    try:
        resp = channels_table.scan()
        for item in resp.get('Items', []):
            channels_table.delete_item(Key={'channel_id': item['channel_id']})
        for c in channels:
            channels_table.put_item(Item={
                'channel_id': c['id'],
                'channel_name': c['name'],
                'is_active': False
            })
        logger.info(f"Added {len(channels)} channels to DynamoDB")
        return get_all_channels()
    except Exception as e:
        logger.error(f"Failed to update channels: {str(e)}")
        raise Exception(f"Failed to update channels: {str(e)}")

def get_all_channels():
    try:
        resp = channels_table.scan()
        all_channels = resp.get('Items', [])
        active_channels = [ch for ch in all_channels if ch['is_active']]
        logger.info(f"Retrieved {len(all_channels)} channels, {len(active_channels)} active")
        return [{
            'channel_id': ch['channel_id'],
            'channel_name': ch['channel_name'],
            'is_active': ch['is_active']
        } for ch in all_channels]
    except Exception as e:
        logger.error(f"Error retrieving channels: {str(e)}")
        raise e

def get_channels_is_active(active_only=True):
    try:
        resp = channels_table.scan()
        all_channels = resp.get('Items', [])
        active = [ch for ch in all_channels if ch['is_active'] == active_only]
        return [ch['channel_id'] for ch in active]
    except Exception as e:
        logger.error(f"Error retrieving active channels: {str(e)}")
        raise e

def update_channel_status(channel_id, is_active):
    try:
        channels_table.update_item(
            Key={'channel_id': channel_id},
            UpdateExpression='SET is_active = :val',
            ExpressionAttributeValues={':val': is_active},
            ReturnValues='UPDATED_NEW'
        )
        logger.info(f"Updated channel {channel_id} status to {is_active}")
        return True
    except ClientError as e:
        logger.warning(f"Channel {channel_id} not found for status update: {str(e)}")
        return False

def get_current_settings():
    try:
        resp = settings_table.scan()
        items = resp.get('Items', [])
        sdict = {}
        for s in items:
            key = s['key']
            val = s['value']
            if key in ['botEnabled', 'enableTrailingStop']:
                val = (val.lower() == 'true')
            elif key in ['maxDailyLoss','maxTradesPerDay','minimumRRR','riskValue']:
                val = float(val)
            sdict[key] = val
        return sdict
    except Exception as e:
        logger.error(f"Error fetching settings: {str(e)}")
        raise e

def validate_setting_value(key, value):
    if key in ['botEnabled', 'enableTrailingStop']:
        if not isinstance(value, bool):
            raise ValueError(f"{key} must be a boolean")
    elif key in ['maxDailyLoss','maxTradesPerDay','minimumRRR','riskValue']:
        try:
            float(value)
        except ValueError:
            raise ValueError(f"{key} must be a number")
    elif key in ['tradingHoursStart','tradingHoursEnd']:
        if not re.match(r'^\d{2}:\d{2}$', str(value)):
            raise ValueError(f"{key} must be in HH:MM format")
    return str(value)

def update_setting(key, value):
    try:
        val = validate_setting_value(key, value)
        settings_table.update_item(
            Key={'key': key},
            UpdateExpression='SET #val = :val',
            ExpressionAttributeNames={'#val': 'value'},
            ExpressionAttributeValues={':val': val}
        )
        logger.info(f"Updated setting {key} to {val}")
        return True
    except ClientError as e:
        logger.error(f"Error updating setting {key}: {str(e)}")
        return False

def create_signal(signal_data):
    required_fields = ['symbol','entry_price','action','stop_loss']
    for f in required_fields:
        if f not in signal_data:
            raise ValueError(f"Missing required field: {f}")
    sig_id = int(uuid.uuid4().int & (1 << 31) - 1)
    created_at = datetime.utcnow().isoformat()
    sig_item = {
        'id': sig_id,
        'channel': 1,
        'symbol': signal_data['symbol'].upper(),
        'entry_price': float(signal_data['entry_price']),
        'action': signal_data['action'].upper(),
        'stop_loss': float(signal_data['stop_loss']),
        'created_at': created_at
    }
    signals_table.put_item(Item=sig_item)

    if 'take_profits' in signal_data and isinstance(signal_data['take_profits'], list):
        for tp in signal_data['take_profits']:
            tp_id = int(uuid.uuid4().int & (1 << 31) - 1)
            take_profits_table.put_item(Item={
                'id': tp_id,
                'signal_id': sig_id,
                'price': float(tp)
            })

    logger.info(f"Created new signal with ID {sig_id}")
    return sig_item

def get_latest_signal():
    try:
        resp = signals_table.scan()
        s = resp.get('Items', [])
        if not s:
            return None
        latest = max(s, key=lambda x: x['created_at'])
        tp_resp = take_profits_table.scan(
            FilterExpression='signal_id = :sid',
            ExpressionAttributeValues={':sid': latest['id']}
        )
        tps = [tp['price'] for tp in tp_resp.get('Items', [])]
        return {
            'channel': latest['channel'],
            'symbol': latest['symbol'],
            'entry_price': latest['entry_price'],
            'action': latest['action'],
            'stop_loss': latest['stop_loss'],
            'take_profits': tps,
            'created_at': latest['created_at']
        }
    except Exception as e:
        logger.error(f"Error fetching latest signal: {str(e)}")
        raise e

def update_signal(channel_id, updates):
    try:
        resp = signals_table.scan(
            FilterExpression='channel = :cid',
            ExpressionAttributeValues={':cid': channel_id}
        )
        s = resp.get('Items', [])
        if not s:
            return False
        sig = s[0]
        sig_id = sig['id']

        update_expr = 'SET '
        expr_vals = {}
        if 'symbol' in updates:
            update_expr += 'symbol = :symbol, '
            expr_vals[':symbol'] = updates['symbol']
        if 'entry_price' in updates:
            update_expr += 'entry_price = :entry_price, '
            expr_vals[':entry_price'] = float(updates['entry_price'])
        if 'action' in updates:
            update_expr += 'action = :action, '
            expr_vals[':action'] = updates['action']
        if 'stop_loss' in updates:
            update_expr += 'stop_loss = :stop_loss, '
            expr_vals[':stop_loss'] = float(updates['stop_loss'])
        update_expr += 'created_at = :created_at'
        expr_vals[':created_at'] = datetime.utcnow().isoformat()

        signals_table.update_item(
            Key={'id': sig_id},
            UpdateExpression=update_expr,
            ExpressionAttributeValues=expr_vals
        )

        if 'take_profits' in updates:
            tp_resp = take_profits_table.scan(
                FilterExpression='signal_id = :sid',
                ExpressionAttributeValues={':sid': sig_id}
            )
            for tp in tp_resp.get('Items', []):
                take_profits_table.delete_item(Key={'id': tp['id']})
            for tp in updates['take_profits']:
                tp_id = int(uuid.uuid4().int & (1 << 31) - 1)
                take_profits_table.put_item(Item={
                    'id': tp_id,
                    'signal_id': sig_id,
                    'price': float(tp)
                })
        logger.info(f"Updated signal for channel {channel_id}")
        return True
    except Exception as e:
        logger.error(f"Error updating signal: {str(e)}")
        return False

# -------------------------------------------------------------------------
# JWT Decorator
# -------------------------------------------------------------------------
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            logger.warning("No valid Authorization header provided")
            return jsonify({"error": "Unauthorized"}), 401
        token = auth_header.split(' ')[1]
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            g.user_id = payload['user_id']
            logger.info("Token validated successfully, user ID: %s", g.user_id)
        except jwt.ExpiredSignatureError:
            logger.warning("Token has expired")
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            logger.warning("Invalid token provided")
            return jsonify({"error": "Invalid token"}), 401
        return f(*args, **kwargs)
    return decorated

# -------------------------------------------------------------------------
# Normal user endpoints: register, login, me, channels, signals, trades, etc.
# (Same as your original code.)
# -------------------------------------------------------------------------

@app.route("/api/register", methods=["POST"])
def register_user():
    # your existing logic
    return jsonify({"todo": "register_user logic"})

@app.route("/api/login", methods=["POST"])
def login_user():
    # your existing logic
    return jsonify({"todo": "login_user logic"})

@app.route("/api/@me")
@token_required
def get_current_user():
    # your existing logic
    return jsonify({"todo": "get_current_user logic"})

# ... (channels, signals, trades) remain the same ...

# -------------------------------------------------------------------------
# (NEW) Single-User Telegram Credentials Endpoint
#  The user can GET (to see current) or POST (to update).
# -------------------------------------------------------------------------
@app.route("/api/telegram/creds", methods=["GET", "POST"])
def update_single_telegram_creds():
    """
    GET: returns current SINGLE_TELEGRAM_CREDS
    POST: overwrites them with user-provided { api_id, api_hash, phone_number }
    NOTE: changes do NOT persist across server restarts unless you store them in DB.
    """
    if request.method == "GET":
        return jsonify({
            "api_id": SINGLE_TELEGRAM_CREDS["api_id"],
            "api_hash": SINGLE_TELEGRAM_CREDS["api_hash"],
            "phone_number": SINGLE_TELEGRAM_CREDS["phone_number"],
        })

    # POST
    data = request.json or {}
    new_api_id = data.get("api_id")
    new_api_hash = data.get("api_hash")
    new_phone = data.get("phone_number")

    if not new_api_id or not new_api_hash or not new_phone:
        return jsonify({
            "status": "error",
            "message": "All of api_id, api_hash, and phone_number are required"
        }), 400

    SINGLE_TELEGRAM_CREDS["api_id"] = new_api_id
    SINGLE_TELEGRAM_CREDS["api_hash"] = new_api_hash
    SINGLE_TELEGRAM_CREDS["phone_number"] = new_phone

    logger.info(f"Updated single-user Telegram creds: {SINGLE_TELEGRAM_CREDS}")
    return jsonify({
        "status": "success",
        "message": "Telegram credentials updated (in memory)"
    })

# -------------------------------------------------------------------------
# Single-User Logic: parse_trading_signal, fetch_subscribed_channels, etc.
# -------------------------------------------------------------------------

def parse_trading_signal(signal_text: str) -> dict:
    # your signal parse logic
    system_prompt = """Extract trading signal details..."""
    # ...
    # placeholder
    return {}

async def fetch_subscribed_channels():
    """
    Single-user approach:
    use SINGLE_TELEGRAM_CREDS to create the client
    """
    api_id = SINGLE_TELEGRAM_CREDS["api_id"]
    api_hash = SINGLE_TELEGRAM_CREDS["api_hash"]
    phone = SINGLE_TELEGRAM_CREDS["phone_number"]

    async with TelegramClient('session', api_id, api_hash) as telegram_Client:
        if not await telegram_Client.is_user_authorized():
            # Ideally you'd do a sign_in() flow once
            raise Exception("Telegram client not authorized. Pre-authorize or sign in needed.")
        dialogs = await telegram_Client.get_dialogs()
        return [
            {"name": d.entity.title, "id": str(d.entity.id)}
            for d in dialogs if d.is_channel
        ]

@app.route('/api/channels', methods=['GET'])
def add_channels_endpoint():
    """
    Overwrites the original single-user approach to fetch channels from Telegram 
    using the updated SINGLE_TELEGRAM_CREDS. Then store them in DynamoDB.
    """
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        channels = loop.run_until_complete(fetch_subscribed_channels())
        loop.close()

        new_channels = add_channels(channels)
        return jsonify({
            'status': 'success',
            'count': len(new_channels),
            'channels': new_channels
        })
    except Exception as e:
        logger.error(f"Error in add_channels_endpoint: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f"Failed to fetch channels: {str(e)}"
        }), 500


@app.route('/api/monitor', methods=['POST'])
@token_required
def monitor_channel():
    """
    Single-user approach again:
    use SINGLE_TELEGRAM_CREDS to create the TelegramClient and watch messages
    """
    try:
        data = request.json
        if not data or 'channel_id' not in data:
            return jsonify({"status": "error", "message": "channel_id is required"}), 400

        channels = [int(x) for x in data.get("channel_id")]
        logger.info(f"Monitoring channel(s): {channels}")

        thread = Thread(target=start_monitoring, args=(channels,))
        thread.daemon = True
        thread.start()

        return jsonify({"status": "Monitoring started", "channel_id": channels}), 200
    except Exception as e:
        logger.error(f"Error in monitor_channel: {str(e)}")
        return jsonify({"status": "error", "message": f"Failed to start monitoring: {str(e)}"}), 500

def start_monitoring(channels):
    """
    Single-user monitoring thread
    """
    async def monitor(channels):
        logger.info(f"Starting monitoring for channels: {channels}")
        try:
            api_id = SINGLE_TELEGRAM_CREDS["api_id"]
            api_hash = SINGLE_TELEGRAM_CREDS["api_hash"]
            phone = SINGLE_TELEGRAM_CREDS["phone_number"]

            async with TelegramClient('session', api_id, api_hash) as telegram_Client:
                if not await telegram_Client.is_user_authorized():
                    logger.error("Telegram client not authorized; skipping monitor.")
                    return

                @telegram_Client.on(events.NewMessage(chats=channels))
                async def handler(event):
                    chat = await event.get_chat()
                    ch_id = chat.id
                    msg_text = event.message.message
                    logger.info(f"Received msg from {ch_id}: {msg_text}")
                    if "buy" in msg_text.lower() or "sell" in msg_text.lower():
                        global signalStatus
                        signalStatus = SignalStatus.UPDATED
                        parsed_signal = parse_trading_signal(msg_text)
                        update_signal(1, parsed_signal)
                        logger.info(f"Signal from {ch_id}: {parsed_signal}")
                        socketio.emit('new_signal', parsed_signal)

                while True:
                    try:
                        await telegram_Client.run_until_disconnected()
                        logger.info("Telegram client disconnected; reconnecting soon...")
                    except Exception as e:
                        logger.error(f"Telegram client error: {str(e)}")
                    await asyncio.sleep(5)

        except Exception as e:
            logger.error(f"Monitoring setup failed: {str(e)}")

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(monitor(channels))
    except KeyboardInterrupt:
        logger.info("Monitoring stopped by user")
    finally:
        loop.close()

# -------------------------------------------------------------------------
# Example trade endpoints (unchanged)
# -------------------------------------------------------------------------
@app.route('/mt/accountinfo', methods=['POST'])
def mt_account():
    return jsonify({"todo": "mt_account logic"})

@app.route('/mt/get_trade', methods=['GET'])
def get_trade():
    return jsonify({"todo": "get_trade logic"})

@app.route('/api/trade', methods=['POST'])
@token_required
def execute_trade():
    return jsonify({"todo": "execute_trade logic"})

# -------------------------------------------------------------------------
# Main
# -------------------------------------------------------------------------
if __name__ == '__main__':
    try:
        init_db()
        logger.info("Starting Flask-SocketIO server on http://0.0.0.0:5000")
        socketio.run(app, host="0.0.0.0", port=5000, debug=False)
    except Exception as e:
        logger.error(f"Failed to start server: {str(e)}")
        exit(1)
