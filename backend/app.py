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
from telethon import TelegramClient, events, errors
from telethon.sessions import StringSession
from openai import OpenAI
from threading import Thread

# ----------------------------------------------------------------------
# 1. ENV & FLASK SETUP
# ----------------------------------------------------------------------
load_dotenv()

app = Flask(__name__)

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

CORS(
    app,
    origins=["https://main.d1bpy75hw1zntc.amplifyapp.com"],
    supports_credentials=True,
    allow_headers=["Authorization", "Content-Type"],
    methods=["GET", "POST", "PUT", "OPTIONS"]
)

socketio = SocketIO(
    app,
    cors_allowed_origins=["https://main.d1bpy75hw1zntc.amplifyapp.com"],
    async_mode="eventlet",
    allow_headers=["Authorization", "Content-Type"],
    methods=["GET", "POST", "PUT", "OPTIONS"]
)

# Hard-coded secret for demonstration only:
secret_key_value = "12345"
app.config['SECRET_KEY'] = secret_key_value
SECRET_KEY = secret_key_value

bcrypt = Bcrypt(app)

# If you have an OpenAI key in .env, you can load it here
openai_Client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# ----------------------------------------------------------------------
# 2. DynamoDB Setup & Tables
# ----------------------------------------------------------------------
dynamodb = boto3.resource('dynamodb')

users_table = dynamodb.Table('Users')
channels_table = dynamodb.Table('Channels')
signals_table = dynamodb.Table('Signals')
take_profits_table = dynamodb.Table('TakeProfits')
settings_table = dynamodb.Table('Settings')
trades_table = dynamodb.Table('Trades')

# ----------------------------------------------------------------------
# 3. Telegram Configuration
# ----------------------------------------------------------------------
API_ID = None
API_HASH = None
PHONE_NUMBER = None
telegram_client = None
pending_code_hash = None  # used to store phone_code_hash once we send an SMS code

def get_telegram_credentials():
    """
    Fetch Telegram credentials from 'Settings' (apiId, apiHash, phoneNumber).
    Initialize Telethon client using 'session.session'.
    """
    global API_ID, API_HASH, PHONE_NUMBER, telegram_client

    response = settings_table.scan(
        FilterExpression='key IN (:apiId, :apiHash, :phoneNumber)',
        ExpressionAttributeValues={
            ':apiId': 'apiId',
            ':apiHash': 'apiHash',
            ':phoneNumber': 'phoneNumber'
        }
    )
    items = response.get('Items', [])
    creds = {item['key']: item['value'] for item in items}

    API_ID = creds.get('apiId')
    API_HASH = creds.get('apiHash')
    PHONE_NUMBER = creds.get('phoneNumber')

    if not API_ID or not API_HASH or not PHONE_NUMBER:
        logger.error(
            f"Missing Telegram credentials in Settings: "
            f"API_ID={API_ID}, API_HASH={API_HASH}, PHONE_NUMBER={PHONE_NUMBER}"
        )
        raise ValueError("apiId, apiHash, and phoneNumber must be set in Settings.")

    logger.info(
        f"Telegram credentials => API_ID={API_ID}, API_HASH={API_HASH}, PHONE_NUMBER={PHONE_NUMBER}"
    )

    API_ID = int(API_ID)
    if telegram_client is None:
        telegram_client = TelegramClient('session.session', API_ID, API_HASH)
        logger.info("Telegram client initialized from DynamoDB settings.")

async def fetch_subscribed_channels():
    """
    Check if we're already authorized with Telethon.
    If not, request SMS code. Otherwise, return channel dialogs.
    """
    global pending_code_hash
    logger.info("Fetching subscribed channels with old logic.")

    get_telegram_credentials()

    async with TelegramClient('session.session', API_ID, API_HASH) as client:
        if not await client.is_user_authorized():
            logger.info(f"Using phone number: {PHONE_NUMBER!r} for SMS request.")
            logger.warning("Session invalid; sending SMS code request.")
            code_request = await client.send_code_request(
                phone=PHONE_NUMBER,
                force_sms=True
            )
            pending_code_hash = code_request.phone_code_hash
            # If we're here, user must verify via /telegram/verify_code
            raise Exception("Verification code required. Use /telegram/verify_code with the code.")

        # If authorized, fetch channel dialogs
        dialogs = await client.get_dialogs()
        channels = [
            {"name": dialog.entity.title, "id": str(dialog.entity.id)}
            for dialog in dialogs if dialog.is_channel
        ]
        return channels

def start_monitoring(channels):
    """
    Start monitoring given channel IDs in a separate async loop.
    If session isn't authorized, it triggers SMS code request.
    """
    async def monitor(channels_list):
        global pending_code_hash
        logger.info(f"Starting monitor for channels: {channels_list}")

        get_telegram_credentials()
        async with TelegramClient('session.session', API_ID, API_HASH) as client:
            if not await client.is_user_authorized():
                logger.warning("Session invalid (monitor); sending SMS code request.")
                code_request = await client.send_code_request(
                    phone=PHONE_NUMBER,
                    force_sms=True
                )
                pending_code_hash = code_request.phone_code_hash
                raise Exception("Verification code needed. /telegram/verify_code")

            @client.on(events.NewMessage(chats=channels_list))
            async def handler(event):
                chat = await event.get_chat()
                channel_id = chat.id
                message_text = event.message.message
                logger.info(f"Received msg from channel {channel_id}: {message_text}")
                if "buy" in message_text.lower() or "sell" in message_text.lower():
                    global signalStatus
                    signalStatus = SignalStatus.UPDATED
                    parsed_signal = parse_trading_signal(message_text)
                    update_signal(1, parsed_signal)
                    logger.info(f"Parsed signal: {parsed_signal}")
                    socketio.emit('new_signal', parsed_signal)

            await client.run_until_disconnected()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(monitor(channels))
    except Exception as e:
        logger.error(f"Monitoring failed or code needed: {str(e)}")
    finally:
        loop.close()

async def sign_in_with_code(code):
    """
    Called by /telegram/verify_code after user enters SMS code.
    """
    global pending_code_hash
    logger.info("Completing sign-in with code (old logic).")

    get_telegram_credentials()
    async with TelegramClient('session.session', API_ID, API_HASH) as client:
        await client.connect()
        try:
            await client.sign_in(PHONE_NUMBER, code, phone_code_hash=pending_code_hash)
            logger.info("Successfully signed in; session.session updated.")
            pending_code_hash = None
        except errors.SessionPasswordNeededError:
            logger.error("2FA required; not supported in this snippet.")
            raise Exception("Two-factor authentication required.")
        except Exception as e:
            logger.error(f"Sign-in with code failed: {str(e)}")
            raise
        finally:
            if client.is_connected():
                await client.disconnect()

# ----------------------------------------------------------------------
# 4. Enums & statuses
# ----------------------------------------------------------------------
class SignalStatus(Enum):
    IDLE = 0
    UPDATED = 1

signalStatus = SignalStatus.IDLE

class SettingStatus(Enum):
    IDLE = 0
    UPDATED = 1

settingStatus = SettingStatus.IDLE

# ----------------------------------------------------------------------
# 5. DB INIT & HELPERS
# ----------------------------------------------------------------------
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
        ('tradingHoursEnd', '16:00'),
        ('apiId', ''),
        ('apiHash', ''),
        ('phoneNumber', '')
    ]
    for key, value in default_settings:
        try:
            response = settings_table.get_item(Key={'key': key})
            if 'Item' not in response:
                settings_table.put_item(Item={'key': key, 'value': value})
        except ClientError as e:
            logger.error(f"Error initializing setting {key}: {str(e)}")
            raise e
    logger.info("DynamoDB initialized with default settings")

def add_channels(channels):
    """
    Replaces all Channels in DB with the fetched ones,
    sets is_active=False initially.
    """
    try:
        response = channels_table.scan()
        for item in response.get('Items', []):
            channels_table.delete_item(Key={'channel_id': item['channel_id']})
        for ch in channels:
            channels_table.put_item(Item={
                'channel_id': ch['id'],
                'channel_name': ch['name'],
                'is_active': False
            })
        logger.info(f"Added {len(channels)} channels to DynamoDB")
        return get_all_channels()
    except Exception as e:
        logger.error(f"Failed to update channels: {str(e)}")
        raise Exception(f"Failed to update channels: {str(e)}")

def get_all_channels():
    try:
        response = channels_table.scan()
        all_channels = response.get('Items', [])
        active_channels = [ch for ch in all_channels if ch['is_active']]
        logger.info(f"Retrieved {len(all_channels)} channels, {len(active_channels)} active")
        return [
            {
                'channel_id': ch['channel_id'],
                'channel_name': ch['channel_name'],
                'is_active': ch['is_active']
            } for ch in all_channels
        ]
    except Exception as e:
        logger.error(f"Error retrieving channels: {str(e)}")
        raise e

def get_channels_is_active(active_only=True):
    try:
        response = channels_table.scan()
        all_channels = response.get('Items', [])
        active_channels = [c for c in all_channels if c['is_active'] == active_only]
        return [c['channel_id'] for c in active_channels]
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
        logger.warning(f"Channel {channel_id} not found: {str(e)}")
        return False

def get_current_settings():
    try:
        response = settings_table.scan()
        items = response.get('Items', [])
        settings_dict = {}
        for setting in items:
            key = setting['key']
            value = setting['value']
            if key in ['botEnabled', 'enableTrailingStop']:
                value = (value.lower() == 'true')
            elif key in ['maxDailyLoss', 'maxTradesPerDay', 'minimumRRR', 'riskValue']:
                value = float(value) if value else value
            settings_dict[key] = value
        return settings_dict
    except Exception as e:
        logger.error(f"Error fetching settings: {str(e)}")
        raise e

def validate_setting_value(key, value):
    if key in ['botEnabled', 'enableTrailingStop']:
        if not isinstance(value, bool):
            raise ValueError(f"{key} must be a boolean")
    elif key in ['maxDailyLoss', 'maxTradesPerDay', 'minimumRRR', 'riskValue']:
        try:
            float(value)
        except ValueError:
            raise ValueError(f"{key} must be a number")
    elif key in ['tradingHoursStart', 'tradingHoursEnd']:
        if not re.match(r'^\d{2}:\d{2}$', str(value)):
            raise ValueError(f"{key} must be in HH:MM format")
    return str(value)

def update_setting(key, value):
    try:
        validated_value = validate_setting_value(key, value)
        settings_table.update_item(
            Key={'key': key},
            UpdateExpression='SET #val = :val',
            ExpressionAttributeNames={'#val': 'value'},
            ExpressionAttributeValues={':val': validated_value}
        )
        logger.info(f"Updated setting {key} to {validated_value}")
        return True
    except ClientError as e:
        logger.error(f"Error updating setting {key}: {str(e)}")
        return False

# ----------------------------------------------------------------------
# 6. Signal methods
# ----------------------------------------------------------------------
def create_signal(signal_data):
    required_fields = ['symbol', 'entry_price', 'action', 'stop_loss']
    for field in required_fields:
        if field not in signal_data:
            raise ValueError(f"Missing required field: {field}")

    signal_id = int(uuid.uuid4().int & (1 << 31) - 1)
    created_at = datetime.utcnow().isoformat()
    signal_item = {
        'id': signal_id,
        'channel': 1,
        'symbol': signal_data['symbol'].upper(),
        'entry_price': float(signal_data['entry_price']),
        'action': signal_data['action'].upper(),
        'stop_loss': float(signal_data['stop_loss']),
        'created_at': created_at
    }
    signals_table.put_item(Item=signal_item)

    if 'take_profits' in signal_data and isinstance(signal_data['take_profits'], list):
        for tp in signal_data['take_profits']:
            tp_id = int(uuid.uuid4().int & (1 << 31) - 1)
            take_profits_table.put_item(Item={
                'id': tp_id,
                'signal_id': signal_id,
                'price': float(tp)
            })

    logger.info(f"Created new signal with ID {signal_id}")
    return signal_item

def get_latest_signal():
    try:
        response = signals_table.scan()
        signals = response.get('Items', [])
        if not signals:
            return None
        latest_signal = max(signals, key=lambda x: x['created_at'])

        tp_response = take_profits_table.scan(
            FilterExpression='signal_id = :sid',
            ExpressionAttributeValues={':sid': latest_signal['id']}
        )
        tps = [tp['price'] for tp in tp_response.get('Items', [])]

        return {
            'channel': latest_signal['channel'],
            'symbol': latest_signal['symbol'],
            'entry_price': latest_signal['entry_price'],
            'action': latest_signal['action'],
            'stop_loss': latest_signal['stop_loss'],
            'take_profits': tps,
            'created_at': latest_signal['created_at']
        }
    except Exception as e:
        logger.error(f"Error fetching latest signal: {str(e)}")
        raise e

def update_signal(channel_id, updates):
    """
    In your example, you always pass channel_id=1 for a single signal.
    This code updates the first matching signal in table for that channel.
    """
    try:
        resp = signals_table.scan(
            FilterExpression='channel = :cid',
            ExpressionAttributeValues={':cid': channel_id}
        )
        signals_found = resp.get('Items', [])
        if not signals_found:
            return False

        signal = signals_found[0]
        signal_id = signal['id']

        update_expression = 'SET '
        expr_values = {}

        if 'symbol' in updates:
            update_expression += 'symbol = :symbol, '
            expr_values[':symbol'] = updates['symbol']

        if 'entry_price' in updates:
            update_expression += 'entry_price = :entry_price, '
            expr_values[':entry_price'] = float(updates['entry_price'])

        if 'action' in updates:
            update_expression += 'action = :action, '
            expr_values[':action'] = updates['action']

        if 'stop_loss' in updates:
            update_expression += 'stop_loss = :stop_loss, '
            expr_values[':stop_loss'] = float(updates['stop_loss'])

        # always update 'created_at' to the latest time
        update_expression += 'created_at = :created_at'
        expr_values[':created_at'] = datetime.utcnow().isoformat()

        signals_table.update_item(
            Key={'id': signal_id},
            UpdateExpression=update_expression,
            ExpressionAttributeValues=expr_values
        )

        if 'take_profits' in updates:
            # remove old TPs
            tp_resp = take_profits_table.scan(
                FilterExpression='signal_id = :sid',
                ExpressionAttributeValues={':sid': signal_id}
            )
            for tp in tp_resp.get('Items', []):
                take_profits_table.delete_item(Key={'id': tp['id']})

            # add new ones
            for tp in updates['take_profits']:
                tp_id = int(uuid.uuid4().int & (1 << 31) - 1)
                take_profits_table.put_item(Item={
                    'id': tp_id,
                    'signal_id': signal_id,
                    'price': float(tp)
                })

        logger.info(f"Updated signal for channel {channel_id}")
        return True
    except Exception as e:
        logger.error(f"Error updating signal: {str(e)}")
        return False

# ----------------------------------------------------------------------
# 7. JWT Decorator
# ----------------------------------------------------------------------
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
            logger.info("Token validated, user ID: %s", g.user_id)
        except jwt.ExpiredSignatureError:
            logger.warning("Token expired")
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            logger.warning("Invalid token provided")
            return jsonify({"error": "Invalid token"}), 401

        return f(*args, **kwargs)
    return decorated

# ----------------------------------------------------------------------
# 8. API Routes
# ----------------------------------------------------------------------
@app.route("/api/register", methods=["POST"])
def register_user():
    """
    Basic user registration: name, email, password -> store in Users table,
    return JWT on success
    """
    name = request.json["name"]
    email = request.json["email"]
    password = request.json["password"]
    try:
        # check if user exists
        resp = users_table.scan(
            FilterExpression='email = :email',
            ExpressionAttributeValues={':email': email}
        )
        if resp.get('Items', []):
            logger.warning(f"Registration attempt with existing email: {email}")
            return jsonify({"error": "User already exists"}), 409

        user_id = int(uuid.uuid4().int & (1 << 31) - 1)
        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')

        users_table.put_item(Item={
            'id': user_id,
            'name': name,
            'email': email,
            'password': hashed_pw
        })

        token = jwt.encode({
            'user_id': user_id,
            'exp': datetime.utcnow() + timedelta(hours=24)
        }, SECRET_KEY, algorithm='HS256')

        logger.info(f"User registered: {email}")
        return jsonify({
            "user": {"id": user_id, "name": name, "email": email},
            "token": token
        })
    except Exception as e:
        logger.error(f"Error registering user: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/login", methods=["POST"])
def login_user():
    """
    Check user email/password, return JWT if valid
    """
    email = request.json["email"]
    password = request.json["password"]
    try:
        resp = users_table.scan(
            FilterExpression='email = :email',
            ExpressionAttributeValues={':email': email}
        )
        user = resp.get('Items', [None])[0]
        if not user:
            logger.warning(f"Login attempt with non-existent email: {email}")
            return jsonify({"error": "Can not find user. Please sign up."}), 401

        if not bcrypt.check_password_hash(user['password'], password):
            logger.warning(f"Invalid password for email: {email}")
            return jsonify({"error": "Invalid email or password."}), 401

        user_id = str(user['id'])
        user_name = user.get('name', '')
        user_email = user['email']

        token = jwt.encode({
            'user_id': user_id,
            'exp': datetime.utcnow() + timedelta(hours=24)
        }, SECRET_KEY, algorithm='HS256')

        current_set = get_current_settings()
        logger.info(f"User logged in: {email}")
        return jsonify({
            "user": {"id": user_id, "name": user_name, "email": user_email},
            "token": token,
            "settings": current_set
        })
    except Exception as e:
        logger.error(f"Error logging in user: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/@me")
#@token_required
def get_current_user():
    """
    Return user info based on JWT token
    """
    user_id = g.user_id
    resp = users_table.get_item(Key={'id': user_id})
    user = resp.get('Item')
    if not user:
        logger.warning(f"User not found for ID: {user_id}")
        return jsonify({"error": "User not found"}), 404

    final_id = user['id']
    logger.info(f"Current user retrieved: {user['email']}")
    return jsonify({
        "user": {"id": final_id, "name": user["name"], "email": user["email"]}
    })

@app.route('/api/channels/all', methods=['GET'])
def get_channels_endpoint():
    """
    Return all channels + which are active. No token check here if you want
    it public, or add @token_required if you prefer
    """
    try:
        chs = get_all_channels()
        active_chs = get_channels_is_active(True)
        if chs:
            return jsonify({
                'status': 'success',
                'count': len(chs),
                'channels': chs,
                'active_channels': active_chs
            })
        return jsonify({
            'status': 'success',
            'message': 'No active channels found',
            'channels': None
        })
    except Exception as e:
        logger.error(f"Error in get_channels_endpoint: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/channels', methods=['GET'])
#@token_required
def add_channels_endpoint():
    """
    - Calls fetch_subscribed_channels (Telethon).
    - If we need a code, raise => 401. Otherwise store channels in DB.
    - Return phoneUsed in the JSON so front end can see phone number if desired.
    """
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        tele_channels = loop.run_until_complete(fetch_subscribed_channels())
        loop.close()

        logger.info(f"Got Telegram channels. PHONE_NUMBER => {PHONE_NUMBER!r}")

        # Add them to DB (is_active=False)
        all_added = add_channels(tele_channels)
        return jsonify({
            'status': 'success',
            'count': len(all_added),
            'channels': all_added,
            'phoneUsed': PHONE_NUMBER
        })
    except Exception as e:
        logger.error(f"Error in add_channels_endpoint: {str(e)}")
        return jsonify({
            'status': 'unauthorized',
            'message': f'Telegram session invalid or code needed: {str(e)}'
        }), 401

@app.route('/telegram/verify_code', methods=['POST'])
#@token_required
def verify_telegram_code():
    """
    POST { "code": "12345" }
    Calls sign_in_with_code to complete the Telethon login
    """
    try:
        data = request.get_json()
        code = data.get('code')
        if not code:
            logger.warning("No verification code provided.")
            return jsonify({'status': 'error', 'message': 'Verification code required'}), 400

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(sign_in_with_code(code))
        loop.close()

        return jsonify({
            'status': 'success',
            'message': 'Telegram session regenerated successfully.'
        }), 200
    except Exception as e:
        logger.error(f"Error verifying Telegram code: {str(e)}")
        return jsonify({'status': 'error', 'message': f"Failed to verify code: {str(e)}"}), 500

@app.route('/api/channels/<string:channel_id>/status', methods=['PUT'])
def update_channel_status_endpoint(channel_id):
    data = request.get_json()
    if 'is_active' not in data:
        logger.warning("Missing is_active param in update_channel_status_endpoint")
        return jsonify({'error': 'is_active parameter required'}), 400

    updated = update_channel_status(channel_id, data['is_active'])
    if updated:
        return jsonify({
            'status': 'success',
            'message': f'Channel {channel_id} updated',
            'is_active': data['is_active']
        })
    return jsonify({'error': 'Channel not found'}), 404

@app.route('/api/settings', methods=['GET'])
#@token_required
def get_settings():
    """
    Return all current settings
    """
    try:
        st = get_current_settings()
        return jsonify({"status": "success", "settings": st}), 200
    except Exception as e:
        logger.error(f"Error fetching settings: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/settings', methods=['POST', 'PUT'])
#@token_required
def update_settings():
    """
    Update settings in DB. If telegram creds changed, reset telegram_client.
    """
    global settingStatus, telegram_client
    settingStatus = SettingStatus.UPDATED
    try:
        data = request.get_json()
        if not data or not isinstance(data, dict):
            logger.warning("Invalid data format in update_settings")
            return jsonify({'status': 'error', 'message': 'Invalid data format'}), 400

        for key, val in data.items():
            if not update_setting(key, val):
                # if update_setting fails, just put item manually
                settings_table.put_item(Item={'key': key, 'value': str(val)})

            if key in ['apiId', 'apiHash', 'phoneNumber']:
                telegram_client = None
                get_telegram_credentials()
                logger.info("Telegram settings updated; client reset.")

        cur_st = get_current_settings()
        return jsonify({
            'status': 'success',
            'message': 'Settings updated',
            'settings': cur_st
        })
    except Exception as e:
        logger.error(f"Error in update_settings: {str(e)}")
        return jsonify({'status': 'error', 'message': f'Failed to update settings: {str(e)}'}), 500

@app.route('/api/signal', methods=['POST'])
#@token_required
def add_signal():
    """
    Create a new signal entry in DB
    """
    try:
        data = request.get_json()
        if not data:
            logger.warning("No data provided in add_signal")
            return jsonify({'status': 'error', 'message': 'No data provided'}), 400
        sig = create_signal(data)
        return jsonify({
            'status': 'success',
            'message': 'Signal created',
            'signal_id': sig['id']
        }), 201
    except ValueError as e:
        logger.error(f"ValueError in add_signal: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 400
    except Exception as e:
        logger.error(f"Error in add_signal: {str(e)}")
        return jsonify({'status': 'error', 'message': f'Failed to create signal: {str(e)}'}), 500

@app.route('/api/signal', methods=['GET'])
#@token_required
def get_signal():
    """
    Return the latest signal from DB
    """
    try:
        sig = get_latest_signal()
        if sig:
            return jsonify({'status': 'success', 'signal': sig})
        return jsonify({
            'status': 'success',
            'message': 'No active signals found',
            'signal': None
        })
    except Exception as e:
        logger.error(f"Error in get_signal: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/signal/history', methods=['GET'])
def get_signal_history():
    """
    Return paginated signal history (no token needed as per your snippet)
    """
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        symbol = request.args.get('symbol')
        action = request.args.get('action')
        channel_id = request.args.get('channel')

        filter_expression = []
        expr_values = {}
        if symbol:
            filter_expression.append('symbol = :symbol')
            expr_values[':symbol'] = symbol.upper()
        if action:
            filter_expression.append('action = :action')
            expr_values[':action'] = action.upper()
        if channel_id:
            filter_expression.append('channel = :channel')
            expr_values[':channel'] = int(channel_id)

        scan_kwargs = {}
        if filter_expression:
            scan_kwargs['FilterExpression'] = ' AND '.join(filter_expression)
            scan_kwargs['ExpressionAttributeValues'] = expr_values

        resp = signals_table.scan(**scan_kwargs)
        all_signals = resp.get('Items', [])
        all_signals.sort(key=lambda x: x['created_at'], reverse=True)

        total = len(all_signals)
        start = (page - 1) * per_page
        end = start + per_page
        paginated = all_signals[start:end]

        sig_list = []
        for sig in paginated:
            tp_resp = take_profits_table.scan(
                FilterExpression='signal_id = :sid',
                ExpressionAttributeValues={':sid': sig['id']}
            )
            tps = [tp['price'] for tp in tp_resp.get('Items', [])]
            sig_list.append({
                'id': sig['id'],
                'channel': sig['channel'],
                'symbol': sig['symbol'],
                'action': sig['action'],
                'entry_price': sig['entry_price'],
                'stop_loss': sig['stop_loss'],
                'take_profits': tps,
                'created_at': sig['created_at']
            })

        return jsonify({
            'status': 'success',
            'signals': sig_list,
            'total': total,
            'pages': (total + per_page - 1) // per_page,
            # This line below is a bit odd, but it's unchanged from your snippet
            'current_page': signals_table.scan if not all_signals else page
        })
    except Exception as e:
        logger.error(f"Error in get_signal_history: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/signal/<int:channel_id>', methods=['GET'])
def get_channel_by_id(channel_id):
    """
    Return a single signal by channel ID
    """
    try:
        resp = signals_table.scan(
            FilterExpression='channel = :cid',
            ExpressionAttributeValues={':cid': channel_id}
        )
        sig = resp.get('Items', [None])[0]
        if not sig:
            return jsonify({'status': 'error', 'message': 'Signal not found'}), 404

        tp_resp = take_profits_table.scan(
            FilterExpression='signal_id = :sid',
            ExpressionAttributeValues={':sid': sig['id']}
        )
        tps = [tp['price'] for tp in tp_resp.get('Items', [])]

        return jsonify({
            'status': 'success',
            'signal': {
                'id': sig['id'],
                'channel': sig['channel'],
                'symbol': sig['symbol'],
                'action': sig['action'],
                'entry_price': sig['entry_price'],
                'stop_loss': sig['stop_loss'],
                'take_profits': tps,
                'created_at': sig['created_at']
            }
        })
    except Exception as e:
        logger.error(f"Error in get_channel_by_id: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/signal/<int:channel_id>', methods=['PUT', 'PATCH'])
def update_signal_endpoint(channel_id):
    """
    Update a signal given channel_id
    """
    try:
        data = request.get_json()
        if not data:
            logger.warning("No data provided in update_signal_endpoint")
            return jsonify({'status': 'error', 'message': 'No data provided'}), 400

        if 'action' in data and data['action'].upper() not in ['BUY', 'SELL']:
            logger.warning(f"Invalid action: {data['action']}")
            return jsonify({'status': 'error', 'message': 'Action must be either BUY or SELL'}), 400

        if update_signal(channel_id, data):
            resp = signals_table.scan(
                FilterExpression='channel = :cid',
                ExpressionAttributeValues={':cid': channel_id}
            )
            sig = resp.get('Items', [None])[0]
            tp_resp = take_profits_table.scan(
                FilterExpression='signal_id = :sid',
                ExpressionAttributeValues={':sid': sig['id']}
            )
            tps = [tp['price'] for tp in tp_resp.get('Items', [])]
            return jsonify({
                'status': 'success',
                'message': 'Signal updated',
                'signal': {
                    'id': sig['id'],
                    'symbol': sig['symbol'],
                    'action': sig['action'],
                    'entry_price': sig['entry_price'],
                    'stop_loss': sig['stop_loss'],
                    'take_profits': tps,
                    'created_at': sig['created_at']
                }
            })
        return jsonify({'status': 'error', 'message': 'Signal not found'}), 404
    except Exception as e:
        logger.error(f"Error in update_signal_endpoint: {str(e)}")
        return jsonify({'status': 'error', 'message': f'Failed to update signal: {str(e)}'}), 500

def parse_trading_signal(signal_text: str) -> dict:
    """
    Parse signals with an OpenAI system prompt
    """
    system_prompt = """Extract trading signal details from the given text...
    (omitted for brevity)
    """

    try:
        response = openai_Client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": signal_text}
            ]
        )
        logger.info(f"OpenAI response: {response.choices[0].message.content}")
        parsed = json.loads(response.choices[0].message.content)
        if parsed.get('take_profits') is None:
            parsed['take_profits'] = []
        return parsed
    except Exception as e:
        logger.error(f"Error parsing trading signal: {str(e)}")
        return {"error": str(e)}

@app.route('/api/monitor', methods=['POST'])
def monitor_channel():
    """
    Start monitoring a list of channel_ids in a background thread
    """
    try:
        get_telegram_credentials()
        data = request.get_json()
        if not data or 'channel_id' not in data:
            logger.warning("Missing channel_id in monitor request")
            return jsonify({"status": "error", "message": "channel_id is required"}), 400

        channels = [int(x) for x in data.get("channel_id")]
        logger.info(f"Starting monitoring for channels: {channels}")

        thread = Thread(target=start_monitoring, args=(channels,))
        thread.daemon = True
        thread.start()

        return jsonify({"status": "Monitoring started", "channel_id": channels}), 200
    except Exception as e:
        logger.error(f"Error in monitor_channel: {str(e)}")
        return jsonify({"status": "error", "message": f"Failed to start monitoring: {str(e)}"}), 500

# ----------------------------------------------------------------------
# 9. Example route for account info from an EA
# ----------------------------------------------------------------------
is_first = True

@app.route('/mt/accountinfo', methods=['POST'])
def mt_account():
    data = request.get_json()
    if data['activeTrades'] is None:
        data['activeTrades'] = []
    if data['tradeshistory'] is None:
        data['tradeshistory'] = []
    logger.info(f"Received account info: {data}")
    socketio.emit('new_metadata', data)

    global signalStatus, settingStatus, is_first

    signal_data = "No Signal"
    setting_data = "No Setting"

    now = datetime.now().time()
    current_settings = get_current_settings()
    current_signal = get_latest_signal()
    allowed_symbols = current_settings['allowedSymbols'].split(',')

    # On the first request, just return 202 w/ settings
    if is_first:
        is_first = False
        return jsonify({"signal": signal_data, "setting": current_settings}), 202

    start_time = datetime.strptime(current_settings['tradingHoursStart'], "%H:%M").time()
    end_time = datetime.strptime(current_settings['tradingHoursEnd'], "%H:%M").time()

    # If the user updated settings but no new signal
    if settingStatus == SettingStatus.UPDATED and signalStatus != SignalStatus.UPDATED:
        settingStatus = SettingStatus.IDLE
        setting_data = current_settings
        logger.info("Setting updated!")
        return jsonify({"signal": signal_data, "setting": setting_data}), 202

    # If within trading hours, bot enabled, a signal is found, and symbol is allowed
    if (
        start_time <= now <= end_time
        and current_settings['botEnabled']
        and current_signal
        and current_signal['symbol'] in allowed_symbols
    ):
        if signalStatus == SignalStatus.UPDATED and settingStatus != SettingStatus.UPDATED:
            signalStatus = SignalStatus.IDLE
            signal_data = current_signal
            logger.info("Signal updated!")
            return jsonify({"signal": signal_data, "setting": setting_data}), 201

    if signal_data == "No Signal" and setting_data == "No Setting":
        logger.info("No Signal or Setting")
        return jsonify({"signal": signal_data, "setting": setting_data}), 203

    return jsonify({"signal": signal_data, "setting": setting_data}), 200

@app.route('/mt/get_trade', methods=['GET'])
def get_trade():
    """
    Return the earliest 'pending' trade from Trades table, then mark it 'sent'
    """
    try:
        resp = trades_table.scan(
            FilterExpression='status = :status',
            ExpressionAttributeValues={':status': 'pending'}
        )
        trades = resp.get('Items', [])
        if not trades:
            logger.debug("No pending trades found")
            return jsonify({})

        trade = min(trades, key=lambda x: x['created_at'])
        trades_table.update_item(
            Key={'id': trade['id']},
            UpdateExpression='SET status = :status',
            ExpressionAttributeValues={':status': 'sent'}
        )
        trade_dict = {
            'id': trade['id'],
            'symbol': trade['symbol'],
            'action': trade['action'],
            'entry_price': trade['entry_price'],
            'stop_loss': trade['stop_loss'],
            'take_profits': json.loads(trade['take_profits']),
            'volume': trade['volume'],
            'status': 'sent',
            'created_at': trade['created_at'],
            'updated_at': trade.get('updated_at')
        }
        logger.info(f"Sending trade to MT5: {trade_dict}")
        return jsonify(trade_dict)
    except Exception as e:
        logger.error(f"Error fetching trade: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/trade', methods=['POST'])
#@token_required
def execute_trade():
    """
    Insert a new trade record w/ status 'pending', so the EA can pick it up
    """
    trade_data = request.json
    logger.info(f"Received trade request: {trade_data}")
    try:
        required_fields = ['symbol', 'action', 'entry_price', 'stop_loss', 'take_profits', 'volume']
        for f in required_fields:
            if f not in trade_data:
                logger.error(f"Missing required field: {f}")
                return jsonify({'status': 'error', 'message': f'Missing required field: {f}'}), 400

        trade_id = int(uuid.uuid4().int & (1 << 31) - 1)
        created_at = datetime.utcnow().isoformat()
        new_trade = {
            'id': trade_id,
            'symbol': trade_data['symbol'].upper(),
            'action': trade_data['action'].upper(),
            'entry_price': float(trade_data['entry_price']),
            'stop_loss': float(trade_data['stop_loss']),
            'take_profits': json.dumps(trade_data['take_profits']),
            'volume': float(trade_data['volume']),
            'status': 'pending',
            'created_at': created_at
        }
        trades_table.put_item(Item=new_trade)
        logger.info(f"Trade queued in DB, ID: {trade_id}")

        trade_dict = {
            'id': trade_id,
            'symbol': new_trade['symbol'],
            'action': new_trade['action'],
            'entry_price': new_trade['entry_price'],
            'stop_loss': new_trade['stop_loss'],
            'take_profits': trade_data['take_profits'],
            'volume': new_trade['volume'],
            'status': 'pending',
            'created_at': created_at,
            'updated_at': new_trade.get('updated_at')
        }
        socketio.emit('trade_signal', trade_dict)
        return jsonify({'status': 'Trade queued for MT5', 'trade_id': trade_id, 'trade': trade_dict})
    except Exception as e:
        logger.error(f"Failed to queue trade: {str(e)}")
        return jsonify({'status': 'error', 'message': f'Failed to queue trade: {str(e)}'}), 500

# ----------------------------------------------------------------------
# 10. Main
# ----------------------------------------------------------------------
if __name__ == '__main__':
    try:
        init_db()
        get_telegram_credentials()  # Optionally load Telegram credentials once
        logger.info("Starting Flask-SocketIO server on http://0.0.0.0:5000")
        socketio.run(app, host="0.0.0.0", port=5000, debug=False)
    except Exception as e:
        logger.error(f"Failed to start server: {str(e)}")
        exit(1)
