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
from boto3.dynamodb.conditions import Attr
from boto3.dynamodb.types import TypeSerializer

REFRESH_SECRET = 'your-refresh-secret-key'  # Use a different secret than access token!

# ----------------------------------------------------------------------
# ENV & FLASK SETUP
# ----------------------------------------------------------------------
load_dotenv()

app = Flask(__name__)

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

CORS(
    app,
    resources={
        r"/api/*": {
            "origins": ["https://main.d1bpy75hw1zntc.amplifyapp.com"],
            "supports_credentials": True,
            "allow_headers": ["Authorization", "Content-Type"],
            "expose_headers": ["Authorization"],
            "methods": ["GET", "POST", "PUT", "OPTIONS"]
        }
    }
)

socketio = SocketIO(
    app,
    cors_allowed_origins=["https://main.d1bpy75hw1zntc.amplifyapp.com"],
    async_mode="eventlet",
    allow_headers=["Authorization", "Content-Type"],
    methods=["GET", "POST", "PUT", "OPTIONS"]
)

secret_key_value = os.getenv("SECRET_KEY", "fallback-secret")
app.config['SECRET_KEY'] = secret_key_value
SECRET_KEY = secret_key_value

bcrypt = Bcrypt(app)

openai_Client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# ----------------------------------------------------------------------
# DynamoDB Tables
# ----------------------------------------------------------------------
dynamodb = boto3.resource('dynamodb')
dynamodb_client = boto3.client('dynamodb', region_name='us-east-2')

users_table = dynamodb.Table('Users')
channels_table = dynamodb.Table('Channels')
signals_table = dynamodb.Table('Signals')
take_profits_table = dynamodb.Table('TakeProfits')
settings_table = dynamodb.Table('Settings')
trades_table = dynamodb.Table('Trades')

# ----------------------------------------------------------------------
# Telegram Configuration
# ----------------------------------------------------------------------
API_ID = None
API_HASH = None
PHONE_NUMBER = None
telegram_client = None
pending_code_hash = None  # Store the code hash for verification

def get_telegram_credentials():
    """Fetch Telegram credentials from the Settings table and initialize client."""
    global API_ID, API_HASH, PHONE_NUMBER, telegram_client
    try:
        settings = get_current_settings()
        API_ID = settings.get('telegramApiId')
        API_HASH = settings.get('telegramApiHash')
        PHONE_NUMBER = settings.get('telegramPhoneNumber')

        if not API_ID or not API_HASH or not PHONE_NUMBER:
            logger.error("Missing Telegram credentials in Settings: API_ID=%s, API_HASH=%s, PHONE_NUMBER=%s",
                        API_ID, API_HASH, PHONE_NUMBER)
            raise ValueError("telegramApiId, telegramApiHash, and telegramPhoneNumber must be set in Settings.")

        API_ID = int(API_ID)  # Ensure API_ID is an integer
        if telegram_client is None:
            telegram_client = TelegramClient('session', API_ID, API_HASH)
            logger.info("Telegram client initialized with settings: API_ID=%s, PHONE_NUMBER=%s", API_ID, PHONE_NUMBER)
        return True
    except ValueError as e:
        logger.error("Invalid Telegram credentials: %s", str(e))
        raise
    except Exception as e:
        logger.error("Failed to fetch Telegram credentials: %s", str(e))
        raise

async def ensure_telegram_session():
    """Ensure the Telegram session is valid, initiating sign-in if necessary."""
    global pending_code_hash
    try:
        await telegram_client.connect()
        if not await telegram_client.is_user_authorized():
            logger.warning("Telegram session invalid or missing; initiating sign-in.")
            code_request = await telegram_client.send_code_request(PHONE_NUMBER)
            pending_code_hash = code_request.phone_code_hash
            logger.info("Code request sent to %s; phone_code_hash: %s", PHONE_NUMBER, pending_code_hash)
            raise Exception("Verification code required to complete sign-in.")
        logger.info("Telegram session is valid.")
    except Exception as e:
        logger.error("Session check failed: %s", str(e))
        raise
    finally:
        if telegram_client.is_connected():
            await telegram_client.disconnect()

async def sign_in_with_code(code):
    """Complete Telegram sign-in with the provided verification code."""
    global pending_code_hash
    try:
        await telegram_client.connect()
        await telegram_client.sign_in(PHONE_NUMBER, code, phone_code_hash=pending_code_hash)
        logger.info("Successfully signed in with code; session saved to session.session.")
        pending_code_hash = None  # Clear after successful sign-in
    except errors.SessionPasswordNeededError:
        logger.error("Two-factor authentication required; not supported yet.")
        raise Exception("Two-factor authentication required; please disable it or handle manually.")
    except Exception as e:
        logger.error("Sign-in with code failed: %s", str(e))
        raise
    finally:
        if telegram_client.is_connected():
            await telegram_client.disconnect()

# ----------------------------------------------------------------------
# Enums
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
# DB INIT & GENERAL HELPERS
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
        ('telegramApiId', ''),
        ('telegramApiHash', ''),
        ('telegramPhoneNumber', '')
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
    try:
        response = channels_table.scan()
        for item in response.get('Items', []):
            channels_table.delete_item(Key={'channel_id': item['channel_id']})
        for channel in channels:
            channels_table.put_item(Item={
                'channel_id': channel['id'],
                'channel_name': channel['name'],
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
        active_channels = [channel for channel in all_channels if channel['is_active']]
        logger.info(f"Retrieved {len(all_channels)} channels, {len(active_channels)} active")
        return [{
            'channel_id': channel['channel_id'],
            'channel_name': channel['channel_name'],
            'is_active': channel['is_active']
        } for channel in all_channels]
    except Exception as e:
        logger.error(f"Error retrieving channels: {str(e)}")
        raise e

def get_channels_is_active(active_only=True):
    try:
        response = channels_table.scan()
        all_channels = response.get('Items', [])
        active_channels = [channel for channel in all_channels if channel['is_active'] == active_only]
        return [channel['channel_id'] for channel in active_channels]
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
        response = settings_table.scan()
        settings = response.get('Items', [])
        settings_dict = {}
        for setting in settings:
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
        take_profits = [tp['price'] for tp in tp_response.get('Items', [])]

        return {
            'channel': latest_signal['channel'],
            'symbol': latest_signal['symbol'],
            'entry_price': latest_signal['entry_price'],
            'action': latest_signal['action'],
            'stop_loss': latest_signal['stop_loss'],
            'take_profits': take_profits,
            'created_at': latest_signal['created_at']
        }
    except Exception as e:
        logger.error(f"Error fetching latest signal: {str(e)}")
        raise e

def update_signal(channel_id, updates):
    try:
        response = signals_table.scan(
            FilterExpression='channel = :cid',
            ExpressionAttributeValues={':cid': channel_id}
        )
        signals = response.get('Items', [])
        if not signals:
            return False

        signal = signals[0]
        signal_id = signal['id']

        update_expression = 'SET '
        expression_attribute_values = {}
        if 'symbol' in updates:
            update_expression += 'symbol = :symbol, '
            expression_attribute_values[':symbol'] = updates['symbol']
        if 'entry_price' in updates:
            update_expression += 'entry_price = :entry_price, '
            expression_attribute_values[':entry_price'] = float(updates['entry_price'])
        if 'action' in updates:
            update_expression += 'action = :action, '
            expression_attribute_values[':action'] = updates['action']
        if 'stop_loss' in updates:
            update_expression += 'stop_loss = :stop_loss, '
            expression_attribute_values[':stop_loss'] = float(updates['stop_loss'])
        update_expression += 'created_at = :created_at'
        expression_attribute_values[':created_at'] = datetime.utcnow().isoformat()

        signals_table.update_item(
            Key={'id': signal_id},
            UpdateExpression=update_expression,
            ExpressionAttributeValues=expression_attribute_values
        )

        if 'take_profits' in updates:
            tp_response = take_profits_table.scan(
                FilterExpression='signal_id = :sid',
                ExpressionAttributeValues={':sid': signal_id}
            )
            for tp in tp_response.get('Items', []):
                take_profits_table.delete_item(Key={'id': tp['id']})
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
# JWT AUTH DECORATOR
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
            g.user_id = int(payload['user_id'])  # Ensure user_id is int
            logger.info("Token validated successfully, user ID: %s", g.user_id)
        except jwt.ExpiredSignatureError:
            logger.warning("Token has expired")
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            logger.warning("Invalid token provided")
            return jsonify({"error": "Invalid token"}), 401
        return f(*args, **kwargs)
    return decorated

# ----------------------------------------------------------------------
# API Routes
# ----------------------------------------------------------------------
@app.route('/api/refresh', methods=['POST'])
def refresh_token():
    refresh_token = request.json.get('refreshToken')
    if not refresh_token:
        return jsonify({'error': 'Missing refresh token'}), 400

    try:
        payload = jwt.decode(refresh_token, REFRESH_SECRET, algorithms=['HS256'])
        user_id = int(payload.get('user_id'))  # Ensure user_id is int
        if not user_id:
            return jsonify({'error': 'Invalid refresh token payload'}), 401

        new_token = jwt.encode({
            'user_id': user_id,
            'exp': datetime.utcnow() + timedelta(minutes=15)
        }, SECRET_KEY, algorithm='HS256')

        return jsonify({'token': new_token})
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Refresh token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid refresh token'}), 401

@app.route("/api/register", methods=["POST"])
def register_user():
    name = request.json["name"]
    email = request.json["email"]
    password = request.json["password"]
    try:
        response = users_table.get_item(
            FilterExpression='email = :email',
            ExpressionAttributeValues={':email': email}
        )
        if response.get('Items', []):
            logger.warning(f"Registration attempt with existing email: {email}")
            return jsonify({"error": "User already exists"}), 409

        user_id = int(uuid.uuid4().int & (1 << 31) - 1)
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        users_table.put_item(Item={
            'id': user_id,
            'name': name,
            'email': email,
            'password': hashed_password
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
    email = request.json["email"]
    password = request.json["password"]
    try:
        response = users_table.get_item(
            FilterExpression='email = :email',
            ExpressionAttributeValues={':email': email}
        )
        user = response.get('Items', [None])[0]
        if not user:
            logger.warning(f"Login attempt with non-existent email: {email}")
            return jsonify({"error": "Can not find user. Please sign up."}), 401

        if not bcrypt.check_password_hash(user['password'], password):
            logger.warning(f"Invalid password for email: {email}")
            return jsonify({"error": "Invalid email or password."}), 401

        user_id = int(user['id']) if 'id' in user else None  # Ensure user_id is int
        user_name = user.get('name', '')
        user_email = user['email']

        token = jwt.encode({
            'user_id': user_id,
            'exp': datetime.utcnow() + timedelta(hours=24)
        }, SECRET_KEY, algorithm='HS256')

        refresh_token = jwt.encode({
            'user_id': user_id,
            'exp': datetime.utcnow() + timedelta(days=7)  # Longer expiration for refresh token
        }, REFRESH_SECRET, algorithm='HS256')

        settings = get_current_settings()
        logger.info(f"User logged in: {email}")
        return jsonify({
            "user": {"id": user_id, "name": user_name, "email": user_email},
            "token": token,
            "refreshToken": refresh_token,  # Added refresh token
            "settings": settings
        })
    except Exception as e:
        logger.error(f"Error logging in user: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/@me")
@token_required
def get_current_user():
    try:
        user_id = int(g.user_id)
        
        # Initialize the TypeSerializer
        serializer = TypeSerializer()
        key = {'id': serializer.serialize(user_id)}
        logger.debug(f"Fetching user from DynamoDB with id: {user_id}")
        response = users_table.get_item(Key=key)
        items = response.get('Items', [])
        if not items:
            logger.warning(f"User not found for ID: {user_id}")
            return jsonify({"error": "User not found"}), 404

        user = items[0]  # Assuming id is unique
        logger.info(f"Current user retrieved: {user['email']}")
        return jsonify({
            "user": {
                "id": user['id'],
                "name": user["name"],
                "email": user["email"]
            }
        })
    except Exception as e:
        logger.error(f"Error in /api/@me: {str(e)}")
        return jsonify({"error": f"Failed to fetch user: {str(e)}"}), 500

@app.route('/api/channels/all', methods=['GET'])
@token_required  # Added protection
def get_channels_endpoint():
    try:
        channels = get_all_channels()
        active_channels = get_channels_is_active(True)
        if channels:
            return jsonify({
                'status': 'success',
                'count': len(channels),
                'channels': channels,
                'active_channels': active_channels
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
@token_required
def add_channels_endpoint():
    try:
        get_telegram_credentials()
        logger.info("Fetching subscribed channels from Telegram.")
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(ensure_telegram_session())
        except Exception as e:
            logger.error("Telegram session requires verification: %s", str(e))
            return jsonify({
                'status': 'unauthorized',
                'message': 'Telegram session invalid. Verification code sent; use /telegram/verify_code to complete sign-in.'
            }), 401

        async def fetch_channels():
            async with telegram_client:
                logger.info("Connected to Telegram for channel fetch.")
                dialogs = await telegram_client.get_dialogs()
                channels = [
                    {"name": d.entity.title, "id": str(d.entity.id)}
                    for d in dialogs if d.is_channel
                ]
                logger.info("Fetched %d channels from Telegram.", len(channels))
                return channels

        channels = loop.run_until_complete(fetch_channels())
        loop.close()

        channels = add_channels(channels)
        return jsonify({
            'status': 'success',
            'count': len(channels),
            'channels': channels
        })
    except Exception as e:
        logger.error(f"Error in add_channels_endpoint: {str(e)}")
        return jsonify({'status': 'error', 'message': f"Failed to fetch channels: {str(e)}"}), 500

@app.route('/telegram/verify_code', methods=['POST'])
@token_required
def verify_telegram_code():
    """Verify the Telegram code and regenerate the session."""
    try:
        data = request.get_json()
        code = data.get('code')
        if not code:
            logger.warning("No verification code provided.")
            return jsonify({'status': 'error', 'message': 'Verification code required'}), 400

        get_telegram_credentials()  # Ensure client is initialized
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
@token_required  # Added protection
def update_channel_status_endpoint(channel_id):
    data = request.get_json()
    if 'is_active' not in data:
        logger.warning("Missing is_active parameter in update_channel_status_endpoint")
        return jsonify({'error': 'is_active parameter required'}), 400
    if update_channel_status(channel_id, data['is_active']):
        return jsonify({
            'status': 'success',
            'message': f'Channel {channel_id} updated',
            'is_active': data['is_active']
        })
    return jsonify({'error': 'Channel not found'}), 404

@app.route('/api/settings', methods=['GET'])
@token_required
def get_settings():
    try:
        settings = get_current_settings()
        return jsonify({"status": "success", "settings": settings}), 200
    except Exception as e:
        logger.error(f"Error fetching settings: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/settings', methods=['POST', 'PUT'])
@token_required
def update_settings():
    global settingStatus, telegram_client
    settingStatus = SettingStatus.UPDATED
    try:
        data = request.get_json()
        if not data or not isinstance(data, dict):
            logger.warning("Invalid data format in update_settings")
            return jsonify({'status': 'error', 'message': 'Invalid data format'}), 400
        for key, value in data.items():
            if not update_setting(key, value):
                settings_table.put_item(Item={'key': key, 'value': str(value)})
            if key in ['telegramApiId', 'telegramApiHash', 'telegramPhoneNumber']:
                telegram_client = None
                get_telegram_credentials()
                logger.info("Telegram settings updated; client reset.")
        current_settings = get_current_settings()
        return jsonify({
            'status': 'success',
            'message': 'Settings updated',
            'settings': current_settings
        })
    except Exception as e:
        logger.error(f"Error in update_settings: {str(e)}")
        return jsonify({'status': 'error', 'message': f'Failed to update settings: {str(e)}'}), 500

@app.route('/api/signal', methods=['POST'])
@token_required
def add_signal():
    try:
        data = request.get_json()
        if not data:
            logger.warning("No data provided in add_signal")
            return jsonify({'status': 'error', 'message': 'No data provided'}), 400
        signal = create_signal(data)
        return jsonify({
            'status': 'success',
            'message': 'Signal created',
            'signal_id': signal['id']
        }), 201
    except ValueError as e:
        logger.error(f"ValueError in add_signal: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 400
    except Exception as e:
        logger.error(f"Error in add_signal: {str(e)}")
        return jsonify({'status': 'error', 'message': f'Failed to create signal: {str(e)}'}), 500

@app.route('/api/signal', methods=['GET'])
@token_required
def get_signal():
    try:
        signal = get_latest_signal()
        if signal:
            return jsonify({'status': 'success', 'signal': signal})
        return jsonify({
            'status': 'success',
            'message': 'No active signals found',
            'signal': None
        })
    except Exception as e:
        logger.error(f"Error in get_signal: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/signal/history', methods=['GET'])
@token_required  # Added protection
def get_signal_history():
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        symbol = request.args.get('symbol')
        action = request.args.get('action')
        channel_id = request.args.get('channel')

        filter_expression = []
        expression_attribute_values = {}
        if symbol:
            filter_expression.append('symbol = :symbol')
            expression_attribute_values[':symbol'] = symbol.upper()
        if action:
            filter_expression.append('action = :action')
            expression_attribute_values[':action'] = action.upper()
        if channel_id:
            filter_expression.append('channel = :channel')
            expression_attribute_values[':channel'] = int(channel_id)

        scan_kwargs = {}
        if filter_expression:
            scan_kwargs['FilterExpression'] = ' AND '.join(filter_expression)
            scan_kwargs['ExpressionAttributeValues'] = expression_attribute_values

        response = signals_table.scan(**scan_kwargs)
        signals = response.get('Items', [])
        signals.sort(key=lambda x: x['created_at'], reverse=True)

        total = len(signals)
        start = (page - 1) * per_page
        end = start + per_page
        paginated_signals = signals[start:end]

        signal_list = []
        for signal in paginated_signals:
            tp_response = take_profits_table.scan(
                FilterExpression='signal_id = :sid',
                ExpressionAttributeValues={':sid': signal['id']}
            )
            take_profits = [tp['price'] for tp in tp_response.get('Items', [])]
            signal_list.append({
                'id': signal['id'],
                'channel': signal['channel'],
                'symbol': signal['symbol'],
                'action': signal['action'],
                'entry_price': signal['entry_price'],
                'stop_loss': signal['stop_loss'],
                'take_profits': take_profits,
                'created_at': signal['created_at']
            })

        return jsonify({
            'status': 'success',
            'signals': signal_list,
            'total': total,
            'pages': (total + per_page - 1) // per_page,
            'current_page': page
        })
    except Exception as e:
        logger.error(f"Error in get_signal_history: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/signal/<int:channel_id>', methods=['GET'])
@token_required  # Added protection
def get_channel_by_id(channel_id):
    try:
        response = signals_table.scan(
            FilterExpression='channel = :cid',
            ExpressionAttributeValues={':cid': channel_id}
        )
        signal = response.get('Items', [None])[0]
        if not signal:
            return jsonify({'status': 'error', 'message': 'Signal not found'}), 404

        tp_response = take_profits_table.scan(
            FilterExpression='signal_id = :sid',
            ExpressionAttributeValues={':sid': signal['id']}
        )
        take_profits = [tp['price'] for tp in tp_response.get('Items', [])]

        return jsonify({
            'status': 'success',
            'signal': {
                'id': signal['id'],
                'channel': signal['channel'],
                'symbol': signal['symbol'],
                'action': signal['action'],
                'entry_price': signal['entry_price'],
                'stop_loss': signal['stop_loss'],
                'take_profits': take_profits,
                'created_at': signal['created_at']
            }
        })
    except Exception as e:
        logger.error(f"Error in get_channel_by_id: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/signal/<int:channel_id>', methods=['PUT', 'PATCH'])
@token_required  # Added protection
def update_signal_endpoint(channel_id):
    try:
        data = request.get_json()
        if not data:
            logger.warning("No data provided in update_signal_endpoint")
            return jsonify({'status': 'error', 'message': 'No data provided'}), 400
        if 'action' in data and data['action'].upper() not in ['BUY', 'SELL']:
            logger.warning(f"Invalid action provided: {data['action']}")
            return jsonify({'status': 'error', 'message': 'Action must be either BUY or SELL'}), 400
        if update_signal(channel_id, data):
            response = signals_table.scan(
                FilterExpression='channel = :cid',
                ExpressionAttributeValues={':cid': channel_id}
            )
            signal = response.get('Items', [None])[0]
            tp_response = take_profits_table.scan(
                FilterExpression='signal_id = :sid',
                ExpressionAttributeValues={':sid': signal['id']}
            )
            take_profits = [tp['price'] for tp in tp_response.get('Items', [])]
            return jsonify({
                'status': 'success',
                'message': 'Signal updated',
                'signal': {
                    'id': signal['id'],
                    'symbol': signal['symbol'],
                    'action': signal['action'],
                    'entry_price': signal['entry_price'],
                    'stop_loss': signal['stop_loss'],
                    'take_profits': take_profits,
                    'created_at': signal['created_at']
                }
            })
        return jsonify({'status': 'error', 'message': 'Signal not found'}), 404
    except Exception as e:
        logger.error(f"Error in update_signal_endpoint: {str(e)}")
        return jsonify({'status': 'error', 'message': f'Failed to update signal: {str(e)}'}), 500

@app.route('/api/settings/<string:key>', methods=['POST', 'PUT'])
@token_required
def update_signal_setting(key):
    try:
        value = request.get_json().get('value')
        if value is None:
            logger.warning("No value provided in update_signal_setting")
            return jsonify({'status': 'error', 'message': 'Value is required'}), 400
        if update_setting(key, value):
            if key in ['telegramApiId', 'telegramApiHash', 'telegramPhoneNumber']:
                global telegram_client
                telegram_client = None
                get_telegram_credentials()
                logger.info("Telegram setting %s updated; client reset.", key)
            return jsonify({
                'status': 'success',
                'message': f'Setting {key} updated',
                'key': key,
                'value': value
            })
        else:
            settings_table.put_item(Item={'key': key, 'value': str(value)})
            if key in ['telegramApiId', 'telegramApiHash', 'telegramPhoneNumber']:
                global telegram_client
                telegram_client = None
                get_telegram_credentials()
                logger.info("New Telegram setting %s created; client reset.", key)
            return jsonify({
                'status': 'success',
                'message': f'New setting {key} created',
                'key': key,
                'value': value
            })
    except Exception as e:
        logger.error(f"Error in update_signal_setting: {str(e)}")
        return jsonify({'status': 'error', 'message': f'Failed to update setting: {str(e)}'}), 500

def parse_trading_signal(signal_text: str) -> dict:
    system_prompt = """Extract trading signal details from the given text and return as JSON with the following structure:
    {
        "symbol": "trading pair (e.g., XAUUSD, ETHUSDT)",
        "entry_price": single price value,
        "action": "BUY or SELL",
        "take_profits": array of price values,
        "stop_loss": single price value
    }
    Handle variations in formatting and extract partial information when possible."""

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
        parsed['take_profits'] = parsed.get('take_profits', []) if parsed.get('take_profits') is not None else []
        return parsed
    except Exception as e:
        logger.error(f"Error parsing trading signal: {str(e)}")
        return {"error": str(e)}

async def fetch_subscribed_channels():
    try:
        get_telegram_credentials()
        logger.info("Fetching subscribed channels.")
        await ensure_telegram_session()
        async with telegram_client:
            dialogs = await telegram_client.get_dialogs()
            channels = [
                {"name": d.entity.title, "id": str(d.entity.id)}
                for d in dialogs if d.is_channel
            ]
            logger.info("Fetched %d channels.", len(channels))
            return channels
    except Exception as e:
        logger.error("Failed to fetch subscribed channels: %s", str(e))
        raise

@app.route('/api/monitor', methods=['POST'])
@token_required  # Added protection
def monitor_channel():
    try:
        get_telegram_credentials()
        data = request.json
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

def start_monitoring(channels):
    async def monitor(channels):
        try:
            get_telegram_credentials()
            logger.info(f"Monitoring channels: {channels}")
            await ensure_telegram_session()
            async with telegram_client:
                @telegram_client.on(events.NewMessage(chats=channels))
                async def handler(event):
                    chat = await event.get_chat()
                    channel_id = chat.id
                    message_text = event.message.message
                    logger.info(f"Received message from channel {channel_id}: {message_text}")
                    if "buy" in message_text.lower() or "sell" in message_text.lower():
                        global signalStatus
                        signalStatus = SignalStatus.UPDATED
                        parsed_signal = parse_trading_signal(message_text)
                        update_signal(1, parsed_signal)
                        logger.info(f"Parsed signal: {parsed_signal}")
                        socketio.emit('new_signal', parsed_signal)

                await telegram_client.run_until_disconnected()
                logger.info("Telegram client disconnected.")
        except Exception as e:
            logger.error(f"Monitoring failed: {str(e)}")
            raise

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(monitor(channels))
    except Exception as e:
        logger.error(f"Error in monitoring loop: {str(e)}")
    finally:
        loop.close()

is_first = True

@app.route('/mt/accountinfo', methods=['POST'])
def mt_account():
    data = request.json
    if data['activeTrades'] is None:
        data['activeTrades'] = []
    if data['tradeshistory'] is None:
        data['tradeshistory'] = []
    logger.info(f"Received account info: {data}")
    socketio.emit('new_metadata', data)
    signal_data = "No Signal"
    setting_data = "No Setting"
    global signalStatus, settingStatus, is_first

    now = datetime.now().time()
    current_settings = get_current_settings()
    current_signal = get_latest_signal()
    allowedsymbol = current_settings['allowedSymbols'].split(',')

    if is_first:
        is_first = False
        return jsonify({"signal": signal_data, "setting": current_settings}), 202

    start_time = datetime.strptime(current_settings['tradingHoursStart'], "%H:%M").time()
    end_time = datetime.strptime(current_settings['tradingHoursEnd'], "%H:%M").time()

    if settingStatus == SettingStatus.UPDATED and signalStatus != SignalStatus.UPDATED:
        settingStatus = SettingStatus.IDLE
        setting_data = current_settings
        logger.info("Setting updated!")
        return jsonify({"signal": signal_data, "setting": setting_data}), 202

    if (start_time <= now <= end_time
            and current_settings['botEnabled']
            and current_signal
            and current_signal['symbol'] in allowedsymbol):
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
    try:
        response = trades_table.scan(
            FilterExpression='status = :status',
            ExpressionAttributeValues={':status': 'pending'}
        )
        trades = response.get('Items', [])
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
@token_required
def execute_trade():
    trade_data = request.json
    logger.info(f"Received trade request: {trade_data}")
    try:
        required_fields = ['symbol', 'action', 'entry_price', 'stop_loss', 'take_profits', 'volume']
        for field in required_fields:
            if field not in trade_data:
                logger.error(f"Missing required field in trade: {field}")
                return jsonify({'status': 'error', 'message': f'Missing required field: {field}'}), 400

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
        logger.info(f"Trade queued in database with ID: {trade_id}")

        trade_dict = {
            'id': trade_id,
            'symbol': new_trade['symbol'],
            'action': new_trade['action'],
            'entry_price': new_trade['entry_price'],
            'stop_loss': new_trade['stop_loss'],
            'take_profits': trade_data['take_profits'],
            'volume': new_trade['volume'],
            'status': new_trade['status'],
            'created_at': new_trade['created_at'],
            'updated_at': new_trade.get('updated_at')
        }
        socketio.emit('trade_signal', trade_dict)
        return jsonify({'status': 'Trade queued for MT5', 'trade_id': trade_id, 'trade': trade_dict})
    except Exception as e:
        logger.error(f"Failed to queue trade: {str(e)}")
        return jsonify({'status': 'error', 'message': f'Failed to queue trade: {str(e)}'}), 500
    
    
@app.route('/api/trade/history', methods=['GET', 'OPTIONS'])
@token_required
def get_trade_history():
    if request.method == 'OPTIONS':
        return '', 200  # Handle preflight request

    try:
        response = trades_table.scan()
        trades = response.get('Items', [])
        trade_list = [{
            'id': trade['id'],
            'symbol': trade['symbol'],
            'action': trade['action'],
            'entry_price': trade['entry_price'],
            'stop_loss': trade['stop_loss'],
            'take_profits': json.loads(trade['take_profits']),
            'volume': trade['volume'],
            'status': trade['status'],
            'created_at': trade['created_at'],
            'updated_at': trade.get('updated_at', '')
        } for trade in trades]
        return jsonify({
            'status': 'success',
            'trades': trade_list,
            'total': len(trade_list)
        })
    except Exception as e:
        logger.error(f"Error in get_trade_history: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------
if __name__ == '__main__':
    try:
        init_db()
        get_telegram_credentials()
        logger.info("Starting Flask-SocketIO server on http://0.0.0.0:5000")
        socketio.run(app, host="0.0.0.0", port=5000, debug=False)
    except Exception as e:
        logger.error(f"Failed to start server: {str(e)}")
        exit(1)