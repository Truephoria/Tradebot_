from flask import Flask, jsonify, request, session
from flask_bcrypt import Bcrypt
from flask_session import Session
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import os
from dotenv import load_dotenv
import json
from telethon import TelegramClient, events
from openai import OpenAI
import asyncio
from threading import Thread
from enum import Enum
import re
from datetime import datetime, timedelta
import jwt
from functools import wraps
import logging
import time
import requests
import boto3
from botocore.exceptions import ClientError
import uuid

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Configure CORS explicitly for API routes
CORS(app, resources={r"/api/*": {"origins": "https://main.d1bpy75hw1zntc.amplifyapp.com/"}}, supports_credentials=True)

# Configure SocketIO with CORS
socketio = SocketIO(app, cors_allowed_origins="https://main.d1bpy75hw1zntc.amplifyapp.com/")

# Configure flask-session to use filesystem (since we're removing SQLAlchemy)
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_PERMANENT"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = 3600
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")

# Initialize flask-session
session_handler = Session(app)
bcrypt = Bcrypt(app)

# Initialize OpenAI client
openai_Client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# Initialize DynamoDB client
dynamodb = boto3.resource('dynamodb')
users_table = dynamodb.Table('Users')
channels_table = dynamodb.Table('Channels')
signals_table = dynamodb.Table('Signals')
take_profits_table = dynamodb.Table('TakeProfits')
settings_table = dynamodb.Table('Settings')
trades_table = dynamodb.Table('Trades')

# Telegram Configuration
API_ID = os.getenv("API_ID")
API_HASH = os.getenv("API_HASH")
PHONE_NUMBER = os.getenv("PHONE_NUMBER")
SECRET_KEY = os.getenv("SECRET_KEY")

# Enums for status tracking
class SignalStatus(Enum):
    IDLE = 0
    UPDATED = 1

signalStatus = SignalStatus.IDLE

class SettingStatus(Enum):
    IDLE = 0
    UPDATED = 1

settingStatus = SettingStatus.IDLE

# Database Initialization
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
            response = settings_table.get_item(Key={'key': key})
            if 'Item' not in response:
                settings_table.put_item(Item={'key': key, 'value': value})
        except ClientError as e:
            logger.error(f"Error initializing setting {key}: {str(e)}")
            raise e
    logger.info("DynamoDB initialized with default settings")

def add_channels(channels):
    try:
        # Delete existing channels
        response = channels_table.scan()
        for item in response.get('Items', []):
            channels_table.delete_item(Key={'channel_id': item['channel_id']})

        # Add new channels
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
        response = channels_table.update_item(
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
                value = value.lower() == 'true'
            elif key in ['maxDailyLoss', 'maxTradesPerDay', 'minimumRRR', 'riskValue']:
                value = float(value)
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
    
    signal_id = int(uuid.uuid4().int & (1<<31)-1)  # Generate a 31-bit integer ID
    created_at = datetime.utcnow().isoformat()
    signal_item = {
        'id': signal_id,
        'channel': 1,  # Hardcoded for now
        'symbol': signal_data['symbol'].upper(),
        'entry_price': float(signal_data['entry_price']),
        'action': signal_data['action'].upper(),
        'stop_loss': float(signal_data['stop_loss']),
        'created_at': created_at
    }
    signals_table.put_item(Item=signal_item)

    if 'take_profits' in signal_data and isinstance(signal_data['take_profits'], list):
        for tp in signal_data['take_profits']:
            tp_id = int(uuid.uuid4().int & (1<<31)-1)
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
        
        # Fetch take profits
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
        
        signal = signals[0]  # Take the first signal for this channel
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
            # Delete existing take profits
            tp_response = take_profits_table.scan(
                FilterExpression='signal_id = :sid',
                ExpressionAttributeValues={':sid': signal_id}
            )
            for tp in tp_response.get('Items', []):
                take_profits_table.delete_item(Key={'id': tp['id']})
            
            # Add new take profits
            for tp in updates['take_profits']:
                tp_id = int(uuid.uuid4().int & (1<<31)-1)
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

# JWT Authentication Decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            logger.warning("No valid Authorization header provided")
            return jsonify({"error": "Unauthorized"}), 401
        token = auth_header.split(' ')[1]
        try:
            jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            logger.info("Token validated successfully")
        except jwt.ExpiredSignatureError:
            logger.warning("Token has expired")
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            logger.warning("Invalid token provided")
            return jsonify({"error": "Invalid token"}), 401
        return f(*args, **kwargs)
    return decorated

# API Routes
@app.route("/api/register", methods=["POST"])
def register_user():
    name = request.json["name"]
    email = request.json["email"]
    password = request.json["password"]
    try:
        response = users_table.scan(
            FilterExpression='email = :email',
            ExpressionAttributeValues={':email': email}
        )
        if response.get('Items', []):
            logger.warning(f"Registration attempt with existing email: {email}")
            return jsonify({"error": "User already exists"}), 409
        
        user_id = int(uuid.uuid4().int & (1<<31)-1)
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
        session['user_id'] = user_id
        logger.info(f"User registered: {email}")
        return jsonify({
            "user": {
                "id": user_id,
                "name": name,
                "email": email,
            },
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
        response = users_table.scan(
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
        
        token = jwt.encode({
            'user_id': user['id'],
            'exp': datetime.utcnow() + timedelta(hours=24)
        }, SECRET_KEY, algorithm='HS256')
        session['user_id'] = user['id']
        logger.info(f"User logged in: {email}")
        return jsonify({
            "user": {
                "id": user['id'],
                "name": user['name'],
                "email": user['email'],
            },
            "token": token
        })
    except Exception as e:
        logger.error(f"Error logging in user: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/logout", methods=["POST"])
def logout_user():
    session.pop("user_id", None)
    logger.info("User logged out")
    return "200"

@app.route("/api/@me")
def get_current_user():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        logger.warning("No Authorization header for /api/@me")
        return jsonify({"error": "Unauthorized"}), 401
    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        user_id = payload['user_id']
        response = users_table.get_item(Key={'id': user_id})
        user = response.get('Item')
        if not user:
            logger.warning(f"User not found for ID: {user_id}")
            return jsonify({"error": "User not found"}), 404
        logger.info(f"Current user retrieved: {user['email']}")
        return jsonify({
            "user": {
                "id": user['id'],
                "name": user['name'],
                "email": user['email'],
            },
            "token": token
        })
    except jwt.ExpiredSignatureError:
        logger.warning("Token expired for /api/@me")
        return jsonify({"error": "Token expired"}), 401
    except jwt.InvalidTokenError:
        logger.warning("Invalid token for /api/@me")
        return jsonify({"error": "Invalid token"}), 401

@app.route('/api/channels/all', methods=['GET'])
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
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/channels', methods=['GET'])
def add_channels_endpoint():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    channels = loop.run_until_complete(fetch_subscribed_channels())
    channels = add_channels(channels)
    return jsonify({
        'status': 'success',
        'count': len(channels),
        'channels': channels
    })

@app.route('/api/channels/<string:channel_id>/status', methods=['PUT'])
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
    global settingStatus
    settingStatus = SettingStatus.UPDATED
    try:
        data = request.get_json()
        if not data or not isinstance(data, dict):
            logger.warning("Invalid data format in update_settings")
            return jsonify({'status': 'error', 'message': 'Invalid data format'}), 400
        for key, value in data.items():
            if not update_setting(key, value):
                settings_table.put_item(Item={'key': key, 'value': str(value)})
        current_settings = get_current_settings()
        return jsonify({
            'status': 'success',
            'message': 'Settings updated',
            'settings': current_settings
        })
    except Exception as e:
        logger.error(f"Error in update_settings: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Failed to update settings: {str(e)}'
        }), 500

@app.route('/api/signal', methods=['POST'])
@token_required
def add_signal():
    try:
        data = request.get_json()
        if not data:
            logger.warning("No data provided in add_signal")
            return jsonify({
                'status': 'error',
                'message': 'No data provided'
            }), 400
        signal = create_signal(data)
        return jsonify({
            'status': 'success',
            'message': 'Signal created',
            'signal_id': signal['id']
        }), 201
    except ValueError as e:
        logger.error(f"ValueError in add_signal: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 400
    except Exception as e:
        logger.error(f"Error in add_signal: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Failed to create signal: {str(e)}'
        }), 500

@app.route('/api/signal', methods=['GET'])
@token_required
def get_signal():
    try:
        signal = get_latest_signal()
        if signal:
            return jsonify({
                'status': 'success',
                'signal': signal
            })
        return jsonify({
            'status': 'success',
            'message': 'No active signals found',
            'signal': None
        })
    except Exception as e:
        logger.error(f"Error in get_signal: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e. __str__())
        }), 500

@app.route('/api/signal/history', methods=['GET'])
def get_signal_history():
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        symbol = request.args.get('symbol')
        action = request.args.get('action')
        channel_id = request.args.get('channel')

        # Scan signals with filters
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

        # Pagination
        total = len(signals)
        start = (page - 1) * per_page
        end = start + per_page
        paginated_signals = signals[start:end]

        # Fetch take profits for each signal
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
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/signal/<int:channel_id>', methods=['GET'])
def get_channel_by_id(channel_id):
    try:
        response = signals_table.scan(
            FilterExpression='channel = :cid',
            ExpressionAttributeValues={':cid': channel_id}
        )
        signal = response.get('Items', [None])[0]
        if not signal:
            return jsonify({
                'status': 'error',
                'message': 'Signal not found'
            }), 404

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
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/signal/<int:channel_id>', methods=['PUT', 'PATCH'])
def update_signal_endpoint(channel_id):
    try:
        data = request.get_json()
        if not data:
            logger.warning("No data provided in update_signal_endpoint")
            return jsonify({
                'status': 'error',
                'message': 'No data provided'
            }), 400
        if 'action' in data and data['action'].upper() not in ['BUY', 'SELL']:
            logger.warning(f"Invalid action provided: {data['action']}")
            return jsonify({
                'status': 'error',
                'message': 'Action must be either BUY or SELL'
            }), 400
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
        return jsonify({
            'status': 'error',
            'message': 'Signal not found'
        }), 404
    except Exception as e:
        logger.error(f"Error in update_signal_endpoint: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Failed to update signal: {str(e)}'
        }), 500

@app.route('/api/settings/<string:key>', methods=['POST', 'PUT'])
@token_required
def update_signal_setting(key):
    try:
        value = request.get_json().get('value')
        if value is None:
            logger.warning("No value provided in update_signal_setting")
            return jsonify({'status': 'error', 'message': 'Value is required'}), 400
        if update_setting(key, value):
            return jsonify({
                'status': 'success',
                'message': f'Setting {key} updated',
                'key': key,
                'value': value
            })
        else:
            settings_table.put_item(Item={'key': key, 'value': str(value)})
            return jsonify({
                'status': 'success',
                'message': f'New setting {key} created',
                'key': key,
                'value': value
            })
    except Exception as e:
        logger.error(f"Error in update_signal_setting: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Failed to update setting: {str(e)}'
        }), 500

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
        return {"error": str(e)}

async def fetch_subscribed_channels():
    async with TelegramClient('session', API_ID, API_HASH) as telegram_Client:
        if not await telegram_Client.is_user_authorized():
            logger.info(f"Authorizing Telegram client with phone number: {PHONE_NUMBER}")
            await telegram_Client.send_code_request(PHONE_NUMBER)
            code = input(f"Enter the code sent to {PHONE_NUMBER}: ")
            await telegram_Client.sign_in(PHONE_NUMBER, code)
        dialogs = await telegram_Client.get_dialogs()
        return [
            {"name": dialog.entity.title, "id": str(dialog.entity.id)}
            for dialog in dialogs if dialog.is_channel
        ]

@app.route('/api/monitor', methods=['POST'])
@token_required
def monitor_channel():
    try:
        data = request.json
        if not data or 'channel_id' not in data:
            return jsonify({"status": "error", "message": "channel_id is required"}), 400
        
        channels = [int(x) for x in data.get("channel_id")]
        logger.info(f"Monitoring channel: {channels}")
        
        thread = Thread(target=start_monitoring, args=(channels,))
        thread.daemon = True
        thread.start()
        
        return jsonify({"status": "Monitoring started", "channel_id": channels}), 200
    except Exception as e:
        logger.error(f"Error in monitor_channel: {str(e)}")
        return jsonify({"status": "error", "message": f"Failed to start monitoring: {str(e)}"}), 500

def start_monitoring(channels):
    async def monitor(channels):
        logger.info(f"Starting monitoring for channels: {channels}")
        try:
            async with TelegramClient('session', API_ID, API_HASH) as telegram_Client:
                if not await telegram_Client.is_user_authorized():
                    logger.warning("Telegram client not authorized; attempting sign-in")
                    await telegram_Client.send_code_request(PHONE_NUMBER)
                    code = input("Enter the Telegram code: ")
                    await telegram_Client.sign_in(PHONE_NUMBER, code)

                @telegram_Client.on(events.NewMessage(chats=channels))
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
                        logger.info(f"Received signal from channel {channel_id}: {parsed_signal}")
                        socketio.emit('new_signal', parsed_signal)

                while True:
                    try:
                        await telegram_Client.run_until_disconnected()
                        logger.info("Telegram client disconnected; attempting to reconnect...")
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
    if start_time <= now <= end_time and current_settings['botEnabled'] and current_signal and current_signal['symbol'] in allowedsymbol:
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

        trade_id = int(uuid.uuid4().int & (1<<31)-1)
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

if __name__ == '__main__':
    try:
        init_db()
        logger.info("Starting Flask-SocketIO server on http://0.0.0.0:5000")
        socketio.run(app, host="0.0.0.0", port=5000, debug=True)
    except Exception as e:
        logger.error(f"Failed to start server: {str(e)}")
        exit(1)