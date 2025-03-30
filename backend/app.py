from flask import Flask, jsonify, request, session
from flask_bcrypt import Bcrypt
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
import sqlalchemy
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import os
from dotenv import load_dotenv
import json
from telethon import TelegramClient, events
from openai import OpenAI
import asyncio
from threading import Thread
from queue import Queue
from enum import Enum
import re
from datetime import datetime, timedelta
import jwt
from functools import wraps
import logging
import time
from pyngrok import ngrok, conf
import atexit
import psutil
import random
import requests

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)



# Set ngrok auth token if available (optional, for free tier)
NGROK_AUTH_TOKEN = os.getenv("NGROK_AUTH_TOKEN")
if NGROK_AUTH_TOKEN:
    ngrok.set_auth_token(NGROK_AUTH_TOKEN)

# Function to kill existing ngrok processes
def kill_ngrok_processes():
    for proc in psutil.process_iter(['pid', 'name']):
        if 'ngrok' in proc.info['name'].lower():
            try:
                proc.kill()
                logger.info(f"Killed existing ngrok process with PID {proc.info['pid']}")
            except psutil.NoSuchProcess:
                pass
    time.sleep(1)  # Wait for process to fully terminate

# Function to check if ngrok is running and get the tunnel URL
def check_ngrok():
    try:
        # Get current tunnels
        tunnels = ngrok.get_tunnels()
        for tunnel in tunnels:
            if 'addr' in tunnel.config and tunnel.config['addr'] == 'http://localhost:5000':
                logger.info(f"ngrok tunnel already exists: {tunnel.public_url}")
                return tunnel.public_url
        return None
    except Exception as e:
        logger.warning(f"Error checking ngrok tunnels: {e}")
        return None

# Function to start ngrok
def start_ngrok():
    public_url = check_ngrok()
    if public_url:
        return public_url
    
    logger.info("Starting ngrok for port 5000...")
    try:
        # Kill any existing ngrok processes to avoid session conflicts
        kill_ngrok_processes()
        
        # Configure ngrok (optional: specify region or config)
        pyngrok_config = conf.PyngrokConfig()
        # Start tunnel
        tunnel = ngrok.connect(5000, proto="http", bind_tls=True, domain="ideal-largely-flamingo.ngrok.app")
        public_url = tunnel.public_url
        logger.info(f"ngrok tunnel started: {public_url}")
        return public_url
    except Exception as e:
        logger.error(f"Failed to start ngrok: {e}")
        raise

# Function to stop ngrok
def stop_ngrok():
    logger.info("Disconnecting ngrok...")
    try:
        tunnels = ngrok.get_tunnels()
        for tunnel in tunnels:
            if 'addr' in tunnel.config and tunnel.config['addr'] == 'http://localhost:5000':
                ngrok.disconnect(tunnel.public_url)
                logger.info(f"Disconnected tunnel: {tunnel.public_url}")
        kill_ngrok_processes()  # Ensure process is fully terminated
    except Exception as e:
        logger.warning(f"Error disconnecting ngrok: {e}")

# Register stop_ngrok to run on exit
atexit.register(stop_ngrok)

# Start ngrok and get the public URL
NGROK_PUBLIC_URL = start_ngrok()

# Configure CORS explicitly for API routes
CORS(app, resources={r"/api/*": {"origins": "http://localhost:3000"}}, supports_credentials=True)

# Configure SocketIO with CORS
socketio = SocketIO(app, cors_allowed_origins="http://localhost:3000")

# Configure SQLAlchemy (for your main database)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///trading_bot.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)  # Your main SQLAlchemy instance

# Configure flask-session to use SQLAlchemy with YOUR existing `db`
app.config["SESSION_TYPE"] = "sqlalchemy"  # Use SQLAlchemy backend
app.config["SESSION_SQLALCHEMY"] = db  # Reuse your existing SQLAlchemy instance
app.config["SESSION_SQLALCHEMY_TABLE"] = "sessions"  # Optional: custom table name
app.config["SESSION_PERMANENT"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = 3600  # Session lifetime in seconds
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")

# Initialize flask-session AFTER SQLAlchemy
session_handler = Session(app)  # Renamed to avoid shadowing built-in `session`
bcrypt = Bcrypt(app)

# Initialize OpenAI client
openai_Client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# Telegram Configuration
API_ID = os.getenv("API_ID")
API_HASH = os.getenv("API_HASH")
PHONE_NUMBER = os.getenv("PHONE_NUMBER")
SECRET_KEY = os.getenv("SECRET_KEY")  # Ensure this is in your .env file

# Enums for status tracking
class SignalStatus(Enum):
    IDLE = 0
    UPDATED = 1

signalStatus = SignalStatus.IDLE

class SettingStatus(Enum):
    IDLE = 0
    UPDATED = 1

settingStatus = SettingStatus.IDLE

# Database Models
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(30))
    email = db.Column(db.String, unique=True)
    password = db.Column(db.String(30))

class Channel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    channel_id = db.Column(db.String(100), unique=True, nullable=False)
    channel_name = db.Column(db.String(100))
    is_active = db.Column(db.Boolean, default=False)

    def to_dict(self):
        return {
            'channel_id': self.channel_id,
            'channel_name': self.channel_name,
            'is_active': self.is_active,
        }

class Signal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    channel = db.Column(db.BigInteger)
    symbol = db.Column(db.String(20))
    entry_price = db.Column(db.Float)
    action = db.Column(db.String(10))  # 'BUY' or 'SELL'
    stop_loss = db.Column(db.Float)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    def to_dict(self):
        return {
            'channel': self.channel,
            'symbol': self.symbol,
            'entry_price': self.entry_price,
            'action': self.action,
            'stop_loss': self.stop_loss
        }

class TakeProfit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    signal_id = db.Column(db.Integer, db.ForeignKey('signal.id'))
    price = db.Column(db.Float)
    signal = db.relationship('Signal', backref=db.backref('take_profits', lazy=True))

class Setting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True)
    value = db.Column(db.String(255))

    @staticmethod
    def get_all_as_dict():
        settings = Setting.query.all()
        return {s.key: s.value for s in settings}
    
class Trade(db.Model):
    __tablename__ = "trades"
    id = db.Column(db.Integer, primary_key=True)
    symbol = db.Column(db.String(20), nullable=False)
    action = db.Column(db.String(10), nullable=False)  # 'BUY' or 'SELL'
    entry_price = db.Column(db.Float, nullable=False)
    stop_loss = db.Column(db.Float, nullable=False)
    take_profits = db.Column(db.Text, nullable=False)  # JSON string of take-profit levels
    volume = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, sent, executed, failed
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    updated_at = db.Column(db.DateTime, onupdate=db.func.current_timestamp())

    def to_dict(self):
        return {
            'id': self.id,
            'symbol': self.symbol,
            'action': self.action,
            'entry_price': self.entry_price,
            'stop_loss': self.stop_loss,
            'take_profits': json.loads(self.take_profits),
            'volume': self.volume,
            'status': self.status,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

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

# Database Initialization
def init_db():
    db.create_all()
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
        if not Setting.query.filter_by(key=key).first():
            db.session.add(Setting(key=key, value=value))
    db.session.commit()
    logger.info("Database initialized with default settings")

def add_channels(channels):
    try:
        Channel.query.delete()
        for channel in channels:
            if not Channel.query.filter_by(channel_id=channel['id']).first():
                db.session.add(Channel(channel_id=channel['id'], channel_name=channel['name'], is_active=False))
        db.session.commit()
        logger.info(f"Added {len(channels)} channels to the database")
        return get_all_channels()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to update channels: {str(e)}")
        raise Exception(f"Failed to update channels: {str(e)}")

def get_all_channels():
    all_channels = Channel.query.all()
    active_channels = [channel for channel in all_channels if channel.is_active]
    logger.info(f"Retrieved {len(all_channels)} channels, {len(active_channels)} active")
    return [{
        'channel_id': channel.channel_id,
        'channel_name': channel.channel_name,
        'is_active': channel.is_active
    } for channel in all_channels]

def get_channels_is_active(active_only=True):
    all_channels = Channel.query.all()
    active_channels = [channel for channel in all_channels if channel.is_active == active_only]
    return [channel.channel_id for channel in active_channels]

def update_channel_status(channel_id, is_active):
    channel = Channel.query.filter_by(channel_id=channel_id).first()
    if channel:
        channel.is_active = is_active
        db.session.commit()
        logger.info(f"Updated channel {channel_id} status to {is_active}")
        return True
    logger.warning(f"Channel {channel_id} not found for status update")
    return False

def get_current_settings():
    settings = Setting.query.all()
    settings_dict = {}
    for setting in settings:
        value = setting.value
        if setting.key in ['botEnabled', 'enableTrailingStop']:
            value = value.lower() == 'true'
        elif setting.key in ['maxDailyLoss', 'maxTradesPerDay', 'minimumRRR', 'riskValue']:
            value = float(value)
        settings_dict[setting.key] = value
    return settings_dict

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
    setting = Setting.query.filter_by(key=key).first()
    if setting:
        validated_value = validate_setting_value(key, value)
        setting.value = validated_value
        db.session.commit()
        logger.info(f"Updated setting {key} to {validated_value}")
        return True
    return False

def create_signal(signal_data):
    required_fields = ['symbol', 'entry_price', 'action', 'stop_loss']
    for field in required_fields:
        if field not in signal_data:
            raise ValueError(f"Missing required field: {field}")
    new_signal = Signal(
        channel=int(1),  # Hardcoded for now; adjust as needed
        symbol=signal_data['symbol'].upper(),
        entry_price=float(signal_data['entry_price']),
        action=signal_data['action'].upper(),
        stop_loss=float(signal_data['stop_loss'])
    )
    db.session.add(new_signal)
    db.session.flush()
    if 'take_profits' in signal_data and isinstance(signal_data['take_profits'], list):
        for tp in signal_data['take_profits']:
            new_tp = TakeProfit(signal_id=new_signal.id, price=float(tp))
            db.session.add(new_tp)
    db.session.commit()
    logger.info(f"Created new signal with ID {new_signal.id}")
    return new_signal

def get_latest_signal():
    signal = Signal.query.order_by(Signal.created_at.desc()).first()
    if signal:
        return {
            'channel': signal.channel,
            'symbol': signal.symbol,
            'entry_price': signal.entry_price,
            'action': signal.action,
            'stop_loss': signal.stop_loss,
            'take_profits': [tp.price for tp in signal.take_profits],
            'created_at': signal.created_at.isoformat()
        }
    return None

def update_signal(channel_id, updates):
    with app.app_context():  # Added Flask app context here
        signal = Signal.query.filter_by(channel=channel_id).first()
        if not signal:
            return False
        if 'symbol' in updates:
            signal.symbol = updates['symbol']
        if 'entry_price' in updates:
            signal.entry_price = updates['entry_price']
        if 'action' in updates:
            signal.action = updates['action']
        if 'stop_loss' in updates:
            signal.stop_loss = updates['stop_loss']
        signal.created_at = db.func.current_timestamp()
        if 'take_profits' in updates:
            TakeProfit.query.filter_by(signal_id=signal.id).delete()
            for tp in updates['take_profits']:
                new_tp = TakeProfit(signal_id=signal.id, price=tp)
                db.session.add(new_tp)
        db.session.commit()
        logger.info(f"Updated signal for channel {channel_id}")
        return True

# API Routes
@app.route("/api/register", methods=["POST"])
def register_user():
    name = request.json["name"]
    email = request.json["email"]
    password = request.json["password"]
    user_exists = User.query.filter_by(email=email).first() is not None
    if user_exists:
        logger.warning(f"Registration attempt with existing email: {email}")
        return jsonify({"error": "User already exists"}), 409
    hashed_password = bcrypt.generate_password_hash(password)
    new_user = User(name=name, email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    token = jwt.encode({
        'user_id': new_user.id,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }, SECRET_KEY, algorithm='HS256')
    session['user_id'] = new_user.id  # Use dictionary access to avoid shadowing
    logger.info(f"User registered: {email}")
    return jsonify({
        "user": {
            "id": new_user.id,
            "name": new_user.name,
            "email": new_user.email,
        },
        "token": token
    })

@app.route("/api/login", methods=["POST"])
def login_user():
    email = request.json["email"]
    password = request.json["password"]
    user = User.query.filter_by(email=email).first()
    if user is None:
        logger.warning(f"Login attempt with non-existent email: {email}")
        return jsonify({"error": "Can not find user. Please sign up."}), 401
    if not bcrypt.check_password_hash(user.password, password):
        logger.warning(f"Invalid password for email: {email}")
        return jsonify({"error": "Invalid email or password."}), 401
    token = jwt.encode({
        'user_id': user.id,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }, SECRET_KEY, algorithm='HS256')
    session['user_id'] = user.id
    logger.info(f"User logged in: {email}")
    return jsonify({
        "user": {
            "id": user.id,
            "name": user.name,
            "email": user.email,
        },
        "token": token
    })

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
        user = User.query.filter_by(id=user_id).first()
        logger.info(f"Current user retrieved: {user.email}")
        return jsonify({
            "user": {
                "id": user.id,
                "name": user.name,
                "email": user.email,
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
                new_setting = Setting(key=key, value=str(value))
                db.session.add(new_setting)
        db.session.commit()
        current_settings = get_current_settings()
        return jsonify({
            'status': 'success',
            'message': 'Settings updated',
            'settings': current_settings
        })
    except Exception as e:
        db.session.rollback()
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
            'signal_id': signal.id
        }), 201
    except ValueError as e:
        db.session.rollback()
        logger.error(f"ValueError in add_signal: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 400
    except Exception as e:
        db.session.rollback()
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
            'message': str(e)
        }), 500

@app.route('/api/signal/history', methods=['GET'])
def get_signal_history():
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        symbol = request.args.get('symbol')
        action = request.args.get('action')
        channel_id = request.args.get('channel')
        query = Signal.query
        if symbol:
            query = query.filter(Signal.symbol == symbol.upper())
        if action:
            query = query.filter(Signal.action == action.upper())
        if channel_id:
            query = query.filter(Signal.channel == int(channel_id))
        signals = query.order_by(Signal.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
        signal_list = [{
            'id': signal.id,
            'channel': signal.channel,
            'symbol': signal.symbol,
            'action': signal.action,
            'entry_price': signal.entry_price,
            'stop_loss': signal.stop_loss,
            'take_profits': [tp.price for tp in signal.take_profits],
            'created_at': signal.created_at.isoformat()
        } for signal in signals.items]
        return jsonify({
            'status': 'success',
            'signals': signal_list,
            'total': signals.total,
            'pages': signals.pages,
            'current_page': signals.page
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
        signal = Signal.query.filter_by(channel=channel_id).first()
        return jsonify({
            'status': 'success',
            'signal': {
                'id': signal.id,
                'channel': signal.channel,
                'symbol': signal.symbol,
                'action': signal.action,
                'entry_price': signal.entry_price,
                'stop_loss': signal.stop_loss,
                'take_profits': [tp.price for tp in signal.take_profits],
                'created_at': signal.created_at.isoformat()
            }
        })
    except Exception as e:
        logger.error(f"Error in get_channel_by_id: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 404 if isinstance(e, sqlalchemy.orm.exc.NoResultFound) else 500

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
            signal = Signal.query.filter_by(channel=channel_id).first()
            return jsonify({
                'status': 'success',
                'message': 'Signal updated',
                'signal': {
                    'id': signal.id,
                    'symbol': signal.symbol,
                    'action': signal.action,
                    'entry_price': signal.entry_price,
                    'stop_loss': signal.stop_loss,
                    'take_profits': [tp.price for tp in signal.take_profits],
                    'created_at': signal.created_at.isoformat()
                }
            })
        return jsonify({
            'status': 'error',
            'message': 'Signal not found'
        }), 404
    except Exception as e:
        db.session.rollback()
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
            new_setting = Setting(key=key, value=str(value))
            db.session.add(new_setting)
            db.session.commit()
            return jsonify({
                'status': 'success',
                'message': f'New setting {key} created',
                'key': key,
                'value': value
            })
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error in update_signal_setting: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Failed to update setting: {str(e)}'
        }), 500

# Function to parse trading signals using GPT-4o
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
    
    max_retries = 3
    for attempt in range(max_retries):
        try:
            # Introduce a small random delay to avoid hitting the rate limit
            time.sleep(2 + random.uniform(0, 1))  # Random jitter

            # OpenAI API call
            response = openai_Client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": signal_text}
                ]
            )
            print(response.choices[0].message.content)
            
            # Log the raw response from OpenAI
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

# API endpoint to start monitoring a channel
@app.route('/api/monitor', methods=['POST'])
@token_required
def monitor_channel():
    try:
        data = request.json
        if not data or 'channel_id' not in data:
            return jsonify({"status": "error", "message": "channel_id is required"}), 400
        
        channels = [int(x) for x in data.get("channel_id")]
        logger.info(f"Monitoring channel: {channels}")
        
        # Start monitoring in a separate thread
        thread = Thread(target=start_monitoring, args=(channels,))
        thread.daemon = True
        thread.start()
        
        return jsonify({"status": "Monitoring started", "channel_id": channels}), 200
    except Exception as e:
        logger.error(f"Error in monitor_channel: {str(e)}")
        return jsonify({"status": "error", "message": f"Failed to start monitoring: {str(e)}"}), 500

# Function to start monitoring a channel
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
                        update_signal(1, parsed_signal)  # Update signal in DB
                        logger.info(f"Received signal from channel {channel_id}: {parsed_signal}")
                        socketio.emit('new_signal', parsed_signal)  # Emit to frontend

                # Keep the client running indefinitely with reconnection handling
                while True:
                    try:
                        await telegram_Client.run_until_disconnected()
                        logger.info("Telegram client disconnected; attempting to reconnect...")
                    except Exception as e:
                        logger.error(f"Telegram client error: {str(e)}")
                    await asyncio.sleep(5)  # Wait before reconnecting

        except Exception as e:
            logger.error(f"Monitoring setup failed: {str(e)}")

    # Use a single, persistent event loop in the thread
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
#@token_required
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
        # Fetch the oldest pending trade
        trade = Trade.query.filter_by(status='pending').order_by(Trade.created_at.asc()).first()
        if trade:
            trade.status = 'sent'  # Mark as sent to MT5
            db.session.commit()
            trade_dict = trade.to_dict()
            logger.info(f"Sending trade to MT5: {trade_dict}")
            return jsonify(trade_dict)
        logger.debug("No pending trades found")
        return jsonify({})
    except Exception as e:
        logger.error(f"Error fetching trade: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/trade', methods=['POST'])
@token_required
def execute_trade():
    trade_data = request.json
    logger.info(f"Received trade request: {trade_data}")
    try:
        # Validate required fields
        required_fields = ['symbol', 'action', 'entry_price', 'stop_loss', 'take_profits', 'volume']
        for field in required_fields:
            if field not in trade_data:
                logger.error(f"Missing required field in trade: {field}")
                return jsonify({'status': 'error', 'message': f'Missing required field: {field}'}), 400

        # Create new Trade record
        new_trade = Trade(
            symbol=trade_data['symbol'].upper(),
            action=trade_data['action'].upper(),
            entry_price=float(trade_data['entry_price']),
            stop_loss=float(trade_data['stop_loss']),
            take_profits=json.dumps(trade_data['take_profits']),
            volume=float(trade_data['volume']),
            status='pending'
        )
        db.session.add(new_trade)
        db.session.commit()
        logger.info(f"Trade queued in database with ID: {new_trade.id}")
        
        socketio.emit('trade_signal', new_trade.to_dict())  # Notify frontend
        return jsonify({'status': 'Trade queued for MT5', 'trade_id': new_trade.id, 'trade': new_trade.to_dict()})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to queue trade: {str(e)}")
        return jsonify({'status': 'error', 'message': f'Failed to queue trade: {str(e)}'}), 500

# Near your other routes in app.py
@app.route('/mt/ngrok_url', methods=['GET'])
def get_ngrok_url():
    return jsonify({"status": "success", "ngrok_url": NGROK_PUBLIC_URL}), 200

if __name__ == '__main__':
    try:
        with app.app_context():
            init_db()
        logger.info("Starting Flask-SocketIO server on http://0.0.0.0:5000")
        socketio.run(app, host="0.0.0.0", port=5000, debug=True)
    except Exception as e:
        logger.error(f"Failed to start server: {str(e)}")
        exit(1)