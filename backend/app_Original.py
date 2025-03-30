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

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")  # Enable WebSocket
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
# app.config['SECRET_KEY'] = "12345"

# Initialize flask-session AFTER SQLAlchemy
session = Session(app)  # Now it won't create a new SQLAlchemy instance
bcrypt = Bcrypt(app)
CORS(app)  # Enable CORS for frontend communication

# Initialize OpenAI client
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# Telegram Configuration
API_ID = os.getenv("API_ID")
API_HASH = os.getenv("API_HASH")
PHONE_NUMBER = os.getenv("PHONE_NUMBER")
SECRET_KEY = "12345"

class SignalStatus(Enum):
    IDLE = 0
    UPDATED = 1

signalStatus = SignalStatus.IDLE
    
class SettingStatus(Enum):
    IDLE = 0
    UPDATED = 1
    
settingStatus = SettingStatus.IDLE

class User(db.Model):
  __tablename__ = "users" #for table name
  id = db.Column( db.Integer, primary_key=True ) #assigns an id as a primary Key
  name = db.Column( db.String(30) ) #limit name to 30 characters
  email = db.Column( db.String, unique = True ) #each email given has to be unique
  password = db.Column(db.String(30)) #limit bycrypt password hash 30

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
    
def init_db():
    db.create_all()
    
    # Add default settings if they don't exist
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
    
def add_channels(channels):
    try:
        Channel.query.delete()
        for channel in channels:
            if not Channel.query.filter_by(channel_id=channel['id']).first():
                db.session.add(Channel(channel_id=channel['id'], channel_name=channel['name'], is_active=False))
        
        db.session.commit()
        return get_all_channels()
    except Exception as e:
        db.session.rollback()
        raise Exception(f"Failed to update channels: {str(e)}")
    
def get_all_channels():
    """
    Get all channels with optional active filter
    Args:
        active_only: If True, returns only active channels
    Returns:
        List of Channel objects
    """
    all_channels = Channel.query.all()
    active_channels = [channel for channel in all_channels if channel.is_active]
    return [{
        'channel_id': channel.channel_id,
        'channel_name': channel.channel_name,
        'is_active': channel.is_active
    } for channel in all_channels]
    
def get_channels_is_active(active_only=True):
    """
    Get channels as a list of dictionaries
    Args:
        active_only: Filter for active channels
    Returns:
        List of channel dictionaries
    """
    all_channels = Channel.query.all()
    active_channels = [channel for channel in all_channels if channel.is_active == active_only]
    return [channel.channel_id for channel in active_channels]

def update_channel_status(channel_id, is_active):
    """
    Update the active status of a channel
    Args:
        channel_id: The channel ID to update
        is_active: Boolean (True/False) for the new status
    Returns:
        True if successful, False if channel not found
    """
    channel = Channel.query.filter_by(channel_id=channel_id).first()
    if channel:
        channel.is_active = is_active
        db.session.commit()
        return True
    return False
    
def get_current_settings():
    settings = Setting.query.all()
    settings_dict = {}
    
    for setting in settings:
        # Convert string values back to their appropriate types
        value = setting.value
        
        if setting.key in ['botEnabled', 'enableTrailingStop']:
            value = value.lower() == 'true'
        elif setting.key in ['maxDailyLoss', 'maxTradesPerDay', 'minimumRRR', 'riskValue']:
            value = float(value)
        
        settings_dict[setting.key] = value
    
    return settings_dict

def validate_setting_value(key, value):
    """Validate setting values based on their expected type"""
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
        return True
    return False

def create_signal(signal_data):
    """
    Create a new trading signal
    Args:
        signal_data: Dictionary containing signal details
    Returns:
        The created Signal object
    """
    # Validate required fields
    required_fields = ['symbol', 'entry_price', 'action', 'stop_loss']
    for field in required_fields:
        if field not in signal_data:
            raise ValueError(f"Missing required field: {field}")

    # Create the signal
    new_signal = Signal(
        channel=int(1),  # Store the channel ID
        symbol=signal_data['symbol'].upper(),
        entry_price=float(signal_data['entry_price']),
        action=signal_data['action'].upper(),
        stop_loss=float(signal_data['stop_loss'])
    )

    db.session.add(new_signal)
    db.session.flush()  # Get the ID before commit

    # Add take profits if provided
    if 'take_profits' in signal_data and isinstance(signal_data['take_profits'], list):
        for tp in signal_data['take_profits']:
            new_tp = TakeProfit(
                signal_id=new_signal.id,
                price=float(tp),
            )
            db.session.add(new_tp)

    db.session.commit()
    return new_signal

def get_latest_signal():
    """Retrieve the most recent trading signal"""
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
    """
    Update an existing signal
    Args:
        signal_id: ID of the signal to update
        updates: Dictionary of fields to update
    """
    signal = Signal.query.filter_by(channel=channel_id).first()
    if not signal:
        return False
    
    # Update basic fields
    if 'symbol' in updates:
        signal.symbol = updates['symbol']
    if 'entry_price' in updates:
        signal.entry_price = updates['entry_price']
    if 'action' in updates:
        signal.action = updates['action']
    if 'stop_loss' in updates:
        signal.stop_loss = updates['stop_loss']
    signal.created_at = db.func.current_timestamp()
    
    # Update take profits if provided
    if 'take_profits' in updates:
        # First remove existing take profits
        TakeProfit.query.filter_by(signal_id=signal.id).delete()
        
        # Add new take profits
        for tp in updates['take_profits']:
            new_tp = TakeProfit(
                signal_id=signal.id,
                price=tp,
            )
            db.session.add(new_tp)
    
    db.session.commit()
    return True

@app.route("/api/register", methods=["POST"])
def register_user():
    #gets email and password input
    name = request.json["name"]
    email = request.json["email"]
    password = request.json["password"]

    user_exists = User.query.filter_by(email=email).first() is not None

    if user_exists:
        return jsonify({"error": "User already exists"}), 409
    bcrypt = Bcrypt()
    hashed_password = bcrypt.generate_password_hash(password)
    new_user = User(name=name, email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    # Generate JWT token
    token = jwt.encode({
        'user_id': new_user.id,
        'exp': datetime.utcnow() + timedelta(hours=24)  # Token expires in 24 hours
    }, SECRET_KEY, algorithm='HS256')
    
    session.user_id = new_user.id
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
        return jsonify({"error": "Can not find user. Please sign up."}), 401
    #checking if the password is the same as hashed password
    if not bcrypt.check_password_hash(user.password, password):
        return jsonify({"error": "Invalid email or password."}), 401
    
    # Generate JWT token
    token = jwt.encode({
        'user_id': user.id,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }, SECRET_KEY, algorithm='HS256')
    
    session.user_id = user.id
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
    session.pop("user_id")
    return "200"

@app.route("/api/@me")
def get_current_user():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({"error": "Unauthorized"}), 401
    
    token = auth_header.split(' ')[1]
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        user_id = payload['user_id']
        user = User.query.filter_by(id=user_id).first()
        
        return jsonify({
            "user": {
                "id": user.id,
                "name": user.name,
                "email": user.email,
            },
            "token": token
        })
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 401
    except jwt.InvalidTokenError:
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
        return jsonify({'error': 'is_active parameter required'}), 400
    
    if update_channel_status(channel_id, data['is_active']):
        return jsonify({
            'status': 'success',
            'message': f'Channel {channel_id} updated',
            'is_active': data['is_active']
        })
    return jsonify({'error': 'Channel not found'}), 404
    
@app.route('/api/settings', methods=['GET'])
def get_settings():
    try:
        current_settings = get_current_settings()
        return jsonify({
            'status': 'success',
            'settings': current_settings
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/settings', methods=['POST', 'PUT'])
def update_settings():
    global settingStatus
    settingStatus = SettingStatus.UPDATED
    try:
        data = request.get_json()
        
        # Validate required fields
        if not data or not isinstance(data, dict):
            return jsonify({'status': 'error', 'message': 'Invalid data format'}), 400
        
        # Update each setting in the request
        for key, value in data.items():
            if not update_setting(key, value):
                # If setting doesn't exist, create it
                new_setting = Setting(key=key, value=str(value))
                db.session.add(new_setting)
        
        db.session.commit()
        
        # Return updated settings
        current_settings = get_current_settings()
        return jsonify({
            'status': 'success',
            'message': 'Settings updated',
            'settings': current_settings
        })
    
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': f'Failed to update settings: {str(e)}'
        }), 500
        
@app.route('/api/signal', methods=['POST'])
def add_signal():
    try:
        data = request.get_json()
        
        # Basic validation
        if not data:
            return jsonify({
                'status': 'error',
                'message': 'No data provided'
            }), 400
        
        # Create the signal
        signal = create_signal(data)
        
        # Broadcast to all connected clients
        # socketio.emit('new_signal', {
        #     'id': signal.id,
        #     'symbol': signal.symbol,
        #     'action': signal.action,
        #     'entry_price': signal.entry_price,
        #     'stop_loss': signal.stop_loss,
        #     'take_profits': [{
        #         'price': tp.price,
        #         'percentage': tp.percentage
        #     } for tp in signal.take_profits],
        #     'created_at': signal.created_at.isoformat()
        # })
        
        return jsonify({
            'status': 'success',
            'message': 'Signal created',
            'signal_id': signal.id
        }), 201
    
    except ValueError as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 400
    
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': f'Failed to create signal: {str(e)}'
        }), 500
        
@app.route('/api/signal', methods=['GET'])
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
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500
        
@app.route('/api/signal/history', methods=['GET'])
def get_signal_history():
    try:
        # Get query parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        symbol = request.args.get('symbol')
        action = request.args.get('action')  # 'BUY' or 'SELL'
        channel_id = request.args.get('channel')  # Optional filter
        
        # Build query
        query = Signal.query
        
        if symbol:
            query = query.filter(Signal.symbol == symbol.upper())
        
        if action:
            query = query.filter(Signal.action == action.upper())
            
        if channel_id:
            query = query.filter(Signal.channel == int(channel_id))
        
        # Order and paginate
        signals = query.order_by(
            Signal.created_at.desc()
        ).paginate(page=page, per_page=per_page, error_out=False)
        
        # Format response
        signal_list = []
        for signal in signals.items:
            signal_list.append({
                'id': signal.id,
                'channel': signal.channel,
                'symbol': signal.symbol,
                'action': signal.action,
                'entry_price': signal.entry_price,
                'stop_loss': signal.stop_loss,
                'take_profits': [tp.price for tp in signal.take_profits],
                'created_at': signal.created_at.isoformat()
            })
        
        return jsonify({
            'status': 'success',
            'signals': signal_list,
            'total': signals.total,
            'pages': signals.pages,
            'current_page': signals.page
        })
    except Exception as e:
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
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 404 if isinstance(e, sqlalchemy.orm.exc.NoResultFound) else 500
        
@app.route('/api/signal/<int:channel_id>', methods=['PUT', 'PATCH'])
def update_signal_endpoint(channel_id):
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'status': 'error',
                'message': 'No data provided'
            }), 400
        
        # Validate required fields for updates
        if 'action' in data and data['action'].upper() not in ['BUY', 'SELL']:
            return jsonify({
                'status': 'error',
                'message': 'Action must be either BUY or SELL'
            }), 400
        
        if update_signal(channel_id, data):
            # Return the updated signal
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
        return jsonify({
            'status': 'error',
            'message': f'Failed to update signal: {str(e)}'
        }), 500
        
@app.route('/api/settings/<string:key>', methods=['POST', 'PUT'])
def update_signal_setting(key):
    try:
        value = request.get_json().get('value')
        
        if value is None:
            return jsonify({'status': 'error', 'message': 'Value is required'}), 400
        
        if update_setting(key, value):
            return jsonify({
                'status': 'success',
                'message': f'Setting {key} updated',
                'key': key,
                'value': value
            })
        else:
            # Create new setting if it doesn't exist
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
        return jsonify({
            'status': 'error',
            'message': f'Failed to update setting: {str(e)}'
        }), 500

# active_channels = [c.channel_id for c in Channel.query.filter_by(is_active=True).all()]

# current_signal = Signal.query.order_by(Signal.created_at.desc()).first()
# if current_signal:
#     signal_data = current_signal.to_dict()
#     signal_data['take_profits'] = [tp.price for tp in current_signal.take_profits]

# Function to parse trading signals using OpenAI
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
        response = client.chat.completions.create(
            model="gpt-4-1106-preview",
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": signal_text}
            ]
        )
        return json.loads(response.choices[0].message.content)
    except Exception as e:
        return {"error": str(e)}

# Function to fetch subscribed channels (only once)
async def fetch_subscribed_channels():
    async with TelegramClient('session', API_ID, API_HASH) as client:
        if not await client.is_user_authorized():
            await client.send_code_request(PHONE_NUMBER)
            await client.sign_in(PHONE_NUMBER, input('Enter the code: '))
        
        dialogs = await client.get_dialogs()
        return [
            {"name": dialog.entity.title, "id": dialog.entity.id}
            for dialog in dialogs if dialog.is_channel
        ]
    
# API endpoint to start monitoring a channel
@app.route('/api/monitor', methods=['POST'])
def monitor_channel():
    # global selected_channel
    data = request.json
    # selected_channel = data.get("channel_id")
    channels = [int(x) for x in data.get("channel_id")]
    
    # Start monitoring in a separate thread
    print(f"Monitoring channel: {channels}")
    start_monitoring(channels)
    return jsonify({"status": "Monitoring started", "channel_id": channels})

# Function to start monitoring a channel
def start_monitoring(channels):
    async def monitor(channels):
        print(f"Starting monitoring for channel: {channels}")
        async with TelegramClient('session', API_ID, API_HASH) as client:
            @client.on(events.NewMessage(chats=channels))
            async def handler(event):
                chat = await event.get_chat()
                channel_id = chat.id
                print(channel_id)
                message_text = event.message.message
                if "buy" in message_text.lower() or "sell" in message_text.lower():
                    global signalStatus
                    signalStatus = SignalStatus.UPDATED
                    parsed_signal = parse_trading_signal(message_text)
                    update_signal(1, parsed_signal)
                    print(f"Received signal: {parsed_signal}")
                    socketio.emit('new_signal', parsed_signal)  # Send signal to frontend
            
            await client.run_until_disconnected()
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(monitor(channels))

is_first = True
@app.route('/mt/accountinfo', methods=['POST'])
def mt_account():
    data = request.json
    if data['activeTrades'] == None:
        data['activeTrades'] = []
    if data['tradeshistory'] == None:
        data['tradeshistory'] = []
    print(data)
    
    socketio.emit('new_metadata', data)  # Send signal to frontend
    signal_data = "No Signal"
    setting_data = "No Setting"
    global signalStatus, settingStatus
    
    now = datetime.now().time()
    # Convert the string times to datetime.time objects
    current_settings = get_current_settings()
    current_signal = get_latest_signal()
    allowedsymbol = current_settings['allowedSymbols'].split(',')
    global is_first
    if is_first:
        is_first = False
        return jsonify({"signal": signal_data, "setting": current_settings}), 202
    start_time = datetime.strptime(current_settings['tradingHoursStart'], "%H:%M").time()
    end_time = datetime.strptime(current_settings['tradingHoursEnd'], "%H:%M").time()
    
    if settingStatus == SettingStatus.UPDATED and signalStatus != SignalStatus.UPDATED:
        settingStatus = SettingStatus.IDLE
        setting_data = current_settings
        print("Setting updated!", current_settings)
        return jsonify({"signal": signal_data, "setting": setting_data}), 202
    
    if start_time <= now <= end_time and current_settings['botEnabled'] and current_signal['symbol'] in allowedsymbol:
        if signalStatus == SignalStatus.UPDATED and settingStatus != SettingStatus.UPDATED:
            signalStatus = SignalStatus.IDLE
            signal_data = current_signal
            print("Signal updated!", current_signal)
            return jsonify({"signal": signal_data, "setting": setting_data}), 201
            
    if signal_data == "No Signal" and setting_data == "No Setting":
        print("No Signal or Setting")
        return jsonify({"signal": signal_data, "setting": setting_data}), 203
            
    return jsonify({"signal": signal_data, "setting": setting_data}), 200

   
if __name__ == '__main__':
    with app.app_context():
        init_db()
    socketio.run(app, debug=True)