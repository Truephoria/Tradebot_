from flask import Flask
from flask import Flask, jsonify, request
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
from datetime import datetime

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for frontend communication
socketio = SocketIO(app, cors_allowed_origins="*")  # Enable WebSocket

# Initialize OpenAI client
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# Telegram Configuration
API_ID = os.getenv("API_ID")
API_HASH = os.getenv("API_HASH")
PHONE_NUMBER = os.getenv("PHONE_NUMBER")

# Global variables
selected_channel = []
cached_channels = None  # Store fetched channels globally

SIGNAL = {
    'symbol': '',
    'entry_price': 0.0,
    'action': '',
    'take_profits': [],
    'stop_loss': 0.0
}

SETTING = {
    "allowedSymbols": "EURUSD,GBPUSD,XAUUSD,USDJPY,US30",
    "botEnabled": True,
    "enableTrailingStop": True,
    "maxDailyLoss": 3,
    "maxTradesPerDay": 10,
    "minimumRRR": 1.5,
    "riskType": "PERCENTAGE",
    "riskValue": 1.5,
    "tradingHoursStart": "08:00",
    "tradingHoursEnd": "16:00",
}

class SignalStatus(Enum):
    IDLE = 0
    UPDATED = 1

signalStatus = SignalStatus.IDLE
    
class SettingStatus(Enum):
    IDLE = 0
    UPDATED = 1
    
settingStatus = SettingStatus.IDLE

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

# API endpoint to fetch subscribed channels
@app.route('/api/channels', methods=['GET'])
def get_channels():
    global cached_channels

    # Fetch channels only if not already cached
    if cached_channels is None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        cached_channels = loop.run_until_complete(fetch_subscribed_channels())
    
    return jsonify(cached_channels)

@app.route('/api/signal', methods=['GET'])
def get_signal():
    return jsonify(SIGNAL)

@app.route('/api/setting', methods=['GET'])
def get_setting():
    return jsonify(SETTING)

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

@app.route('/api/update_setting', methods=['POST'])
def update_setting():
    global SETTING
    data = request.json
    if SETTING != data:
        global settingStatus
        settingStatus = SettingStatus.UPDATED
        SETTING.update(data)
        return jsonify({"status": "Setting updated"}), 200
    return jsonify({"status": "Setting is already set"}), 400

@app.route('/mt/accountinfo', methods=['POST'])
def mt_account():
    data = request.json
    print(data)
    socketio.emit('new_metadata', data)  # Send signal to frontend
    signal_data = "No Signal"
    setting_data = "No Setting"
    global signalStatus, settingStatus
    global SIGNAL, SETTING
    
    now = datetime.now().time()
    # Convert the string times to datetime.time objects
    start_time = datetime.strptime(SETTING['tradingHoursStart'], "%H:%M").time()
    end_time = datetime.strptime(SETTING['tradingHoursEnd'], "%H:%M").time()
    
    if settingStatus == SettingStatus.UPDATED:
        settingStatus = SettingStatus.IDLE
        setting_data = SETTING
        print("Setting updated!", SETTING)
    
    # if start_time <= now <= end_time and SETTING['botEnabled']:
    if signalStatus == SignalStatus.UPDATED:
        signalStatus = SignalStatus.IDLE
        signal_data = SIGNAL
        print("Signal updated!", SIGNAL)
            
    if signal_data == "No Signal" and setting_data == "No Setting":
        print("No Signal or Setting")
        return jsonify({"signal": signal_data, "setting": setting_data}), 201
            
    return jsonify({"signal": signal_data, "setting": setting_data}), 200

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
                    parsed_signal = parse_trading_signal(message_text)
                    global SIGNAL
                    if SIGNAL != parsed_signal:
                        global signalStatus
                        signalStatus = SignalStatus.UPDATED
                        SIGNAL.update(parsed_signal)
                        print(f"Received signal: {SIGNAL}")
                        socketio.emit('new_signal', parsed_signal)  # Send signal to frontend
            
            await client.run_until_disconnected()
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(monitor(channels))

# Run the Flask app with WebSocket support
if __name__ == '__main__':
    socketio.run(app, debug=True)