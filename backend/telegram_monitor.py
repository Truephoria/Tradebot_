import os
from telethon import TelegramClient, events
import json
import requests
import asyncio
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

API_ID = os.getenv("API_ID")
API_HASH = os.getenv("API_HASH")
PHONE_NUMBER = os.getenv("PHONE_NUMBER")
API_URL = os.getenv("API_URL")  # API Gateway URL

async def main():
    async with TelegramClient('session', API_ID, API_HASH) as client:
        # Manual authentication (you'll need to pre-authenticate and store the session)
        channels = [int(cid) for cid in os.getenv("CHANNEL_IDS").split(",")]

        @client.on(events.NewMessage(chats=channels))
        async def handler(event):
            chat = await event.get_chat()
            channel_id = chat.id
            message_text = event.message.message
            if "buy" in message_text.lower() or "sell" in message_text.lower():
                # Parse signal (you can call OpenAI here if needed)
                parsed_signal = {"symbol": "XAUUSD", "action": "BUY", "entry_price": 2000, "stop_loss": 1950, "take_profits": [2050]}
                # Update signal via API
                requests.post(
                    f"{API_URL}/api/signal",
                    json=parsed_signal,
                    headers={"Authorization": f"Bearer {os.getenv('API_TOKEN')}"}
                )
                logger.info(f"Sent signal from channel {channel_id}: {parsed_signal}")

        await client.run_until_disconnected()

if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())