import json
import boto3
import jwt
import os
from botocore.exceptions import ClientError

# Initialize DynamoDB client
dynamodb = boto3.resource('dynamodb')
signals_table = dynamodb.Table('Signals')  # Assumes a Signals table populated by telegram_monitoring.py

# Environment variable for JWT secret
JWT_SECRET = os.environ.get('JWT_SECRET', 'your-secret-key')

def lambda_handler(event, context):
    try:
        # Extract HTTP method and path
        http_method = event['httpMethod']
        path = event['path']

        # Extract JWT token from headers
        token = event['headers'].get('Authorization', '').replace('Bearer ', '')
        if not token:
            return {
                'statusCode': 401,
                'body': json.dumps({'error': 'No token provided'})
            }

        # Decode and verify JWT token
        try:
            decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            user_id = decoded['sub']
        except jwt.InvalidTokenError:
            return {
                'statusCode': 401,
                'body': json.dumps({'error': 'Invalid token'})
            }

        # Handle /api/signal endpoint
        if path == '/api/signal' and http_method == 'GET':
            return fetch_latest_signal(user_id)
        else:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'Not found'})
            }

    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def fetch_latest_signal(user_id):
    try:
        # Query the Signals table for the latest signal
        response = signals_table.query(
            KeyConditionExpression='user_id = :uid',
            ExpressionAttributeValues={':uid': user_id},
            ScanIndexForward=False,  # Sort in descending order (latest first)
            Limit=1
        )
        items = response.get('Items', [])
        if not items:
            return {
                'statusCode': 200,
                'body': json.dumps({'signal': None})
            }

        signal = items[0]
        return {
            'statusCode': 200,
            'body': json.dumps({
                'signal': {
                    'symbol': signal.get('symbol'),
                    'action': signal.get('action'),
                    'entry_price': float(signal.get('entry_price', 0)),
                    'stop_loss': float(signal.get('stop_loss', 0)),
                    'take_profits': signal.get('take_profits', []),
                    'channel_id': signal.get('channel_id'),
                    'channel_name': signal.get('channel_name')
                }
            })
        }
    except ClientError as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }