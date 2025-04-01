import json
import boto3
import jwt
import os
from botocore.exceptions import ClientError

# Initialize DynamoDB client
dynamodb = boto3.resource('dynamodb')
users_table = dynamodb.Table('Users')  # We'll create this table later

# Environment variable for JWT secret (set this in Lambda configuration)
JWT_SECRET = os.environ.get('JWT_SECRET', 'your-secret-key')  # Replace with a secure key in production

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

        # Handle different channel-related endpoints
        if path == '/api/channels' and http_method == 'GET':
            return fetch_channels(user_id)
        elif path == '/api/channels/all' and http_method == 'GET':
            return fetch_all_channels(user_id)
        elif path.startswith('/api/channels/') and path.endswith('/status') and http_method == 'PUT':
            channel_id = path.split('/')[-2]
            body = json.loads(event['body'])
            is_active = body.get('is_active', False)
            return update_channel_status(user_id, channel_id, is_active)
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

def fetch_channels(user_id):
    # Fetch user-specific active channels
    try:
        response = users_table.get_item(Key={'user_id': user_id})
        user = response.get('Item')
        if not user:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'User not found'})
            }
        
        # In a real app, you'd fetch Telegram channels here (e.g., via Telegram API)
        # For now, return mock data
        channels = [
            {'channel_id': 'channel1', 'channel_name': 'Trading Channel 1', 'is_active': False},
            {'channel_id': 'channel2', 'channel_name': 'Trading Channel 2', 'is_active': False},
        ]
        
        # Update with user's active channels
        active_channels = user.get('active_channels', [])
        for channel in channels:
            channel['is_active'] = channel['channel_id'] in active_channels
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'channels': channels,
                'active_channels': active_channels,
                'count': len(channels)
            })
        }
    except ClientError as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def fetch_all_channels(user_id):
    # Similar to fetch_channels, but might include additional logic for "all" channels
    return fetch_channels(user_id)

def update_channel_status(user_id, channel_id, is_active):
    try:
        # Fetch current user data
        response = users_table.get_item(Key={'user_id': user_id})
        user = response.get('Item')
        if not user:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'User not found'})
            }
        
        # Update active channels list
        active_channels = user.get('active_channels', [])
        if is_active and channel_id not in active_channels:
            active_channels.append(channel_id)
        elif not is_active and channel_id in active_channels:
            active_channels.remove(channel_id)
        
        # Update DynamoDB
        users_table.update_item(
            Key={'user_id': user_id},
            UpdateExpression='SET active_channels = :channels',
            ExpressionAttributeValues={':channels': active_channels}
        )
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': f'Channel {channel_id} updated',
                'is_active': is_active
            })
        }
    except ClientError as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }