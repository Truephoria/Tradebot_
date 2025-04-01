import json
import boto3
import jwt
import os
from botocore.exceptions import ClientError

# Initialize DynamoDB and AppSync clients
dynamodb = boto3.resource('dynamodb')
users_table = dynamodb.Table('Users')
appsync_client = boto3.client('appsync')

# Environment variables
JWT_SECRET = os.environ.get('JWT_SECRET', 'your-secret-key')
APPSYNC_API_ID = os.environ.get('APPSYNC_API_ID', 'your-appsync-api-id')  # Set this in Lambda configuration

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

        # Handle signal-related endpoints
        if path == '/api/monitor' and http_method == 'POST':
            body = json.loads(event['body'])
            channel_ids = body.get('channel_id', [])
            return start_monitoring(user_id, channel_ids)
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

def start_monitoring(user_id, channel_ids):
    try:
        # Update user's active channels
        users_table.update_item(
            Key={'user_id': user_id},
            UpdateExpression='SET active_channels = :channels',
            ExpressionAttributeValues={':channels': channel_ids}
        )
        
        # In a real app, you'd start monitoring Telegram channels here
        # For now, simulate a signal
        signal = {
            'symbol': 'EURUSD',
            'entry_price': 1.0850,
            'action': 'BUY',
            'stop_loss': 1.0820,
            'take_profits': [1.0880, 1.0900]
        }
        
        # Publish signal to AppSync
        publish_signal(user_id, signal)
        
        return {
            'statusCode': 200,
            'body': json.dumps({'message': 'Monitoring started', 'signal': signal})
        }
    except ClientError as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def publish_signal(user_id, signal):
    try:
        response = appsync_client.start_execution(
            graphqlApiId=APPSYNC_API_ID,
            query='''
            mutation PublishSignal($userId: ID!, $signal: SignalInput!) {
              publishSignal(userId: $userId, signal: $signal) {
                symbol
                entry_price
                action
                stop_loss
                take_profits
              }
            }
            ''',
            variables={
                'userId': user_id,
                'signal': signal
            }
        )
        return response
    except ClientError as e:
        print(f"Error publishing signal to AppSync: {str(e)}")
        raise e