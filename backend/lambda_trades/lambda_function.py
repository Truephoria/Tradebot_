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
APPSYNC_API_ID = os.environ.get('APPSYNC_API_ID', 'your-appsync-api-id')

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

        # Handle trade-related endpoints
        if path == '/api/trade' and http_method == 'POST':
            body = json.loads(event['body'])
            return execute_trade(user_id, body)
        elif path == '/mt/accountinfo' and http_method == 'POST':
            body = json.loads(event['body'])
            return update_account_info(user_id, body)
        elif path == '/mt/get_trade' and http_method == 'GET':
            return get_trade(user_id)
        elif path == '/mt/get_credentials' and http_method == 'POST':
            return get_credentials(user_id)
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

def execute_trade(user_id, trade_data):
    try:
        # Validate trade data
        required_fields = ['symbol', 'action', 'entry_price', 'stop_loss', 'take_profits', 'volume']
        for field in required_fields:
            if field not in trade_data:
                return {
                    'statusCode': 400,
                    'body': json.dumps({'error': f'Missing required field: {field}'})
                }
        
        # Store trade in DynamoDB
        users_table.update_item(
            Key={'user_id': user_id},
            UpdateExpression='SET active_trades = list_append(if_not_exists(active_trades, :empty_list), :trade)',
            ExpressionAttributeValues={
                ':trade': [trade_data],
                ':empty_list': []
            }
        )
        
        # In a real app, you'd send the trade to MetaTrader 5 here
        # For now, simulate success
        return {
            'statusCode': 200,
            'body': json.dumps({'message': 'Trade executed', 'trade': trade_data})
        }
    except ClientError as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def update_account_info(user_id, account_info):
    try:
        # Validate account info
        required_fields = ['balance', 'pnl', 'tradeshistory', 'winRate', 'totalTrades']
        for field in required_fields:
            if field not in account_info:
                return {
                    'statusCode': 400,
                    'body': json.dumps({'error': f'Missing required field: {field}'})
                }
        
        # Update DynamoDB
        users_table.update_item(
            Key={'user_id': user_id},
            UpdateExpression='SET balance = :balance, pnl = :pnl, tradeshistory = :tradeshistory, winRate = :winRate, totalTrades = :totalTrades, activeTrades = :activeTrades',
            ExpressionAttributeValues={
                ':balance': account_info['balance'],
                ':pnl': account_info['pnl'],
                ':tradeshistory': account_info['tradeshistory'],
                ':winRate': account_info['winRate'],
                ':totalTrades': account_info['totalTrades'],
                ':activeTrades': account_info.get('activeTrades', [])
            }
        )
        
        # Publish metadata to AppSync
        publish_metadata(user_id, account_info)
        
        return {
            'statusCode': 200,
            'body': json.dumps({'message': 'Account info updated'})
        }
    except ClientError as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def get_trade(user_id):
    try:
        # Fetch user's active trades
        response = users_table.get_item(Key={'user_id': user_id})
        user = response.get('Item')
        if not user:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'User not found'})
            }
        
        active_trades = user.get('active_trades', [])
        if not active_trades:
            return {
                'statusCode': 200,
                'body': json.dumps({'trade': None})
            }
        
        # Return the most recent trade
        return {
            'statusCode': 200,
            'body': json.dumps({'trade': active_trades[-1]})
        }
    except ClientError as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def get_credentials(user_id):
    try:
        # Fetch user's MT5 credentials
        response = users_table.get_item(Key={'user_id': user_id})
        user = response.get('Item')
        if not user:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'User not found'})
            }
        
        mt5_credentials = user.get('mt5_credentials', {})
        if not mt5_credentials:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'MT5 credentials not found'})
            }
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'email': mt5_credentials.get('email'),
                'password': mt5_credentials.get('password')
            })
        }
    except ClientError as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def publish_metadata(user_id, metadata):
    try:
        response = appsync_client.start_execution(
            graphqlApiId=APPSYNC_API_ID,
            query='''
            mutation PublishMetaData($userId: ID!, $metaData: MetaDataInput!) {
              publishMetaData(userId: $userId, metaData: $metaData) {
                balance
                pnl
                tradeshistory {
                  symbol
                  type
                  entryPrice
                  lotSize
                  profit
                  time
                }
                winRate
                totalTrades
                activeTrades {
                  symbol
                  volume
                  priceOpen
                  sl
                  tp
                  type
                  time
                }
              }
            }
            ''',
            variables={
                'userId': user_id,
                'metaData': metadata
            }
        )
        return response
    except ClientError as e:
        print(f"Error publishing metadata to AppSync: {str(e)}")
        raise e