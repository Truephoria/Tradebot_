// app/api/telegram/auth_settings/route.ts
import { NextResponse } from 'next/server';

/**
 * Receives Telegram auth data and forwards it to your Python backend
 * Example request body:
 *  { user_id, apiId, apiHash, phoneNumber }
 *
 * Adjust the pythonEndpoint to match your Python service URL
 */
export async function POST(req: Request) {
  try {
    // 1) Read the JSON body from the request
    const body = await req.json();
    
    // 2) Forward that body to your Python backend
    const pythonEndpoint = process.env.PYTHON_SERVER_URL || 'http://localhost:5000/user_sessions';
    const response = await fetch(pythonEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    // 3) If the Python service fails, forward that error back to the client
    if (!response.ok) {
      const errorText = await response.text();
      return new NextResponse(JSON.stringify({ error: errorText }), {
        status: response.status,
      });
    }

    // 4) Otherwise, return the Python response as JSON
    const data = await response.json();
    return NextResponse.json(data);
    
  } catch (error: any) {
    console.error('Error in /api/telegram/auth_settings:', error);
    return new NextResponse(JSON.stringify({ error: 'Internal Server Error' }), { status: 500 });
  }
}