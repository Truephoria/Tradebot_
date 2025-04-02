// app/api/settings/route.ts
import { NextRequest, NextResponse } from 'next/server';

/**
 * Proxy GET/POST requests to the Python backend.
 * Example Python routes:
 *    @app.route('/api/settings', methods=['GET'])
 *    @app.route('/api/settings', methods=['POST'])
 */
const PYTHON_BASE_URL = process.env.PYTHON_SERVER_URL || 'http://localhost:5000';

export async function GET(req: NextRequest) {
  try {
    // Forward the Bearer token if it exists
    const authHeader = req.headers.get('authorization') || '';

    const resp = await fetch(`${PYTHON_BASE_URL}/api/settings`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        Authorization: authHeader,
      },
    });

    if (!resp.ok) {
      // If Python returns an error, forward the response body
      const errorText = await resp.text();
      return new NextResponse(JSON.stringify({ error: errorText }), {
        status: resp.status,
      });
    }

    // Return success as JSON
    const data = await resp.json();
    return NextResponse.json(data);

  } catch (error: any) {
    console.error('[GET /api/settings] Proxy error:', error);
    return NextResponse.json(
      { error: 'Internal Server Error in Next.js route.' },
      { status: 500 }
    );
  }
}

export async function POST(req: NextRequest) {
  try {
    // Read the JSON body from Next.js request
    const body = await req.json();

    // Forward the Bearer token if it exists
    const authHeader = req.headers.get('authorization') || '';

    const resp = await fetch(`${PYTHON_BASE_URL}/api/settings`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: authHeader,
      },
      body: JSON.stringify(body),
    });

    if (!resp.ok) {
      const errorText = await resp.text();
      return new NextResponse(JSON.stringify({ error: errorText }), {
        status: resp.status,
      });
    }

    const data = await resp.json();
    return NextResponse.json(data);

  } catch (error: any) {
    console.error('[POST /api/settings] Proxy error:', error);
    return NextResponse.json(
      { error: 'Internal Server Error in Next.js route.' },
      { status: 500 }
    );
  }
}
