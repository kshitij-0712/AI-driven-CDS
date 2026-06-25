import uvicorn
from fastapi import FastAPI, Request, Form, Response
from fastapi.responses import HTMLResponse, JSONResponse
import logging

app = FastAPI(title="Premium Daamy App")
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Reusable UI components
def get_html_header(title="Daamy App"):
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{title}</title>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600&display=swap" rel="stylesheet">
        <style>
            :root {{
                --bg-color: #0f172a;
                --text-color: #f8fafc;
                --card-bg: rgba(30, 41, 59, 0.7);
                --primary: #3b82f6;
                --primary-hover: #2563eb;
                --accent: #8b5cf6;
                --border: rgba(255, 255, 255, 0.1);
            }}
            body {{
                font-family: 'Inter', sans-serif;
                background: var(--bg-color);
                color: var(--text-color);
                margin: 0;
                padding: 0;
                display: flex;
                flex-direction: column;
                align-items: center;
                min-height: 100vh;
                background-image: radial-gradient(circle at top right, rgba(59, 130, 246, 0.15), transparent 400px),
                                  radial-gradient(circle at bottom left, rgba(139, 92, 246, 0.15), transparent 400px);
            }}
            .container {{
                width: 100%;
                max-width: 900px;
                padding: 40px 20px;
                display: grid;
                gap: 24px;
            }}
            .header {{
                text-align: center;
                margin-bottom: 20px;
            }}
            .header h1 {{
                font-size: 2.5rem;
                font-weight: 600;
                background: linear-gradient(to right, var(--primary), var(--accent));
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                margin: 0 0 10px 0;
            }}
            .header p {{
                color: #94a3b8;
                font-size: 1.1rem;
            }}
            .card {{
                background: var(--card-bg);
                backdrop-filter: blur(12px);
                -webkit-backdrop-filter: blur(12px);
                border: 1px solid var(--border);
                border-radius: 16px;
                padding: 24px;
                box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
                transition: transform 0.2s ease, box-shadow 0.2s ease;
            }}
            .card:hover {{
                transform: translateY(-2px);
                box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.2), 0 4px 6px -2px rgba(0, 0, 0, 0.1);
                border-color: rgba(255, 255, 255, 0.2);
            }}
            .card h3 {{
                margin-top: 0;
                font-weight: 600;
                border-bottom: 1px solid var(--border);
                padding-bottom: 12px;
                margin-bottom: 16px;
                display: flex;
                align-items: center;
                gap: 10px;
            }}
            .badge {{
                font-size: 0.7rem;
                padding: 2px 8px;
                border-radius: 12px;
                background: rgba(239, 68, 68, 0.2);
                color: #fca5a5;
                border: 1px solid rgba(239, 68, 68, 0.3);
            }}
            .form-group {{
                margin-bottom: 16px;
            }}
            label {{
                display: block;
                margin-bottom: 6px;
                font-size: 0.9rem;
                color: #cbd5e1;
            }}
            input[type="text"], input[type="password"] {{
                width: 100%;
                padding: 10px 12px;
                border-radius: 8px;
                border: 1px solid var(--border);
                background: rgba(15, 23, 42, 0.5);
                color: white;
                font-family: inherit;
                box-sizing: border-box;
                transition: border-color 0.2s;
            }}
            input:focus {{
                outline: none;
                border-color: var(--primary);
            }}
            button {{
                background: var(--primary);
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 8px;
                font-weight: 600;
                cursor: pointer;
                transition: background 0.2s, transform 0.1s;
                font-family: inherit;
                width: 100%;
            }}
            button:hover {{
                background: var(--primary-hover);
            }}
            button:active {{
                transform: scale(0.98);
            }}
            .grid-2 {{
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 20px;
            }}
            @media (max-width: 600px) {{
                .grid-2 {{
                    grid-template-columns: 1fr;
                }}
            }}
            .result-box {{
                background: rgba(0,0,0,0.3);
                padding: 15px;
                border-radius: 8px;
                font-family: monospace;
                color: #a7f3d0;
                border: 1px solid rgba(16, 185, 129, 0.2);
                margin-top: 15px;
            }}
            a {{ color: var(--primary); text-decoration: none; }}
            a:hover {{ text-decoration: underline; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Adaptive Network Terminal</h1>
                <p>Advanced System Management Interface</p>
            </div>
    """

def get_html_footer():
    return """
        </div>
    </body>
    </html>
    """

@app.get("/", response_class=HTMLResponse)
async def home():
    content = get_html_header() + """
        <div class="grid-2">
            <div class="card">
                <h3>Authentication <span class="badge">Brute-Force</span></h3>
                <form action="/login" method="POST">
                    <div class="form-group">
                        <label>Admin Username</label>
                        <input type="text" name="username" placeholder="admin">
                    </div>
                    <div class="form-group">
                        <label>Password</label>
                        <input type="password" name="password" placeholder="••••••••">
                    </div>
                    <button type="submit">Secure Login</button>
                </form>
            </div>

            <div class="card">
                <h3>User Directory <span class="badge">SQLi</span></h3>
                <form action="/profile" method="GET">
                    <div class="form-group">
                        <label>User ID</label>
                        <input type="text" name="id" placeholder="1 or 1' OR 1=1--">
                    </div>
                    <button type="submit">Lookup Profile</button>
                </form>
            </div>

            <div class="card">
                <h3>System Logs <span class="badge">Path Traversal</span></h3>
                <form action="/export" method="GET">
                    <div class="form-group">
                        <label>Log File Path</label>
                        <input type="text" name="file" placeholder="syslog.log or ../../../etc/passwd">
                    </div>
                    <button type="submit">Download Log</button>
                </form>
            </div>

            <div class="card">
                <h3>Diagnostic Ping <span class="badge">Command Injection</span></h3>
                <form action="/api/ping" method="POST">
                    <div class="form-group">
                        <label>Target Host</label>
                        <input type="text" name="host" placeholder="127.0.0.1; cat /etc/shadow">
                    </div>
                    <button type="submit">Run Diagnostic</button>
                </form>
            </div>
            
            <div class="card" style="grid-column: 1 / -1;">
                <h3>Admin Panel <span class="badge">Header Injection</span></h3>
                <p style="font-size: 0.9rem; color: #94a3b8; margin-bottom: 15px;">
                    This endpoint verifies if your connection originates from the internal network by checking headers like X-Forwarded-For and User-Agent.
                </p>
                <a href="/admin" style="display: inline-block; background: var(--accent); padding: 8px 16px; border-radius: 8px; color: white; font-weight: 600; text-align: center;">Access Admin Panel</a>
            </div>
        </div>
    """ + get_html_footer()
    return HTMLResponse(content=content)

@app.post("/login")
async def login(request: Request):
    form_data = await request.form()
    username = form_data.get("username", "unknown")
    logger.info(f"Failed login attempt for user: {username}")
    return JSONResponse(status_code=401, content={"error": "Unauthorized", "message": "Invalid credentials", "ip": request.client.host})

@app.get("/profile", response_class=HTMLResponse)
async def profile(id: str = ""):
    content = get_html_header(f"Profile: {id}") + f"""
        <div class="card">
            <h3>Profile Results</h3>
            <p>Executing query: <code style="color: #fca5a5;">SELECT * FROM users WHERE id = '{id}';</code></p>
            <div class="result-box">
                User not found. Check the ID and try again.
            </div>
            <br>
            <a href="/">← Back to Dashboard</a>
        </div>
    """ + get_html_footer()
    return HTMLResponse(content=content)

@app.get("/export", response_class=HTMLResponse)
async def export_file(file: str = ""):
    content = get_html_header("File Export") + f"""
        <div class="card">
            <h3>Export Failed</h3>
            <p>Attempted to read: <code style="color: #fca5a5;">/var/log/app/{file}</code></p>
            <div class="result-box">
                Error: Permission denied or file not found.
            </div>
            <br>
            <a href="/">← Back to Dashboard</a>
        </div>
    """ + get_html_footer()
    return HTMLResponse(content=content)

@app.post("/api/ping", response_class=HTMLResponse)
async def ping(request: Request):
    form_data = await request.form()
    host = form_data.get("host", "")
    content = get_html_header("Diagnostic Ping") + f"""
        <div class="card">
            <h3>Diagnostic Results</h3>
            <p>Running: <code style="color: #fca5a5;">ping -c 4 {host}</code></p>
            <div class="result-box">
                Ping request could not find host {host}. Please check the name and try again.
            </div>
            <br>
            <a href="/">← Back to Dashboard</a>
        </div>
    """ + get_html_footer()
    return HTMLResponse(content=content)

@app.get("/admin", response_class=HTMLResponse)
async def admin(request: Request):
    user_agent = request.headers.get('User-Agent', 'Unknown')
    x_forwarded_for = request.headers.get('X-Forwarded-For', 'None')
    
    content = get_html_header("Admin Panel") + f"""
        <div class="card">
            <h3>Access Denied</h3>
            <p>Your request lacks the required internal headers.</p>
            <div class="result-box" style="color: #93c5fd; border-color: rgba(59, 130, 246, 0.2);">
                <strong>Logged Headers:</strong><br><br>
                User-Agent: {user_agent}<br>
                X-Forwarded-For: {x_forwarded_for}<br>
                IP: {request.client.host}
            </div>
            <p style="margin-top: 15px; font-size: 0.85rem; color: #94a3b8;">
                Hint: Try modifying headers with curl. AdaptiveShield checks these for injection patterns.
            </p>
            <a href="/">← Back to Dashboard</a>
        </div>
    """ + get_html_footer()
    return HTMLResponse(content=content)

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8090)
