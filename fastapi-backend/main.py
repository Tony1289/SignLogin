from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, EmailStr
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
from dotenv import load_dotenv
import mysql.connector
import bcrypt
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, EmailStr
from datetime import datetime
from dotenv import load_dotenv
import mysql.connector
import bcrypt
import os

# Load environment variables
load_dotenv()

DB_HOST = os.getenv("DB_HOST")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_NAME = os.getenv("DB_NAME")
ADMIN_CODE_HASH = os.getenv("ADMIN_CODE_HASH")  # hashed using bcrypt

app = FastAPI()
# Absolute path to the React dist folder
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REACT_DIST = os.path.abspath(os.path.join(BASE_DIR, "../admin-login-app/dist"))

# Mount static assets like CSS and JS (optional but useful for debugging)
app.mount("/assets", StaticFiles(directory=os.path.join(REACT_DIST, "assets")), name="assets")

# Serve static files like vite.svg (optional)
app.mount("/static", StaticFiles(directory=REACT_DIST), name="static")

# Serve React index.html for root
@app.get("/")
def serve_index():
    return FileResponse(os.path.join(REACT_DIST, "index.html"))

# Catch-all route to serve index.html for frontend routing
@app.get("/{full_path:path}")
def serve_vue_routes(full_path: str):
    full_file_path = os.path.join(REACT_DIST, full_path)
    if os.path.exists(full_file_path) and os.path.isfile(full_file_path):
        return FileResponse(full_file_path)
    return FileResponse(os.path.join(REACT_DIST, "index.html"))

# Enable CORS (safe for development; restrict in production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Change to ["http://your-frontend-domain.com"] for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# ----------- Pydantic Models -----------
class SignupData(BaseModel):
    username: str
    email: EmailStr
    password: str
    role: str
    security_code: str | None = None

class LoginData(BaseModel):
    email: EmailStr
    password: str
    role: str
    security_code: str | None = None

class LogoutData(BaseModel):
    email: EmailStr


# ----------- DB Connection -----------
def get_db():
    conn = mysql.connector.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME
    )
    ensure_tables_exist(conn)
    return conn


# ----------- Auto-create Tables -----------
def ensure_tables_exist(conn):
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS newusers (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(100),
            hashed_email TEXT,
            hashed_password TEXT,
            role VARCHAR(20),
            login_time DATETIME,
            logout_time DATETIME
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS loginlogs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            email VARCHAR(255),
            username VARCHAR(100),
            hashed_email TEXT,
            hashed_password TEXT,
            role VARCHAR(20),
            login_time DATETIME,
            logout_time DATETIME
        )
    """)

    conn.commit()
    cursor.close()


# ----------- API Routes -----------

@app.post("/signup")
def signup(data: SignupData):
    db = get_db()
    cursor = db.cursor()

    if data.role == "admin":
        if not data.security_code or not bcrypt.checkpw(data.security_code.encode(), ADMIN_CODE_HASH.encode()):
            raise HTTPException(status_code=403, detail="Invalid admin security code.")

    hashed_pw = bcrypt.hashpw(data.password.encode(), bcrypt.gensalt()).decode()
    hashed_email = bcrypt.hashpw(data.email.encode(), bcrypt.gensalt()).decode()

    try:
        cursor.execute(
            """
            INSERT INTO newusers (username, hashed_email, hashed_password, role, login_time, logout_time)
            VALUES (%s, %s, %s, %s, NULL, NULL)
            """,
            (data.username, hashed_email, hashed_pw, data.role)
        )
        db.commit()
        return {"message": f"{data.role.capitalize()} registered successfully!"}
    except mysql.connector.IntegrityError:
        raise HTTPException(status_code=409, detail="User already exists.")
    finally:
        db.close()


@app.post("/login")
def login(data: LoginData):
    db = get_db()
    cursor = db.cursor(dictionary=True)

    cursor.execute("SELECT * FROM newusers")
    all_users = cursor.fetchall()

    matched_user = None
    for user in all_users:
        if bcrypt.checkpw(data.email.encode(), user["hashed_email"].encode()):
            matched_user = user
            break

    if not matched_user or not bcrypt.checkpw(data.password.encode(), matched_user["hashed_password"].encode()):
        db.close()
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if data.role == "admin":
        if not data.security_code or not bcrypt.checkpw(data.security_code.encode(), ADMIN_CODE_HASH.encode()):
            db.close()
            raise HTTPException(status_code=403, detail="Invalid admin security code.")

    # Log login
    hashed_email = bcrypt.hashpw(data.email.encode(), bcrypt.gensalt()).decode()
    hashed_pw = bcrypt.hashpw(data.password.encode(), bcrypt.gensalt()).decode()
    login_time = datetime.now()

    cursor = db.cursor()
    cursor.execute(
        """
        INSERT INTO loginlogs (email, username, hashed_email, hashed_password, role, login_time)
        VALUES (%s, %s, %s, %s, %s, %s)
        """,
        (data.email, matched_user["username"], hashed_email, hashed_pw, data.role, login_time)
    )
    db.commit()
    db.close()

    return {"message": f"Welcome back, {matched_user['username']}!", "role": data.role}


@app.post("/logout")
def logout(data: LogoutData):
    db = get_db()
    cursor = db.cursor()

    cursor.execute(
        """
        UPDATE loginlogs
        SET logout_time = %s
        WHERE email = %s AND logout_time IS NULL
        ORDER BY login_time DESC
        LIMIT 1
        """,
        (datetime.now(), data.email)
    )
    db.commit()
    db.close()
    return {"message": "Logout time recorded successfully."}


@app.get("/admin/users")
def get_users():
    db = get_db()
    cursor = db.cursor(dictionary=True)

    cursor.execute("""
        SELECT username, hashed_email, hashed_password, login_time, logout_time
        FROM loginlogs
        WHERE role = 'user'
    """)
    logs = cursor.fetchall()
    db.close()
    return {"users": logs}

import os

# Load environment variables
load_dotenv()

DB_HOST = os.getenv("DB_HOST")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_NAME = os.getenv("DB_NAME")
ADMIN_CODE_HASH = os.getenv("ADMIN_CODE_HASH")  # hashed using bcrypt

app = FastAPI()

# Allow CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For development, restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------- Pydantic Models -----------
class SignupData(BaseModel):
    username: str
    email: EmailStr
    password: str
    role: str
    security_code: str | None = None

class LoginData(BaseModel):
    email: EmailStr
    password: str
    role: str
    security_code: str | None = None

class LogoutData(BaseModel):
    email: EmailStr


# ----------- DB Connection -----------
def get_db():
    conn = mysql.connector.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME
    )
    ensure_tables_exist(conn)
    return conn


# ----------- Auto-create tables and columns if missing -----------
def ensure_tables_exist(conn):
    cursor = conn.cursor()

    # Create newusers table if it doesn't exist
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS newusers (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(100),
            hashed_email TEXT,
            hashed_password TEXT,
            role VARCHAR(20),
            login_time DATETIME,
            logout_time DATETIME
        )
    """)

    # Create loginlogs table if it doesn't exist
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS loginlogs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            email VARCHAR(255),
            username VARCHAR(100),
            hashed_email TEXT,
            hashed_password TEXT,
            role VARCHAR(20),
            login_time DATETIME,
            logout_time DATETIME
        )
    """)

    conn.commit()
    cursor.close()


# ----------- API ROUTES -----------

@app.post("/signup")
def signup(data: SignupData):
    db = get_db()
    cursor = db.cursor()

    if data.role == "admin":
        if not data.security_code or not bcrypt.checkpw(data.security_code.encode(), ADMIN_CODE_HASH.encode()):
            raise HTTPException(status_code=403, detail="Invalid admin security code.")

    hashed_pw = bcrypt.hashpw(data.password.encode(), bcrypt.gensalt()).decode()
    hashed_email = bcrypt.hashpw(data.email.encode(), bcrypt.gensalt()).decode()

    try:
        cursor.execute(
            """
            INSERT INTO newusers (username, hashed_email, hashed_password, role, login_time, logout_time)
            VALUES (%s, %s, %s, %s, NULL, NULL)
            """,
            (data.username, hashed_email, hashed_pw, data.role)
        )
        db.commit()
        return {"message": f"{data.role.capitalize()} registered successfully!"}
    except mysql.connector.IntegrityError:
        raise HTTPException(status_code=409, detail="User already exists.")
    finally:
        db.close()


@app.post("/login")
def login(data: LoginData):
    db = get_db()
    cursor = db.cursor(dictionary=True)

    # Validate user
    cursor.execute("SELECT * FROM newusers")
    all_users = cursor.fetchall()

    matched_user = None
    for user in all_users:
        if bcrypt.checkpw(data.email.encode(), user["hashed_email"].encode()):
            matched_user = user
            break

    if not matched_user or not bcrypt.checkpw(data.password.encode(), matched_user["hashed_password"].encode()):
        db.close()
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if data.role == "admin":
        if not data.security_code or not bcrypt.checkpw(data.security_code.encode(), ADMIN_CODE_HASH.encode()):
            db.close()
            raise HTTPException(status_code=403, detail="Invalid admin security code.")

    # Log to loginlogs
    hashed_email = bcrypt.hashpw(data.email.encode(), bcrypt.gensalt()).decode()
    hashed_pw = bcrypt.hashpw(data.password.encode(), bcrypt.gensalt()).decode()
    login_time = datetime.now()

    cursor = db.cursor()
    cursor.execute(
        """
        INSERT INTO loginlogs (email, username, hashed_email, hashed_password, role, login_time)
        VALUES (%s, %s, %s, %s, %s, %s)
        """,
        (data.email, matched_user["username"], hashed_email, hashed_pw, data.role, login_time)
    )
    db.commit()
    db.close()

    return {"message": f"Welcome back, {matched_user['username']}!", "role": data.role}


@app.post("/logout")
def logout(data: LogoutData):
    db = get_db()
    cursor = db.cursor()

    cursor.execute(
        """
        UPDATE loginlogs
        SET logout_time = %s
        WHERE email = %s AND logout_time IS NULL
        ORDER BY login_time DESC
        LIMIT 1
        """,
        (datetime.now(), data.email)
    )
    db.commit()
    db.close()
    return {"message": "Logout time recorded successfully."}


@app.get("/admin/users")
def get_users():
    db = get_db()
    cursor = db.cursor(dictionary=True)

    cursor.execute("""
        SELECT username, hashed_email, hashed_password, login_time, logout_time
        FROM loginlogs
        WHERE role = 'user'
    """)
    logs = cursor.fetchall()
    db.close()
    return {"users": logs}
