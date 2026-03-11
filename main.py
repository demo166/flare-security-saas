from fastapi import BackgroundTasks, FastAPI, Depends, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from pydantic import BaseModel
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials 
from google.auth.transport.requests import Request as GoogleRequest
from passlib.context import CryptContext
from typing import List
import base64
import json
import requests
import jwt

# Add these lines to connect to your database files
from database import get_db, engine  
from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordBearer
from services.scan_manager import run_parallel_scan

import models, database
from utils.google_integration import (
    get_personal_flow, 
    ensure_quarantine_label, 
    create_quarantine_filter,
    get_quarantined_emails,
    release_email_from_quarantine,
    verify_enterprise_sync,
    watch_gmail_inbox
)

# Ensure tables are created
models.Base.metadata.create_all(bind=engine)
app = FastAPI()

# Security & CORS
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000", "https://demoopwr.in", "https://www.demoopwr.in"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- JWT SECURITY CONFIGURATION ---
SECRET_KEY = "techflare_super_secret_key_change_in_production" 
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(database.get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired. Please log in again.")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    
    user = db.query(models.User).filter(models.User.email == email).first()
    if user is None:
        raise HTTPException(status_code=401, detail="User no longer exists")
    return user


# --- WEBSOCKET MANAGER ---
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            await connection.send_text(message)

manager = ConnectionManager()

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)


# --- CORE LOGIC: AUTO-TRIAGE ---
async def auto_triage_quarantine(user_email: str, db: Session, history_id: str):
    # 1. SETUP CODE 
    user = db.query(models.User).filter(models.User.email == user_email).first()
    if not user or not user.organization or not user.organization.google_refresh_token:
        print(f"❌ User {user_email} not connected")
        return

    # Create the Gmail 'service' object
    token = user.organization.google_refresh_token
    flow = get_personal_flow()
    client_config = flow.client_config
    creds = Credentials(
        None, 
        refresh_token=token, 
        token_uri=client_config['token_uri'], 
        client_id=client_config['client_id'], 
        client_secret=client_config['client_secret'], 
        scopes=flow.oauth2session.scope
    )
    creds.refresh(GoogleRequest())
    service = build('gmail', 'v1', credentials=creds)

    # Get the Label ID
    labels_res = service.users().labels().list(userId='me').execute()
    q_label = next((l for l in labels_res.get('labels', []) if l['name'] == 'Flare_Quarantine'), None)
    if not q_label: 
        return
    q_label_id = q_label['id']
    
    # 2. FETCH MESSAGES
    msg_results = service.users().messages().list(userId='me', labelIds=[q_label_id]).execute()
    messages = msg_results.get('messages', [])
    
    for msg in messages:
        msg_id = msg['id']
        
        # Check if already fully scanned
        existing_log = db.query(models.EmailLog).filter(models.EmailLog.message_id == msg_id).first()
        if existing_log and existing_log.ai_score > 0:
            continue 

        # Fetch and Scan
        full_msg = service.users().messages().get(userId='me', id=msg_id, format='full').execute()
        
        # Get Subject for the log
        headers = full_msg['payload'].get('headers', [])
        subj = next((h['value'] for h in headers if h['name'] == 'Subject'), "No Subject")
        
        total_score, category, breakdown = await run_parallel_scan(full_msg, user.organization.google_domain)
        
        # 3. Update or Save to Database
        pending_log = db.query(models.EmailLog).filter(models.EmailLog.message_id == str(history_id)).first()

        if pending_log:
            pending_log.message_id = msg_id # Swap temporary historyId for real messageId
            pending_log.subject = subj
            pending_log.ai_score = total_score
            pending_log.ai_category = category
            pending_log.action_taken = "Auto-Released" if category == "Safe" else "Quarantined"
            print(f"🔄 Sync Complete: {subj}")
        else:
            new_log = models.EmailLog(
                organization_id=user.organization.id,
                message_id=msg_id,
                sender=user_email,
                subject=subj,
                ai_score=total_score,
                ai_category=category,
                action_taken="Auto-Released" if category == "Safe" else "Quarantined"
            )
            db.add(new_log)
            print(f"🆕 Created new log for: {subj}")

        db.commit() 

        # 4. REMOVE LABEL (This stops the infinite loop!)
        service.users().messages().modify(
            userId='me',
            id=msg_id,
            body={'removeLabelIds': [q_label_id]}
        ).execute()

        # 5. BROADCAST TO DASHBOARD
        await manager.broadcast(json.dumps({
            "event": "new_email",
            "message": f"Scan complete: {subj}"
        }))
        
        print(f"✅ Scanned & Released from loop: {subj}")    


# --- WEBHOOKS & BACKGROUND TASKS ---
async def process_webhook_background(email_address: str, history_id: str):
    db = database.SessionLocal()
    try:
        await auto_triage_quarantine(email_address, db, history_id)
    finally:
        db.close()

@app.post("/webhook/gmail")
async def receive_gmail_webhook(payload: dict, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    try:
        print("📥 Webhook Received!")
        decoded_data = base64.b64decode(payload['message']['data']).decode('utf-8')
        event_info = json.loads(decoded_data)
        email_address = event_info.get("emailAddress")
        history_id = event_info.get("historyId")
        print(f"📧 Processing email: {email_address}")

        user = db.query(models.User).filter(models.User.email == email_address).first()
        if not user:
            print(f"❌ ERROR: No user found in DB for {email_address}")
            return {"status": "error", "detail": "User not found"}

        # Check for existing pending log to prevent webhook duplicates
        existing_pending = db.query(models.EmailLog).filter(
            models.EmailLog.message_id == str(history_id) 
        ).first()

        if not existing_pending:
            new_log = models.EmailLog(
                organization_id=user.organization.id,
                message_id=str(history_id),
                subject="Scanning Incoming Mail...",
                sender=email_address,
                ai_score=0,
                action_taken="Pending"
            )
            db.add(new_log)
            db.commit()
            print("✅ SUCCESS: Initializing Scan...") 
        else:
            print("⏭️ Skipping: Webhook duplicate detected.")

        background_tasks.add_task(process_webhook_background, email_address, str(history_id))
        return {"status": "success"}
    except Exception as e:
        print(f"🔥 CRITICAL ERROR: {str(e)}")
        return {"status": "error", "detail": str(e)}


# --- Data Models ---
class ConnectRequest(BaseModel):
    user_email: str
    admin_email: str = None
    auth_code: str = None
    mode: str = "personal"

class LoginRequest(BaseModel):
    email: str
    password: str

class RegisterRequest(BaseModel):
    email: str
    password: str
    first_name: str = "User"
    last_name: str = "Admin"

class ReleaseRequest(BaseModel):
    user_email: str
    message_id: str

class DisconnectRequest(BaseModel):
    user_email: str


# --- Authentication Routes ---
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

@app.post("/auth/register")
def register(user_data: RegisterRequest, db: Session = Depends(database.get_db)):
    existing_user = db.query(models.User).filter(models.User.email == user_data.email).first()
    if existing_user: raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_pw = get_password_hash(user_data.password)
    new_user = models.User(email=user_data.email, hashed_password=hashed_pw, first_name=user_data.first_name, last_name=user_data.last_name)
    new_org = models.Organization(name="TechFlare Security")
    new_user.organization = new_org
    db.add(new_user)
    db.commit()
    return {"message": "User created successfully"}

@app.post("/auth/login")
def login(user_data: LoginRequest, db: Session = Depends(database.get_db)):
    user = db.query(models.User).filter(models.User.email == user_data.email).first()
    if not user or not verify_password(user_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    
    access_token = create_access_token(data={"sub": user.email})
    
    return {
        "access_token": access_token, 
        "token_type": "bearer", 
        "email": user.email, 
        "first_name": user.first_name
    }

# --- Public Google Routes ---
@app.get("/auth/google/personal-url")
def get_auth_url():
    try:
        flow = get_personal_flow()
        auth_url, _ = flow.authorization_url(prompt='consent', access_type='offline')
        return {"url": auth_url}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# --- Protected Routes ---
@app.get("/organization/status/{email}")
def get_org_status(email: str, current_user: models.User = Depends(get_current_user), db: Session = Depends(database.get_db)):
    if current_user.email != email:
        raise HTTPException(status_code=403, detail="Not authorized")
        
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user or not user.organization: raise HTTPException(status_code=404, detail="User not found")
    
    return {
        "is_connected": user.organization.is_google_connected,
        "domain": user.organization.google_domain or "Not Connected"
    }

@app.get("/organization/metrics/{email}")
def get_org_metrics(email: str, current_user: models.User = Depends(get_current_user), db: Session = Depends(database.get_db)):
    if current_user.email != email:
        raise HTTPException(status_code=403, detail="Not authorized")
        
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user or not user.organization: 
        raise HTTPException(status_code=404, detail="User not found")
        
    org = user.organization
    auto_rel = org.auto_released if org.auto_released else 0
    manual_rel = org.manual_released if org.manual_released else 0
    total_mitigated = auto_rel + manual_rel
    
    return {
        "totalScanned": org.total_scanned if org.total_scanned else 0,
        "falsePositivesMitigated": total_mitigated,
        "mttd": "1.2s" 
    }

@app.get("/organization/email-logs/{email}")
def get_email_logs(email: str, current_user: models.User = Depends(get_current_user), db: Session = Depends(database.get_db)):
    if current_user.email != email:
        raise HTTPException(status_code=403, detail="Not authorized")
        
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user or not user.organization: 
        raise HTTPException(status_code=404, detail="Organization not found")
        
    logs = db.query(models.EmailLog).filter(
        models.EmailLog.organization_id == user.organization.id
    ).order_by(models.EmailLog.timestamp.desc()).all()
    
    formatted_logs = []
    for log in logs:
        formatted_logs.append({
            "id": log.message_id,
            "sender": log.sender,
            "recipient": log.recipient,
            "subject": log.subject,
            "ai_category": log.ai_category,
            "ai_score": log.ai_score,
            "action": log.action_taken,
            "date": log.timestamp.strftime("%b %d, %Y %H:%M:%S") 
        })
        
    return {"logs": formatted_logs}

@app.get("/google/quarantine-emails/{user_email}")
async def get_quarantine_emails_endpoint(user_email: str, current_user: models.User = Depends(get_current_user), db: Session = Depends(database.get_db)):
    if current_user.email != user_email:
        raise HTTPException(status_code=403, detail="Not authorized")
        
    user = db.query(models.User).filter(models.User.email == user_email).first()
    if not user or not user.organization:
        return {"emails": []}
    
    logs = db.query(models.EmailLog).filter(
        models.EmailLog.organization_id == user.organization.id
    ).order_by(models.EmailLog.timestamp.desc()).limit(10).all()

    emails = []
    for log in logs:
        emails.append({
            "id": log.message_id,
            "sender": log.sender,
            "subject": log.subject,
            "snippet": "", 
            "ai_score": log.ai_score,
            "ai_category": log.ai_category,
            "auth_score": log.auth_score,
            "identity_score": log.identity_score,
            "behavioral_score": log.behavioral_score,
            "action": log.action_taken,
            "date": log.timestamp.strftime("%b %d, %Y %H:%M:%S")
        })
            
    return {"emails": emails}

@app.post("/integrations/google/connect")
def connect_google(data: ConnectRequest, current_user: models.User = Depends(get_current_user), db: Session = Depends(database.get_db)):
    if current_user.email != data.user_email:
        raise HTTPException(status_code=403, detail="Not authorized")
        
    try:
        flow = get_personal_flow()
        flow.fetch_token(code=data.auth_code)
        creds = flow.credentials
        
        service = build('gmail', 'v1', credentials=creds)
        profile = service.users().getProfile(userId='me').execute()
        email_address = profile.get('emailAddress')
        
        label_res = ensure_quarantine_label(service)
        if label_res["success"]:
            create_quarantine_filter(service, label_res["label_id"])
        
        watch_gmail_inbox(service)
        
        user = db.query(models.User).filter(models.User.email == data.user_email).first()
        if user and user.organization:
            user.organization.is_google_connected = True
            user.organization.google_domain = email_address
            if creds.refresh_token:
                user.organization.google_refresh_token = creds.refresh_token
            db.commit()
        return {"success": True, "email": email_address}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/google/release-email")
def release_email_endpoint(data: ReleaseRequest, current_user: models.User = Depends(get_current_user), db: Session = Depends(database.get_db)):
    if current_user.email != data.user_email:
        raise HTTPException(status_code=403, detail="Not authorized")
        
    user = db.query(models.User).filter(models.User.email == data.user_email).first()
    if not user or not user.organization or not user.organization.google_refresh_token:
        raise HTTPException(status_code=400, detail="User not connected")

    try:
        token = user.organization.google_refresh_token
        flow = get_personal_flow()
        client_config = flow.client_config
        creds = Credentials(None, refresh_token=token, token_uri=client_config['token_uri'], client_id=client_config['client_id'], client_secret=client_config['client_secret'], scopes=flow.oauth2session.scope)
        creds.refresh(GoogleRequest())
        service = build('gmail', 'v1', credentials=creds)
        
        result = release_email_from_quarantine(service, data.message_id)
        
        if user.organization.manual_released is None: user.organization.manual_released = 0
        user.organization.manual_released += 1
        
        log = db.query(models.EmailLog).filter(models.EmailLog.message_id == data.message_id).first()
        if log:
            log.action_taken = "Released (Manual)"

        db.commit()
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/google/purge-email")
def purge_email_endpoint(data: ReleaseRequest, current_user: models.User = Depends(get_current_user), db: Session = Depends(database.get_db)):
    if current_user.email != data.user_email:
        raise HTTPException(status_code=403, detail="Not authorized")
        
    user = db.query(models.User).filter(models.User.email == data.user_email).first()
    if not user or not user.organization or not user.organization.google_refresh_token:
        raise HTTPException(status_code=400, detail="User not connected")

    try:
        token = user.organization.google_refresh_token
        flow = get_personal_flow()
        client_config = flow.client_config
        creds = Credentials(None, refresh_token=token, token_uri=client_config['token_uri'], client_id=client_config['client_id'], client_secret=client_config['client_secret'], scopes=flow.oauth2session.scope)
        creds.refresh(GoogleRequest())
        service = build('gmail', 'v1', credentials=creds)
        
        service.users().messages().trash(userId='me', id=data.message_id).execute()
        
        log = db.query(models.EmailLog).filter(models.EmailLog.message_id == data.message_id).first()
        if log:
            log.action_taken = "Purged (Deleted)"
            db.commit()
            
        return {"success": True, "message": "Email permanently purged."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/integrations/google/disconnect")
def disconnect_google(data: DisconnectRequest, current_user: models.User = Depends(get_current_user), db: Session = Depends(database.get_db)):
    if current_user.email != data.user_email:
        raise HTTPException(status_code=403, detail="Not authorized")
        
    user = db.query(models.User).filter(models.User.email == data.user_email).first()

    if not user or not user.organization or not user.organization.google_refresh_token:
        raise HTTPException(status_code=400, detail="Organization is not currently connected.")

    try:
        token = user.organization.google_refresh_token
        flow = get_personal_flow() 
        client_config = flow.client_config
        creds = Credentials(None, refresh_token=token, token_uri=client_config['token_uri'], client_id=client_config['client_id'], client_secret=client_config['client_secret'], scopes=flow.oauth2session.scope)
        creds.refresh(GoogleRequest())
        service = build('gmail', 'v1', credentials=creds)
        
        try:
            labels_res = service.users().labels().list(userId='me').execute()
            q_label = next((l for l in labels_res.get('labels', []) if l['name'] == 'Flare_Quarantine'), None)
            
            if q_label:
                label_id = q_label['id']
                filters_res = service.users().settings().filters().list(userId='me').execute()
                for f in filters_res.get('filter', []):
                    if label_id in f.get('action', {}).get('addLabelIds', []):
                        service.users().settings().filters().delete(userId='me', id=f['id']).execute()
                        
                service.users().labels().delete(userId='me', id=label_id).execute()
        except Exception as e:
            print(f"Cleanup Warning: {e}")

        try:
            service.users().stop(userId='me').execute()
        except Exception as e:
            print(f"Watch Stop Warning: {e}")

        try:
            requests.post('https://oauth2.googleapis.com/revoke',
                params={'token': token},
                headers={'content-type': 'application/x-www-form-urlencoded'}
            )
        except Exception as e:
            print(f"Revocation Warning: {e}")

        user.organization.is_google_connected = False
        user.organization.google_domain = None
        user.organization.google_refresh_token = None
        db.commit()

        return {"success": True, "message": "Google integration disconnected."}
    except Exception as e:
        print(f"Disconnect Error: {str(e)}")
        raise HTTPException(status_code=500, detail="An error occurred while disconnecting.")