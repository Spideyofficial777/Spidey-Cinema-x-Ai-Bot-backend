from fastapi import FastAPI, APIRouter, HTTPException, Depends, status, Form
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field, EmailStr, validator
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import disposable_email_domains
import secrets
import uuid
import os
import logging
from pathlib import Path
from typing import List, Optional
from dotenv import load_dotenv
import asyncio

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Security
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# JWT Settings
SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "your-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Email Settings
GMAIL_USERNAME = os.environ.get("GMAIL_USERNAME", "gmainghatyar777@gmail.com")
GMAIL_APP_PASSWORD = os.environ.get("GMAIL_APP_PASSWORD", "xvjxaszgbseqjwon")

app = FastAPI(title="Spidey Official Bot Showcase", description="Premium Telegram Bot Platform")
api_router = APIRouter(prefix="/api")

# Models
class User(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    email: EmailStr
    password_hash: str
    is_verified: bool = False
    verification_token: Optional[str] = None
    otp_code: Optional[str] = None
    otp_expires: Optional[datetime] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    referral_count: int = 0
    is_premium: bool = False

class UserRegistration(BaseModel):
    email: EmailStr
    password: str
    confirm_password: str
    
    @validator('email')
    def validate_email(cls, v):
        domain = v.split('@')[-1]
        if disposable_email_domains.check(domain):
            raise ValueError('Disposable email addresses are not allowed')
        return v
    
    @validator('confirm_password')
    def passwords_match(cls, v, values):
        if 'password' in values and v != values['password']:
            raise ValueError('Passwords do not match')
        return v
    
    @validator('password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        return v

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class OTPVerification(BaseModel):
    email: EmailStr
    otp: str

class OTPRequest(BaseModel):
    email: EmailStr

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None

class FeedbackCreate(BaseModel):
    name: str
    email: EmailStr
    subject: str
    message: str
    category: str = "general"

class Feedback(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    email: EmailStr
    subject: str
    message: str
    category: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    status: str = "pending"

class EmailVerification(BaseModel):
    token: str

class BotStats(BaseModel):
    total_users: int = 15420
    total_downloads: int = 89734
    referral_signups: int = 3205
    premium_users: int = 892

# Utility Functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def generate_verification_token():
    return secrets.token_urlsafe(32)

def generate_otp():
    return str(secrets.randbelow(900000) + 100000)  # 6-digit OTP

async def send_verification_email(email: str, token: str):
    try:
        msg = MIMEMultipart()
        msg['From'] = GMAIL_USERNAME
        msg['To'] = email
        msg['Subject'] = "🕷️ Verify Your Spidey Official Account"
        
        verification_link = f"https://telegram-hub-2.preview.emergentagent.com/verify-email?token={token}"
        
        html_body = f"""
        <html>
            <body style="font-family: Arial, sans-serif; background: linear-gradient(135deg, #1a1a2e, #16213e); color: #fff; padding: 20px;">
                <div style="max-width: 600px; margin: 0 auto; background: rgba(255,255,255,0.1); border-radius: 15px; padding: 30px; backdrop-filter: blur(10px);">
                    <div style="text-align: center; margin-bottom: 30px;">
                        <img src="https://envs.sh/uQX.jpg" alt="Spidey Official" style="width: 80px; height: 80px; border-radius: 50%; margin-bottom: 15px;">
                        <h1 style="color: #00d4ff; margin: 0;">Spidey Official</h1>
                        <p style="color: #a0a0ff; margin: 5px 0;">Premium Telegram Bot Platform</p>
                    </div>
                    
                    <h2 style="color: #fff; text-align: center;">🚀 Welcome to the Future!</h2>
                    <p style="font-size: 16px; line-height: 1.6; color: #e0e0ff;">
                        Thank you for joining Spidey Official! You're just one click away from accessing our premium Telegram bot features.
                    </p>
                    
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="{verification_link}" style="display: inline-block; background: linear-gradient(45deg, #00d4ff, #0099ff); color: white; padding: 15px 30px; text-decoration: none; border-radius: 30px; font-weight: bold; box-shadow: 0 8px 25px rgba(0, 212, 255, 0.3); transition: all 0.3s ease;">
                            ✨ Verify My Account ✨
                        </a>
                    </div>
                    
                    <div style="background: rgba(255,255,255,0.05); border-radius: 10px; padding: 20px; margin: 20px 0;">
                        <h3 style="color: #00ff88; margin-top: 0;">🎯 What's Next?</h3>
                        <ul style="color: #e0e0ff; line-height: 1.8;">
                            <li>Access our premium Telegram bot (@spideycinemax_ai_bot)</li>
                            <li>Download movies, music, and Instagram videos</li>
                            <li>Generate QR codes and custom fonts</li>
                            <li>Join our referral program (10 invites = 1 month premium)</li>
                        </ul>
                    </div>
                    
                    <p style="font-size: 14px; color: #a0a0ff; text-align: center; margin-top: 30px;">
                        This verification link expires in 24 hours.<br>
                        Can't click? Copy and paste: {verification_link}
                    </p>
                    
                    <hr style="border: 1px solid rgba(255,255,255,0.1); margin: 30px 0;">
                    <p style="text-align: center; color: #8080ff; font-size: 12px;">
                        © 2025 Spidey Official. Premium Bot Platform.<br>
                        Need help? Contact us through our website.
                    </p>
                </div>
            </body>
        </html>
        """
        
        msg.attach(MIMEText(html_body, 'html'))
        
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(GMAIL_USERNAME, GMAIL_APP_PASSWORD)
            server.send_message(msg)
            
        return True
    except Exception as e:
        logging.error(f"Failed to send verification email: {str(e)}")
        return False

async def send_otp_email(email: str, otp: str):
    try:
        msg = MIMEMultipart()
        msg['From'] = GMAIL_USERNAME
        msg['To'] = email
        msg['Subject'] = "🔐 Your Spidey Official Login OTP"
        
        html_body = f"""
        <html>
            <body style="font-family: Arial, sans-serif; background: linear-gradient(135deg, #1a1a2e, #16213e); color: #fff; padding: 20px;">
                <div style="max-width: 500px; margin: 0 auto; background: rgba(255,255,255,0.1); border-radius: 15px; padding: 30px; backdrop-filter: blur(10px);">
                    <div style="text-align: center; margin-bottom: 30px;">
                        <img src="https://envs.sh/uQX.jpg" alt="Spidey Official" style="width: 60px; height: 60px; border-radius: 50%; margin-bottom: 15px;">
                        <h1 style="color: #00d4ff; margin: 0; font-size: 24px;">Spidey Official</h1>
                        <p style="color: #a0a0ff; margin: 5px 0;">Secure Login Verification</p>
                    </div>
                    
                    <h2 style="color: #fff; text-align: center; margin-bottom: 20px;">🔐 Your Login OTP</h2>
                    
                    <div style="text-align: center; margin: 30px 0;">
                        <div style="display: inline-block; background: linear-gradient(45deg, #00d4ff, #0099ff); color: white; padding: 20px 40px; border-radius: 15px; font-size: 32px; font-weight: bold; letter-spacing: 8px; box-shadow: 0 8px 25px rgba(0, 212, 255, 0.3);">
                            {otp}
                        </div>
                    </div>
                    
                    <div style="background: rgba(255, 255, 0, 0.1); border-radius: 10px; padding: 15px; margin: 20px 0; border-left: 4px solid #ffeb3b;">
                        <p style="color: #fff; margin: 0; font-size: 14px;">
                            ⏰ <strong>Important:</strong> This OTP expires in 10 minutes.<br>
                            🔒 Never share this code with anyone.<br>
                            📱 Use it only on the official Spidey website.
                        </p>
                    </div>
                    
                    <p style="font-size: 14px; color: #a0a0ff; text-align: center; margin-top: 30px;">
                        If you didn't request this OTP, please ignore this email.
                    </p>
                    
                    <hr style="border: 1px solid rgba(255,255,255,0.1); margin: 30px 0;">
                    <p style="text-align: center; color: #8080ff; font-size: 12px;">
                        © 2025 Spidey Official. Premium Bot Platform.<br>
                        Secure • Fast • Reliable
                    </p>
                </div>
            </body>
        </html>
        """
        
        msg.attach(MIMEText(html_body, 'html'))
        
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(GMAIL_USERNAME, GMAIL_APP_PASSWORD)
            server.send_message(msg)
            
        return True
    except Exception as e:
        logging.error(f"Failed to send OTP email: {str(e)}")
        return False

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception
    
    user_data = await db.users.find_one({"email": email})
    if user_data is None:
        raise credentials_exception
    return User(**user_data)

# API Routes
@api_router.post("/register", response_model=dict)
async def register_user(user_data: UserRegistration):
    # Check if user already exists
    existing_user = await db.users.find_one({"email": user_data.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create new user
    hashed_password = get_password_hash(user_data.password)
    verification_token = generate_verification_token()
    
    user = User(
        email=user_data.email,
        password_hash=hashed_password,
        verification_token=verification_token
    )
    
    # Save to database
    await db.users.insert_one(user.dict())
    
    # Send verification email
    email_sent = await send_verification_email(user_data.email, verification_token)
    
    if not email_sent:
        raise HTTPException(status_code=500, detail="Failed to send verification email")
    
    return {
        "message": "Registration successful! Please check your email to verify your account.",
        "email": user_data.email
    }

@api_router.post("/login", response_model=dict)
async def login_user(user_data: UserLogin):
    user_doc = await db.users.find_one({"email": user_data.email})
    
    if not user_doc or not verify_password(user_data.password, user_doc["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password"
        )
    
    if not user_doc["is_verified"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email not verified. Please check your email for verification link."
        )
    
    # Generate and send OTP
    otp = generate_otp()
    otp_expires = datetime.utcnow() + timedelta(minutes=10)
    
    # Update user with OTP
    await db.users.update_one(
        {"email": user_data.email},
        {"$set": {"otp_code": otp, "otp_expires": otp_expires}}
    )
    
    # Send OTP email
    email_sent = await send_otp_email(user_data.email, otp)
    
    if not email_sent:
        raise HTTPException(status_code=500, detail="Failed to send OTP email")
    
    return {
        "message": "OTP sent to your email. Please verify to complete login.",
        "email": user_data.email,
        "requires_otp": True
    }

@api_router.post("/verify-otp", response_model=Token)
async def verify_otp(otp_data: OTPVerification):
    user_doc = await db.users.find_one({"email": otp_data.email})
    
    if not user_doc:
        raise HTTPException(status_code=404, detail="User not found")
    
    if not user_doc.get("otp_code"):
        raise HTTPException(status_code=400, detail="No OTP found. Please login again.")
    
    if user_doc["otp_expires"] < datetime.utcnow():
        raise HTTPException(status_code=400, detail="OTP expired. Please login again.")
    
    if user_doc["otp_code"] != otp_data.otp:
        raise HTTPException(status_code=400, detail="Invalid OTP")
    
    # Clear OTP after successful verification
    await db.users.update_one(
        {"email": otp_data.email},
        {"$unset": {"otp_code": "", "otp_expires": ""}}
    )
    
    # Generate JWT token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": otp_data.email}, expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}

@api_router.post("/verify-email")
async def verify_email(verification: EmailVerification):
    user_doc = await db.users.find_one({"verification_token": verification.token})
    
    if not user_doc:
        raise HTTPException(status_code=400, detail="Invalid verification token")
    
    if user_doc["is_verified"]:
        raise HTTPException(status_code=400, detail="Email already verified")
    
    # Update user as verified
    await db.users.update_one(
        {"verification_token": verification.token},
        {"$set": {"is_verified": True, "verification_token": None}}
    )
    
    return {"message": "Email verified successfully! You can now log in."}

@api_router.get("/me", response_model=dict)
async def get_current_user_profile(current_user: User = Depends(get_current_user)):
    return {
        "email": current_user.email,
        "is_verified": current_user.is_verified,
        "created_at": current_user.created_at,
        "referral_count": current_user.referral_count,
        "is_premium": current_user.is_premium
    }

@api_router.post("/feedback", response_model=dict)
async def submit_feedback(feedback_data: FeedbackCreate):
    # Create feedback record
    feedback = Feedback(**feedback_data.dict())
    await db.feedback.insert_one(feedback.dict())
    
    # Note: Email functionality temporarily disabled
    # TODO: Implement feedback email sending with new email system
    
    return {
        "message": "Feedback submitted successfully! We'll get back to you soon.",
        "feedback_id": feedback.id
    }

@api_router.get("/bot-stats", response_model=BotStats)
async def get_bot_stats():
    # In a real app, these would be calculated from actual data
    return BotStats()

@api_router.get("/bot-features", response_model=List[dict])
async def get_bot_features():
    features = [
        {
            "id": "font-customization",
            "title": "Font Customization",
            "description": "Choose from 50+ premium fonts to customize your text experience",
            "icon": "🎨",
            "premium": False
        },
        {
            "id": "movie-request",
            "title": "Movie Request System",
            "description": "Request movies directly via website or bot /request command",
            "icon": "🎬",
            "premium": True
        },
        {
            "id": "privacy-protection",
            "title": "Privacy Protection",
            "description": "Your privacy is strictly maintained for all requests and downloads",
            "icon": "🔒",
            "premium": False
        },
        {
            "id": "referral-system",
            "title": "Referral System",
            "description": "Invite 10 new members to unlock 1 month of premium access",
            "icon": "🎯",
            "premium": False
        },
        {
            "id": "smart-greeting",
            "title": "Smart Greeting System",
            "description": "Time-based greetings (Good Morning, Afternoon, Evening)",
            "icon": "👋",
            "premium": False
        },
        {
            "id": "premium-movies",
            "title": "Premium Movie Access",
            "description": "Access exclusive movies only available to premium users",
            "icon": "⭐",
            "premium": True
        },
        {
            "id": "feedback-support",
            "title": "Feedback & Support",
            "description": "Send feedback from website & bot with private admin replies",
            "icon": "💬",
            "premium": False
        },
        {
            "id": "instagram-download",
            "title": "Instagram Video Downloader",
            "description": "Download Instagram videos, reels, and stories instantly",
            "icon": "📱",
            "premium": False
        },
        {
            "id": "music-download",
            "title": "Music & Song Downloader",
            "description": "Download high-quality music with artwork and metadata",
            "icon": "🎵",
            "premium": False
        },
        {
            "id": "qr-generator",
            "title": "QR Code Generator",
            "description": "Generate custom QR codes for any text or URL",
            "icon": "📊",
            "premium": False
        }
    ]
    return features

# Health check
@api_router.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow()}

# Include router
app.include_router(api_router)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
