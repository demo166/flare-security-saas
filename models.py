from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from datetime import datetime
from database import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    first_name = Column(String)
    last_name = Column(String)
    organization_id = Column(Integer, ForeignKey("organizations.id"))
    
    organization = relationship("Organization", back_populates="users")

class Organization(Base):
    __tablename__ = "organizations"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    is_google_connected = Column(Boolean, default=False)
    google_domain = Column(String, nullable=True)
    google_refresh_token = Column(String, nullable=True)
    
    total_scanned = Column(Integer, default=0)
    auto_released = Column(Integer, default=0)
    manual_released = Column(Integer, default=0)
    
    users = relationship("User", back_populates="organization")
    
    # 👈 THIS IS THE LINE THAT WAS MISSING!
    email_logs = relationship("EmailLog", back_populates="organization") 

# models.py -> FIX THIS SECTION
class EmailLog(Base):
    __tablename__ = "email_logs"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"))
    
    # Core Email Data
    message_id = Column(String, index=True)
    sender = Column(String)
    recipient = Column(String)
    subject = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    # AI Threat Intelligence
    ai_score = Column(Integer)
    ai_category = Column(String)
    
    # Status: "Quarantined", "Auto-Released", "Manual-Released", etc.
    action_taken = Column(String)

    # 🛡️ MOVE THESE INSIDE (Align with 'id', 'sender', etc.)
    auth_score = Column(Integer, default=0)
    identity_score = Column(Integer, default=0)
    behavioral_score = Column(Integer, default=0)

    organization = relationship("Organization", back_populates="email_logs")