from sqlalchemy import Column, DateTime, Integer, String, func, Boolean, Float
from database import Base

class Client(Base):
    __tablename__ = "clients"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    contact = Column(String)
class Secrets(Base):
    __tablename__ = "secrets"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    key = Column(String)
class Document(Base):
    __tablename__ = "documents"
    id = Column(Integer, primary_key=True, index=True)
    blob_key = Column(String, unique=True, nullable=False)
    safe = Column(Boolean, default=False)
    checked_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    sechash = Column(String, nullable=True)
    upload_kind = Column(String, nullable=True)
    seal_mtime = Column(Float, nullable=True)