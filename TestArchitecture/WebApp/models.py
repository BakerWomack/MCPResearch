from sqlalchemy import Column, Integer, String, Boolean, DateTime, Float
from sqlalchemy.sql import func
from database import Base


class Client(Base):
    """CRM clients — same table as MCP server when DATABASE_URL is shared."""

    __tablename__ = "clients"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    contact = Column(String)


class Document(Base):
    __tablename__ = "documents"
    id = Column(Integer, primary_key=True, index=True)
    blob_key = Column(String, unique=True, nullable=False)
    safe = Column(Boolean, default=False)
    checked_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    sechash = Column(String, nullable=True)
    # vulnerable | secure | secure_ts
    upload_kind = Column(String, nullable=True)
    # Blob storage mtime at seal time (secure_ts only)
    seal_mtime = Column(Float, nullable=True)