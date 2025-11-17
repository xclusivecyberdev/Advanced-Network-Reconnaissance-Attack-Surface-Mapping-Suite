"""Database models for storing scan results."""

from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Float, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime

Base = declarative_base()


class Scan(Base):
    """Scan session model."""
    __tablename__ = 'scans'

    id = Column(Integer, primary_key=True)
    target = Column(String(255), nullable=False)
    scan_type = Column(String(50))
    status = Column(String(50))
    start_time = Column(DateTime, default=datetime.utcnow)
    end_time = Column(DateTime)
    duration = Column(Float)
    results = Column(Text)  # JSON


class Host(Base):
    """Discovered host model."""
    __tablename__ = 'hosts'

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer)
    ip_address = Column(String(45))
    hostname = Column(String(255))
    state = Column(String(50))
    os = Column(String(255))
    discovered_at = Column(DateTime, default=datetime.utcnow)


class Service(Base):
    """Detected service model."""
    __tablename__ = 'services'

    id = Column(Integer, primary_key=True)
    host_id = Column(Integer)
    port = Column(Integer)
    protocol = Column(String(10))
    service_name = Column(String(100))
    version = Column(String(100))
    banner = Column(Text)
    cpe = Column(String(255))


class Vulnerability(Base):
    """Identified vulnerability model."""
    __tablename__ = 'vulnerabilities'

    id = Column(Integer, primary_key=True)
    service_id = Column(Integer)
    cve_id = Column(String(50))
    severity = Column(String(20))
    cvss_score = Column(Float)
    description = Column(Text)
    discovered_at = Column(DateTime, default=datetime.utcnow)


class User(Base):
    """User model for authentication."""
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    username = Column(String(100), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    email = Column(String(255))
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)


def init_db(database_url='sqlite:///recon_suite.db'):
    """Initialize database."""
    engine = create_engine(database_url)
    Base.metadata.create_all(engine)
    return engine


def get_session(engine):
    """Get database session."""
    Session = sessionmaker(bind=engine)
    return Session()
