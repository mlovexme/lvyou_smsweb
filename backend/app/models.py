from sqlalchemy import BigInteger, Column, Integer, String, Text
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class Device(Base):
    __tablename__ = "devices"
    id           = Column(Integer, primary_key=True, index=True)
    devId        = Column(String(128), unique=True, nullable=True)
    grp          = Column(String(64),  default="auto")
    ip           = Column(String(45),  unique=True, index=True, nullable=False)
    mac          = Column(String(32),  unique=True, nullable=True, default=None)
    user         = Column(String(64),  default="")
    passwd       = Column(String(64),  default="")
    status       = Column(String(32),  default="unknown")
    lastSeen     = Column(BigInteger,  default=0)
    sim1number   = Column(String(32),  default="")
    sim1operator = Column(String(64),  default="")
    sim1signal   = Column(Integer,     default=0)
    sim2number   = Column(String(32),  default="")
    sim2operator = Column(String(64),  default="")
    sim2signal   = Column(Integer,     default=0)
    token        = Column(Text,        default="")
    firmware_version = Column(String(64), default="")
    alias        = Column(String(128), default="")
    created      = Column(String(32),  default="")


class AuthToken(Base):
    __tablename__ = "auth_tokens"
    token    = Column(String(128), primary_key=True)
    username = Column(String(64),  default="")
    exp      = Column(BigInteger,  default=0, index=True)
