from typing import List, Optional

from pydantic import BaseModel, field_validator

from .config import PHONE_RE, SMS_MAX_LEN


class LoginReq(BaseModel):
    username: str
    password: str


class DirectSmsReq(BaseModel):
    deviceId: int
    phone: str
    content: str
    slot: int

    @field_validator("phone")
    @classmethod
    def _check_phone(cls, v):
        v = (v or "").strip()
        if not v or not PHONE_RE.match(v):
            raise ValueError("手机号格式不正确")
        return v

    @field_validator("content")
    @classmethod
    def _check_content(cls, v):
        v = (v or "").strip()
        if not v:
            raise ValueError("短信内容不能为空")
        if len(v) > SMS_MAX_LEN:
            raise ValueError(f"短信内容超出长度限制（最多{SMS_MAX_LEN}字）")
        return v


class DirectDialReq(BaseModel):
    deviceId:     int
    slot:         int
    phone:        str
    tts:          str = ""
    duration:     int = 175
    tts_times:    int = 2
    tts_pause:    int = 1
    after_action: int = 1

    @field_validator("phone")
    @classmethod
    def _check_phone(cls, v):
        v = (v or "").strip()
        if not v or not PHONE_RE.match(v):
            raise ValueError("手机号格式不正确")
        return v


class AliasReq(BaseModel):
    alias: str


class GroupReq(BaseModel):
    group: str


class BatchDeleteReq(BaseModel):
    device_ids: List[int]


class BatchWifiReq(BaseModel):
    device_ids: List[int]
    ssid: str
    pwd:  str


class SimReq(BaseModel):
    sim1: str = ""
    sim2: str = ""


class BatchSimReq(BaseModel):
    device_ids: List[int]
    sim1: str = ""
    sim2: str = ""


class BatchConfigReadReq(BaseModel):
    device_ids: List[int]


class BatchConfigPreviewReq(BaseModel):
    device_ids:   List[int]
    pattern:      str
    replacement:  str = ""
    flags:        str = ""


class BatchConfigWriteReq(BaseModel):
    device_ids:   List[int]
    pattern:      str
    replacement:  str = ""
    flags:        str = ""


class BatchConfigPresetReq(BaseModel):
    device_ids: List[int]
    preset:     str = "clean_message_templates"


class BatchForwardReq(BaseModel):
    device_ids: List[int]
    forwardUrl:  str = ""
    notifyUrl:   str = ""


class EnhancedBatchForwardReq(BaseModel):
    device_ids:    List[int]
    forward_method:str
    forwardUrl:    str = ""
    notifyUrl:     str = ""
    deviceKey0:    str = ""
    deviceKey1:    str = ""
    deviceKey2:    str = ""
    smtpProvider:  str = ""
    smtpServer:    str = ""
    smtpPort:      str = ""
    smtpAccount:   str = ""
    smtpPassword:  str = ""
    smtpFromEmail: str = ""
    smtpToEmail:   str = ""
    smtpEncryption:str = ""
    webhookUrl1:   str = ""
    webhookUrl2:   str = ""
    webhookUrl3:   str = ""
    signKey1:      str = ""
    signKey2:      str = ""
    signKey3:      str = ""
    sc3ApiUrl:     str = ""
    sctSendKey:    str = ""
    PPToken:       str = ""
    PPChannel:     str = ""
    PPWebhook:     str = ""
    PPFriends:     str = ""
    PPGroupId:     str = ""
    WPappToken:    str = ""
    WPUID:         str = ""
    WPTopicId:     str = ""
    lyApiUrl:      str = ""


class ScanStartReq(BaseModel):
    cidr:     Optional[str] = None
    group:    Optional[str] = None


class BatchOtaReq(BaseModel):
    device_ids: List[int]
