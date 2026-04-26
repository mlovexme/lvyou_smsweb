import json
import re
from typing import Any, Callable, Dict, List, Optional

from fastapi import HTTPException

from .config import CONFIG_BATCH_MAX, CONFIG_MAX_CHARS

ReadConfigFn = Callable[[str, str, str], Optional[str]]
WriteConfigFn = Callable[[str, str, str, str], bool]
AuditFn = Optional[Callable[[str, str], None]]


def apply_regex(config: str, pattern: str, replacement: str, flags_str: str) -> Optional[str]:
    try:
        flags = 0
        for f in flags_str.lower():
            if f == "i":
                flags |= re.IGNORECASE
            elif f == "m":
                flags |= re.MULTILINE
            elif f == "s":
                flags |= re.DOTALL
            elif f.strip():
                return None
        return re.sub(pattern, replacement, config, flags=flags)
    except re.error:
        return None


def config_main_json(content: str) -> Optional[Dict[str, Any]]:
    main_part = (content or "").split("~~--==~~--==", 1)[0].strip()
    if not main_part:
        return None
    try:
        parsed = json.loads(main_part)
    except Exception:
        return None
    if not isinstance(parsed, dict) or not parsed:
        return None
    return parsed


def validate_config_content(original: str, replaced: str) -> Optional[str]:
    original_main = config_main_json(original)
    replaced_main = config_main_json(replaced)
    if original_main and replaced_main is None:
        return "替换后开头主配置 JSON 无效，已阻止写入"
    if original_main and "~~--==~~--==" in original and "~~--==~~--==" not in replaced:
        return "替换后消息模板分隔符丢失，已阻止写入"
    if replaced.strip() in ("{}", ""):
        return "替换结果为空配置，已阻止写入"
    if replaced_main is not None:
        required_keys = {"wps", "uip"}
        if not required_keys.issubset(replaced_main.keys()):
            return "替换后主配置缺少关键字段，已阻止写入"
    return None


CLEAN_MESSAGE_TEMPLATES = """~~--==~~--==
502
{
  "msgtype": "text",
  "text": {
    "content": "【短信外发成功】{{LN}}对方号码：{{phNum|$jsonEscape()}}{{LN}}短信内容：{{smsBd|$jsonEscape()}}{{LN}}发出时间：{{YMDHMS}}{{LN}}{{LN}}发出设备：{{{devName|$jsonEscape()}}}{{LN}}发出卡槽：{{msIsdn}}（卡{{slot}}）{{scName|$jsonEscape()}}"
  }
}
~~--==~~--==
603
{
  "msgtype": "text",
  "text": {
    "content": "【来电提醒】{{LN}}号码：{{phNum|$jsonEscape()}}{{LN}}通话时间：{{telStartTs|$ts2hhmmss(':')}} 至 {{telEndTs|$ts2hhmmss(':')}}{{LN}}{{LN}}来自设备：{{{devName|$jsonEscape()}}}{{LN}}卡槽：{{msIsdn}}（卡{{slot}}）{{scName|$jsonEscape()}}"
  }
}
~~--==~~--==
695
{
  "msgtype": "voice",
  "voice": { "media_id": "{{telMediaId}}" }
}
~~--==~~--==
501
{
  "msgtype": "text",
  "text": {
    "content": "{{smsBd|$jsonEscape()}}{{LN}}短信号码：{{phNum|$jsonEscape()}}{{LN}}短信时间：{{smsTs|$ts2yyyymmddhhmmss('-',':')}}{{LN}}{{LN}}来自设备：{{{devName|$jsonEscape()}}}{{LN}}卡槽：{{msIsdn}}（卡{{slot}}）{{scName|$jsonEscape()}}"
  }
}
~~--==~~--==
209
{
  "msgtype": "text",
  "text": {
    "content": "卡{{slot}}存在故障，请将卡放入手机检查原因！{{LN}}{{LN}}SIM卡信息：{{LN}}ICCID：{{iccId}}{{LN}}IMSI：{{imsi}}{{LN}}卡号：{{msIsdn}} {{scName|$jsonEscape()}}{{LN}}{{LN}}来自设备：{{{devName|$jsonEscape()}}}{{LN}}卡槽：卡{{slot}}"
  }
}
~~--==~~--==
205
{
  "msgtype": "text",
  "text": {
    "content": "卡{{slot}}已从设备中取出！{{LN}}{{LN}}SIM卡信息：{{LN}}ICCID：{{iccId}}{{LN}}IMSI：{{imsi}}{{LN}}卡号：{{msIsdn}} {{scName|$jsonEscape()}}{{LN}}{{LN}}来自设备：{{{devName|$jsonEscape()}}}{{LN}}卡槽：卡{{slot}}"
  }
}
~~--==~~--==
204
{
  "msgtype": "text",
  "text": {
    "content": "卡{{slot}}已就绪！{{LN}}{{LN}}SIM卡信息：{{LN}}ICCID：{{iccId}}{{LN}}IMSI：{{imsi}}{{LN}}卡号：{{msIsdn}} {{scName|$jsonEscape()}}{{LN}}信号强度：{{dbm}}%{{LN}}{{LN}}来自设备：{{{devName|$jsonEscape()}}}{{LN}}卡槽：卡{{slot}}"
  }
}
~~--==~~--==
102
{
  "msgtype": "text",
  "text": {
    "content": "【设备上线提醒】{{LN}}设备已通过 卡2 上线！{{LN}}{{LN}}SIM卡信息：{{LN}}ICCID：{{iccId}}{{LN}}IMSI：{{imsi}}{{LN}}卡号：{{msIsdn}} {{scName|$jsonEscape()}}{{LN}}信号强度：{{dbm}}%{{LN}}{{LN}}来自设备：{{{devName|$jsonEscape()}}}{{LN}}卡槽：卡{{slot}}"
  }
}
~~--==~~--==
101
{
  "msgtype": "text",
  "text": {
    "content": "【设备上线提醒】{{LN}}设备已通过 卡1 上线！{{LN}}{{LN}}SIM卡信息：{{LN}}ICCID：{{iccId}}{{LN}}IMSI：{{imsi}}{{LN}}卡号：{{msIsdn}} {{scName|$jsonEscape()}}{{LN}}信号强度：{{dbm}}%{{LN}}{{LN}}来自设备：{{{devName|$jsonEscape()}}}{{LN}}卡槽：卡{{slot}}"
  }
}
~~--==~~--==
100
{
  "msgtype": "text",
  "text": {
    "content": "【设备上线提醒】{{LN}}设备已通过 WiFi 上线！{{LN}}{{LN}}本机IP：{{ip}}{{LN}}WiFi热点：{{ssid|$jsonEscape()}}{{LN}}信号强度：{{dbm}}%{{LN}}{{LN}}来自设备：{{{devName|$jsonEscape()}}}"
  }
}"""


def apply_clean_message_template(config: str) -> Optional[str]:
    main = (config or "").split("~~--==~~--==", 1)[0].rstrip()
    if config_main_json(main) is None:
        return None
    return f"{main}\n\n{CLEAN_MESSAGE_TEMPLATES}"


def config_read_task(device_info: Dict[str, Any], read_config: ReadConfigFn) -> Dict[str, Any]:
    ip   = device_info["ip"]
    user = device_info["user"]
    pw   = device_info["pw"]
    try:
        config = read_config(ip, user, pw)
        if config is None:
            return {"id": device_info["id"], "ip": ip, "ok": False, "error": "读取配置失败"}
        return {"id": device_info["id"], "ip": ip, "ok": True, "config": config}
    except HTTPException as exc:
        return {"id": device_info["id"], "ip": ip, "ok": False, "error": exc.detail}
    except Exception as exc:
        return {"id": device_info["id"], "ip": ip, "ok": False, "error": str(exc)}


def config_preview_task(device_info: Dict[str, Any], pattern: str, replacement: str, flags_str: str, read_config: ReadConfigFn) -> Dict[str, Any]:
    result = config_read_task(device_info, read_config)
    if not result.get("ok"):
        return result
    config = result.get("config", "")
    replaced = apply_regex(config, pattern, replacement, flags_str)
    if replaced is None:
        return {"id": device_info["id"], "ip": device_info["ip"], "ok": False, "error": "正则表达式或标志位无效"}
    return {
        "id": device_info["id"],
        "ip": device_info["ip"],
        "ok": True,
        "original": config,
        "replaced": replaced,
        "changed": config != replaced,
    }


def config_preset_preview_task(device_info: Dict[str, Any], preset: str, read_config: ReadConfigFn) -> Dict[str, Any]:
    result = config_read_task(device_info, read_config)
    if not result.get("ok"):
        return result
    config = str(result.get("config", ""))
    if preset != "clean_message_templates":
        return {"id": device_info["id"], "ip": device_info["ip"], "ok": False, "error": "未知配置预设"}
    replaced = apply_clean_message_template(config)
    if replaced is None:
        return {"id": device_info["id"], "ip": device_info["ip"], "ok": False, "error": "主配置 JSON 无效，不能应用预设"}
    return {
        "id": device_info["id"],
        "ip": device_info["ip"],
        "ok": True,
        "original": config,
        "replaced": replaced,
        "changed": config != replaced,
    }


def config_write_task(device_info: Dict[str, Any], pattern: str, replacement: str, flags_str: str, read_config: ReadConfigFn, write_config: WriteConfigFn, audit: AuditFn = None) -> Dict[str, Any]:
    preview = config_preview_task(device_info, pattern, replacement, flags_str, read_config)
    if not preview.get("ok"):
        return preview
    if not preview.get("changed"):
        return {"id": device_info["id"], "ip": device_info["ip"], "ok": True, "changed": False}
    replaced = str(preview.get("replaced", ""))
    original = str(preview.get("original", ""))
    validation_error = validate_config_content(original, replaced)
    if validation_error:
        return {"id": device_info["id"], "ip": device_info["ip"], "ok": False, "error": validation_error}
    if not write_config(device_info["ip"], device_info["user"], device_info["pw"], replaced):
        return {"id": device_info["id"], "ip": device_info["ip"], "ok": False, "error": "写入配置失败"}
    saved = read_config(device_info["ip"], device_info["user"], device_info["pw"])
    if saved is None:
        return {"id": device_info["id"], "ip": device_info["ip"], "ok": False, "error": "写入后读取校验失败"}
    saved_error = validate_config_content(original, saved)
    if saved_error:
        write_config(device_info["ip"], device_info["user"], device_info["pw"], original)
        return {"id": device_info["id"], "ip": device_info["ip"], "ok": False, "error": f"写入后校验失败，已尝试恢复原配置：{saved_error}"}
    if audit:
        audit("config_write", f"device={device_info['id']} ip={device_info['ip']}")
    return {"id": device_info["id"], "ip": device_info["ip"], "ok": True, "changed": True}


def config_preset_write_task(device_info: Dict[str, Any], preset: str, read_config: ReadConfigFn, write_config: WriteConfigFn, audit: AuditFn = None) -> Dict[str, Any]:
    preview = config_preset_preview_task(device_info, preset, read_config)
    if not preview.get("ok"):
        return preview
    if not preview.get("changed"):
        return {"id": device_info["id"], "ip": device_info["ip"], "ok": True, "changed": False}
    replaced = str(preview.get("replaced", ""))
    original = str(preview.get("original", ""))
    validation_error = validate_config_content(original, replaced)
    if validation_error:
        return {"id": device_info["id"], "ip": device_info["ip"], "ok": False, "error": validation_error}
    if not write_config(device_info["ip"], device_info["user"], device_info["pw"], replaced):
        return {"id": device_info["id"], "ip": device_info["ip"], "ok": False, "error": "写入配置失败"}
    saved = read_config(device_info["ip"], device_info["user"], device_info["pw"])
    if saved is None:
        return {"id": device_info["id"], "ip": device_info["ip"], "ok": False, "error": "写入后读取校验失败"}
    saved_error = validate_config_content(original, saved)
    if saved_error:
        write_config(device_info["ip"], device_info["user"], device_info["pw"], original)
        return {"id": device_info["id"], "ip": device_info["ip"], "ok": False, "error": f"写入后校验失败，已尝试恢复原配置：{saved_error}"}
    if audit:
        audit("config_preset_write", f"device={device_info['id']} ip={device_info['ip']} preset={preset}")
    return {"id": device_info["id"], "ip": device_info["ip"], "ok": True, "changed": True}


def validate_config_regex(pattern: str, replacement: str) -> None:
    if not pattern:
        raise HTTPException(status_code=400, detail="正则表达式不能为空")
    if len(pattern) > 10000:
        raise HTTPException(status_code=400, detail="正则表达式过长")
    if len(replacement) > CONFIG_MAX_CHARS:
        raise HTTPException(status_code=400, detail="替换内容过长")


def check_config_device_ids(device_ids: List[int]) -> None:
    if not device_ids:
        raise HTTPException(status_code=400, detail="device_ids required")
    if len(device_ids) > CONFIG_BATCH_MAX:
        raise HTTPException(status_code=400, detail=f"单次批量配置不得超过 {CONFIG_BATCH_MAX} 台")
