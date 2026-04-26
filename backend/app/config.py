import os
import re

DBPATH      = os.environ.get("BMDB",      "/opt/board-manager/data/data.db")
STATICDIR   = os.environ.get("BMSTATIC",  "/opt/board-manager/static")
DEFAULTUSER = "admin"
DEFAULTPASS = "admin"
TIMEOUT            = float(os.environ.get("BMHTTPTIMEOUT",    "5.0"))
CONCURRENCY        = int(os.environ.get("BMSCANCONCURRENCY", "64"))
TCP_CONCURRENCY    = int(os.environ.get("BMTCPCONCURRENCY",  "128"))
TCP_TIMEOUT        = float(os.environ.get("BMTCPTIMEOUT",    "0.3"))
CIDRFALLBACKLIMIT  = int(os.environ.get("BMCIDRFALLBACKLIMIT","1024"))
SCAN_RETRIES       = int(os.environ.get("BMSCANRETRIES",     "3"))
SCAN_RETRY_SLEEP_MS= int(os.environ.get("BMSCANRETRYSLEEPMS","300"))
SCAN_TTL           = int(os.environ.get("BMSCANTTL",         str(3600)))
UIUSER             = os.environ.get("BMUIUSER",  "admin")
UIPASS             = os.environ.get("BMUIPASS",  "admin")
TOKEN_TTL_SECONDS  = int(os.environ.get("BMTOKENTTL", str(8 * 60 * 60)))
PREWARM_CONCURRENCY = int(os.environ.get("BMPREWARMCONCURRENCY", "64"))
OTA_BATCH_MAX      = int(os.environ.get("BMOTABATCHMAX",       "64"))
CONFIG_BATCH_MAX   = int(os.environ.get("BMCONFIGBATCHMAX",    str(OTA_BATCH_MAX)))
CONFIG_MAX_CHARS   = int(os.environ.get("BMCONFIGMAXCHARS",    "524288"))
TRUSTED_PROXY_HOPS = int(os.environ.get("BMTRUSTEDPROXYHOPS",  "0"))

FORWARD_METHOD_BASIC = "99"

PHONE_RE    = re.compile(r"^\+?[0-9]{5,15}$")
SMS_MAX_LEN = int(os.environ.get("BMSMSMAXLEN", "500"))
