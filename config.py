import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    ES_HOST = os.getenv("ES_HOST", "https://localhost:9200")
    ES_USERNAME = os.getenv("ES_USERNAME", "elastic")
    ES_PASSWORD = os.getenv("ES_PASSWORD", "")
    ES_VERIFY_CERTS = os.getenv("ES_VERIFY_CERTS", "false").lower() == "true"

    ZEEK_INDEX_PATTERN = os.getenv("ZEEK_INDEX_PATTERN", "*:so-zeek-*")
    SYSMON_INDEX_PATTERN = os.getenv("SYSMON_INDEX_PATTERN", "*:so-sysmon-*")

    POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "30"))

    HOST = os.getenv("HOST", "0.0.0.0")
    PORT = int(os.getenv("PORT", "8080"))
