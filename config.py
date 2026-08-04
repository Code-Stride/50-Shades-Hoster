# -*- coding: utf-8 -*-
import os
import sys
import logging
from dotenv import load_dotenv

# Load .env
load_dotenv()

# Setup logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def get_env(name, default=None, required=False, cast=str):
    value = os.getenv(name, default)

    # Treat empty string as missing/None
    if value == "":
        value = None

    if required and value is None:
        raise ValueError(f"❌ ENV ERROR: {name} is missing 💀")

    # Type casting
    try:
        if value is not None:
            return cast(value)
    except Exception:
        raise ValueError(f"❌ ENV ERROR: {name} invalid type")

    return value

# --- CONFIG ---
TOKEN = get_env("BOT_TOKEN", required=True)
OWNER_ID = get_env("OWNER_ID", required=True, cast=int)

# ADMIN fallback to OWNER
ADMIN_ID = get_env("ADMIN_ID", default=OWNER_ID, cast=int)

# Optional values
YOUR_USERNAME = get_env("YOUR_USERNAME", required=False)
UPDATE_CHANNEL = get_env("UPDATE_CHANNEL", required=False)
WEB_PANEL_URL = get_env("WEB_PANEL_URL", default="https://your-bot-domain.up.railway.app")

# Folder setup
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_BOTS_DIR = os.path.join(BASE_DIR, 'upload_bots')
IROTECH_DIR = os.path.join(BASE_DIR, 'inf')
DATABASE_PATH = os.path.join(IROTECH_DIR, 'bot_data.db')

# File upload limits
FREE_USER_LIMIT = 2
SUBSCRIBED_USER_LIMIT = 20
ADMIN_LIMIT = 999
OWNER_LIMIT = float('inf')

# Create necessary directories
os.makedirs(UPLOAD_BOTS_DIR, exist_ok=True)
os.makedirs(IROTECH_DIR, exist_ok=True)

# Security Settings
SECURITY_CONFIG = {
    'blocked_modules': ['os.system', 'os', 'zipfile', 'subprocess.Popen', 'subprocess', 'eval', 'exec','compile', '__import__'],
    'max_file_size': 20 * 1024 * 1024,  # 20MB
    'max_script_runtime': 3600,  # 1 hour
    'allowed_extensions': ['.py', '.js'],
    'blocked_imports': ['shutil.rmtree', 'subprocess','os.remove', 'os.unlink']
}

# Command Button Layouts - Rearranged & Anonymized for Public Launch (Fixes Layout & Privacy)
COMMAND_BUTTONS_LAYOUT_USER_SPEC = [
    ["📤 Upload Script"],
    ["📂 My Scripts", "⚡ Test Ping"],
    ["📢 Updates Channel", "🆘 Help Guide"]
]

ADMIN_COMMAND_BUTTONS_LAYOUT_USER_SPEC = [
    ["📤 Upload Script"],
    ["📂 My Scripts", "⚡ Test Ping"],
    ["💳 Subscriptions", "📢 Broadcast"],
    ["🔒 Lock Bot", "👑 Admin Panel"],
    ["📢 Channel Add", "👥 User Management"],
    ["🛠️ Admin Install", "⚙️ Settings"],
    ["📢 Updates Channel", "🆘 Help Guide"]
]
