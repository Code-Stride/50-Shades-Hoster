# -*- coding: utf-8 -*-
import os
import sys
import time
import re
import shutil
import tempfile
import zipfile
import hashlib
import sqlite3
import secrets
import logging
import threading
import subprocess
import atexit
import ast
from datetime import datetime, timedelta
import requests
import psutil
import telebot
from telebot import types
from html import escape as escape_html
from flask import Flask, request, redirect, url_for, render_template_string, session, jsonify, Response
from dotenv import load_dotenv

# Load .env
load_dotenv()

# Setup logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def get_env(name, default=None, required=False, cast=str):
    value = os.getenv(name, default)
    if value == "":
        value = None
    if required and value is None:
        raise ValueError(f"❌ ENV ERROR: {name} is missing 💀")
    try:
        if value is not None:
            return cast(value)
    except Exception:
        raise ValueError(f"❌ ENV ERROR: {name} invalid type")
    return value

# =====================================================================
# ⚙️ CENTRALIZED CONFIGURATIONS
# =====================================================================
TOKEN = get_env("BOT_TOKEN", required=True)
OWNER_ID = get_env("OWNER_ID", required=True, cast=int)
ADMIN_ID = get_env("ADMIN_ID", default=OWNER_ID, cast=int)

YOUR_USERNAME = get_env("YOUR_USERNAME", required=False)
UPDATE_CHANNEL = get_env("UPDATE_CHANNEL", required=False)
WEB_PANEL_URL = get_env("WEB_PANEL_URL", default="https://your-bot-domain.up.railway.app")

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_BOTS_DIR = os.path.join(BASE_DIR, 'upload_bots')
IROTECH_DIR = os.path.join(BASE_DIR, 'inf')
DATABASE_PATH = os.path.join(IROTECH_DIR, 'bot_data.db')

FREE_USER_LIMIT = 2
SUBSCRIBED_USER_LIMIT = 20
ADMIN_LIMIT = 999
OWNER_LIMIT = float('inf')

os.makedirs(UPLOAD_BOTS_DIR, exist_ok=True)
os.makedirs(IROTECH_DIR, exist_ok=True)

# Initialize telebot
bot = telebot.TeleBot(TOKEN)

# --- Security Settings (Harden Sanboxing) ---
SECURITY_CONFIG = {
    'blocked_modules': ['os.system', 'os', 'zipfile', 'subprocess.Popen', 'subprocess', 'eval', 'exec','compile', '__import__'],
    'max_file_size': 20 * 1024 * 1024,  # 20MB
    'max_script_runtime': 3600,  # 1 hour
    'allowed_extensions': ['.py', '.js'],
    'blocked_imports': ['shutil.rmtree', 'subprocess','os.remove', 'os.unlink']
}

# Hashed Path traversal & absolute path traversal blocklist (Fixes Sandboxing)
DANGEROUS_PATTERNS = [
    r'\bos\.system\b',
    r'\bos\.(popen|fork|exec|kill|spawn)\b',
    r'\bshutdown\b',
    r'\breboot\b',
    r'rm\s+-rf',
    r'format\s+c:',
    r'dd\s+if=',
    r'\bmkfs\b',
    r'\bfdisk\b',
    r'chmod\s+777',
    r'chmod\s+\+x',
    r'\bsys\.exit\b',
    r'\bsys\.argv\b',
    r'\bvps\b',
    r'\bkillall\b',
    r'\bpkill\b',
    r'\bhalt\b',
    r'\bpoweroff\b',
    r'\binit\s+0',
    r'\binit\s+6',
    r'\btelinit\s+0',
    r'\btelinit\s+6',
    r'\bmv\b.*/dev/null',
    r'\bcat\s+>/dev/null',
    r'>\s*/dev/null',
    r'2>\s*&1',
    r'\b&\s*$',
    r'\bnohup\b',
    r'\bdisown\b',
    r'rm\s+-rf\s+/',
    r'rm\s+-rf\s+~',
    r'rm\s+-rf\s+\.',
    r'rm\s+-rf\s+\*',
    r'rm\s+-rf\s+.*',
    r'\bdd\s+if=/dev/zero',
    r'\bdd\s+of=/dev/sda',
    r'\bmv\s+/dev/null',
    r'>\s+\.bash_history',
    r'>\s+\.zsh_history',
    r'echo\s+""\s+>',
    r'truncate\s+-s\s+0',
    r':>\s*',
    r'\bctypes\b',
    r'\bctypes\.(CDLL|WinDLL|PyDLL|cdll|windll|oledll|py_object|Structure|Union)\b',
    r'\bCDLL\b',
    r'\bWinDLL\b',
    r'\blibc\b',
    r'\bFILE_p\b',
    r'\blibc\.(system|exec|fork|kill|popen)\b',
    r'\bmemset\b',
    r'\bmemcpy\b',
    r'\bmprotect\b',
    r'\bmmap\b',
    r'\bVirtualAlloc\b',
    r'\bCreateProcess\b',
    r'\bLoadLibrary\b',
    r'\bGetProcAddress\b',
    r'\bsubprocess\b',
    r'\bsubprocess\.(Popen|call|run|check_output|getoutput|getstatusoutput)\b',
    r'\beval\s*\(',
    r'\bexec\s*\(',
    r'\bcompile\s*\(',
    r'\b__import__\b',
    r'\bshutil\.(rmtree|copytree|move|disk_usage)\b',
    r'\bcPickle\b',
    r'\bshelve\b',
    r'\bparamiko\b',
    r'\bscp\b',
    r'\bssh\b',
    r'\bsshlib\b',
    r'\bpexpect\b',
    r'\bfabric\b',
    r'/bin/sh',
    r'/bin/bash',
    r'/bin/zsh',
    r'/bin/dash',
    r'nc\s+-e',
    r'netcat',
    r'\becho\b.*\|',
    r'/etc/passwd',
    r'/etc/shadow',
    r'/etc/hosts',
    r'/etc/resolv.conf',
    r'\.ssh/',
    r'id_rsa',
    r'id_dsa',
    r'authorized_keys',
    r'known_hosts',
    r'\.bashrc',
    r'\.bash_profile',
    r'\.zshrc',
    r'\.profile',
    r'\bpynput\b',
    r'\bkeyboard\b',
    r'\bmouse\b',
    r'\bwin32api\b',
    r'\bwin32com\b',
    r'\bwin32con\b',
    r'\bwin32event\b',
    r'\bwin32file\b',
    r'\bwin32process\b',
    r'\bwin32security\b',
    r'\bwmi\b',
    r'\bregedit\b',
    r'\bGetAsyncKeyState\b',
    r'\bSetWindowsHookEx\b',
    r'\btaskkill\b',
    r'\btasklist\b',
    r'\bschtasks\b',
    r'\bsudo\b',
    r'\bsu\s+',
    r'\brunas\b',
    r'\bescalation\b',
    r'\buac\b',
    r'\bbypassuac\b',
    r'\.\.[/\\]',                         # Blocks '../' or '..\\' directory traversal
    r'\bpathlib\.Path\s*\(.*?\.\..*?\)',  # Blocks Path('..') traversal
    r'/\.\.',                             # Blocks '/..' path traversal
    r'\\\.{2}',                           # Blocks '\..' path traversal
    r'["\']/[a-zA-Z_]',                  # Blocks absolute Unix paths in string literals
    r'["\'][a-zA-Z]:[/\\]',              # Blocks absolute Windows drive paths
]

# Map of package imports to standard PyPI/npm modules
TELEGRAM_MODULES = {
    'telebot': 'pyTelegramBotAPI',
    'telegram': 'python-telegram-bot',
    'python_telegram_bot': 'python-telegram-bot',
    'aiogram': 'aiogram',
    'pyrogram': 'pyrogram',
    'telethon': 'telethon',
    'telepot': 'telepot',
    'pytg': 'pytg',
    'tgcrypto': 'tgcrypto',
    'telegram_upload': 'telegram-upload',
    'telegram_send': 'telegram-send',
    'telegram_text': 'telegram-text',
    'mtproto': 'telegram-mtproto',
}

STD_LIB_MODULES = {
    'sys', 'os', 'time', 'datetime', 'math', 're', 'json', 'subprocess',
    'threading', 'logging', 'hashlib', 'shutil', 'tempfile', 'zipfile',
    'socket', 'sqlite3', 'ast', 'select', 'signal', 'urllib', 'collections',
    'random', 'uuid', 'functools', 'itertools', 'traceback', 'io', 'base64',
    'platform', 'weakref', 'gc', 'atexit', 'ctypes', 'inspect', 'pickle', 'csv',
    'asyncio', 'abc', 'typing', 'string', 'glob', 'pathlib'
}

JS_CORE_MODULES = {
    'path', 'fs', 'crypto', 'os', 'http', 'https', 'child_process',
    'querystring', 'url', 'util', 'events', 'stream', 'readline', 'process'
}

# =====================================================================
# 💾 IN-MEMORY CACHE & DATA STATE
# =====================================================================
bot_scripts = {}
user_subscriptions = {}
user_files = {}
active_users = set()
admin_ids = {ADMIN_ID, OWNER_ID}
banned_users = set()
user_limits = {}
bot_locked = False

# Persistent configurations
free_mode = False
script_auto_restart = {}  # {f"{user_id}_{file_name}": True/False}
mandatory_channels = {}  # {channel_id: {'username': 'channel_username', 'name': 'Channel Name'}}

pending_modules = {}
manual_install_requests = {}
pending_zip_files = {}

# =====================================================================
# 🔌 DATABASE IMPLEMENTATION (ROBUST POSTGRESQL + SQLITE AS PRIMARY ENGINE)
# =====================================================================
DB_LOCK = threading.Lock()
DATABASE_URL = os.getenv("DATABASE_URL")

if DATABASE_URL:
    try:
        import psycopg2
        logger.info("🔌 Detected DATABASE_URL in environment. Using PostgreSQL!")
    except ImportError:
        logger.error("❌ psycopg2-binary not installed. Falling back to SQLite.")
        DATABASE_URL = None

def get_conn():
    if DATABASE_URL:
        import psycopg2
        attempts = 3
        for attempt in range(attempts):
            try:
                conn = psycopg2.connect(DATABASE_URL)
                return conn
            except Exception as e:
                logger.error(f"Database connection attempt {attempt+1} failed: {e}")
                if attempt < attempts - 1:
                    time.sleep(1.5 * (attempt + 1))
                else:
                    raise e
    else:
        return sqlite3.connect(DATABASE_PATH, check_same_thread=False)

def translate_query(query):
    if not DATABASE_URL:
        return query
    query = query.replace('?', '%s')
    if 'CREATE TABLE IF NOT EXISTS' in query:
        query = query.replace('INTEGER PRIMARY KEY AUTOINCREMENT', 'SERIAL PRIMARY KEY')
        
    if 'INSERT OR REPLACE INTO banned_users' in query:
        return "INSERT INTO banned_users (user_id, reason, banned_by, ban_date) VALUES (%s, %s, %s, %s) ON CONFLICT (user_id) DO UPDATE SET reason = EXCLUDED.reason, banned_by = EXCLUDED.banned_by, ban_date = EXCLUDED.ban_date"
    if 'INSERT OR REPLACE INTO user_limits' in query:
        return "INSERT INTO user_limits (user_id, file_limit, set_by, set_date) VALUES (%s, %s, %s, %s) ON CONFLICT (user_id) DO UPDATE SET file_limit = EXCLUDED.file_limit, set_by = EXCLUDED.set_by, set_date = EXCLUDED.set_date"
    if 'INSERT OR REPLACE INTO user_files' in query:
        return "INSERT INTO user_files (user_id, file_name, file_type) VALUES (%s, %s, %s) ON CONFLICT (user_id, file_name) DO UPDATE SET file_type = EXCLUDED.file_type"
    if 'INSERT OR REPLACE INTO active_users' in query:
        return "INSERT INTO active_users (user_id, join_date, last_seen) VALUES (%s, %s, %s) ON CONFLICT (user_id) DO UPDATE SET last_seen = EXCLUDED.last_seen"
    if 'INSERT OR REPLACE INTO subscriptions' in query:
        return "INSERT INTO subscriptions (user_id, expiry) VALUES (%s, %s) ON CONFLICT (user_id) DO UPDATE SET expiry = EXCLUDED.expiry"
    if 'INSERT OR REPLACE INTO mandatory_channels' in query:
        return "INSERT INTO mandatory_channels (channel_id, channel_username, channel_name, added_by, added_date) VALUES (%s, %s, %s, %s, %s) ON CONFLICT (channel_id) DO UPDATE SET channel_username = EXCLUDED.channel_username, channel_name = EXCLUDED.channel_name, added_by = EXCLUDED.added_by, added_date = EXCLUDED.added_date"
    if 'INSERT OR REPLACE INTO bot_settings' in query:
        return "INSERT INTO bot_settings (key, value) VALUES (%s, %s) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"
    if 'INSERT OR REPLACE INTO script_settings' in query:
        return "INSERT INTO script_settings (user_id, file_name, auto_restart) VALUES (%s, %s, %s) ON CONFLICT (user_id, file_name) DO UPDATE SET auto_restart = EXCLUDED.auto_restart"
    if 'INSERT OR IGNORE INTO admins' in query:
        return "INSERT INTO admins (user_id, added_by, added_date) VALUES (%s, %s, %s) ON CONFLICT (user_id) DO NOTHING"
    if 'INSERT OR IGNORE INTO license_keys' in query:
        return "INSERT INTO license_keys (key, days, created_by, created_date) VALUES (%s, %s, %s, %s) ON CONFLICT (key) DO NOTHING"
    
    return query

def init_db():
    logger.info("Initializing database...")
    with DB_LOCK:
        try:
            conn = get_conn()
            c = conn.cursor()
            q_uid_type = "BIGINT" if DATABASE_URL else "INTEGER"
            
            c.execute(f"CREATE TABLE IF NOT EXISTS subscriptions (user_id {q_uid_type} PRIMARY KEY, expiry TEXT)")
            c.execute(f"CREATE TABLE IF NOT EXISTS user_files (user_id {q_uid_type}, file_name TEXT, file_type TEXT, PRIMARY KEY (user_id, file_name))")
            c.execute(f"CREATE TABLE IF NOT EXISTS active_users (user_id {q_uid_type} PRIMARY KEY, join_date TEXT, last_seen TEXT)")
            c.execute(f"CREATE TABLE IF NOT EXISTS admins (user_id {q_uid_type} PRIMARY KEY, added_by {q_uid_type}, added_date TEXT)")
            c.execute(f"CREATE TABLE IF NOT EXISTS banned_users (user_id {q_uid_type} PRIMARY KEY, reason TEXT, banned_by {q_uid_type}, ban_date TEXT)")
            c.execute(f"CREATE TABLE IF NOT EXISTS user_limits (user_id {q_uid_type} PRIMARY KEY, file_limit INTEGER, set_by {q_uid_type}, set_date TEXT)")
            c.execute("CREATE TABLE IF NOT EXISTS bot_settings (key TEXT PRIMARY KEY, value TEXT)")
            c.execute(f"CREATE TABLE IF NOT EXISTS script_settings (user_id {q_uid_type}, file_name TEXT, auto_restart INTEGER, PRIMARY KEY (user_id, file_name))")
            c.execute(f"CREATE TABLE IF NOT EXISTS license_keys (key TEXT PRIMARY KEY, days INTEGER, created_by {q_uid_type}, created_date TEXT, redeemed_by {q_uid_type}, redeemed_date TEXT)")
            c.execute(f"CREATE TABLE IF NOT EXISTS mandatory_channels (channel_id TEXT PRIMARY KEY, channel_username TEXT, channel_name TEXT, added_by {q_uid_type}, added_date TEXT)")
            c.execute(translate_query(f"CREATE TABLE IF NOT EXISTS install_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id {q_uid_type}, module_name TEXT, package_name TEXT, status TEXT, log TEXT, install_date TEXT)"))
            
            # Seed default admin
            seed_q = translate_query('INSERT OR IGNORE INTO admins (user_id, added_by, added_date) VALUES (?, ?, ?)')
            c.execute(seed_q, (OWNER_ID, OWNER_ID, datetime.now().isoformat()))
            if ADMIN_ID != OWNER_ID:
                c.execute(seed_q, (ADMIN_ID, OWNER_ID, datetime.now().isoformat()))
                
            conn.commit()
            conn.close()
            logger.info("Database schema initialized successfully.")
        except Exception as e:
            logger.critical(f"❌ Database schema initialization error: {e}", exc_info=True)

def load_data():
    logger.info("Loading persistent database cache into memory...")
    try:
        conn = get_conn()
        c = conn.cursor()

        c.execute(translate_query('SELECT user_id, expiry FROM subscriptions'))
        for user_id, expiry in c.fetchall():
            try: user_subscriptions[user_id] = {'expiry': datetime.fromisoformat(expiry)}
            except ValueError: pass

        c.execute(translate_query('SELECT user_id, file_name, file_type FROM user_files'))
        for user_id, file_name, file_type in c.fetchall():
            if user_id not in user_files: user_files[user_id] = []
            user_files[user_id].append((file_name, file_type))

        c.execute(translate_query('SELECT user_id FROM active_users'))
        active_users.update(user_id for (user_id,) in c.fetchall())

        c.execute(translate_query('SELECT user_id FROM admins'))
        admin_ids.update(user_id for (user_id,) in c.fetchall())

        c.execute(translate_query('SELECT user_id FROM banned_users'))
        banned_users.update(user_id for (user_id,) in c.fetchall())

        c.execute(translate_query('SELECT user_id, file_limit FROM user_limits'))
        for user_id, file_limit in c.fetchall():
            user_limits[user_id] = file_limit

        c.execute(translate_query('SELECT channel_id, channel_username, channel_name FROM mandatory_channels'))
        for channel_id, channel_username, channel_name in c.fetchall():
            mandatory_channels[channel_id] = {'username': channel_username, 'name': channel_name}

        # Persistent setting (free_mode)
        c.execute(translate_query("SELECT value FROM bot_settings WHERE key = 'free_mode'"))
        row = c.fetchone()
        if row:
            global free_mode
            free_mode = row[0].lower() == 'true'
            logger.info(f"Loaded persistent free_mode state: {free_mode}")

        # Persistent auto_restart script mappings
        c.execute(translate_query("SELECT user_id, file_name, auto_restart FROM script_settings"))
        for user_id, file_name, auto_restart in c.fetchall():
            script_auto_restart[f"{user_id}_{file_name}"] = auto_restart == 1

        conn.close()
        logger.info("Data state loading completed successfully.")
    except Exception as e:
        logger.error(f"❌ Error loading persistent cache: {e}", exc_info=True)

# --- Database Writers ---
def ban_user_db(user_id, reason, banned_by):
    with DB_LOCK:
        conn = get_conn()
        c = conn.cursor()
        try:
            ban_date = datetime.now().isoformat()
            c.execute(translate_query('INSERT OR REPLACE INTO banned_users (user_id, reason, banned_by, ban_date) VALUES (?, ?, ?, ?)'), (user_id, reason, banned_by, ban_date))
            conn.commit()
            banned_users.add(user_id)
            return True
        except Exception as e: logger.error(f"Error banning: {e}"); return False
        finally: conn.close()

def unban_user_db(user_id):
    with DB_LOCK:
        conn = get_conn()
        c = conn.cursor()
        try:
            c.execute(translate_query('DELETE FROM banned_users WHERE user_id = ?'), (user_id,))
            conn.commit()
            banned_users.discard(user_id)
            return True
        except Exception as e: logger.error(f"Error unbanning: {e}"); return False
        finally: conn.close()

def set_user_limit_db(user_id, limit, set_by):
    with DB_LOCK:
        conn = get_conn()
        c = conn.cursor()
        try:
            set_date = datetime.now().isoformat()
            c.execute(translate_query('INSERT OR REPLACE INTO user_limits (user_id, file_limit, set_by, set_date) VALUES (?, ?, ?, ?)'), (user_id, limit, set_by, set_date))
            conn.commit()
            user_limits[user_id] = limit
            return True
        except Exception as e: logger.error(f"Error limiting: {e}"); return False
        finally: conn.close()

def remove_user_limit_db(user_id):
    with DB_LOCK:
        conn = get_conn()
        c = conn.cursor()
        try:
            c.execute(translate_query('DELETE FROM user_limits WHERE user_id = ?'), (user_id,))
            conn.commit()
            if user_id in user_limits: del user_limits[user_id]
            return True
        except Exception as e: logger.error(f"Error removing limit: {e}"); return False
        finally: conn.close()

def save_user_file(user_id, file_name, file_type='py'):
    with DB_LOCK:
        conn = get_conn()
        c = conn.cursor()
        try:
            c.execute(translate_query('INSERT OR REPLACE INTO user_files (user_id, file_name, file_type) VALUES (?, ?, ?)'), (user_id, file_name, file_type))
            conn.commit()
            if user_id not in user_files: user_files[user_id] = []
            user_files[user_id] = [(fn, ft) for fn, ft in user_files[user_id] if fn != file_name]
            user_files[user_id].append((file_name, file_type))
        except Exception as e: logger.error(f"Error saving user file: {e}")
        finally: conn.close()

def remove_user_file_db(user_id, file_name):
    with DB_LOCK:
        conn = get_conn()
        c = conn.cursor()
        try:
            c.execute(translate_query('DELETE FROM user_files WHERE user_id = ? AND file_name = ?'), (user_id, file_name))
            c.execute(translate_query('DELETE FROM script_settings WHERE user_id = ? AND file_name = ?'), (user_id, file_name))
            conn.commit()
            if user_id in user_files:
                user_files[user_id] = [f for f in user_files[user_id] if f[0] != file_name]
                if not user_files[user_id]: del user_files[user_id]
            if f"{user_id}_{file_name}" in script_auto_restart:
                del script_auto_restart[f"{user_id}_{file_name}"]
        except Exception as e: logger.error(f"Error removing user file: {e}")
        finally: conn.close()

def add_active_user(user_id):
    active_users.add(user_id)
    with DB_LOCK:
        conn = get_conn()
        c = conn.cursor()
        try:
            join_date = datetime.now().isoformat()
            c.execute(translate_query('INSERT OR REPLACE INTO active_users (user_id, join_date, last_seen) VALUES (?, ?, ?)'), (user_id, join_date, join_date))
            conn.commit()
        except Exception as e: logger.error(f"Error updating user: {e}")
        finally: conn.close()

def save_subscription(user_id, expiry):
    with DB_LOCK:
        conn = get_conn()
        c = conn.cursor()
        try:
            expiry_str = expiry.isoformat()
            c.execute(translate_query('INSERT OR REPLACE INTO subscriptions (user_id, expiry) VALUES (?, ?)'), (user_id, expiry_str))
            conn.commit()
            user_subscriptions[user_id] = {'expiry': expiry}
        except Exception as e: logger.error(f"Error saving subscription: {e}")
        finally: conn.close()

def remove_subscription_db(user_id):
    with DB_LOCK:
        conn = get_conn()
        c = conn.cursor()
        try:
            c.execute(translate_query('DELETE FROM subscriptions WHERE user_id = ?'), (user_id,))
            conn.commit()
            if user_id in user_subscriptions: del user_subscriptions[user_id]
        except Exception as e: logger.error(f"Error removing subscription: {e}")
        finally: conn.close()

def add_admin_db(admin_id, added_by):
    with DB_LOCK:
        conn = get_conn()
        c = conn.cursor()
        try:
            added_date = datetime.now().isoformat()
            c.execute(translate_query('INSERT OR IGNORE INTO admins (user_id, added_by, added_date) VALUES (?, ?, ?)'), (admin_id, added_by, added_date))
            conn.commit()
            admin_ids.add(admin_id)
        except Exception as e: logger.error(f"Error adding admin: {e}")
        finally: conn.close()

def remove_admin_db(admin_id):
    if admin_id == OWNER_ID: return False
    with DB_LOCK:
        conn = get_conn()
        c = conn.cursor()
        removed = False
        try:
            c.execute(translate_query('SELECT 1 FROM admins WHERE user_id = ?'), (admin_id,))
            if c.fetchone():
                c.execute(translate_query('DELETE FROM admins WHERE user_id = ?'), (admin_id,))
                conn.commit()
                removed = True
                admin_ids.discard(admin_id)
            return removed
        except Exception as e: logger.error(f"Error removing admin: {e}"); return False
        finally: conn.close()

def save_mandatory_channel(channel_id, channel_username, channel_name, added_by):
    with DB_LOCK:
        conn = get_conn()
        c = conn.cursor()
        try:
            added_date = datetime.now().isoformat()
            c.execute(translate_query('INSERT OR REPLACE INTO mandatory_channels (channel_id, channel_username, channel_name, added_by, added_date) VALUES (?, ?, ?, ?, ?)'), (channel_id, channel_username, channel_name, added_by, added_date))
            conn.commit()
            mandatory_channels[channel_id] = {'username': channel_username, 'name': channel_name}
            return True
        except Exception as e: logger.error(f"Error saving channel: {e}"); return False
        finally: conn.close()

def remove_mandatory_channel_db(channel_id):
    with DB_LOCK:
        conn = get_conn()
        c = conn.cursor()
        try:
            c.execute(translate_query('DELETE FROM mandatory_channels WHERE channel_id = ?'), (channel_id,))
            conn.commit()
            if channel_id in mandatory_channels: del mandatory_channels[channel_id]
            return True
        except Exception as e: logger.error(f"Error removing channel: {e}"); return False
        finally: conn.close()

def save_install_log(user_id, module_name, package_name, status, log):
    with DB_LOCK:
        conn = get_conn()
        c = conn.cursor()
        try:
            install_date = datetime.now().isoformat()
            c.execute(translate_query('INSERT INTO install_logs (user_id, module_name, package_name, status, log, install_date) VALUES (?, ?, ?, ?, ?, ?)'), (user_id, module_name, package_name, status, log, install_date))
            conn.commit()
        except Exception as e: logger.error(f"Error saving install log: {e}")
        finally: conn.close()

def get_recent_install_logs(limit=20):
    with DB_LOCK:
        conn = get_conn()
        c = conn.cursor()
        try:
            query = translate_query('SELECT user_id, module_name, package_name, status, install_date FROM install_logs ORDER BY install_date DESC LIMIT ?')
            c.execute(query, (limit,))
            return c.fetchall()
        except Exception as e: logger.error(f"Error querying install logs: {e}"); return []
        finally: conn.close()

def save_bot_setting(key, value):
    with DB_LOCK:
        conn = get_conn()
        c = conn.cursor()
        try:
            c.execute(translate_query('INSERT OR REPLACE INTO bot_settings (key, value) VALUES (?, ?)'), (key, str(value)))
            conn.commit()
            return True
        except Exception as e: logger.error(f"Error saving persistent config: {e}"); return False
        finally: conn.close()

def save_script_auto_restart(user_id, file_name, enabled):
    with DB_LOCK:
        conn = get_conn()
        c = conn.cursor()
        try:
            val = 1 if enabled else 0
            c.execute(translate_query('INSERT OR REPLACE INTO script_settings (user_id, file_name, auto_restart) VALUES (?, ?, ?)'), (user_id, file_name, val))
            conn.commit()
            script_auto_restart[f"{user_id}_{file_name}"] = enabled
            return True
        except Exception as e: logger.error(f"Error saving auto-restart settings: {e}"); return False
        finally: conn.close()

def generate_license_key_db(key, days, created_by):
    with DB_LOCK:
        conn = get_conn()
        c = conn.cursor()
        try:
            created_date = datetime.now().isoformat()
            c.execute(translate_query('INSERT OR IGNORE INTO license_keys (key, days, created_by, created_date) VALUES (?, ?, ?, ?)'), (key, days, created_by, created_date))
            conn.commit()
            return True
        except Exception as e: logger.error(f"Error saving license key: {e}"); return False
        finally: conn.close()

def check_and_redeem_license_key_db(key, redeemed_by):
    with DB_LOCK:
        conn = get_conn()
        c = conn.cursor()
        try:
            c.execute(translate_query('SELECT days, redeemed_by FROM license_keys WHERE key = ?'), (key,))
            row = c.fetchone()
            if not row: return False, "❌ Invalid License Key! Double-check formatting."
            days, already_redeemed_by = row
            if already_redeemed_by: return False, "⚠️ This license key has already been redeemed!"
            
            redeemed_date = datetime.now().isoformat()
            c.execute(translate_query('UPDATE license_keys SET redeemed_by = ?, redeemed_date = ? WHERE key = ?'), (redeemed_by, redeemed_date, key))
            conn.commit()
            
            current_sub = user_subscriptions.get(redeemed_by)
            now = datetime.now()
            if current_sub and current_sub.get('expiry') > now:
                new_expiry = current_sub['expiry'] + timedelta(days=days)
            else:
                new_expiry = now + timedelta(days=days)
            
            c.execute(translate_query('INSERT OR REPLACE INTO subscriptions (user_id, expiry) VALUES (?, ?)'), (redeemed_by, new_expiry.isoformat()))
            conn.commit()
            
            user_subscriptions[redeemed_by] = {'expiry': new_expiry}
            return True, f"🎉 **Success**! Plan extended by **{days} days**! Expiry: {new_expiry.strftime('%Y-%m-%d %H:%M')}"
        except Exception as e:
            logger.error(f"Error redeeming license: {e}", exc_info=True)
            return False, f"❌ Error processing key redemption: {e}"
        finally: conn.close()

# =====================================================================
# 🛠️ HELPER UTILITIES & PARSERS
# =====================================================================
def get_user_folder(user_id):
    """Get or create user's folder for storing files with complete hashed isolation & anonymity"""
    user_hash = hashlib.sha256(str(user_id).encode('utf-8')).hexdigest()[:16]
    user_folder = os.path.join(UPLOAD_BOTS_DIR, user_hash)
    os.makedirs(user_folder, exist_ok=True)
    return user_folder

def get_user_file_limit(user_id):
    if free_mode: return OWNER_LIMIT
    if user_id == OWNER_ID: return OWNER_LIMIT
    if user_id in admin_ids: return ADMIN_LIMIT
    if user_id in user_subscriptions:
        expiry = user_subscriptions[user_id].get('expiry')
        if expiry and expiry > datetime.now():
            return SUBSCRIBED_USER_LIMIT
    return FREE_USER_LIMIT

def get_user_file_count(user_id):
    return len(user_files.get(user_id, []))

def is_user_member(user_id, channel_id):
    try:
        chat_member = bot.get_chat_member(channel_id, user_id)
        return chat_member.status in ['member', 'administrator', 'creator']
    except telebot.apihelper.ApiTelegramException as e:
        err_desc = str(e).lower()
        if "bot is not a member" in err_desc or "chat not found" in err_desc or "admin" in err_desc:
            logger.error(f"❌ Mandatory Channel Configuration Error: Bot has no admin access in {channel_id}: {e}")
            return True # Safety bypass (Fixes Lockout)
        return False
    except Exception: return False

def check_mandatory_subscription(user_id):
    if free_mode: return True, []
    if not mandatory_channels: return True, []
    not_joined = []
    for cid, info in mandatory_channels.items():
        if not is_user_member(user_id, cid):
            not_joined.append((cid, info))
    if not_joined: return False, not_joined
    return True, []

def create_subscription_check_message(not_joined_channels):
    message = "📢 **Important: Join Our Channels First:**\n\n"
    markup = types.InlineKeyboardMarkup()
    for cid, info in not_joined_channels:
        username = info.get('username', '')
        name = info.get('name', 'Channel')
        link = f"https://t.me/{username.replace('@', '')}" if username else f"https://t.me/c/{cid.replace('-100', '')}"
        message += f"• {name}\n"
        markup.add(btn(f"Join {name}", url=link, style='primary'))
    markup.add(btn("✅ Verify Subscription", callback_data='check_subscription_status', style='success'))
    return message, markup

def is_user_banned(user_id):
    return user_id in banned_users

def make_progress_bar(percent):
    filled = int(percent / 10)
    bar = "█" * filled + "░" * (10 - filled)
    return f"`[{bar}] {percent}%`"

# --- Styled UI Builders (Bot API 9.4) ---
def btn(text, callback_data=None, url=None, style=None):
    button = types.InlineKeyboardButton(text, callback_data=callback_data, url=url)
    if style: button.style = style
    return button

def kb_btn(text, style=None):
    button = types.KeyboardButton(text)
    if style: button.style = style
    return button

def cancel_markup():
    markup = types.InlineKeyboardMarkup()
    markup.add(btn("🔙 Cancel & Back", callback_data="cancel_next_step", style="danger"))
    return markup

# --- Static Script Scanners & Dependency Evaluators (Feature 1 Auto-Install) ---
def extract_imports(file_path):
    imports = set()
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            tree = ast.parse(f.read(), filename=file_path)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names: imports.add(alias.name.split('.')[0])
            elif isinstance(node, ast.ImportFrom):
                if node.level == 0 and node.module: imports.add(node.module.split('.')[0])
    except Exception as e: logger.error(f"Error statically parsing Python imports: {e}")
    return imports

def extract_js_imports(file_path):
    imports = set()
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            code = f.read()
        req_matches = re.findall(r"require\s*\(\s*['\x22](.+?)['\x22]\s*\)", code)
        for m in req_matches:
            if not m.startswith('.') and not m.startswith('/'): imports.add(m.split('/')[0])
        imp_matches = re.findall(r"from\s*['\x22](.+?)['\x22]", code)
        for m in imp_matches:
            if not m.startswith('.') and not m.startswith('/'): imports.add(m.split('/')[0])
    except Exception as e: logger.error(f"Error statically parsing JS imports: {e}")
    return imports

# --- Security Analyzers ---
def check_code_security(file_path, file_type):
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        found = []
        for pat in DANGEROUS_PATTERNS:
            if re.search(pat, content, re.IGNORECASE): found.append(pat)
        if found:
            logger.warning(f"🚨 Dangerous patterns matched in {file_path}: {found}")
            return False, f"Code failed security constraints: {', '.join(found[:4])}"
        return True, "Safe"
    except Exception as e: return False, f"Error scanning: {e}"

def scan_zip_security(zip_path):
    try:
        with zipfile.ZipFile(zip_path, 'r') as ref:
            for info in ref.infolist():
                if info.filename.endswith(('.py', '.js', '.zip', '.txt', '.sh', '.bat', '.cmd')):
                    with ref.open(info.filename) as f:
                        try: content = f.read().decode('utf-8', errors='ignore')
                        except: continue
                        found = []
                        for pat in DANGEROUS_PATTERNS:
                            if re.search(pat, content, re.IGNORECASE): found.append(pat)
                        if found:
                            return False, f"File '{info.filename}' failed security check: {found[0]}"
        return True, "Safe"
    except Exception as e: return False, f"Error scanning archive: {e}"

# =====================================================================
# 📦 PROCESS MANAGEMENT ENGINE & SYSTEM SUBPROCESSES
# =====================================================================
def is_bot_running(script_owner_id, file_name):
    script_key = f"{script_owner_id}_{file_name}"
    info = bot_scripts.get(script_key)
    if info and info.get('process'):
        try:
            proc = psutil.Process(info['process'].pid)
            running = proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE
            if not running:
                if 'log_file' in info and not info['log_file'].closed: info['log_file'].close()
                if script_key in bot_scripts: del bot_scripts[script_key]
            return running
        except psutil.NoSuchProcess:
            if 'log_file' in info and not info['log_file'].closed: info['log_file'].close()
            if script_key in bot_scripts: del bot_scripts[script_key]
            return False
    return False

def kill_process_tree(info):
    pid = None
    script_key = info.get('script_key', 'N/A')
    try:
        if 'log_file' in info and not info['log_file'].closed:
            try: info['log_file'].close()
            except: pass
        process = info.get('process')
        if process and hasattr(process, 'pid'):
            pid = process.pid
            if pid:
                try:
                    parent = psutil.Process(pid)
                    children = parent.children(recursive=True)
                    for child in children:
                        try: child.terminate()
                        except: pass
                    psutil.wait_procs(children, timeout=1)
                    try: parent.terminate(); parent.wait(timeout=1)
                    except psutil.TimeoutExpired: parent.kill()
                except psutil.NoSuchProcess: pass
    except Exception as e: logger.error(f"Error killing process {pid}: {e}")

def attempt_install_pip(module_name, chat_id, manual_request=False):
    package_name = TELEGRAM_MODULES.get(module_name.lower(), module_name)
    if package_name is None: return False, "Core"
    try:
        if manual_request:
            bot.send_message(chat_id, f"🔄 Manual installation requested for `<code>{package_name}</code>`...", parse_mode='HTML')
        else:
            bot.send_message(chat_id, f"🐍 Module <code>{module_name}</code> not found. Auto-installing <code>{package_name}</code>...", parse_mode='HTML')
        
        cmd = [sys.executable, '-m', 'pip', 'install', package_name]
        res = subprocess.run(cmd, capture_output=True, text=True, check=False, encoding='utf-8', errors='ignore')
        if res.returncode == 0:
            bot.send_message(chat_id, f"✅ Package <code>{package_name}</code> successfully installed!", parse_mode='HTML')
            save_install_log(chat_id, module_name, package_name, "success", res.stdout)
            return True, res.stdout
        else:
            escaped_log = escape_html(res.stderr or res.stdout)
            if len(escaped_log) > 3000: escaped_log = escaped_log[:3000] + "\n... (Truncated)"
            bot.send_message(chat_id, f"❌ <b>Failed to install</b> <code>{package_name}</code>.\\n<b>Log</b>:\\n<pre>{escaped_log}</pre>", parse_mode='HTML')
            save_install_log(chat_id, module_name, package_name, "failed", res.stderr or res.stdout)
            return False, res.stderr
    except Exception as e:
        bot.send_message(chat_id, f"❌ Error installing package: {e}")
        return False, str(e)

def attempt_install_npm(module_name, user_folder, chat_id, manual_request=False):
    try:
        if manual_request:
            bot.send_message(chat_id, f"🔄 Manual Node install requested for <code>{module_name}</code>...", parse_mode='HTML')
        else:
            bot.send_message(chat_id, f"🟠 Node module <code>{module_name}</code> not found. Auto-installing locally...", parse_mode='HTML')
        
        cmd = ['npm', 'install', module_name]
        res = subprocess.run(cmd, capture_output=True, text=True, check=False, cwd=user_folder, encoding='utf-8', errors='ignore')
        if res.returncode == 0:
            bot.send_message(chat_id, f"✅ Node module <code>{module_name}</code> successfully installed!", parse_mode='HTML')
            save_install_log(chat_id, module_name, module_name, "success", res.stdout)
            return True, res.stdout
        else:
            escaped_log = escape_html(res.stderr or res.stdout)
            if len(escaped_log) > 3000: escaped_log = escaped_log[:3000] + "\n... (Truncated)"
            bot.send_message(chat_id, f"❌ <b>Failed to install Node package</b> <code>{module_name}</code>.\\n<b>Log</b>:\\n<pre>{escaped_log}</pre>", parse_mode='HTML')
            save_install_log(chat_id, module_name, module_name, "failed", res.stderr or res.stdout)
            return False, res.stderr
    except FileNotFoundError:
        bot.send_message(chat_id, "❌ Error: 'npm' bin not found inside system environment.")
        return False, "NPM not found"
    except Exception as e:
        bot.send_message(chat_id, f"❌ Error installing Node module: {e}")
        return False, str(e)

def run_script(script_path, script_owner_id, user_folder, file_name, target_chat_id, attempt=1):
    max_attempts = 2
    if attempt > max_attempts:
        bot.send_message(script_owner_id, f"❌ Failed to start script '{file_name}' after {max_attempts} attempts.")
        return
        
    script_key = f"{script_owner_id}_{file_name}"
    try:
        if not os.path.exists(script_path):
            bot.send_message(script_owner_id, f"❌ Script '{file_name}' missing from directory!")
            remove_user_file_db(script_owner_id, file_name)
            return
            
        # Static dependencies scanning (Feature 1 Auto-Install)
        try:
            logger.info(f"Statically scanning {file_name} for Python dependencies...")
            detected_deps = extract_imports(script_path)
            non_core_deps = [d for d in detected_deps if d not in STD_LIB_MODULES]
            for dep in non_core_deps:
                attempt_install_pip(dep, target_chat_id)
        except Exception as scan_e:
            logger.error(f"Error statically auto-installing Python deps: {scan_e}")

        # Execute
        log_file_path = os.path.join(user_folder, f"{os.path.splitext(file_name)[0]}.log")
        log_file = open(log_file_path, 'w', encoding='utf-8', errors='ignore')
        startupinfo = None; creationflags = 0
        if os.name == 'nt':
            startupinfo = subprocess.STARTUPINFO(); startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
            
        process = subprocess.Popen(
            [sys.executable, script_path], cwd=user_folder, stdout=log_file, stderr=log_file,
            stdin=subprocess.PIPE, startupinfo=startupinfo, creationflags=creationflags,
            encoding='utf-8', errors='ignore'
        )
        logger.info(f"Started Python process {process.pid} for {script_key}")
        bot_scripts[script_key] = {
            'process': process, 'log_file': log_file, 'file_name': file_name,
            'chat_id': target_chat_id, 'script_owner_id': script_owner_id,
            'start_time': datetime.now(), 'user_folder': user_folder, 'type': 'py', 'script_key': script_key
        }
        bot.send_message(target_chat_id, f"✅ Python script '{file_name}' started! (PID: {process.pid})")
    except Exception as e:
        bot.send_message(target_chat_id, f"❌ Unexpected error starting Python script '{file_name}': {e}")
        if script_key in bot_scripts: del bot_scripts[script_key]

def run_js_script(script_path, script_owner_id, user_folder, file_name, target_chat_id, attempt=1):
    max_attempts = 2
    if attempt > max_attempts:
        bot.send_message(script_owner_id, f"❌ Failed to start JS script '{file_name}' after {max_attempts} attempts.")
        return
        
    script_key = f"{script_owner_id}_{file_name}"
    try:
        if not os.path.exists(script_path):
            bot.send_message(script_owner_id, f"❌ JS Script '{file_name}' missing from directory!")
            remove_user_file_db(script_owner_id, file_name)
            return
            
        # Static dependencies scanning (Feature 1 Auto-Install)
        try:
            logger.info(f"Statically scanning {file_name} for Node.js dependencies...")
            detected_deps = extract_js_imports(script_path)
            non_core_deps = [d for d in detected_deps if d not in JS_CORE_MODULES]
            for dep in non_core_deps:
                attempt_install_npm(dep, user_folder, target_chat_id)
        except Exception as scan_e:
            logger.error(f"Error statically auto-installing JS deps: {scan_e}")

        # Execute
        log_file_path = os.path.join(user_folder, f"{os.path.splitext(file_name)[0]}.log")
        log_file = open(log_file_path, 'w', encoding='utf-8', errors='ignore')
        startupinfo = None; creationflags = 0
        if os.name == 'nt':
            startupinfo = subprocess.STARTUPINFO(); startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
            
        process = subprocess.Popen(
            ['node', script_path], cwd=user_folder, stdout=log_file, stderr=log_file,
            stdin=subprocess.PIPE, startupinfo=startupinfo, creationflags=creationflags,
            encoding='utf-8', errors='ignore'
        )
        logger.info(f"Started JS process {process.pid} for {script_key}")
        bot_scripts[script_key] = {
            'process': process, 'log_file': log_file, 'file_name': file_name,
            'chat_id': target_chat_id, 'script_owner_id': script_owner_id,
            'start_time': datetime.now(), 'user_folder': user_folder, 'type': 'js', 'script_key': script_key
        }
        bot.send_message(target_chat_id, f"✅ JS script '{file_name}' started! (PID: {process.pid})")
    except Exception as e:
        bot.send_message(target_chat_id, f"❌ Unexpected error starting JS script '{file_name}': {e}")
        if script_key in bot_scripts: del bot_scripts[script_key]

def process_zip_file(zip_path, user_id, user_folder, file_name_zip, reply_message_obj, temp_dir=None):
    cleanup_temp = False
    if temp_dir is None:
        temp_dir = tempfile.mkdtemp(prefix=f"user_{user_id}_zip_")
        cleanup_temp = True
    try:
        with zipfile.ZipFile(zip_path, 'r') as ref:
            for member in ref.infolist():
                m_path = os.path.abspath(os.path.join(temp_dir, member.filename))
                if not m_path.startswith(os.path.abspath(temp_dir)):
                    raise zipfile.BadZipFile(f"Zip has unsafe path: {member.filename}")
            ref.extractall(temp_dir)
            
        extracted = os.listdir(temp_dir)
        py_files = [f for f in extracted if f.endswith('.py')]
        js_files = [f for f in extracted if f.endswith('.js')]
        req_file = 'requirements.txt' if 'requirements.txt' in extracted else None
        pkg_json = 'package.json' if 'package.json' in extracted else None
        
        chat_id = user_id
        if req_file:
            req_path = os.path.join(temp_dir, req_file)
            bot.send_message(chat_id, f"🔄 Installing Python deps from `{req_file}`...")
            try:
                subprocess.run([sys.executable, '-m', 'pip', 'install', '-r', req_path], check=True, capture_output=True)
                bot.send_message(chat_id, f"✅ Python deps from `{req_file}` successfully installed!")
            except subprocess.CalledProcessError as e:
                escaped_log = escape_html(e.stderr or e.stdout)
                if len(escaped_log) > 3000: escaped_log = escaped_log[:3000] + "\n... (Truncated)"
                bot.send_message(chat_id, f"❌ <b>Failed to install Python deps from</b> <code>{req_file}</code>.\\n<b>Log</b>:\\n<pre>{escaped_log}</pre>", parse_mode='HTML')
                return
                
        if pkg_json:
            bot.send_message(chat_id, f"🔄 Installing Node deps from `{pkg_json}`...")
            try:
                subprocess.run(['npm', 'install'], check=True, cwd=temp_dir, capture_output=True)
                bot.send_message(chat_id, f"✅ Node deps from `{pkg_json}` successfully installed!")
            except FileNotFoundError:
                bot.send_message(chat_id, "❌ 'npm' bin not found. Cannot install Node deps.")
                return
            except subprocess.CalledProcessError as e:
                escaped_log = escape_html(e.stderr or e.stdout)
                if len(escaped_log) > 3000: escaped_log = escaped_log[:3000] + "\n... (Truncated)"
                bot.send_message(chat_id, f"❌ <b>Failed to install Node deps from</b> <code>{pkg_json}</code>.\\n<b>Log</b>:\\n<pre>{escaped_log}</pre>", parse_mode='HTML')
                return

        main_script_name = None; file_type = None
        preferred_py = ['main.py', 'bot.py', 'app.py']
        preferred_js = ['index.js', 'main.js', 'bot.js', 'app.js']
        for p in preferred_py:
            if p in py_files: main_script_name = p; file_type = 'py'; break
        if not main_script_name:
            for p in preferred_js:
                if p in js_files: main_script_name = p; file_type = 'js'; break
        if not main_script_name:
            if py_files: main_script_name = py_files[0]; file_type = 'py'
            elif js_files: main_script_name = js_files[0]; file_type = 'js'
        if not main_script_name:
            bot.send_message(chat_id, "❌ No `.py` or `.js` script found inside ZIP archive!")
            return

        # Move files excluding zip file itself (Fixes Storage Waste)
        moved = 0
        for item in os.listdir(temp_dir):
            src_path = os.path.join(temp_dir, item)
            dest_path = os.path.join(user_folder, item)
            if item == file_name_zip: continue
            if os.path.isdir(dest_path): shutil.rmtree(dest_path)
            elif os.path.exists(dest_path): os.remove(dest_path)
            shutil.move(src_path, dest_path)
            moved += 1
            
        save_user_file(user_id, main_script_name, file_type)
        main_script_path = os.path.join(user_folder, main_script_name)
        bot.send_message(chat_id, f"✅ Files extracted. Starting main script: `{main_script_name}`...", parse_mode='Markdown')
        
        if file_type == 'py':
            threading.Thread(target=run_script, args=(main_script_path, user_id, user_folder, main_script_name, chat_id)).start()
        elif file_type == 'js':
            threading.Thread(target=run_js_script, args=(main_script_path, user_id, user_folder, main_script_name, chat_id)).start()
    except Exception as e:
        logger.error(f"Error processing ZIP: {e}", exc_info=True)
        bot.send_message(user_id, f"❌ Error processing zip file: {e}")
    finally:
        if cleanup_temp and temp_dir and os.path.exists(temp_dir):
            try: shutil.rmtree(temp_dir)
            except: pass

# =====================================================================
# 🖥️ FLASK WEB PORTAL & IDE SUB-SERVER
# =====================================================================
app = Flask('')
app.secret_key = "50_shades_hoster_standlone_super_secret_session_key"

LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🎭 50 Shades Hoster - Web Login</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>body { background-color: #0f172a; background-image: radial-gradient(at 50% 50%, rgba(16, 185, 129, 0.05) 0, transparent 50%); }</style>
</head>
<body class="min-h-screen flex items-center justify-center text-slate-100 p-4">
    <div class="w-full max-w-md bg-slate-900 border border-emerald-500/20 rounded-2xl p-8 shadow-2xl shadow-emerald-500/10">
        <div class="text-center mb-8">
            <h1 class="text-3xl font-extrabold text-emerald-400 mb-2 tracking-tight">🎭 50 Shades Hoster</h1>
            <p class="text-slate-400 text-sm">Secure & Anonymous Web File Manager</p>
        </div>
        {% if error %}<div class="mb-6 bg-red-950/40 border border-red-500/30 text-red-300 text-sm rounded-lg p-4 flex items-center gap-3"><i class="fa-solid fa-triangle-exclamation"></i><span>{{ error }}</span></div>{% endif %}
        <form action="/login" method="POST" class="space-y-6">
            <div>
                <label class="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">Telegram User ID</label>
                <input type="number" name="user_id" required class="w-full px-4 py-3 bg-slate-950 border border-slate-800 rounded-xl focus:outline-none focus:border-emerald-500 text-slate-100">
            </div>
            <div>
                <label class="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">Anonymous Hash Key</label>
                <input type="text" name="hash_key" required class="w-full px-4 py-3 bg-slate-950 border border-slate-800 rounded-xl focus:outline-none focus:border-emerald-500 text-slate-100">
            </div>
            <button type="submit" class="w-full bg-emerald-500 hover:bg-emerald-600 text-slate-950 font-bold py-3 px-4 rounded-xl shadow-lg transition-all duration-150 flex items-center justify-center gap-2">Sign In To Sandbox</button>
        </form>
    </div>
</body>
</html>
"""

DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🎭 50 Shades Hoster - Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>body { background-color: #0b0f19; }</style>
</head>
<body class="min-h-screen text-slate-100 flex flex-col font-sans">
    <nav class="bg-slate-900 border-b border-slate-800/80 sticky top-0 backdrop-blur-md z-40">
        <div class="max-w-7xl mx-auto px-4 flex items-center justify-between h-16">
            <div class="flex items-center gap-3">
                <span class="text-emerald-400 text-2xl"><i class="fa-solid fa-server"></i></span>
                <span class="font-extrabold text-xl tracking-tight text-slate-100">50 Shades Hoster</span>
            </div>
            <div class="flex items-center gap-6">
                <p class="text-sm font-bold text-slate-200 font-mono">{{ user_hash }}</p>
                <a href="/logout" class="bg-slate-800 hover:bg-slate-700 border border-slate-700 px-4 py-2 rounded-xl text-sm font-semibold transition-all">Log Out</a>
            </div>
        </div>
    </nav>
    <main class="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 lg:p-8 space-y-6">
        <div class="bg-slate-900 border border-slate-800/80 rounded-2xl p-6 flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
                <h1 class="text-2xl font-bold">📂 Hashed Sandbox Explorer</h1>
                <p class="text-slate-400 text-sm mt-1">Manage files, upload new codes, download backups, or edit in real-time.</p>
            </div>
            <a href="/api/backup" class="bg-emerald-500 hover:bg-emerald-600 text-slate-950 font-bold px-4 py-2.5 rounded-xl text-sm transition-all flex items-center gap-2">Download Backup (.zip)</a>
        </div>
        <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div class="lg:col-span-2 space-y-6">
                <div class="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden">
                    <div class="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
                        <h2 class="font-bold text-slate-200 flex items-center gap-2">Workspace Files</h2>
                        <span class="bg-slate-800 text-slate-400 text-xs px-2.5 py-1 rounded-full font-mono">{{ files|length }} files</span>
                    </div>
                    {% if files %}
                    <div class="overflow-x-auto">
                        <table class="w-full text-left">
                            <thead>
                                <tr class="border-b border-slate-800 text-slate-400 text-xs font-semibold bg-slate-950/20">
                                    <th class="py-4 px-6">Name</th>
                                    <th class="py-4 px-6">Size</th>
                                    <th class="py-4 px-6">Last Modified</th>
                                    <th class="py-4 px-6 text-right">Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for f in files %}
                                <tr class="hover:bg-slate-800/10 border-b border-slate-800/20">
                                    <td class="py-4 px-6 font-mono text-slate-200 truncate max-w-[200px]">{{ f.name }}</td>
                                    <td class="py-4 px-6 text-sm text-slate-400 font-mono">{{ f.size_kb }} KB</td>
                                    <td class="py-4 px-6 text-sm text-slate-400 font-mono">{{ f.mtime }}</td>
                                    <td class="py-4 px-6 text-right">
                                        <div class="flex items-center justify-end gap-2">
                                            {% if f.name.endswith(('.py', '.js', '.txt', '.json', '.log')) %}
                                            <a href="/edit/{{ f.name }}" class="bg-slate-800 hover:bg-emerald-500/10 border border-slate-700 hover:border-emerald-500/30 text-slate-300 hover:text-emerald-400 p-2 rounded-lg text-xs font-semibold transition-all">Edit</a>
                                            {% endif %}
                                            <a href="/api/download/{{ f.name }}" class="bg-slate-800 hover:bg-slate-700 p-2 rounded-lg text-xs text-slate-300">Download</a>
                                            <button onclick="deleteFile('{{ f.name }}')" class="bg-slate-800 hover:bg-red-500/10 border border-slate-700 hover:border-red-500/30 text-slate-300 hover:text-red-400 p-2 rounded-lg text-xs font-semibold">Delete</button>
                                        </div>
                                    </td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                    {% else %}<div class="py-16 text-center text-slate-500"><p class="text-sm">This hashed sandbox is empty.</p></div>{% endif %}
                </div>
                <div class="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden flex flex-col">
                    <div class="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
                        <h2 class="font-bold text-slate-200">Live Script Log Monitor</h2>
                        <select id="log-selector" onchange="loadLog()" class="bg-slate-800 border border-slate-700 text-slate-300 rounded-lg px-3 py-1.5 text-xs font-mono">
                            <option value="">-- Select log --</option>
                            {% for f in files %}{% if f.name.endswith('.log') %}<option value="{{ f.name }}">{{ f.name }}</option>{% endif %}{% endfor %}
                        </select>
                    </div>
                    <div class="p-6 bg-slate-950 font-mono text-xs text-emerald-400 min-h-[220px] max-h-[350px] overflow-y-auto" id="terminal-screen">
                        <p class="text-slate-500"># Select log file to monitor script logs...</p>
                    </div>
                </div>
            </div>
            <div class="lg:col-span-1 space-y-6">
                <div class="bg-slate-900 border border-slate-800 rounded-2xl p-6">
                    <h2 class="font-bold text-slate-200 mb-4">Upload Script / Zip</h2>
                    <div id="drop-zone" class="border-2 border-dashed border-slate-800 hover:border-emerald-500/50 rounded-2xl p-8 text-center bg-slate-950/25 min-h-[200px] flex flex-col justify-center items-center">
                        <p class="text-sm font-semibold">Drag & Drop file here</p>
                        <input type="file" id="file-input" class="hidden" onchange="handleFileSelect()">
                        <button onclick="document.getElementById('file-input').click()" class="bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold px-4 py-2 rounded-lg mt-4 transition-all">Browse Files</button>
                    </div>
                </div>
            </div>
        </div>
    </main>
    <script>
        function deleteFile(filename) {
            if (confirm("Are you sure?")) {
                fetch('/api/delete/' + filename, { method: 'POST' }).then(res => res.json()).then(d => { if (d.success) location.reload(); });
            }
        }
        function handleFileSelect() {
            const input = document.getElementById('file-input');
            if (input.files.length > 0) uploadFile(input.files[0]);
        }
        function uploadFile(file) {
            const formData = new FormData();
            formData.append('file', file);
            fetch('/api/upload', { method: 'POST', body: formData }).then(res => res.json()).then(d => { location.reload(); });
        }
        function loadLog() {
            const selector = document.getElementById('log-selector');
            const screen = document.getElementById('terminal-screen');
            const filename = selector.value;
            if (!filename) { screen.innerHTML = ''; return; }
            fetch('/api/log/' + filename).then(res => res.json()).then(d => {
                if (d.success) screen.innerHTML = '<pre class="whitespace-pre-wrap">' + escapeHtml(d.content) + '</pre>';
            });
        }
        function escapeHtml(text) {
            return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
        }
    </script>
</body>
</html>
"""

EDIT_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🎭 Web IDE - Editing {{ filename }}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>.code-area { font-family: monospace; background-color: #030712; color: #10b981; }</style>
</head>
<body class="min-h-screen text-slate-100 flex flex-col bg-slate-950">
    <nav class="bg-slate-900 border-b border-slate-800 sticky top-0 z-40">
        <div class="max-w-7xl mx-auto px-4 flex items-center justify-between h-16">
            <div class="flex items-center gap-3">
                <a href="/dashboard" class="text-slate-400 hover:text-slate-100"><i class="fa-solid fa-arrow-left"></i> Back</a>
                <span class="font-mono text-sm font-bold text-slate-200">{{ filename }}</span>
            </div>
            <div class="flex items-center gap-3">
                <button onclick="saveCode()" class="bg-emerald-500 hover:bg-emerald-600 text-slate-950 font-bold px-4 py-2 rounded-xl text-sm transition-all">Save Code</button>
            </div>
        </div>
    </nav>
    <main class="flex-1 max-w-7xl w-full mx-auto p-4 flex flex-col">
        <textarea id="editor" class="flex-1 w-full code-area p-6 focus:outline-none resize-none font-mono text-sm leading-relaxed" spellcheck="false">{{ content }}</textarea>
    </main>
    <script>
        function saveCode() {
            const code = document.getElementById('editor').value;
            fetch('/api/save/{{ filename }}', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ code: code })
            }).then(res => res.json()).then(d => { if (d.success) alert("Saved successfully!"); });
        }
    </script>
</body>
</html>
"""

@app.route('/')
def home():
    return redirect(url_for('dashboard')) if 'user_id' in session else redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        uid_str = request.form.get('user_id', '').strip()
        h_key = request.form.get('hash_key', '').strip()
        try:
            user_id = int(uid_str)
            if h_key == get_user_hash(user_id):
                session['user_id'] = user_id
                session['user_hash'] = h_key
                return redirect(url_for('dashboard'))
            return render_template_string(LOGIN_TEMPLATE, error="❌ Incorrect credentials!")
        except: return render_template_string(LOGIN_TEMPLATE, error="❌ Invalid format!")
    return render_template_string(LOGIN_TEMPLATE, error=None)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session: return redirect(url_for('login'))
    user_id = session['user_id']
    user_folder = get_user_folder_by_id(user_id)
    files_list = []
    for f in os.listdir(user_folder):
        f_path = os.path.join(user_folder, f)
        if os.path.isfile(f_path):
            size_kb = round(os.path.getsize(f_path) / 1024, 2)
            mtime = datetime.fromtimestamp(os.path.getmtime(f_path)).strftime('%Y-%m-%d %H:%M')
            files_list.append({'name': f, 'size_kb': size_kb, 'mtime': mtime})
    return render_template_string(DASHBOARD_TEMPLATE, user_hash=session['user_hash'], files=files_list)

@app.route('/edit/<filename>')
def edit_file(filename):
    if 'user_id' not in session: return redirect(url_for('login'))
    user_folder = get_user_folder_by_id(session['user_id'])
    file_path = os.path.join(user_folder, filename)
    if not is_safe_path(user_folder, file_path) or not os.path.exists(file_path):
        return "Access Denied", 403
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    return render_template_string(EDIT_TEMPLATE, filename=filename, content=content)

@app.route('/api/save/<filename>', methods=['POST'])
def api_save_file(filename):
    if 'user_id' not in session: return jsonify({'success': False}), 401
    user_folder = get_user_folder_by_id(session['user_id'])
    file_path = os.path.join(user_folder, filename)
    if not is_safe_path(user_folder, file_path): return jsonify({'success': False}), 403
    try:
        data = request.get_json()
        with open(file_path, 'w', encoding='utf-8') as f: f.write(data.get('code', ''))
        return jsonify({'success': True})
    except Exception as e: return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/delete/<filename>', methods=['POST'])
def api_delete_file(filename):
    if 'user_id' not in session: return jsonify({'success': False}), 401
    user_folder = get_user_folder_by_id(session['user_id'])
    file_path = os.path.join(user_folder, filename)
    if not is_safe_path(user_folder, file_path) or not os.path.exists(file_path): return jsonify({'success': False}), 403
    try:
        os.remove(file_path)
        return jsonify({'success': True})
    except Exception as e: return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/upload', methods=['POST'])
def api_upload_file():
    if 'user_id' not in session: return jsonify({'success': False}), 401
    user_folder = get_user_folder_by_id(session['user_id'])
    if 'file' not in request.files: return jsonify({'success': False}), 400
    uploaded_file = request.files['file']
    if uploaded_file.filename == '': return jsonify({'success': False}), 400
    try:
        file_path = os.path.join(user_folder, uploaded_file.filename)
        if not is_safe_path(user_folder, file_path): return jsonify({'success': False}), 403
        uploaded_file.save(file_path)
        return jsonify({'success': True})
    except Exception as e: return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/download/<filename>')
def api_download_file(filename):
    if 'user_id' not in session: return redirect(url_for('login'))
    user_folder = get_user_folder_by_id(session['user_id'])
    file_path = os.path.join(user_folder, filename)
    if not is_safe_path(user_folder, file_path) or not os.path.exists(file_path): return "Access Denied", 403
    return send_from_directory(user_folder, filename, as_attachment=True)

@app.route('/api/backup')
def api_download_backup():
    if 'user_id' not in session: return redirect(url_for('login'))
    user_id = session['user_id']
    user_folder = get_user_folder_by_id(user_id)
    try:
        temp_dir = tempfile.mkdtemp(prefix=f"web_backup_{user_id}_")
        zip_name = f"backup_web_{user_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
        zip_path = os.path.join(temp_dir, zip_name)
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zip_f:
            for root, dirs, files in os.walk(user_folder):
                for f in files:
                    file_abs = os.path.join(root, f)
                    file_rel = os.path.relpath(file_abs, user_folder)
                    if f.endswith('.log'): continue
                    zip_f.write(file_abs, file_rel)
        def generate_file():
            with open(zip_path, 'rb') as f: yield from f
            try: shutil.rmtree(temp_dir)
            except: pass
        return Response(generate_file(), mimetype='application/zip', headers={'Content-Disposition': f'attachment; filename={zip_name}'})
    except Exception as e: return "Internal Error", 500

@app.route('/api/log/<filename>')
def api_view_log(filename):
    if 'user_id' not in session: return jsonify({'success': False}), 401
    user_folder = get_user_folder_by_id(session['user_id'])
    file_path = os.path.join(user_folder, filename)
    if not is_safe_path(user_folder, file_path) or not os.path.exists(file_path): return jsonify({'success': False}), 403
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()[-150:]
            content = "".join(lines)
        return jsonify({'success': True, 'content': content if content.strip() else "(Log empty)"})
    except Exception as e: return jsonify({'success': False, 'message': str(e)}), 500

# --- Flask Server Thread Starter ---
def run_flask():
    try:
        port = int(os.environ.get("PORT", 8080))
        app.run(host='0.0.0.0', port=port)
    except OSError: logger.error("Port already bound.")
    except Exception as e: logger.error(f"Flask Web Server Error: {e}")

def keep_alive():
    t = threading.Thread(target=run_flask)
    t.daemon = True
    t.start()
    logger.info("🎭 Web IDE Panel & Keep-Alive Server initialized on background thread.")

# =====================================================================
# 👑 TELEGRAM HANDLERS, COMMANDS, CALLBACKS, & BUTTON METRICS
# =====================================================================
def create_main_menu_inline(user_id):
    markup = types.InlineKeyboardMarkup(row_width=2)
    btn_web_panel = btn('🌐 Open Web Panel', url=WEB_PANEL_URL, style='success')
    btn_upload = btn('📤 Upload Script', callback_data='upload', style='success')
    btn_check = btn('📂 My Scripts', callback_data='check_files', style='primary')
    btn_speed = btn('⚡ Test Ping', callback_data='speed', style='primary')
    btn_updates = btn('📢 Updates Channel', url=f'https://t.me/{UPDATE_CHANNEL.replace("@", "")}', style='primary')
    btn_help_guide = btn('🆘 Help Guide', callback_data='back_to_main', style='primary')
    
    if user_id in admin_ids:
        btn_sub = btn('💳 Subscriptions', callback_data='subscription', style='primary')
        btn_stats = btn('📊 Statistics', callback_data='stats', style='primary')
        btn_lock = btn('🔒 Lock Bot' if not bot_locked else '🔓 Unlock Bot', 
                       callback_data='lock_bot' if not bot_locked else 'unlock_bot',
                       style='danger' if not bot_locked else 'success')
        btn_broadcast = btn('📢 Broadcast', callback_data='broadcast', style='primary')
        btn_admin_panel = btn('👑 Admin Panel', callback_data='admin_panel', style='danger')
        btn_channel_add = btn('📢 Channel Add', callback_data='manage_mandatory_channels', style='success')
        btn_user_mgmt = btn('👥 User Management', callback_data='user_management', style='danger')
        btn_admin_install = btn('🛠️ Admin Install', callback_data='admin_install', style='success')
        btn_settings = btn('⚙️ Settings', callback_data='admin_settings', style='primary')
        
        markup.add(btn_web_panel)
        markup.add(btn_upload)
        markup.add(btn_check, btn_speed)
        markup.add(btn_sub, btn_stats)
        markup.add(btn_lock, btn_admin_panel)
        markup.add(btn_channel_add, btn_admin_install)
        markup.add(btn_user_mgmt, btn_settings)
        markup.add(btn_updates, btn_help_guide)
    else:
        markup.add(btn_web_panel)
        markup.add(btn_upload)
        markup.add(btn_check, btn_speed)
        markup.add(btn_updates, btn_help_guide)
    return markup

def create_reply_keyboard_main_menu(user_id):
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    button_styles = {
        "📤 Upload Script": "success",
        "📂 My Scripts": "primary",
        "⚡ Test Ping": "primary",
        "🆘 Help Guide": "primary",
        "🔒 Lock Bot": "danger",
        "👑 Admin Panel": "danger",
        "👥 User Management": "danger",
        "📢 Broadcast": "primary",
        "💳 Subscriptions": "primary",
        "📢 Channel Add": "success",
        "🛠️ Manual Install": "success",
        "🧹 Cleanup Files": "danger",
        "⚙️ Settings": "primary"
    }
    layout_to_use = ADMIN_COMMAND_BUTTONS_LAYOUT_USER_SPEC if user_id in admin_ids else COMMAND_BUTTONS_LAYOUT_USER_SPEC
    for row in layout_to_use:
        row_buttons = []
        for text in row:
            style = button_styles.get(text)
            row_buttons.append(kb_btn(text, style=style))
        markup.add(*row_buttons)
    return markup

def create_control_buttons(script_owner_id, file_name, is_running=True):
    markup = types.InlineKeyboardMarkup(row_width=2)
    auto_restart = script_auto_restart.get(f"{script_owner_id}_{file_name}", False)
    btn_auto = btn("🔄 Auto-Restart: ON" if auto_restart else "🔄 Auto-Restart: OFF",
                   callback_data=f"toggle_autorestart_{script_owner_id}_{file_name}",
                   style="success" if auto_restart else "danger")
    if is_running:
        markup.row(
            btn("🔴 Stop", callback_data=f'stop_{script_owner_id}_{file_name}', style='danger'),
            btn("🔄 Restart", callback_data=f'restart_{script_owner_id}_{file_name}', style='success')
        )
        markup.row(
            btn("🗑️ Delete", callback_data=f'delete_{script_owner_id}_{file_name}', style='danger'),
            btn("📜 Logs", callback_data=f'logs_{script_owner_id}_{file_name}', style='primary')
        )
    else:
        markup.row(
            btn("🟢 Start", callback_data=f'start_{script_owner_id}_{file_name}', style='success'),
            btn("🗑️ Delete", callback_data=f'delete_{script_owner_id}_{file_name}', style='danger')
        )
        markup.row(
            btn("📜 View Logs", callback_data=f'logs_{script_owner_id}_{file_name}', style='primary')
        )
    markup.row(btn_auto)
    markup.row(
        btn("📂 File Explorer", callback_data=f"explorer_{script_owner_id}", style="primary"),
        btn("💾 Get Backup (.zip)", callback_data=f"backup_{script_owner_id}", style="success")
    )
    markup.add(btn("🔙 Back to Files", callback_data='check_files', style='primary'))
    return markup

def create_admin_panel():
    markup = types.InlineKeyboardMarkup(row_width=2)
    markup.row(
        btn('➕ Add Admin', callback_data='add_admin', style='success'),
        btn('➖ Remove Admin', callback_data='remove_admin', style='danger')
    )
    markup.row(btn('📋 List Admins', callback_data='list_admins', style='primary'))
    markup.row(btn('🔙 Back to Main', callback_data='back_to_main', style='primary'))
    return markup

def create_user_management_menu():
    markup = types.InlineKeyboardMarkup(row_width=2)
    markup.row(
        btn('🚫 Ban User', callback_data='ban_user', style='danger'),
        btn('✅ Unban User', callback_data='unban_user', style='success')
    )
    markup.row(
        btn('📊 User Info', callback_data='user_info', style='primary'),
        btn('👥 All Users', callback_data='all_users', style='primary')
    )
    markup.row(
        btn('🔧 Set User Limit', callback_data='set_user_limit', style='primary'),
        btn('🗑️ Remove User Limit', callback_data='remove_user_limit', style='danger')
    )
    markup.row(btn('🔙 Back to Main', callback_data='back_to_main', style='primary'))
    return markup

def create_subscription_menu():
    markup = types.InlineKeyboardMarkup(row_width=2)
    markup.row(
        btn('➕ Add Subscription', callback_data='add_subscription', style='success'),
        btn('➖ Remove Subscription', callback_data='remove_subscription', style='danger')
    )
    markup.row(btn('🔍 Check Subscription', callback_data='check_subscription', style='primary'))
    markup.row(btn('🔙 Back to Main', callback_data='back_to_main', style='primary'))
    return markup

def create_admin_settings_menu():
    markup = types.InlineKeyboardMarkup(row_width=2)
    btn_mode = btn("🔄 Bot Mode: FREE (All Unlocked)" if free_mode else "🔄 Bot Mode: PREMIUM (Subs Active)", callback_data="toggle_free_mode", style="success" if free_mode else "danger")
    markup.row(btn_mode)
    markup.row(
        btn('📊 System Info', callback_data='system_info', style='primary'),
        btn('📈 Bot Performance', callback_data='bot_performance', style='primary')
    )
    markup.row(
        btn('🧹 Cleanup Files', callback_data='cleanup_files', style='danger'),
        btn('📋 Installation Logs', callback_data='install_logs', style='primary')
    )
    markup.row(btn("🔑 Generate License Key", callback_data="admin_genkey", style="success"))
    markup.row(btn('🔙 Back to Main', callback_data='back_to_main', style='primary'))
    return markup

# --- File Upload Receivers ---
def handle_zip_file(downloaded_file_content, file_name_zip, message):
    user_id = message.from_user.id
    user_folder = get_user_folder(user_id)
    temp_dir = None
    try:
        temp_dir = tempfile.mkdtemp(prefix=f"user_{user_id}_zip_")
        zip_path = os.path.join(temp_dir, file_name_zip)
        with open(zip_path, 'wb') as new_file: new_file.write(downloaded_file_content)
        
        is_safe, security_msg = scan_zip_security(zip_path)
        if not is_safe:
            if os.path.exists(zip_path):
                try: os.remove(zip_path)
                except: pass
            bot.reply_to(message, f"❌ **Upload Rejected**:\n\nYour ZIP archive `{file_name_zip}` failed our security scans and was deleted immediately for server safety.\n\n⚠️ **Reason**: {security_msg}", parse_mode='Markdown')
            return
            
        process_zip_file(zip_path, user_id, user_folder, file_name_zip, message, temp_dir)
    except zipfile.BadZipFile as e:
        bot.reply_to(message, f"❌ Error: Invalid or corrupted ZIP archive: {e}")
    except Exception as e:
        bot.reply_to(message, f"❌ Unexpected error processing ZIP: {e}")
    finally:
        if temp_dir and os.path.exists(temp_dir):
            try: shutil.rmtree(temp_dir)
            except: pass

def handle_js_file(file_path, script_owner_id, user_folder, file_name, message):
    try:
        save_user_file(script_owner_id, file_name, 'js')
        threading.Thread(target=run_js_script, args=(file_path, script_owner_id, user_folder, file_name, script_owner_id)).start()
    except Exception as e: bot.reply_to(message, f"❌ Error: {e}")

def handle_py_file(file_path, script_owner_id, user_folder, file_name, message):
    try:
        save_user_file(script_owner_id, file_name, 'py')
        threading.Thread(target=run_script, args=(file_path, script_owner_id, user_folder, file_name, script_owner_id)).start()
    except Exception as e: bot.reply_to(message, f"❌ Error: {e}")

# --- Bot Commands Logic ---
def _logic_send_welcome(message):
    user_id = message.from_user.id
    chat_id = message.chat.id
    user_name = message.from_user.first_name
    
    if is_user_banned(user_id):
        bot.send_message(chat_id, "❌ You are banned from using this bot.")
        return
        
    is_subscribed, not_joined = check_mandatory_subscription(user_id)
    if not is_subscribed and user_id not in admin_ids:
        msg, markup = create_subscription_check_message(not_joined)
        bot.send_message(chat_id, msg, reply_markup=markup, parse_mode='Markdown')
        return
        
    if bot_locked and user_id not in admin_ids:
        bot.send_message(chat_id, "⚠️ Bot locked by admin. Try later.")
        return
        
    user_hash = hashlib.sha256(str(user_id).encode('utf-8')).hexdigest()[:16]
    if user_id not in active_users:
        add_active_user(user_id)
        try:
            bot.send_message(OWNER_ID, f"🎉 A new anonymous user has started the bot!\n🆔 Anonymous Hash ID: `{user_hash}`")
        except: pass
        
    file_limit = get_user_file_limit(user_id)
    current_files = get_user_file_count(user_id)
    limit_str = str(file_limit) if file_limit != float('inf') else "Unlimited"
    expiry_info = ""
    
    if user_id == OWNER_ID: user_status = "👑 Owner"
    elif user_id in admin_ids: user_status = "🛡️ Admin"
    elif user_id in user_subscriptions:
        expiry = user_subscriptions[user_id].get('expiry')
        if expiry and expiry > datetime.now():
            user_status = "⭐ Premium"
            expiry_info = f"\n⏳ Subscription expires in: {(expiry - datetime.now()).days} days"
        else:
            user_status = "🆓 Free User (Expired)"
            remove_subscription_db(user_id)
    else: user_status = "🆓 Free User"

    welcome_msg = (f"〽️ **Welcome to 50 Shades Hoster!**\n\n"
                  f"🆔 **Your Anonymous Hash ID**: `{user_hash}`\n"
                  f"🔰 **Your Status**: {user_status}{expiry_info}\n"
                  f"📁 **Files Uploaded**: {current_files} / {limit_str}\n\n"
                  f"🌐 **Web Dashboard & IDE**:\n"
                  f"👉 **[Click Here to Open Web Panel]({WEB_PANEL_URL})**\n"
                  f"🔑 *Login using your User ID and the Hash Key above!*\n\n"
                  f"🤖 Host & run Python (`.py`) or JS (`.js`) scripts.\n"
                  f"   Fully isolated workspace sandbox configuration.\n\n"
                  f"👇 Use the restructured buttons below to control.")
                  
    bot.send_message(chat_id, welcome_msg, reply_markup=create_reply_keyboard_main_menu(user_id), parse_mode='Markdown')

def _logic_updates_channel(message):
    markup = types.InlineKeyboardMarkup()
    markup.add(btn('📢 Updates Channel', url=f'https://t.me/{UPDATE_CHANNEL.replace("@", "")}', style='primary'))
    bot.reply_to(message, "Visit our Updates Channel:", reply_markup=markup)

def _logic_upload_file(message):
    user_id = message.from_user.id
    if is_user_banned(user_id): return
    is_sub, not_joined = check_mandatory_subscription(user_id)
    if not is_sub and user_id not in admin_ids:
        msg, markup = create_subscription_check_message(not_joined)
        bot.reply_to(message, msg, reply_markup=markup, parse_mode='Markdown')
        return
    if bot_locked and user_id not in admin_ids:
        bot.reply_to(message, "⚠️ Bot locked by admin.")
        return
        
    if get_user_file_count(user_id) >= get_user_file_limit(user_id):
        bot.reply_to(message, "⚠️ File upload limit reached! Delete some scripts first.")
        return
    bot.reply_to(message, "📤 Send your Python (`.py`), JS (`.js`), or ZIP (`.zip`) file.")

def _logic_check_files(message):
    user_id = message.from_user.id
    if is_user_banned(user_id): return
    is_sub, not_joined = check_mandatory_subscription(user_id)
    if not is_sub and user_id not in admin_ids:
        msg, markup = create_subscription_check_message(not_joined)
        bot.reply_to(message, msg, reply_markup=markup, parse_mode='Markdown')
        return
        
    user_files_list = user_files.get(user_id, [])
    if not user_files_list:
        bot.reply_to(message, "📂 Your files:\n\n(No files uploaded yet)")
        return
    markup = types.InlineKeyboardMarkup(row_width=1)
    for file_name, file_type in sorted(user_files_list):
        is_running = is_bot_running(user_id, file_name)
        status_icon = "🟢 Running" if is_running else "🔴 Stopped"
        markup.add(btn(f"{file_name} ({file_type}) - {status_icon}", callback_data=f'file_{user_id}_{file_name}', style='primary'))
    bot.reply_to(message, "📂 Your files:\nClick to manage.", reply_markup=markup, parse_mode='Markdown')

def _logic_bot_speed(message):
    user_id = message.from_user.id
    if is_user_banned(user_id): return
    is_sub, not_joined = check_mandatory_subscription(user_id)
    if not is_sub and user_id not in admin_ids:
        msg, markup = create_subscription_check_message(not_joined)
        bot.reply_to(message, msg, reply_markup=markup, parse_mode='Markdown')
        return
        
    start_time_ping = time.time()
    wait_msg = bot.reply_to(message, "🏃 Testing speed...")
    try:
        bot.send_chat_action(message.chat.id, 'typing')
        response_time = round((time.time() - start_time_ping) * 1000, 2)
        status = "🔓 Unlocked" if not bot_locked else "🔒 Locked"
        user_level = "👑 Owner" if user_id == OWNER_ID else "🛡️ Admin" if user_id in admin_ids else "⭐ Premium" if user_id in user_subscriptions else "🆓 Free User"
        
        cpu_p = psutil.cpu_percent()
        ram_p = psutil.virtual_memory().percent
        disk_p = psutil.disk_usage('/').percent
        
        speed_msg = (f"⚡ **System Monitor & Health Info**:\n\n"
                     f"⏱️ **Ping Response**: `{response_time} ms`\n"
                     f"🚦 **Bot Status**: {status}\n"
                     f"👤 **Your Account**: {user_level}\n\n"
                     f"💻 **CPU Usage**:\n{make_progress_bar(cpu_p)}\n"
                     f"🧠 **RAM Usage**:\n{make_progress_bar(ram_p)}\n"
                     f"💾 **Disk Storage**:\n{make_progress_bar(disk_p)}")
        bot.edit_message_text(speed_msg, message.chat.id, wait_msg.message_id, parse_mode='Markdown')
    except Exception as e:
        logger.error(f"Error during ping test: {e}")

def _logic_contact_owner(message):
    markup = types.InlineKeyboardMarkup()
    markup.add(btn('📞 Contact Owner', url=f'https://t.me/{YOUR_USERNAME.replace("@", "")}', style='primary'))
    bot.reply_to(message, "Click to contact Owner:", reply_markup=markup)

def _logic_manual_install(message):
    user_id = message.from_user.id
    if user_id in admin_ids:
        manual_install_module_init(message)
    else:
        bot.reply_to(message, "⚠️ **Manual Installation Restricted**:\n\nFor server safety, manual pip/npm installations can only be initiated by Admins. If you need any packages installed, please contact the **Owner**.", parse_mode='Markdown')

def _logic_help(message):
    help_text = f"""
🎭 **50 Shades Hoster - Help Guide**

Welcome to the most secure, completely anonymous, and isolated hosting environment for your Python (`.py`) and JavaScript (`.js`) scripts!

🌐 **Web Dashboard & In-Browser IDE:**
• You can manage your files, view live script logs, upload files via drag-and-drop, and edit your code in real-time right from your web browser!
• 👉 **[Click Here to Open Web Panel]({WEB_PANEL_URL})**
• 🔑 **To Login**: Enter your numeric Telegram User ID and your **16-character Anonymous Hash ID** (which you see when you run `/start`).

⚙️ **How It Works:**
1️⃣ **Upload your script**: Simply send your `.py`, `.js` file, or a `.zip` archive containing your bot.
2️⃣ **Automatic Sandbox**: Your files are instantly stored in an anonymous, hashed directory for complete isolation.
3️⃣ **Auto Dependency Installer**: If your script needs packages, the bot detects imports and installs them. If you upload a `.zip`, it auto-installs packages listed inside `requirements.txt` or `package.json`!
4️⃣ **Control Panel**: Once uploaded, click **📂 My Scripts** to start, stop, restart, delete, or view the real-time runtime logs of your bots!

🛡️ **Harden Sandbox Security:**
• Standard directory traversal and absolute path traversal attempts are strictly scanned and blocked.
• Manual pip/npm installations are restricted to Admins only. Place your packages inside a `requirements.txt` or `package.json` file inside your `.zip` archive for automated installs!

📌 **Basic Commands:**
• /start - Start or restart the bot interface.
• /help - View this help guide.

👤 **Your Identity is 100% Protected:**
• Hashed directory isolation on-disk.
• No Telegram name, username, or raw ID is logged or shown.
• 100% zero-tracking.

📢 **Updates Channel**: {UPDATE_CHANNEL}
"""
    bot.reply_to(message, help_text, parse_mode='Markdown')

def _logic_subscriptions_panel(message):
    if message.from_user.id not in admin_ids: return
    bot.reply_to(message, "💳 Subscription Management\nSelect action:", reply_markup=create_subscription_menu())

def _logic_statistics(message):
    user_id = message.from_user.id
    if is_user_banned(user_id): return
    if not free_mode:
        is_sub, not_joined = check_mandatory_subscription(user_id)
        if not is_sub and user_id not in admin_ids: return
        
    total_users = len(active_users)
    total_files_records = sum(len(files) for files in user_files.values())
    running_bots_count = len(bot_scripts)
    user_running_bots = sum(1 for k in bot_scripts if k.startswith(f"{user_id}_"))
    
    stats_msg = (f"📊 **Bot Statistics**:\n\n"
                 f"👥 **Total Users**: `{total_users}`\n"
                 f"🚫 **Banned Users**: `{len(banned_users)}`\n"
                 f"📂 **Total File Records**: `{total_files_records}`\n"
                 f"🟢 **Total Active Bots**: `{running_bots_count}`\n"
                 f"🤖 **Your Running Bots**: `{user_running_bots}`")
    bot.reply_to(message, stats_msg, parse_mode='Markdown')

def _logic_broadcast_init(message):
    if message.from_user.id not in admin_ids: return
    msg = bot.reply_to(message, "📢 Send broadcast message or /cancel:")
    bot.register_next_step_handler(msg, process_broadcast_message)

def _logic_toggle_lock_bot(message):
    if message.from_user.id not in admin_ids: return
    global bot_locked
    bot_locked = not bot_locked
    status = "locked" if bot_locked else "unlocked"
    bot.reply_to(message, f"🔒 Bot has been {status}.")

def _logic_admin_panel(message):
    if message.from_user.id not in admin_ids: return
    bot.reply_to(message, "👑 Admin Panel\nManage admins (Owner actions may be restricted).", reply_markup=create_admin_panel())

def _logic_user_management(message):
    if message.from_user.id not in admin_ids: return
    bot.reply_to(message, "👥 User Management\nManage users, set limits, ban/unban.", reply_markup=create_user_management_menu())

def _logic_admin_settings(message):
    if message.from_user.id not in admin_ids: return
    bot.reply_to(message, "⚙️ Admin Settings\nSystem information and management.", reply_markup=create_admin_settings_menu())

def _logic_manage_mandatory_channels(message):
    if message.from_user.id not in admin_ids: return
    bot.reply_to(message, "📢 Manage Mandatory Channels:", reply_markup=create_mandatory_channels_menu())

def _logic_admin_install(message):
    if message.from_user.id not in admin_ids: return
    msg = bot.reply_to(message, "🛠️ **Admin Module Installation**:\n\nSend User ID and module name (e.g., `12345678 requests`):", reply_markup=cancel_markup(), parse_mode='Markdown')
    bot.register_next_step_handler(msg, process_admin_install)

# --- Automated Input Processors ---
def process_manual_install_module(message):
    user_id = message.from_user.id
    if is_user_banned(user_id): return
    if message.text.lower() == '/cancel':
        bot.reply_to(message, "❌ Aborted.")
        return
    module_name = message.text.strip()
    if module_name.lower().startswith('npm:'):
        module_name = module_name[4:].strip()
        user_folder = get_user_folder(user_id)
        attempt_install_npm(module_name, user_folder, message.chat.id, manual_request=True)
    else:
        attempt_install_pip(module_name, message.chat.id, manual_request=True)

def manual_install_module_init(message):
    user_id = message.from_user.id
    msg = bot.reply_to(message, "📦 **Module Installation**:\n\nSend module name to install (e.g., `requests` or `pillow`)\nFor Node.js, use format: `npm:module_name`", reply_markup=cancel_markup(), parse_mode='Markdown')
    bot.register_next_step_handler(msg, process_manual_install_module)

def process_admin_install(message):
    admin_id = message.from_user.id
    if admin_id not in admin_ids: return
    if message.text.lower() == '/cancel':
        bot.reply_to(message, "❌ Cancelled.")
        return
    try:
        parts = message.text.split()
        if len(parts) < 2:
            bot.reply_to(message, "⚠️ Format: `user_id module_name`\nExample: `12345678 requests`")
            return
        target_uid = int(parts[0])
        mod_name = parts[1].strip()
        if mod_name.lower().startswith('npm:'):
            mod_name = mod_name[4:].strip()
            user_folder = get_user_folder(target_uid)
            success, log = attempt_install_npm(mod_name, user_folder, message.chat.id, manual_request=True)
        else:
            success, log = attempt_install_pip(mod_name, message.chat.id, manual_request=True)
            
        if success:
            try: bot.send_message(target_uid, f"📦 Admin installed module `{mod_name}` for you.")
            except: pass
    except: bot.reply_to(message, "❌ Error parsing inputs!")

# --- Reply Keyboard Text Handler ---
BUTTON_TEXT_TO_LOGIC = {
    "📤 Upload Script": _logic_upload_file,
    "📂 My Scripts": _logic_check_files,
    "⚡ Test Ping": _logic_bot_speed,
    "🆘 Help Guide": _logic_help,
    "📊 Statistics": _logic_statistics, 
    "💳 Subscriptions": _logic_subscriptions_panel,
    "📢 Broadcast": _logic_broadcast_init,
    "🔒 Lock Bot": _logic_toggle_lock_bot, 
    "👑 Admin Panel": _logic_admin_panel,
    "📢 Channel Add": _logic_manage_mandatory_channels,
    "👥 User Management": _logic_user_management,
    "🛠️ Manual Install": _logic_manual_install,
    "⚙️ Settings": _logic_admin_settings,
    "📦 Manual Install": _logic_manual_install,
    "🆘 Help": _logic_help
}

@bot.message_handler(func=lambda message: message.text in BUTTON_TEXT_TO_LOGIC)
def handle_button_text(message):
    logic_func = BUTTON_TEXT_TO_LOGIC.get(message.text)
    if logic_func: logic_func(message)

# --- Telebot Command Decorators ---
@bot.message_handler(commands=['start', 'help'])
def command_start_help(message):
    if message.text == '/help': _logic_help(message)
    else: _logic_send_welcome(message)

@bot.message_handler(commands=['status'])
def command_status(message): _logic_statistics(message)

@bot.message_handler(commands=['updateschannel'])
def cmd_updates(message): _logic_updates_channel(message)
@bot.message_handler(commands=['uploadfile'])
def cmd_upload(message): _logic_upload_file(message)
@bot.message_handler(commands=['checkfiles'])
def cmd_check(message): _logic_check_files(message)
@bot.message_handler(commands=['botspeed'])
def cmd_speed(message): _logic_bot_speed(message)
@bot.message_handler(commands=['contactowner'])
def cmd_contact(message): _logic_contact_owner(message)
@bot.message_handler(commands=['subscriptions'])
def cmd_sub(message): _logic_subscriptions_panel(message)
@bot.message_handler(commands=['statistics'])
def cmd_stats(message): _logic_statistics(message)
@bot.message_handler(commands=['broadcast'])
def cmd_broad(message): _logic_broadcast_init(message)
@bot.message_handler(commands=['lockbot'])
def cmd_lock(message): _logic_toggle_lock_bot(message)
@bot.message_handler(commands=['adminpanel'])
def cmd_admin(message): _logic_admin_panel(message)
@bot.message_handler(commands=['managechannels'])
def cmd_channels(message): _logic_manage_mandatory_channels(message)
@bot.message_handler(commands=['usermanagement'])
def cmd_usermgmt(message): _logic_user_management(message)
@bot.message_handler(commands=['manualinstall'])
def cmd_manual(message): _logic_manual_install(message)
@bot.message_handler(commands=['admininstall'])
def cmd_admininst(message): _logic_admin_install(message)

@bot.message_handler(commands=['ping'])
def command_ping(message):
    start = time.time()
    msg = bot.reply_to(message, "Pong!")
    bot.edit_message_text(f"Pong! `{round((time.time() - start)*1000, 2)} ms`", message.chat.id, msg.message_id, parse_mode='Markdown')

@bot.message_handler(content_types=['document'])
def handle_file_upload_doc(message):
    user_id = message.from_user.id
    if is_user_banned(user_id): return
    is_sub, not_joined = check_mandatory_subscription(user_id)
    if not is_sub and user_id not in admin_ids:
        msg, markup = create_subscription_check_message(not_joined)
        bot.reply_to(message, msg, reply_markup=markup, parse_mode='Markdown')
        return
    if bot_locked and user_id not in admin_ids:
        bot.reply_to(message, "⚠️ Bot locked by admin.")
        return
        
    doc = message.document
    file_name = doc.file_name
    file_ext = os.path.splitext(file_name)[1].lower()
    
    if file_ext not in SECURITY_CONFIG['allowed_extensions'] and file_ext != '.zip':
        bot.reply_to(message, f"❌ Unsupported file format! Only {', '.join(SECURITY_CONFIG['allowed_extensions'])} or `.zip` files are allowed.")
        return
    if doc.file_size > SECURITY_CONFIG['max_file_size']:
        bot.reply_to(message, f"❌ File too large (max {SECURITY_CONFIG['max_file_size']//1024//1024}MB allowed).")
        return
        
    if get_user_file_count(user_id) >= get_user_file_limit(user_id) and file_ext != '.zip':
        bot.reply_to(message, "⚠️ File upload limit reached! Delete some scripts first.")
        return
        
    try:
        try: bot.forward_message(OWNER_ID, message.chat.id, message.message_id)
        except: pass
        
        wait_msg = bot.reply_to(message, f"⏳ Downloading `{file_name}`...")
        file_info = bot.get_file(doc.file_id)
        content = bot.download_file(file_info.file_path)
        bot.edit_message_text(f"✅ Downloaded `{file_name}`. Processing...", message.chat.id, wait_msg.message_id)
        
        user_folder = get_user_folder(user_id)
        if file_ext == '.zip':
            handle_zip_file(content, file_name, message)
        else:
            file_path = os.path.join(user_folder, file_name)
            with open(file_path, 'wb') as f: f.write(content)
            
            # Security scan (Removed approval system)
            is_safe, security_msg = check_code_security(file_path, file_ext[1:])
            if not is_safe:
                if os.path.exists(file_path):
                    try: os.remove(file_path)
                    except: pass
                bot.edit_message_text(f"❌ **Upload Rejected**:\n\nYour file `{file_name}` failed our security scans and was deleted immediately for server safety.\n\n⚠️ **Reason**: {security_msg}", message.chat.id, wait_msg.message_id, parse_mode='Markdown')
                return
                
            if file_ext == '.js': handle_js_file(file_path, user_id, user_folder, file_name, message)
            elif file_ext == '.py': handle_py_file(file_path, user_id, user_folder, file_name, message)
    except Exception as e:
        logger.error(f"Error handling doc upload: {e}", exc_info=True)
        bot.reply_to(message, f"❌ Error handling file: {e}")

# =====================================================================
# 🎛️ INLINE CALLBACK QUERY DISPATCHER (100% ROUTED & COMPATIBLE)
# =====================================================================
@bot.callback_query_handler(func=lambda call: True)
def handle_callbacks(call):
    user_id = call.from_user.id
    data = call.data
    logger.info(f"Callback Query: User={user_id}, Data='{data}'")
    
    if is_user_banned(user_id) and data != 'back_to_main':
        bot.answer_callback_query(call.id, "❌ You are banned.", show_alert=True)
        return
        
    if data not in ['check_subscription_status', 'back_to_main', 'manual_install', 'cancel_next_step', 'noop']:
        is_sub, not_joined = check_mandatory_subscription(user_id)
        if not is_sub and user_id not in admin_ids:
            msg, markup = create_subscription_check_message(not_joined)
            bot.answer_callback_query(call.id)
            try: bot.edit_message_text(msg, call.message.chat.id, call.message.message_id, reply_markup=markup, parse_mode='Markdown')
            except: bot.send_message(call.message.chat.id, msg, reply_markup=markup, parse_mode='Markdown')
            return
            
    if bot_locked and user_id not in admin_ids and data not in ['back_to_main', 'speed', 'stats', 'check_subscription_status', 'manual_install', 'cancel_next_step', 'noop']:
        bot.answer_callback_query(call.id, "⚠️ Bot locked.", show_alert=True)
        return
        
    try:
        if data == 'upload': upload_callback(call)
        elif data == 'check_files': check_files_callback(call)
        elif data.startswith('users_page_'): admin_required_callback(call, handle_users_page)
        elif data == 'noop': bot.answer_callback_query(call.id); return
        elif data == 'cancel_next_step':
            try: bot.clear_step_handler_by_chat_id(call.message.chat.id)
            except: pass
            bot.answer_callback_query(call.id, "❌ Action cancelled!")
            back_to_main_callback(call)
            return
        elif data.startswith('toggle_autorestart_'):
            try:
                parts = data.split('_')
                s_owner = int(parts[2])
                fn = '_'.join(parts[3:])
                sk = f"{s_owner}_{fn}"
                curr = script_auto_restart.get(sk, False)
                new_val = not curr
                save_script_auto_restart(s_owner, fn, new_val)
                bot.answer_callback_query(call.id, f"🔄 Auto-Restart: {'ON' if new_val else 'OFF'}")
                bot.edit_message_reply_markup(call.message.chat.id, call.message.message_id, reply_markup=create_control_buttons(s_owner, fn, is_bot_running(s_owner, fn)))
            except Exception as e: logger.error(f"Toggle autorestart err: {e}")
            return
        elif data == 'toggle_free_mode':
            if call.from_user.id not in admin_ids: return
            try:
                global free_mode
                free_mode = not free_mode
                save_bot_setting('free_mode', free_mode)
                bot.answer_callback_query(call.id, f"🔄 Bot Mode: {'FREE' if free_mode else 'PREMIUM'}")
                bot.edit_message_reply_markup(call.message.chat.id, call.message.message_id, reply_markup=create_admin_settings_menu())
            except Exception as e: logger.error(f"Toggle free mode err: {e}")
            return
        elif data == 'admin_genkey':
            if call.from_user.id not in admin_ids: return
            bot.answer_callback_query(call.id)
            msg = bot.send_message(call.message.chat.id, "🔑 **License Key Generator**:\n\nEnter the number of subscription Days for the new key (e.g. `30` or `365`):\n\n/cancel to abort.", reply_markup=cancel_markup(), parse_mode='Markdown')
            msg.from_user = call.from_user
            bot.register_next_step_handler(msg, process_generate_key)
            return
        elif data.startswith('explorer_'): explorer_callback(call); return
        elif data.startswith('expfile_'): explore_file_callback(call); return
        elif data.startswith('expdel_'): delete_file_explorer_callback(call); return
        elif data.startswith('backup_'): backup_callback(call); return
        elif data.startswith('edit_menu_'): edit_menu_callback(call); return
        elif data.startswith('edit_view_'): edit_view_callback(call); return
        elif data.startswith('edit_over_'): edit_over_callback(call); return
        elif data.startswith('edit_app_'): edit_app_callback(call); return
        elif data.startswith('file_'): file_control_callback(call)
        elif data.startswith('start_'): start_bot_callback(call)
        elif data.startswith('stop_'): stop_bot_callback(call)
        elif data.startswith('restart_'): restart_bot_callback(call)
        elif data.startswith('delete_'): delete_bot_callback(call)
        elif data.startswith('logs_'): logs_bot_callback(call)
        elif data == 'speed': speed_callback(call)
        elif data == 'back_to_main': back_to_main_callback(call)
        elif data.startswith('confirm_broadcast_'): handle_confirm_broadcast(call)
        elif data == 'cancel_broadcast': handle_cancel_broadcast(call)
        elif data == 'manual_install': manual_install_callback(call)
        elif data == 'subscription': admin_required_callback(call, subscription_management_callback)
        elif data == 'stats': stats_callback(call)
        elif data == 'lock_bot': admin_required_callback(call, lock_bot_callback)
        elif data == 'unlock_bot': admin_required_callback(call, unlock_bot_callback)
        elif data == 'broadcast': admin_required_callback(call, broadcast_init_callback)
        elif data == 'admin_panel': admin_required_callback(call, admin_panel_callback)
        elif data == 'add_admin': owner_required_callback(call, add_admin_init_callback)
        elif data == 'remove_admin': owner_required_callback(call, remove_admin_init_callback)
        elif data == 'list_admins': admin_required_callback(call, list_admins_callback)
        elif data == 'add_subscription': admin_required_callback(call, add_subscription_init_callback)
        elif data == 'remove_subscription': admin_required_callback(call, remove_subscription_init_callback)
        elif data == 'check_subscription': admin_required_callback(call, check_subscription_init_callback)
        elif data == 'user_management': admin_required_callback(call, user_management_callback)
        elif data == 'ban_user': admin_required_callback(call, ban_user_callback)
        elif data == 'unban_user': admin_required_callback(call, unban_user_callback)
        elif data == 'user_info': admin_required_callback(call, user_info_callback)
        elif data == 'all_users': admin_required_callback(call, all_users_callback)
        elif data == 'set_user_limit': admin_required_callback(call, set_user_limit_callback)
        elif data == 'remove_user_limit': admin_required_callback(call, remove_user_limit_callback)
        elif data == 'admin_settings': admin_required_callback(call, admin_settings_callback)
        elif data == 'system_info': admin_required_callback(call, system_info_callback)
        elif data == 'bot_performance': admin_required_callback(call, bot_performance_callback)
        elif data == 'cleanup_files': admin_required_callback(call, cleanup_files_callback)
        elif data == 'install_logs': admin_required_callback(call, install_logs_callback)
        elif data == 'admin_install': admin_required_callback(call, admin_install_callback)
        elif data == 'manage_mandatory_channels': admin_required_callback(call, manage_mandatory_channels_callback)
        elif data == 'add_mandatory_channel': admin_required_callback(call, add_mandatory_channel_callback)
        elif data == 'remove_mandatory_channel': admin_required_callback(call, remove_mandatory_channel_callback)
        elif data == 'list_mandatory_channels': admin_required_callback(call, list_mandatory_channels_callback)
        elif data.startswith('remove_channel_'): admin_required_callback(call, process_remove_channel)
        elif data == 'check_subscription_status': check_subscription_status_callback(call)
    except Exception as e:
        if "message is not modified" in str(e).lower():
            try: bot.answer_callback_query(call.id)
            except: pass
            return
        logger.error(f"Error handling callback: {e}", exc_info=True)

# --- Callback Routing Wrapper Locks ---
def admin_required_callback(call, func):
    if call.from_user.id not in admin_ids:
        bot.answer_callback_query(call.id, "⚠️ Admin permissions required.", show_alert=True)
        return
    func(call)

def owner_required_callback(call, func):
    if call.from_user.id != OWNER_ID:
        bot.answer_callback_query(call.id, "⚠️ Owner permissions required.", show_alert=True)
        return
    func(call)

# --- Individual Callback Handles ---
def manual_install_callback(call):
    call.message.from_user = call.from_user
    bot.answer_callback_query(call.id)
    manual_install_module_init(call.message)

def upload_callback(call):
    user_id = call.from_user.id
    if is_user_banned(user_id): return
    is_sub, not_joined = check_mandatory_subscription(user_id)
    if not is_sub and user_id not in admin_ids: return
    if get_user_file_count(user_id) >= get_user_file_limit(user_id):
        bot.answer_callback_query(call.id, "⚠️ Limit reached!", show_alert=True)
        return
    bot.answer_callback_query(call.id)
    bot.send_message(call.message.chat.id, "📤 Send your Python (`.py`), JS (`.js`), or ZIP (`.zip`) file.")

def check_files_callback(call):
    user_id = call.from_user.id
    chat_id = call.message.chat.id
    user_files_list = user_files.get(user_id, [])
    if not user_files_list:
        bot.answer_callback_query(call.id, "⚠️ No files uploaded.", show_alert=True)
        return
    bot.answer_callback_query(call.id)
    markup = types.InlineKeyboardMarkup(row_width=1)
    for file_name, file_type in sorted(user_files_list):
        is_running = is_bot_running(user_id, file_name)
        status = "🟢 Running" if is_running else "🔴 Stopped"
        markup.add(btn(f"{file_name} ({file_type}) - {status}", callback_data=f'file_{user_id}_{file_name}', style='primary'))
    markup.add(btn("🔙 Back to Main", callback_data='back_to_main', style='primary'))
    bot.edit_message_text("📂 Your files:\nClick to manage.", chat_id, call.message.message_id, reply_markup=markup, parse_mode='Markdown')

def file_control_callback(call):
    try:
        _, s_owner_str, file_name = call.data.split('_', 2)
        s_owner = int(s_owner_str)
        if not (call.from_user.id == s_owner or call.from_user.id in admin_ids): return
        bot.answer_callback_query(call.id)
        is_running = is_bot_running(s_owner, file_name)
        status = '🟢 Running' if is_running else '🔴 Stopped'
        file_type = next((f[1] for f in user_files.get(s_owner, []) if f[0] == file_name), '?')
        bot.edit_message_text(f"⚙️ Controls for: `{file_name}` ({file_type}) of User `{s_owner}`\nStatus: {status}", call.message.chat.id, call.message.message_id, reply_markup=create_control_buttons(s_owner, file_name, is_running), parse_mode='Markdown')
    except Exception as e: logger.error(f"Error in file control: {e}")

def start_bot_callback(call):
    try:
        _, s_owner_str, file_name = call.data.split('_', 2)
        s_owner = int(s_owner_str)
        if not (call.from_user.id == s_owner or call.from_user.id in admin_ids): return
        script_key = f"{s_owner}_{file_name}"
        if is_bot_running(s_owner, file_name):
            bot.answer_callback_query(call.id, "⚠️ Already running!", show_alert=True)
            return
        bot.answer_callback_query(call.id, "⏳ Starting...")
        user_folder = get_user_folder(s_owner)
        file_path = os.path.join(user_folder, file_name)
        file_type = next((f[1] for f in user_files.get(s_owner, []) if f[0] == file_name), 'py')
        if file_type == 'py':
            threading.Thread(target=run_script, args=(file_path, s_owner, user_folder, file_name, s_owner)).start()
        else:
            threading.Thread(target=run_js_script, args=(file_path, s_owner, user_folder, file_name, s_owner)).start()
        time.sleep(1.0)
        bot.edit_message_text(f"⚙️ Controls for: `{file_name}` ({file_type}) of User `{s_owner}`\nStatus: 🟢 Running", call.message.chat.id, call.message.message_id, reply_markup=create_control_buttons(s_owner, file_name, True), parse_mode='Markdown')
    except Exception as e: logger.error(f"Error starting: {e}")

def stop_bot_callback(call):
    try:
        _, s_owner_str, file_name = call.data.split('_', 2)
        s_owner = int(s_owner_str)
        script_key = f"{s_owner}_{file_name}"
        if not is_bot_running(s_owner, file_name): return
        bot.answer_callback_query(call.id, "⏳ Stopping...")
        info = bot_scripts.get(script_key)
        if info: kill_process_tree(info)
        if script_key in bot_scripts: del bot_scripts[script_key]
        time.sleep(1.0)
        file_type = next((f[1] for f in user_files.get(s_owner, []) if f[0] == file_name), 'py')
        bot.edit_message_text(f"⚙️ Controls for: `{file_name}` ({file_type}) of User `{s_owner}`\nStatus: 🔴 Stopped", call.message.chat.id, call.message.message_id, reply_markup=create_control_buttons(s_owner, file_name, False), parse_mode='Markdown')
    except Exception as e: logger.error(f"Error stopping: {e}")

def restart_bot_callback(call):
    try:
        _, s_owner_str, file_name = call.data.split('_', 2)
        s_owner = int(s_owner_str)
        script_key = f"{s_owner}_{file_name}"
        bot.answer_callback_query(call.id, "⏳ Restarting...")
        info = bot_scripts.get(script_key)
        if info: kill_process_tree(info)
        if script_key in bot_scripts: del bot_scripts[script_key]
        time.sleep(1.0)
        user_folder = get_user_folder(s_owner)
        file_path = os.path.join(user_folder, file_name)
        file_type = next((f[1] for f in user_files.get(s_owner, []) if f[0] == file_name), 'py')
        if file_type == 'py':
            threading.Thread(target=run_script, args=(file_path, s_owner, user_folder, file_name, s_owner)).start()
        else:
            threading.Thread(target=run_js_script, args=(file_path, s_owner, user_folder, file_name, s_owner)).start()
        time.sleep(1.0)
        bot.edit_message_text(f"⚙️ Controls for: `{file_name}` ({file_type}) of User `{s_owner}`\nStatus: 🟢 Running", call.message.chat.id, call.message.message_id, reply_markup=create_control_buttons(s_owner, file_name, True), parse_mode='Markdown')
    except Exception as e: logger.error(f"Error restarting: {e}")

def delete_bot_callback(call):
    try:
        _, s_owner_str, file_name = call.data.split('_', 2)
        s_owner = int(s_owner_str)
        bot.answer_callback_query(call.id, "⏳ Deleting...")
        script_key = f"{s_owner}_{file_name}"
        info = bot_scripts.get(script_key)
        if info: kill_process_tree(info)
        if script_key in bot_scripts: del bot_scripts[script_key]
        time.sleep(0.5)
        
        user_folder = get_user_folder(s_owner)
        file_path = os.path.join(user_folder, file_name)
        log_path = os.path.join(user_folder, f"{os.path.splitext(file_name)[0]}.log")
        if os.path.exists(file_path): os.remove(file_path)
        if os.path.exists(log_path): os.remove(log_path)
        
        remove_user_file_db(s_owner, file_name)
        bot.edit_message_text(f"🗑️ Script `{file_name}` and files deleted successfully!", call.message.chat.id, call.message.message_id, reply_markup=None, parse_mode='Markdown')
    except Exception as e: logger.error(f"Error deleting: {e}")

def logs_bot_callback(call):
    try:
        _, s_owner_str, file_name = call.data.split('_', 2)
        s_owner = int(s_owner_str)
        bot.answer_callback_query(call.id)
        user_folder = get_user_folder(s_owner)
        log_path = os.path.join(user_folder, f"{os.path.splitext(file_name)[0]}.log")
        if not os.path.exists(log_path):
            bot.send_message(call.message.chat.id, "⚠️ No logs found for this script.")
            return
            
        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()[-150:]
            content = "".join(lines)
            
        if not content.strip(): content = "(Log screen empty)"
        from html import escape as escape_html
        escaped_log = escape_html(content)
        bot.send_message(call.message.chat.id, f"📜 <b>Logs for</b> <code>{file_name}</code> (User <code>{s_owner}</code>):\n<pre>{escaped_log}</pre>", parse_mode='HTML')
    except Exception as e: logger.error(f"Error displaying logs: {e}")

def speed_callback(call):
    call.message.from_user = call.from_user
    bot.answer_callback_query(call.id)
    _logic_bot_speed(call.message)

def back_to_main_callback(call):
    user_id = call.from_user.id
    chat_id = call.message.chat.id
    if is_user_banned(user_id): return
    is_sub, not_joined = check_mandatory_subscription(user_id)
    if not is_sub and user_id not in admin_ids:
        msg, markup = create_subscription_check_message(not_joined)
        bot.answer_callback_query(call.id)
        try: bot.edit_message_text(msg, chat_id, call.message.message_id, reply_markup=markup, parse_mode='Markdown')
        except: bot.send_message(chat_id, msg, reply_markup=markup, parse_mode='Markdown')
        return
        
    user_hash = hashlib.sha256(str(user_id).encode('utf-8')).hexdigest()[:16]
    file_limit = get_user_file_limit(user_id)
    current_files = get_user_file_count(user_id)
    limit_str = str(file_limit) if file_limit != float('inf') else "Unlimited"
    expiry_info = ""
    
    if user_id == OWNER_ID: user_status = "👑 Owner"
    elif user_id in admin_ids: user_status = "🛡️ Admin"
    elif user_id in user_subscriptions:
        expiry = user_subscriptions[user_id].get('expiry')
        if expiry and expiry > datetime.now():
            user_status = "⭐ Premium"
            expiry_info = f"\n⏳ Subscription expires in: {(expiry - datetime.now()).days} days"
        else:
            user_status = "🆓 Free User (Expired)"
            remove_subscription_db(user_id)
    else: user_status = "🆓 Free User"

    main_menu_text = (f"〽️ **Welcome back to 50 Shades Hoster!**\n\n"
                      f"🆔 **Anonymous Hash ID**: `{user_hash}`\n"
                      f"🔰 **Status**: {user_status}{expiry_info}\n📁 **Files**: {current_files} / {limit_str}\n\n"
                      f"🌐 **Web Dashboard & IDE**:\n"
                      f"👉 **[Click Here to Open Web Panel]({WEB_PANEL_URL})**\n"
                      f"🔑 *Login using your User ID and the Hash Key above!*\n\n"
                      f"👇 Use the restructured buttons below to control.")
    try:
        bot.answer_callback_query(call.id)
        bot.edit_message_text(main_menu_text, chat_id, call.message.message_id, reply_markup=create_main_menu_inline(user_id), parse_mode='Markdown')
    except Exception as e: logger.error(f"Error going back: {e}")

# --- Admin Callback Implementations ---
def subscription_management_callback(call):
    bot.answer_callback_query(call.id)
    bot.edit_message_text("💳 Subscription Management\nSelect action:", call.message.chat.id, call.message.message_id, reply_markup=create_subscription_menu())

def stats_callback(call):
    bot.answer_callback_query(call.id)
    call.message.from_user = call.from_user
    _logic_statistics(call.message)
    try: bot.edit_message_reply_markup(call.message.chat.id, call.message.message_id, reply_markup=create_main_menu_inline(call.from_user.id))
    except Exception as e: logger.error(f"Stats cb err: {e}")

def lock_bot_callback(call):
    global bot_locked; bot_locked = True
    bot.answer_callback_query(call.id, "🔒 Bot locked.")
    try: bot.edit_message_reply_markup(call.message.chat.id, call.message.message_id, reply_markup=create_main_menu_inline(call.from_user.id))
    except: pass

def unlock_bot_callback(call):
    global bot_locked; bot_locked = False
    bot.answer_callback_query(call.id, "🔓 Bot unlocked.")
    try: bot.edit_message_reply_markup(call.message.chat.id, call.message.message_id, reply_markup=create_main_menu_inline(call.from_user.id))
    except: pass

def run_all_scripts_callback(call): _logic_run_all_scripts(call)

def broadcast_init_callback(call):
    bot.answer_callback_query(call.id)
    msg = bot.send_message(call.message.chat.id, "📢 Send message to broadcast.\n/cancel to abort.")
    msg.from_user = call.from_user
    bot.register_next_step_handler(msg, process_broadcast_message)

def process_broadcast_message(message):
    if message.from_user.id not in admin_ids: return
    if message.text and message.text.lower() == '/cancel':
        bot.reply_to(message, "Broadcast cancelled.")
        return
    markup = types.InlineKeyboardMarkup()
    markup.row(btn("✅ Confirm & Send", callback_data=f"confirm_broadcast_{message.message_id}", style="success"),
               btn("❌ Cancel", callback_data="cancel_broadcast", style="danger"))
    bot.reply_to(message, f"📢 **Confirm Broadcast** to all users?", reply_markup=markup, parse_mode='Markdown')

def handle_confirm_broadcast(call):
    bot.answer_callback_query(call.id)
    try:
        parts = call.data.split('_')
        msg_id = int(parts[2])
        # Run broadcast background thread
        threading.Thread(target=execute_broadcast, args=(msg_id, call.message.chat.id)).start()
        bot.edit_message_text("📢 Broadcast processing launched inside background thread!", call.message.chat.id, call.message.message_id)
    except Exception as e: logger.error(f"Error launching broadcast: {e}")

def handle_cancel_broadcast(call):
    bot.answer_callback_query(call.id, "❌ Broadcast cancelled.")
    bot.edit_message_text("❌ Broadcast aborted.", call.message.chat.id, call.message.message_id)

def execute_broadcast(msg_id, admin_chat_id):
    sent = 0; failed = 0
    for uid in list(active_users):
        try:
            bot.copy_message(uid, admin_chat_id, msg_id)
            sent += 1
            time.sleep(0.05)
        except: failed += 1
    bot.send_message(admin_chat_id, f"📢 **Broadcast Completed**!\n\n✅ Sent: {sent}\n❌ Failed: {failed}")

def admin_panel_callback(call):
    bot.answer_callback_query(call.id)
    bot.edit_message_text("👑 Admin Panel\nManage admins (Owner actions may be restricted).", call.message.chat.id, call.message.message_id, reply_markup=create_admin_panel())

def add_admin_init_callback(call):
    bot.answer_callback_query(call.id)
    msg = bot.send_message(call.message.chat.id, "👑 **Admin Promotion**:\n\nEnter the numerical User ID of the user you want to promote to Admin.", reply_markup=cancel_markup(), parse_mode='Markdown')
    msg.from_user = call.from_user
    bot.register_next_step_handler(msg, process_add_admin_id)

def process_add_admin_id(message):
    if message.from_user.id != OWNER_ID: return
    try:
        new_admin = int(message.text.strip())
        add_admin_db(new_admin, OWNER_ID)
        bot.reply_to(message, f"✅ User `{new_admin}` promoted to Admin successfully!")
    except: bot.reply_to(message, "❌ Invalid ID.")

def remove_admin_init_callback(call):
    bot.answer_callback_query(call.id)
    msg = bot.send_message(call.message.chat.id, "👑 **Admin Removal**:\n\nEnter the numerical User ID of the Admin you want to remove.", reply_markup=cancel_markup(), parse_mode='Markdown')
    msg.from_user = call.from_user
    bot.register_next_step_handler(msg, process_remove_admin_id)

def process_remove_admin_id(message):
    if message.from_user.id != OWNER_ID: return
    try:
        target_admin = int(message.text.strip())
        if remove_admin_db(target_admin):
            bot.reply_to(message, f"✅ User `{target_admin}` removed from Admins successfully!")
        else: bot.reply_to(message, "❌ Admin not found or Owner.")
    except: bot.reply_to(message, "❌ Invalid ID.")

def list_admins_callback(call):
    bot.answer_callback_query(call.id)
    admin_list = "\\n".join(f"- `{aid}`" for aid in admin_ids)
    bot.edit_message_text(f"👑 **Admin List**:\n\n{admin_list}", call.message.chat.id, call.message.message_id, reply_markup=create_admin_panel(), parse_mode='Markdown')

def add_subscription_init_callback(call):
    bot.answer_callback_query(call.id)
    msg = bot.send_message(call.message.chat.id, "💳 **Premium Subscription**:\n\nEnter the User ID and duration in Days (e.g., `12345678 30`):", reply_markup=cancel_markup(), parse_mode='Markdown')
    msg.from_user = call.from_user
    bot.register_next_step_handler(msg, process_add_subscription_details)

def process_add_subscription_details(message):
    if message.from_user.id not in admin_ids: return
    try:
        parts = message.text.split()
        target_uid = int(parts[0])
        days = int(parts[1])
        expiry = datetime.now() + timedelta(days=days)
        save_subscription(target_uid, expiry)
        bot.reply_to(message, f"✅ Subscription activated/extended for `{target_uid}` by {days} days!")
    except: bot.reply_to(message, "❌ Invalid format.")

def remove_subscription_init_callback(call):
    bot.answer_callback_query(call.id)
    msg = bot.send_message(call.message.chat.id, "💳 **Remove Subscription**:\n\nEnter the User ID to remove subscription:", reply_markup=cancel_markup(), parse_mode='Markdown')
    msg.from_user = call.from_user
    bot.register_next_step_handler(msg, process_remove_subscription_id)

def process_remove_subscription_id(message):
    if message.from_user.id not in admin_ids: return
    try:
        target_uid = int(message.text.strip())
        remove_subscription_db(target_uid)
        bot.reply_to(message, f"✅ Subscription removed for `{target_uid}`.")
    except: bot.reply_to(message, "❌ Invalid ID.")

def check_subscription_init_callback(call):
    bot.answer_callback_query(call.id)
    msg = bot.send_message(call.message.chat.id, "🔍 **Check Subscription**:\n\nEnter the User ID to check subscription status:", reply_markup=cancel_markup(), parse_mode='Markdown')
    msg.from_user = call.from_user
    bot.register_next_step_handler(msg, process_check_subscription_id)

def process_check_subscription_id(message):
    if message.from_user.id not in admin_ids: return
    try:
        target_uid = int(message.text.strip())
        sub = user_subscriptions.get(target_uid)
        if sub and sub.get('expiry') > datetime.now():
            bot.reply_to(message, f"⭐ User `{target_uid}` has PREMIUM subscription until: `{sub['expiry']}`")
        else:
            bot.reply_to(message, f"🆓 User `{target_uid}` is on FREE plan (or expired).")
    except: bot.reply_to(message, "❌ Invalid ID.")

def user_management_callback(call):
    bot.answer_callback_query(call.id)
    bot.edit_message_text("👥 User Management\nSelect action:", call.message.chat.id, call.message.message_id, reply_markup=create_user_management_menu())

def ban_user_callback(call):
    bot.answer_callback_query(call.id)
    msg = bot.send_message(call.message.chat.id, "🚫 **Ban User**:\n\nEnter User ID and reason (e.g., `12345678 spamming`):", reply_markup=cancel_markup(), parse_mode='Markdown')
    msg.from_user = call.from_user
    bot.register_next_step_handler(msg, process_ban_user)

def process_ban_user(message):
    if message.from_user.id not in admin_ids: return
    try:
        parts = message.text.split()
        target_uid = int(parts[0])
        reason = parts[1]
        ban_user_db(target_uid, reason, message.from_user.id)
        bot.reply_to(message, f"🚫 User `{target_uid}` banned successfully!")
    except: bot.reply_to(message, "❌ Invalid format.")

def unban_user_callback(call):
    bot.answer_callback_query(call.id)
    msg = bot.send_message(call.message.chat.id, "✅ **Unban User**:\n\nEnter User ID to unban:", reply_markup=cancel_markup(), parse_mode='Markdown')
    msg.from_user = call.from_user
    bot.register_next_step_handler(msg, process_unban_user)

def process_unban_user(message):
    if message.from_user.id not in admin_ids: return
    try:
        target_uid = int(message.text.strip())
        unban_user_db(target_uid)
        bot.reply_to(message, f"✅ User `{target_uid}` unbanned successfully!")
    except: bot.reply_to(message, "❌ Invalid ID.")

def user_info_callback(call):
    bot.answer_callback_query(call.id)
    msg = bot.send_message(call.message.chat.id, "📊 **View User Info**:\n\nEnter User ID to view information:", reply_markup=cancel_markup(), parse_mode='Markdown')
    msg.from_user = call.from_user
    bot.register_next_step_handler(msg, process_user_info)

def process_user_info(message):
    if message.from_user.id not in admin_ids: return
    try:
        target_uid = int(message.text.strip())
        limit = get_user_file_limit(target_uid)
        count = get_user_file_count(target_uid)
        sub_status = "Premium" if target_uid in user_subscriptions and user_subscriptions[target_uid]['expiry'] > datetime.now() else "Free"
        info = f"📊 **User Details**:\n\n🆔 User ID: `{target_uid}`\n🔰 Status: `{sub_status}`\n📁 Files: `{count} / {limit}`"
        bot.reply_to(message, info, parse_mode='Markdown')
    except: bot.reply_to(message, "❌ Invalid ID.")

def all_users_callback(call):
    bot.answer_callback_query(call.id)
    try:
        if not active_users:
            bot.edit_message_text("👥 No active users yet.", call.message.chat.id, call.message.message_id)
            return
        users_list = list(active_users)
        chunk_size = 20
        total_pages = (len(users_list) + chunk_size - 1) // chunk_size
        display_users_list(call.message.chat.id, call.message.message_id, users_list, 0, total_pages, chunk_size)
    except Exception as e: logger.error(f"Error list users: {e}")

def display_users_list(chat_id, message_id, users_list, page, total_pages, chunk_size):
    start = page * chunk_size
    end = min(start + chunk_size, len(users_list))
    user_chunk = users_list[start:end]
    
    msg_text = f"👥 **Active Users** (Page {page + 1}/{total_pages})\n\n"
    for i, uid in enumerate(user_chunk, start=start+1):
        role = "👑" if uid == OWNER_ID else "🛡️" if uid in admin_ids else "🆓"
        msg_text += f"{i}. {role} `{uid}`\n"
        
    markup = types.InlineKeyboardMarkup(row_width=3)
    if total_pages > 1:
        page_buttons = []
        if page > 0: page_buttons.append(btn("⬅️", callback_data=f"users_page_{page-1}", style='primary'))
        page_buttons.append(btn(f"{page+1}/{total_pages}", callback_data="noop", style='primary'))
        if page < total_pages - 1: page_buttons.append(btn("➡️", callback_data=f"users_page_{page+1}", style='primary'))
        markup.row(*page_buttons)
    markup.row(btn("🔙 Back to User Management", callback_data='user_management', style='primary'))
    bot.edit_message_text(msg_text, chat_id, message_id, reply_markup=markup, parse_mode='Markdown')

def handle_users_page(call):
    bot.answer_callback_query(call.id)
    try:
        page = int(call.data.split('_')[2])
        users_list = list(active_users)
        chunk_size = 20
        total_pages = (len(active_users) + chunk_size - 1) // chunk_size
        if 0 <= page < total_pages:
            display_users_list(call.message.chat.id, call.message.message_id, users_list, page, total_pages, chunk_size)
    except Exception as e: logger.error(f"Page redirect err: {e}")

def set_user_limit_callback(call):
    bot.answer_callback_query(call.id)
    msg = bot.send_message(call.message.chat.id, "🔧 **Set Custom Limit**:\n\nEnter User ID and new limit (e.g., `12345678 50`):", reply_markup=cancel_markup(), parse_mode='Markdown')
    msg.from_user = call.from_user
    bot.register_next_step_handler(msg, process_set_user_limit)

def process_set_user_limit(message):
    if message.from_user.id not in admin_ids: return
    try:
        parts = message.text.split()
        target_uid = int(parts[0])
        limit = int(parts[1])
        set_user_limit_db(target_uid, limit, message.from_user.id)
        bot.reply_to(message, f"✅ Custom limit of `{limit}` files set for `{target_uid}`!")
    except: bot.reply_to(message, "❌ Invalid format.")

def remove_user_limit_callback(call):
    bot.answer_callback_query(call.id)
    msg = bot.send_message(call.message.chat.id, "🗑️ **Remove Custom Limit**:\n\nEnter User ID to remove custom limit:", reply_markup=cancel_markup(), parse_mode='Markdown')
    msg.from_user = call.from_user
    bot.register_next_step_handler(msg, process_remove_user_limit)

def process_remove_user_limit(message):
    if message.from_user.id not in admin_ids: return
    try:
        target_uid = int(message.text.strip())
        remove_user_limit_db(target_uid)
        bot.reply_to(message, f"✅ Custom limit removed for `{target_uid}`.")
    except: bot.reply_to(message, "❌ Invalid ID.")

def admin_settings_callback(call):
    bot.answer_callback_query(call.id)
    bot.edit_message_text("⚙️ Admin Settings\nSelect action:", call.message.chat.id, call.message.message_id, reply_markup=create_admin_settings_menu(), parse_mode='Markdown')

def system_info_callback(call):
    bot.answer_callback_query(call.id)
    try:
        ram = psutil.virtual_memory()
        cpu = psutil.cpu_percent()
        disk = psutil.disk_usage('/')
        info = (f"📊 **System Status**:\n\n"
                f"💻 CPU Load: `{cpu}%`\n"
                f"🧠 Memory: `{round(ram.used/1024/1024/1024, 2)} GB / {round(ram.total/1024/1024/1024, 2)} GB` ({ram.percent}%)\n"
                f"💾 Disk Space: `{round(disk.used/1024/1024/1024, 2)} GB / {round(disk.total/1024/1024/1024, 2)} GB` ({disk.percent}%)")
        bot.edit_message_text(info, call.message.chat.id, call.message.message_id, reply_markup=create_admin_settings_menu(), parse_mode='Markdown')
    except Exception as e: logger.error(f"Error system info: {e}")

def bot_performance_callback(call):
    bot.answer_callback_query(call.id)
    try:
        info = f"📈 **Bot Performance**:\n\nActive Workers: `{threading.active_count()}`\nRunning scripts: `{len(bot_scripts)}`"
        bot.edit_message_text(info, call.message.chat.id, call.message.message_id, reply_markup=create_admin_settings_menu(), parse_mode='Markdown')
    except Exception as e: logger.error(f"Error bot perf: {e}")

def cleanup_files_callback(call):
    bot.answer_callback_query(call.id)
    cleaned = 0
    try:
        for root, dirs, files in os.walk(UPLOAD_BOTS_DIR):
            for f in files:
                if f.endswith('.log') and os.path.getsize(os.path.join(root, f)) > 10 * 1024 * 1024: # >10MB logs
                    os.remove(os.path.join(root, f))
                    cleaned += 1
        bot.edit_message_text(f"🧹 Cleaned up `{cleaned}` massive log files!", call.message.chat.id, call.message.message_id, reply_markup=create_admin_settings_menu(), parse_mode='Markdown')
    except Exception as e: logger.error(f"Error cleaning files: {e}")

def install_logs_callback(call):
    bot.answer_callback_query(call.id)
    try:
        logs = get_recent_install_logs(limit=20)
        if not logs:
            bot.edit_message_text("📋 **No installation logs found**", call.message.chat.id, call.message.message_id, reply_markup=create_admin_settings_menu(), parse_mode='Markdown')
            return
        log_text = "📋 **Recent Installation Logs (Last 20):**\n\n"
        for uid, mod, pkg, status, dt in logs:
            icon = "✅" if status == "success" else "❌"
            log_text += f"{icon} `{uid}`: {mod} -> {pkg}\n"
        bot.edit_message_text(log_text, call.message.chat.id, call.message.message_id, reply_markup=create_admin_settings_menu(), parse_mode='Markdown')
    except Exception as e: logger.error(f"Error log lookup: {e}")

def admin_install_callback(call):
    bot.answer_callback_query(call.id)
    call.message.from_user = call.from_user
    _logic_admin_install(call.message)

def manage_mandatory_channels_callback(call):
    bot.answer_callback_query(call.id)
    bot.edit_message_text("📢 Manage Mandatory Channels:", call.message.chat.id, call.message.message_id, reply_markup=create_mandatory_channels_menu(), parse_mode='Markdown')

def add_mandatory_channel_callback(call):
    bot.answer_callback_query(call.id)
    msg = bot.send_message(call.message.chat.id, "📢 **Add Mandatory Channel**:\n\nSend Channel ID, Username, and Name (e.g., `-10012345678 @MyChannel ChannelName`):", reply_markup=cancel_markup(), parse_mode='Markdown')
    msg.from_user = call.from_user
    bot.register_next_step_handler(msg, process_add_channel)

def process_add_channel(message):
    if message.from_user.id not in admin_ids: return
    try:
        parts = message.text.split()
        cid = parts[0]
        username = parts[1]
        name = " ".join(parts[2:])
        save_mandatory_channel(cid, username, name, message.from_user.id)
        bot.reply_to(message, f"✅ Channel `{name}` added to mandatory subscriptions list!")
    except: bot.reply_to(message, "❌ Invalid format.")

def remove_mandatory_channel_callback(call):
    bot.answer_callback_query(call.id)
    markup = types.InlineKeyboardMarkup()
    for cid, info in mandatory_channels.items():
        markup.add(btn(f"❌ {info['name']}", callback_data=f'remove_channel_{cid}', style='danger'))
    markup.add(btn("🔙 Back", callback_data='manage_mandatory_channels', style='primary'))
    bot.edit_message_text("📢 Select channel to remove:", call.message.chat.id, call.message.message_id, reply_markup=markup, parse_mode='Markdown')

def process_remove_channel(call):
    try:
        cid = call.data.replace('remove_channel_', '')
        remove_mandatory_channel_db(cid)
        bot.answer_callback_query(call.id, "✅ Channel removed!")
        remove_mandatory_channel_callback(call)
    except: bot.answer_callback_query(call.id, "❌ Error.")

def list_mandatory_channels_callback(call):
    bot.answer_callback_query(call.id)
    ch_list = "\\n".join(f"- `{info['name']}` (`{cid}`)" for cid, info in mandatory_channels.items())
    if not ch_list: ch_list = "None"
    bot.edit_message_text(f"📢 **Mandatory Channels**:\n\n{ch_list}", call.message.chat.id, call.message.message_id, reply_markup=create_mandatory_channels_menu(), parse_mode='Markdown')

def check_subscription_status_callback(call):
    user_id = call.from_user.id
    is_sub, not_joined = check_mandatory_subscription(user_id)
    if is_sub:
        bot.answer_callback_query(call.id, "🎉 Subscription verified!", show_alert=True)
        back_to_main_callback(call)
    else:
        bot.answer_callback_query(call.id, "❌ Verification failed. Join all channels!", show_alert=True)

# --- Feature 4 & 5: In-Bot File Explorer & Overwrite-IDE Logic ---
def explorer_callback(call):
    bot.answer_callback_query(call.id)
    try:
        s_owner = int(call.data.split('_')[1])
        if not (call.from_user.id == s_owner or call.from_user.id in admin_ids): return
        user_folder = get_user_folder(s_owner)
        files = os.listdir(user_folder)
        markup = types.InlineKeyboardMarkup(row_width=1)
        for f in sorted(files):
            if f.startswith('.') or f.endswith('.log'): continue
            size = round(os.path.getsize(os.path.join(user_folder, f)) / 1024, 2)
            markup.add(btn(f"📄 {f} ({size} KB)", callback_data=f"expfile_{s_owner}_{f}", style='primary'))
        markup.add(btn("🔙 Back to Controls", callback_data='check_files', style='primary'))
        bot.edit_message_text(f"📂 **Sandbox Explorer**:\n\nSelect any file to read details or edit:", call.message.chat.id, call.message.message_id, reply_markup=markup, parse_mode='Markdown')
    except Exception as e: logger.error(f"Explorer err: {e}")

def explore_file_callback(call):
    bot.answer_callback_query(call.id)
    try:
        parts = call.data.split('_', 2)
        s_owner = int(parts[1])
        file_name = parts[2]
        if not (call.from_user.id == s_owner or call.from_user.id in admin_ids): return
        user_folder = get_user_folder(s_owner)
        file_path = os.path.join(user_folder, file_name)
        if not os.path.exists(file_path): return
        
        size = round(os.path.getsize(file_path) / 1024, 2)
        mtime = datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M:%S')
        markup = types.InlineKeyboardMarkup(row_width=2)
        markup.row(
            btn("🔍 View Code", callback_data=f"edit_view_{s_owner}_{file_name}", style='primary'),
            btn("✏️ Edit File", callback_data=f"edit_menu_{s_owner}_{file_name}", style='success')
        )
        markup.row(
            btn("🗑️ Delete File", callback_data=f"expdel_{s_owner}_{file_name}", style='danger'),
            btn("🔙 Back to Explorer", callback_data=f"explorer_{s_owner}", style='primary')
        )
        bot.edit_message_text(f"📄 **File Explorer**: `{file_name}`\n\n📏 **Size**: `{size} KB`\n📅 **Last Modified**: `{mtime}`", call.message.chat.id, call.message.message_id, reply_markup=markup, parse_mode='Markdown')
    except Exception as e: logger.error(f"Explore file err: {e}")

def delete_file_explorer_callback(call):
    try:
        parts = call.data.split('_', 2)
        s_owner = int(parts[1])
        file_name = parts[2]
        if not (call.from_user.id == s_owner or call.from_user.id in admin_ids): return
        file_path = os.path.join(get_user_folder(s_owner), file_name)
        if os.path.exists(file_path):
            os.remove(file_path)
            bot.answer_callback_query(call.id, "✅ File deleted successfully!", show_alert=True)
            if any(f[0] == file_name for f in user_files.get(s_owner, [])):
                remove_user_file_db(s_owner, file_name)
            explorer_callback(call)
    except Exception as e: logger.error(f"Explorer file delete err: {e}")

def backup_callback(call):
    bot.answer_callback_query(call.id)
    try:
        s_owner = int(call.data.split('_')[1])
        if not (call.from_user.id == s_owner or call.from_user.id in admin_ids): return
        user_folder = get_user_folder(s_owner)
        bot.send_message(call.message.chat.id, "⏳ **Generating Sandbox Backup**... Please wait.")
        
        temp_dir = tempfile.mkdtemp(prefix=f"backup_user_{s_owner}_")
        zip_name = f"backup_{s_owner}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
        zip_path = os.path.join(temp_dir, zip_name)
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zip_f:
            for root, dirs, files in os.walk(user_folder):
                for f in files:
                    if f.endswith('.log'): continue
                    zip_f.write(os.path.join(root, f), os.path.relpath(os.path.join(root, f), user_folder))
        with open(zip_path, 'rb') as f:
            bot.send_document(call.message.chat.id, f, caption=f"💾 **Backup Archive**\n🆔 ID: `{s_owner}`", parse_mode='Markdown')
        shutil.rmtree(temp_dir)
    except Exception as e: logger.error(f"Backup err: {e}")

def edit_menu_callback(call):
    bot.answer_callback_query(call.id)
    try:
        parts = call.data.split('_', 2)
        s_owner = int(parts[1])
        file_name = parts[2]
        markup = types.InlineKeyboardMarkup(row_width=2)
        markup.row(
            btn("📝 Overwrite Code", callback_data=f"edit_over_{s_owner}_{file_name}", style='success'),
            btn("➕ Append Code", callback_data=f"edit_app_{s_owner}_{file_name}", style='primary')
        )
        markup.row(btn("🔙 Back to File", callback_data=f"expfile_{s_owner}_{file_name}", style='primary'))
        bot.edit_message_text(f"✏️ **Real-Time Code Editor**: `{file_name}`\n\nSelect action:", call.message.chat.id, call.message.message_id, reply_markup=markup, parse_mode='Markdown')
    except Exception as e: logger.error(f"Edit menu err: {e}")

def edit_view_callback(call):
    bot.answer_callback_query(call.id)
    try:
        parts = call.data.split('_', 2)
        s_owner = int(parts[1])
        file_name = parts[2]
        file_path = os.path.join(get_user_folder(s_owner), file_name)
        if not os.path.exists(file_path): return
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f: code_content = f.read()
        
        truncated = False
        if len(code_content) > 3500:
            code_content = code_content[:3500]
            truncated = True
        escaped_code = escape_html(code_content)
        
        view_text = f"🔍 <b>Viewer</b>: <code>{file_name}</code>"
        if truncated: view_text += " <i>(Truncated)*</i>"
        view_text += f"\n\n<pre>{escaped_code}</pre>"
        
        markup = types.InlineKeyboardMarkup()
        markup.add(btn("🔙 Back", callback_data=f"expfile_{s_owner}_{file_name}", style='primary'))
        bot.edit_message_text(view_text, call.message.chat.id, call.message.message_id, reply_markup=markup, parse_mode='HTML')
    except Exception as e: logger.error(f"Edit view err: {e}")

def edit_over_callback(call):
    bot.answer_callback_query(call.id)
    try:
        parts = call.data.split('_', 2)
        s_owner = int(parts[1])
        file_name = parts[2]
        msg = bot.send_message(call.message.chat.id, f"📝 **Overwrite Code**: `{file_name}`\n\nPlease send a text message containing the **complete new code** for this file.\n\n/cancel to abort.", reply_markup=cancel_markup(), parse_mode='Markdown')
        msg.from_user = call.from_user
        bot.register_next_step_handler(msg, lambda message: process_overwrite_code(message, s_owner, file_name))
    except Exception as e: logger.error(f"Edit over cb err: {e}")

def process_overwrite_code(message, s_owner, file_name):
    if message.text and message.text.lower() == '/cancel':
        bot.reply_to(message, "❌ Aborted.")
        return
    if not message.text: return
    try:
        file_path = os.path.join(get_user_folder(s_owner), file_name)
        with open(file_path, 'w', encoding='utf-8') as f: f.write(message.text)
        markup = types.InlineKeyboardMarkup()
        markup.add(btn("📂 Back to File", callback_data=f"expfile_{s_owner}_{file_name}", style='primary'))
        bot.reply_to(message, f"✅ **Success**! File `{file_name}` overwritten!", reply_markup=markup, parse_mode='Markdown')
    except Exception as e: logger.error(f"Overwrite err: {e}")

def edit_app_callback(call):
    bot.answer_callback_query(call.id)
    try:
        parts = call.data.split('_', 2)
        s_owner = int(parts[1])
        file_name = parts[2]
        msg = bot.send_message(call.message.chat.id, f"➕ **Append Code**: `{file_name}`\n\nPlease send the code you want to **append** to the end of this file.\n\n/cancel to abort.", reply_markup=cancel_markup(), parse_mode='Markdown')
        msg.from_user = call.from_user
        bot.register_next_step_handler(msg, lambda message: process_append_code(message, s_owner, file_name))
    except Exception as e: logger.error(f"Edit app cb err: {e}")

def process_append_code(message, s_owner, file_name):
    if message.text and message.text.lower() == '/cancel':
        bot.reply_to(message, "❌ Aborted.")
        return
    if not message.text: return
    try:
        file_path = os.path.join(get_user_folder(s_owner), file_name)
        with open(file_path, 'a', encoding='utf-8') as f: f.write("\n\n" + message.text)
        markup = types.InlineKeyboardMarkup()
        markup.add(btn("📂 Back to File", callback_data=f"expfile_{s_owner}_{file_name}", style='primary'))
        bot.reply_to(message, f"✅ **Success**! Code appended to `{file_name}`!", reply_markup=markup, parse_mode='Markdown')
    except Exception as e: logger.error(f"Append err: {e}")

# --- Core Cleanup Registrations ---
def cleanup():
    logger.warning("Shutdown initiated. Cleaning up script processes...")
    for key, info in list(bot_scripts.items()):
        kill_process_tree(info)
    logger.warning("Wipeout completed.")

atexit.register(cleanup)

# =====================================================================
# 🧬 MAIN SYSTEM LAUNCHER (ZOMBIE monitor, WATCHDOG & LOOP RUNNER)
# =====================================================================
if __name__ == '__main__':
    logger.info("Initializing Hoster database...")
    init_db()
    load_data()
    
    # Active Watchdog Thread for Zombie & Crash auto-restarts (Feature 2)
    def watchdog_loop():
        logger.info("👀 Watchdog thread started. Monitoring processes with Auto-Restart...")
        while True:
            try:
                time.sleep(15)
                for script_key in list(bot_scripts.keys()):
                    info = bot_scripts.get(script_key)
                    if not info: continue
                    process = info.get('process')
                    if process and process.poll() is not None:
                        logger.info(f"🚨 Watchdog detected stopped process: {script_key}")
                        if 'log_file' in info and not info['log_file'].closed:
                            try: info['log_file'].close()
                            except: pass
                        
                        chat_id = info.get('chat_id')
                        file_name = info.get('file_name', 'script')
                        s_owner = info.get('script_owner_id')
                        user_folder = info.get('user_folder')
                        script_type = info.get('type')
                        restarts = info.get('restarts', 0)
                        
                        auto_restart_enabled = script_auto_restart.get(f"{s_owner}_{file_name}", False)
                        if auto_restart_enabled:
                            if restarts < 3:
                                restarts += 1
                                script_path = os.path.join(user_folder, file_name)
                                if script_type == 'py':
                                    threading.Thread(target=run_script, args=(script_path, s_owner, user_folder, file_name, chat_id)).start()
                                else:
                                    threading.Thread(target=run_js_script, args=(script_path, s_owner, user_folder, file_name, chat_id)).start()
                                time.sleep(1.0)
                                if script_key in bot_scripts: bot_scripts[script_key]['restarts'] = restarts
                                try: bot.send_message(chat_id, f"🔄 **Auto-Restart (Attempt {restarts}/3)**: Your script `{file_name}` stopped (Exit Code: {process.returncode}) but has been automatically restarted!", parse_mode='Markdown')
                                except: pass
                                continue
                            else:
                                try: bot.send_message(chat_id, f"⚠️ **Auto-Restart Failed**: Your script `{file_name}` crashed 3 consecutive times. Auto-restart disabled for stability. Please fix any bugs and start manually.", parse_mode='Markdown')
                                except: pass
                        else:
                            try: bot.send_message(chat_id, f"⚠️ **Alert**: Your script `{file_name}` has stopped running (Exit Code: {process.returncode}).", parse_mode='Markdown')
                            except: pass
                        if script_key in bot_scripts: del bot_scripts[script_key]
            except Exception as e: logger.error(f"Watchdog err: {e}")
            
    watchdog = threading.Thread(target=watchdog_loop)
    watchdog.daemon = True
    watchdog.start()
    
    # Flask Web manager daemon thread
    keep_alive()
    
    logger.info("🚀 Starting polling...")
    while True:
        try:
            bot.infinity_polling(logger_level=logging.INFO, timeout=60, long_polling_timeout=30)
        except requests.exceptions.ReadTimeout:
            time.sleep(5)
        except requests.exceptions.ConnectionError:
            time.sleep(15)
        except Exception as e:
            logger.critical(f"💥 Polling error: {e}")
            time.sleep(30)
