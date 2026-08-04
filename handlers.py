# -*- coding: utf-8 -*-
import os
import sys
import time
import shutil
import tempfile
import zipfile
import re
import psutil
import logging
import threading
from datetime import datetime, timedelta
import sqlite3
import requests
import telebot
from telebot import types

# Import from our modular files
from config import (
    OWNER_ID, ADMIN_ID, YOUR_USERNAME, UPDATE_CHANNEL, BASE_DIR, 
    UPLOAD_BOTS_DIR, FREE_USER_LIMIT, SUBSCRIBED_USER_LIMIT, 
    ADMIN_LIMIT, OWNER_LIMIT, SECURITY_CONFIG, 
    COMMAND_BUTTONS_LAYOUT_USER_SPEC, ADMIN_COMMAND_BUTTONS_LAYOUT_USER_SPEC
)
from bot_instance import bot
import state
from database import (
    DB_LOCK, save_user_file, remove_user_file_db, add_active_user, 
    save_subscription, remove_subscription_db, add_admin_db, remove_admin_db, 
    save_mandatory_channel, remove_mandatory_channel_db, set_user_limit_db, 
    remove_user_limit_db, ban_user_db, unban_user_db, DATABASE_PATH
)
from security import check_code_security, scan_zip_security
from process_manager import (
    is_bot_running, kill_process_tree, attempt_install_pip, 
    attempt_install_npm, run_script, run_js_script, process_zip_file
)

logger = logging.getLogger(__name__)

# References to mutable state in state.py so they stay in sync (Fixes Bug #4 & #1)
banned_users = state.banned_users
active_users = state.active_users
admin_ids = state.admin_ids
user_subscriptions = state.user_subscriptions
user_files = state.user_files
user_limits = state.user_limits
pending_modules = state.pending_modules
manual_install_requests = state.manual_install_requests
mandatory_channels = state.mandatory_channels
pending_zip_files = state.pending_zip_files

# Local primitive states
bot_locked = False

# Helper to create styled inline buttons utilizing Bot API 9.4 (danger, success, primary)
def btn(text, callback_data=None, url=None, style=None):
    button = types.InlineKeyboardButton(text, callback_data=callback_data, url=url)
    if style:
        button.style = style
    return button

# Helper to create styled reply keyboard buttons utilizing Bot API 9.4 (danger, success, primary)
def kb_btn(text, style=None):
    button = types.KeyboardButton(text)
    if style:
        button.style = style
    return button

# Helper to create a single red cancel & back inline button (Fixes /cancel text prompt flow)
def cancel_markup():
    markup = types.InlineKeyboardMarkup()
    markup.add(btn("🔙 Cancel & Back", callback_data="cancel_next_step", style="danger"))
    return markup




# --- HELPER FUNCTIONS EXTRACTED FROM TEST.PY ---

# Helper to create styled visual progress bars for CPU/RAM/Disk metrics (Feature 3)
def make_progress_bar(percent):
    filled = int(percent / 10)
    bar = "█" * filled + "░" * (10 - filled)
    return f"`[{bar}] {percent}%`"

def is_user_member(user_id, channel_id):
    """Check if user is member of a channel"""
    try:
        chat_member = bot.get_chat_member(channel_id, user_id)
        return chat_member.status in ['member', 'administrator', 'creator']
    except telebot.apihelper.ApiTelegramException as e:
        err_desc = str(e).lower()
        if "bot is not a member" in err_desc or "chat not found" in err_desc or "admin" in err_desc:
            logger.error(f"❌ Mandatory Channel Configuration Error: Bot is not admin/member in {channel_id}: {e}")
            # Fix Bug #6: Bypass check if bot lacks admin/access rights, preventing lockdown
            return True
        logger.error(f"Error checking channel membership for {user_id} in {channel_id}: {e}")
        return False
    except Exception as e:
        logger.error(f"Error checking channel membership for {user_id} in {channel_id}: {e}")
        return False


def check_mandatory_subscription(user_id):
    """Check if user is subscribed to all mandatory channels (Bypassed if bot is in FREE mode)"""
    if state.free_mode:
        return True, []
    if not mandatory_channels:
        return True, []  # No mandatory channels exist
    
    not_joined = []
    for channel_id, channel_info in mandatory_channels.items():
        if not is_user_member(user_id, channel_id):
            not_joined.append((channel_id, channel_info))
    
    if not_joined:
        return False, not_joined
    return True, []


def create_mandatory_channels_menu():
    """Create mandatory channels management menu"""
    markup = types.InlineKeyboardMarkup(row_width=2)
    markup.row(
        btn('➕ Add Channel', callback_data='add_mandatory_channel', style='success'),
        btn('➖ Remove Channel', callback_data='remove_mandatory_channel', style='danger')
    )
    markup.row(btn('📋 List Channels', callback_data='list_mandatory_channels', style='primary'))
    markup.row(btn('🔙 Back to Main', callback_data='back_to_main', style='primary'))
    return markup


def create_subscription_check_message(not_joined_channels):
    """Create subscription verification message"""
    message = "📢 **Important: Join Our Channels First:**\n\n"
    
    markup = types.InlineKeyboardMarkup()
    
    for channel_id, channel_info in not_joined_channels:
        channel_username = channel_info.get('username', '')
        channel_name = channel_info.get('name', 'Channel')
        
        if channel_username:
            channel_link = f"https://t.me/{channel_username.replace('@', '')}"
        else:
            channel_link = f"https://t.me/c/{channel_id.replace('-100', '')}"
        
        message += f"• {channel_name}\n"
        markup.add(btn(f"Join {channel_name}", url=channel_link, style='primary'))
    
    markup.add(btn("✅ Verify Subscription", callback_data='check_subscription_status', style='success'))
    
    return message, markup

# --- Database Lock ---
DB_LOCK = threading.Lock()

# --- User Management Functions ---

def is_user_banned(user_id):
    """Check if user is banned"""
    return user_id in banned_users


import hashlib

def get_user_folder(user_id):
    """Get or create user's folder for storing files with complete hashed isolation & anonymity"""
    # Create a unique 16-character SHA-256 hash of the user_id (Fixes Complete Isolation)
    user_hash = hashlib.sha256(str(user_id).encode('utf-8')).hexdigest()[:16]
    user_folder = os.path.join(UPLOAD_BOTS_DIR, user_hash)
    os.makedirs(user_folder, exist_ok=True)
    return user_folder


def get_user_file_limit(user_id):
    """Get the file upload limit for a user (Bypassed if bot is in FREE mode)"""
    if state.free_mode:
        return OWNER_LIMIT
    if user_id == OWNER_ID: return OWNER_LIMIT
    if user_id in admin_ids: return ADMIN_LIMIT
    if user_id in user_limits: return user_limits[user_id]
    if user_id in user_subscriptions and user_subscriptions[user_id]['expiry'] > datetime.now():
        return SUBSCRIBED_USER_LIMIT
    return FREE_USER_LIMIT


def get_user_file_count(user_id):
    """Get the number of files uploaded by a user"""
    return len(user_files.get(user_id, []))


def manual_install_module_init(message):
    """Initialize manual module installation"""
    user_id = message.from_user.id
    
    if is_user_banned(user_id):
        bot.reply_to(message, "❌ You are banned from using this bot.")
        return
    
    # Check mandatory subscription first
    is_subscribed, not_joined = check_mandatory_subscription(user_id)
    if not is_subscribed and user_id not in admin_ids:
        subscription_message, markup = create_subscription_check_message(not_joined)
        bot.reply_to(message, subscription_message, reply_markup=markup, parse_mode='Markdown')
        return
    
    if bot_locked and user_id not in admin_ids:
        bot.reply_to(message, "⚠️ Bot locked by admin. Try later.")
        return
    
    msg = bot.reply_to(message, "📦 **Module Installation**:\n\nSend module name to install (e.g., `requests` or `pillow`)\nFor Node.js, use format: `npm:module_name`", reply_markup=cancel_markup(), parse_mode='Markdown')
    bot.register_next_step_handler(msg, process_manual_install_module)


def process_manual_install_module(message):
    """Process manual module installation"""
    user_id = message.from_user.id
    
    if is_user_banned(user_id):
        bot.reply_to(message, "❌ You are banned from using this bot.")
        return
    
    if message.text.lower() == '/cancel':
        bot.reply_to(message, "❌ Installation cancelled.")
        return
    
    module_name = message.text.strip()
    
    # Check if it's a Node.js module
    if module_name.lower().startswith('npm:'):
        module_name = module_name[4:].strip()
        user_folder = get_user_folder(user_id)
        success, log = attempt_install_npm(module_name, user_folder, message, manual_request=True)
    else:
        # Python module
        success, log = attempt_install_pip(module_name, message, manual_request=True)
    
    if success:
        logger.info(f"User {user_id} manually installed module: {module_name}")

# --- Database Operations ---

# --- END OF HELPER FUNCTIONS ---


def create_main_menu_inline(user_id):
    markup = types.InlineKeyboardMarkup(row_width=2)
    
    # 100% Anonymous & Rearranged UI Elements (Fixes Privacy & Button Rearranging)
    btn_upload = btn('📤 Upload Script', callback_data='upload', style='success')
    btn_check = btn('📂 My Scripts', callback_data='check_files', style='primary')
    btn_speed = btn('⚡ Test Ping', callback_data='speed', style='primary')
    btn_updates = btn('📢 Updates Channel', url=f'https://t.me/{UPDATE_CHANNEL.replace("@", "")}', style='primary')
    btn_help_guide = btn('🆘 Help Guide', callback_data='back_to_main', style='primary') # Dummy callback, standard back to main works
    
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
        
        # Grid layout for Admin Main Menu (Hides personal contacts to preserve identity)
        markup.add(btn_upload)
        markup.add(btn_check, btn_speed)
        markup.add(btn_sub, btn_stats)
        markup.add(btn_lock, btn_admin_panel)
        markup.add(btn_channel_add, btn_admin_install)
        markup.add(btn_user_mgmt, btn_settings)
        markup.add(btn_updates, btn_help_guide)
    else:
        # Perfectly Rearranged & Hashed Layout for Regular Public Users
        markup.add(btn_upload)
        markup.add(btn_check, btn_speed)
        markup.add(btn_updates, btn_help_guide)
        
    return markup

def create_reply_keyboard_main_menu(user_id):
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    
    # Map of custom reply keyboard button styles (Anonymized & Rearranged labels)
    button_styles = {
        "📤 Upload Script": "success",   # Green
        "📂 My Scripts": "primary",      # Blue
        "⚡ Test Ping": "primary",        # Blue
        "🆘 Help Guide": "primary",      # Blue
        "📈 Bot Performance": "primary", # Blue
        "🔒 Lock Bot": "danger",         # Red
        "👑 Admin Panel": "danger",      # Red
        "👥 User Management": "danger", # Red
        "📢 Broadcast": "primary",       # Blue
        "💳 Subscriptions": "primary",   # Blue
        "📢 Channel Add": "success",     # Green
        "🛠️ Manual Install": "success",   # Green
        "🧹 Cleanup Files": "danger",    # Red
        "⚙️ Settings": "primary",        # Blue
    }
    
    layout_to_use = ADMIN_COMMAND_BUTTONS_LAYOUT_USER_SPEC if user_id in admin_ids else COMMAND_BUTTONS_LAYOUT_USER_SPEC
    for row_buttons_text in layout_to_use:
        row_buttons = []
        for text in row_buttons_text:
            style = button_styles.get(text)
            row_buttons.append(kb_btn(text, style=style))
        markup.add(*row_buttons)
    return markup

def create_control_buttons(script_owner_id, file_name, is_running=True):
    markup = types.InlineKeyboardMarkup(row_width=2)
    
    # Get current auto-restart toggle state from memory cache (Feature 2)
    auto_restart = state.script_auto_restart.get(f"{script_owner_id}_{file_name}", False)
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
        
    # Auto-Restart & Extra Utilities Row (Feature 2, 4, 5)
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
    
    # Persistent Free/Premium Mode Toggle for Public Launcher (Admin Toggle)
    btn_mode = btn("🔄 Bot Mode: FREE (All Unlocked)" if state.free_mode else "🔄 Bot Mode: PREMIUM (Subs Active)",
                   callback_data="toggle_free_mode",
                   style="success" if state.free_mode else "danger")
                   
    markup.row(btn_mode)
    markup.row(
        btn('📊 System Info', callback_data='system_info', style='primary'),
        btn('📈 Bot Performance', callback_data='bot_performance', style='primary')
    )
    markup.row(
        btn('🧹 Cleanup Files', callback_data='cleanup_files', style='danger'),
        btn('📋 Installation Logs', callback_data='install_logs', style='primary')
    )
    
    # Key Generator Button for Monetization License Keys (Feature 1)
    markup.row(btn("🔑 Generate License Key", callback_data="admin_genkey", style="success"))
    
    markup.row(btn('🔙 Back to Main', callback_data='back_to_main', style='primary'))
    return markup

# --- File Handling ---
def handle_zip_file(downloaded_file_content, file_name_zip, message):
    user_id = message.from_user.id
    user_folder = get_user_folder(user_id)
    temp_dir = None 
    try:
        temp_dir = tempfile.mkdtemp(prefix=f"user_{user_id}_zip_")
        logger.info(f"Temp dir for zip: {temp_dir}")
        zip_path = os.path.join(temp_dir, file_name_zip)
        with open(zip_path, 'wb') as new_file: new_file.write(downloaded_file_content)
        
        # Security check for ZIP
        is_safe, security_msg = scan_zip_security(zip_path)
        if not is_safe:
            # Send security warning to admin for approval
            security_warning_msg = f"🚨 File needs approval:\n👤 User: {user_id}\n📁 File: {file_name_zip}\n⚠️ Reason: {security_msg}"
            markup = types.InlineKeyboardMarkup()
            markup.row(
                btn("✅ Approve", callback_data=f"approve_zip_{user_id}_{file_name_zip}", style="success"),
                btn("❌ Reject", callback_data=f"reject_zip_{user_id}_{file_name_zip}", style="danger")
            )
            for admin_id in admin_ids:
                try:
                    bot.send_message(admin_id, security_warning_msg, reply_markup=markup)
                except Exception as e:
                    logger.error(f"Failed to send security warning to admin {admin_id}: {e}")
            
            # Store the file content for later approval
            if user_id not in pending_zip_files:
                pending_zip_files[user_id] = {}
            pending_zip_files[user_id][file_name_zip] = downloaded_file_content
            
            bot.reply_to(message, f"⏳ File under security review. You will be notified upon approval.")
            return

        # Process ZIP file if safe
        process_zip_file(zip_path, user_id, user_folder, file_name_zip, message, temp_dir)
        
    except zipfile.BadZipFile as e:
        logger.error(f"Bad zip file from {user_id}: {e}")
        bot.reply_to(message, f"❌ Error: Invalid/corrupted ZIP. {e}")
    except Exception as e:
        logger.error(f"❌ Error processing zip for {user_id}: {e}", exc_info=True)
        bot.reply_to(message, f"❌ Error processing zip: {str(e)}")
    finally:
        if temp_dir and os.path.exists(temp_dir):
            try: shutil.rmtree(temp_dir); logger.info(f"Cleaned temp dir: {temp_dir}")
            except Exception as e: logger.error(f"Failed to clean temp dir {temp_dir}: {e}", exc_info=True)

def handle_js_file(file_path, script_owner_id, user_folder, file_name, message):
    try:
        save_user_file(script_owner_id, file_name, 'js')
        threading.Thread(target=run_js_script, args=(file_path, script_owner_id, user_folder, file_name, message)).start()
    except Exception as e:
        logger.error(f"❌ Error processing JS file {file_name} for {script_owner_id}: {e}", exc_info=True)
        bot.reply_to(message, f"❌ Error processing JS file: {str(e)}")

def handle_py_file(file_path, script_owner_id, user_folder, file_name, message):
    try:
        save_user_file(script_owner_id, file_name, 'py')
        threading.Thread(target=run_script, args=(file_path, script_owner_id, user_folder, file_name, message)).start()
    except Exception as e:
        logger.error(f"❌ Error processing Python file {file_name} for {script_owner_id}: {e}", exc_info=True)
        bot.reply_to(message, f"❌ Error processing Python file: {str(e)}")

# --- Automatic Package Installation & Script Running ---
def _logic_send_welcome(message):
    user_id = message.from_user.id
    chat_id = message.chat.id
    user_name = message.from_user.first_name

    logger.info(f"Welcome request from user_id: {user_id}")

    # Check if user is banned
    if is_user_banned(user_id):
        bot.send_message(chat_id, "❌ You are banned from using this bot.")
        return

    # Check mandatory subscription FIRST - before anything else
    is_subscribed, not_joined = check_mandatory_subscription(user_id)
    if not is_subscribed and user_id not in admin_ids:
        subscription_message, markup = create_subscription_check_message(not_joined)
        bot.send_message(chat_id, subscription_message, reply_markup=markup, parse_mode='Markdown')
        return

    if bot_locked and user_id not in admin_ids:
        bot.send_message(chat_id, "⚠️ Bot locked by admin. Try later.")
        return

    user_hash = hashlib.sha256(str(user_id).encode('utf-8')).hexdigest()[:16]
    
    if user_id not in active_users:
        add_active_user(user_id)
        try:
            # Completely Anonymous Owner Notification (Fixes Owner-to-User linking privacy)
            owner_notification = (f"🎉 A new anonymous user has started the bot!\n🆔 Anonymous Hash ID: `{user_hash}`")
            bot.send_message(OWNER_ID, owner_notification, parse_mode='Markdown')
        except Exception as e: 
            logger.error(f"⚠️ Failed to notify owner about new user {user_id}: {e}")

    file_limit = get_user_file_limit(user_id)
    current_files = get_user_file_count(user_id)
    limit_str = str(file_limit) if file_limit != float('inf') else "Unlimited"
    expiry_info = ""
    
    if user_id == OWNER_ID: 
        user_status = "👑 Owner"
    elif user_id in admin_ids: 
        user_status = "🛡️ Admin"
    elif user_id in user_subscriptions:
        expiry_date = user_subscriptions[user_id].get('expiry')
        if expiry_date and expiry_date > datetime.now():
            user_status = "⭐ Premium"
            days_left = (expiry_date - datetime.now()).days
            expiry_info = f"\n⏳ Subscription expires in: {days_left} days"
        else: 
            user_status = "🆓 Free User (Expired Sub)"
            remove_subscription_db(user_id)
    else: 
        user_status = "🆓 Free User"

    # Completely Anonymous Interface (No names, no raw telegram IDs)
    welcome_msg_text = (f"〽️ **Welcome to 50 Shades Hoster!**\n\n"
                        f"🆔 **Your Anonymous Hash ID**: `{user_hash}`\n"
                        f"🔰 **Your Status**: {user_status}{expiry_info}\n"
                        f"📁 **Files Uploaded**: {current_files} / {limit_str}\n\n"
                        f"🤖 Host & run Python (`.py`) or JS (`.js`) scripts.\n"
                        f"   Upload single scripts or `.zip` archives.\n"
                        f"📦 Fully isolated workspace sandbox configuration.\n\n"
                        f"👇 Use the restructured buttons below to control.")
    
    main_reply_markup = create_reply_keyboard_main_menu(user_id)
    try:
        bot.send_message(chat_id, welcome_msg_text, reply_markup=main_reply_markup, parse_mode='Markdown')
    except Exception as e:
        logger.error(f"Error sending welcome to {user_id}: {e}", exc_info=True)

def _logic_updates_channel(message):
    markup = types.InlineKeyboardMarkup()
    markup.add(btn('📢 Updates Channel', url=f'https://t.me/{UPDATE_CHANNEL.replace("@", "")}', style='primary'))
    bot.reply_to(message, "Visit our Updates Channel:", reply_markup=markup)

def _logic_upload_file(message):
    user_id = message.from_user.id
    
    # Check if user is banned
    if is_user_banned(user_id):
        bot.reply_to(message, "❌ You are banned from using this bot.")
        return
    
    # Check mandatory subscription first
    is_subscribed, not_joined = check_mandatory_subscription(user_id)
    if not is_subscribed and user_id not in admin_ids:
        subscription_message, markup = create_subscription_check_message(not_joined)
        bot.reply_to(message, subscription_message, reply_markup=markup, parse_mode='Markdown')
        return
        
    if bot_locked and user_id not in admin_ids:
        bot.reply_to(message, "⚠️ Bot locked by admin, cannot accept files.")
        return

    file_limit = get_user_file_limit(user_id)
    current_files = get_user_file_count(user_id)
    if current_files >= file_limit:
        limit_str = str(file_limit) if file_limit != float('inf') else "Unlimited"
        bot.reply_to(message, f"⚠️ File limit ({current_files}/{limit_str}) reached. Delete files first.")
        return
    bot.reply_to(message, "📤 Send your Python (`.py`), JS (`.js`), or ZIP (`.zip`) file.")

def _logic_check_files(message):
    user_id = message.from_user.id
    
    # Check if user is banned
    if is_user_banned(user_id):
        bot.reply_to(message, "❌ You are banned from using this bot.")
        return
    
    # Check mandatory subscription first
    is_subscribed, not_joined = check_mandatory_subscription(user_id)
    if not is_subscribed and user_id not in admin_ids:
        subscription_message, markup = create_subscription_check_message(not_joined)
        bot.reply_to(message, subscription_message, reply_markup=markup, parse_mode='Markdown')
        return
        
    user_files_list = user_files.get(user_id, [])
    if not user_files_list:
        bot.reply_to(message, "📂 Your files:\n\n(No files uploaded yet)")
        return
    markup = types.InlineKeyboardMarkup(row_width=1)
    for file_name, file_type in sorted(user_files_list):
        is_running = is_bot_running(user_id, file_name) # Use user_id for checking status
        status_icon = "🟢 Running" if is_running else "🔴 Stopped"
        btn_text = f"{file_name} ({file_type}) - {status_icon}"
        # Callback data includes user_id as script_owner_id
        markup.add(btn(btn_text, callback_data=f'file_{user_id}_{file_name}', style='primary'))
    bot.reply_to(message, "📂 Your files:\nClick to manage.", reply_markup=markup, parse_mode='Markdown')

def _logic_bot_speed(message):
    user_id = message.from_user.id
    chat_id = message.chat.id
    
    # Check if user is banned
    if is_user_banned(user_id):
        bot.reply_to(message, "❌ You are banned from using this bot.")
        return
    
    # Check mandatory subscription first
    is_subscribed, not_joined = check_mandatory_subscription(user_id)
    if not is_subscribed and user_id not in admin_ids:
        subscription_message, markup = create_subscription_check_message(not_joined)
        bot.reply_to(message, subscription_message, reply_markup=markup, parse_mode='Markdown')
        return
        
    start_time_ping = time.time()
    wait_msg = bot.reply_to(message, "🏃 Testing speed and compiling resource info...")
    try:
        bot.send_chat_action(chat_id, 'typing')
        response_time = round((time.time() - start_time_ping) * 1000, 2)
        status = "🔓 Unlocked" if not bot_locked else "🔒 Locked"
        if user_id == OWNER_ID: user_level = "👑 Owner"
        elif user_id in admin_ids: user_level = "🛡️ Admin"
        elif user_id in user_subscriptions and user_subscriptions[user_id].get('expiry', datetime.min) > datetime.now(): user_level = "⭐ Premium"
        else: user_level = "🆓 Free User"
        
        # Calculate live system metrics with progress bars (Feature 3)
        cpu_p = psutil.cpu_percent()
        ram_p = psutil.virtual_memory().percent
        disk_p = psutil.disk_usage('/').percent
        
        cpu_bar = make_progress_bar(cpu_p)
        ram_bar = make_progress_bar(ram_p)
        disk_bar = make_progress_bar(disk_p)
        
        speed_msg = (f"⚡ **System Monitor & Health Info**:\n\n"
                     f"⏱️ **Ping Response**: `{response_time} ms`\n"
                     f"🚦 **Bot Status**: {status}\n"
                     f"👤 **Your Account**: {user_level}\n\n"
                     f"💻 **CPU Usage**:\n{cpu_bar}\n"
                     f"🧠 **RAM Usage**:\n{ram_bar}\n"
                     f"💾 **Disk Storage**:\n{disk_bar}")
        bot.edit_message_text(speed_msg, chat_id, wait_msg.message_id, parse_mode='Markdown')
    except Exception as e:
        logger.error(f"Error during speed test (cmd): {e}", exc_info=True)
        bot.edit_message_text("❌ Error during speed test.", chat_id, wait_msg.message_id)

def _logic_contact_owner(message):
    markup = types.InlineKeyboardMarkup()
    markup.add(btn('📞 Contact Owner', url=f'https://t.me/{YOUR_USERNAME.replace("@", "")}', style='primary'))
    bot.reply_to(message, "Click to contact Owner:", reply_markup=markup)

def _logic_manual_install(message):
    """Handle manual installation request from user (Restricted on Public Launch for safety)"""
    user_id = message.from_user.id
    if user_id in admin_ids:
        manual_install_module_init(message)
    else:
        bot.reply_to(message, "⚠️ **Manual Installation Restricted**:\n\nFor server safety, manual pip/npm installations can only be initiated by Admins. If you need any packages installed, please contact the **Owner**.", parse_mode='Markdown')

def _logic_help(message):
    help_text = f"""
🎭 **50 Shades Hoster - Help Guide**

Welcome to the most secure, completely anonymous, and isolated hosting environment for your Python (`.py`) and JavaScript (`.js`) scripts!

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

# --- Admin Logic Functions ---
def _logic_subscriptions_panel(message):
    if message.from_user.id not in admin_ids:
        bot.reply_to(message, "⚠️ Admin permissions required.")
        return
    bot.reply_to(message, "💳 Subscription Management\nUse inline buttons from /start or admin command menu.", reply_markup=create_subscription_menu())

def _logic_statistics(message):
    user_id = message.from_user.id
    
    # Check if user is banned
    if is_user_banned(user_id):
        bot.reply_to(message, "❌ You are banned from using this bot.")
        return
    
    # Check mandatory subscription first
    is_subscribed, not_joined = check_mandatory_subscription(user_id)
    if not is_subscribed and user_id not in admin_ids:
        subscription_message, markup = create_subscription_check_message(not_joined)
        bot.reply_to(message, subscription_message, reply_markup=markup, parse_mode='Markdown')
        return
        
    total_users = len(active_users)
    total_files_records = sum(len(files) for files in user_files.values())

    running_bots_count = 0
    user_running_bots = 0

    for script_key_iter, script_info_iter in list(bot_scripts.items()):
        s_owner_id, _ = script_key_iter.split('_', 1) # Extract owner_id from key
        if is_bot_running(int(s_owner_id), script_info_iter['file_name']):
            running_bots_count += 1
            if int(s_owner_id) == user_id:
                user_running_bots +=1

    stats_msg_base = (f"📊 Bot Statistics:\n\n"
                      f"👥 Total Users: {total_users}\n"
                      f"🚫 Banned Users: {len(banned_users)}\n"
                      f"📂 Total File Records: {total_files_records}\n"
                      f"🟢 Total Active Bots: {running_bots_count}\n")

    if user_id in admin_ids:
        stats_msg_admin = (f"🔒 Bot Status: {'🔴 Locked' if bot_locked else '🟢 Unlocked'}\n"
                           f"📢 Mandatory Channels: {len(mandatory_channels)}\n"
                           f"⚙️ Custom Limits: {len(user_limits)}\n"
                           f"🤖 Your Running Bots: {user_running_bots}")
        stats_msg = stats_msg_base + stats_msg_admin
    else:
        stats_msg = stats_msg_base + f"🤖 Your Running Bots: {user_running_bots}"

    bot.reply_to(message, stats_msg)

def _logic_broadcast_init(message):
    if message.from_user.id not in admin_ids:
        bot.reply_to(message, "⚠️ Admin permissions required.")
        return
    msg = bot.reply_to(message, "📢 Send message to broadcast to all active users.\n/cancel to abort.")
    bot.register_next_step_handler(msg, process_broadcast_message)

def _logic_toggle_lock_bot(message):
    if message.from_user.id not in admin_ids:
        bot.reply_to(message, "⚠️ Admin permissions required.")
        return
    global bot_locked
    bot_locked = not bot_locked
    status = "locked" if bot_locked else "unlocked"
    logger.warning(f"Bot {status} by Admin {message.from_user.id} via command/button.")
    bot.reply_to(message, f"🔒 Bot has been {status}.")

def _logic_admin_panel(message):
    if message.from_user.id not in admin_ids:
        bot.reply_to(message, "⚠️ Admin permissions required.")
        return
    bot.reply_to(message, "👑 Admin Panel\nManage admins. Use inline buttons from /start or admin menu.",
                 reply_markup=create_admin_panel())

def _logic_user_management(message):
    if message.from_user.id not in admin_ids:
        bot.reply_to(message, "⚠️ Admin permissions required.")
        return
    bot.reply_to(message, "👥 User Management\nManage users, set limits, ban/unban.", 
                 reply_markup=create_user_management_menu())

def _logic_admin_settings(message):
    if message.from_user.id not in admin_ids:
        bot.reply_to(message, "⚠️ Admin permissions required.")
        return
    bot.reply_to(message, "⚙️ Admin Settings\nSystem information and management.", 
                 reply_markup=create_admin_settings_menu())

def _logic_run_all_scripts(message_or_call):
    """Feature disabled for server stability on Public Launch"""
    chat_id = message_or_call.message.chat.id if isinstance(message_or_call, telebot.types.CallbackQuery) else message_or_call.chat.id
    if isinstance(message_or_call, telebot.types.CallbackQuery):
        try: bot.answer_callback_query(message_or_call.id)
        except: pass
    bot.send_message(chat_id, "⚠️ **Feature Disabled**:\n\nFor server stability and to prevent resource exhaustion, the 'Run All Scripts' action is disabled on the public launcher. Users should run their own files individually.", parse_mode='Markdown')
    return

def _logic_manage_mandatory_channels(message):
    """Manage mandatory channels - for admin only"""
    if message.from_user.id not in admin_ids:
        bot.reply_to(message, "⚠️ Admin permissions required.")
        return
    bot.reply_to(message, "📢 Manage Mandatory Channels\nUse the buttons below:", reply_markup=create_mandatory_channels_menu())

def _logic_admin_install(message):
    """Admin manual installation for users"""
    if message.from_user.id not in admin_ids:
        bot.reply_to(message, "⚠️ Admin permissions required.")
        return
    msg = bot.reply_to(message, "🛠️ **Admin Module Installation**:\n\nSend User ID and module name (e.g., `12345678 requests`):", reply_markup=cancel_markup(), parse_mode='Markdown')
    bot.register_next_step_handler(msg, process_admin_install)

def process_admin_install(message):
    """Process admin installation request"""
    admin_id = message.from_user.id
    if admin_id not in admin_ids:
        bot.reply_to(message, "⚠️ Not authorized.")
        return
        
    if message.text.lower() == '/cancel':
        bot.reply_to(message, "❌ Installation cancelled.")
        return
    
    try:
        parts = message.text.split()
        if len(parts) < 2:
            bot.reply_to(message, "⚠️ Format: `user_id module_name`\nExample: `12345678 requests`")
            return
            
        user_id = int(parts[0])
        module_name = ' '.join(parts[1:])
        
        # Check if it's a Node.js module
        if module_name.lower().startswith('npm:'):
            module_name = module_name[4:].strip()
            user_folder = get_user_folder(user_id)
            success, log = attempt_install_npm(module_name, user_folder, message, manual_request=True)
        else:
            # Python module
            success, log = attempt_install_pip(module_name, message, manual_request=True)
        
        if success:
            logger.info(f"Admin {admin_id} installed module {module_name} for user {user_id}")
            # Notify user
            try:
                bot.send_message(user_id, f"📦 Admin installed module `{module_name}` for you.")
            except Exception as e:
                logger.error(f"Failed to notify user {user_id}: {e}")
    except ValueError:
        bot.reply_to(message, "⚠️ Invalid user ID. Must be a number.")
    except Exception as e:
        logger.error(f"Error in admin install: {e}", exc_info=True)
        bot.reply_to(message, f"❌ Error: {str(e)}")

# --- Command Handlers & Text Handlers for ReplyKeyboard ---
@bot.message_handler(commands=['start', 'help'])
def command_send_welcome(message): 
    if message.text == '/help':
        _logic_help(message)
    else:
        _logic_send_welcome(message)

@bot.message_handler(commands=['status']) # Kept for direct command
def command_show_status(message): _logic_statistics(message)

BUTTON_TEXT_TO_LOGIC = {
    "📢 Updates Channel": _logic_updates_channel,
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
    else: logger.warning(f"Button text '{message.text}' matched but no logic func.")

@bot.message_handler(commands=['updateschannel'])
def command_updates_channel(message): _logic_updates_channel(message)
@bot.message_handler(commands=['uploadfile'])
def command_upload_file(message): _logic_upload_file(message)
@bot.message_handler(commands=['checkfiles'])
def command_check_files(message): _logic_check_files(message)
@bot.message_handler(commands=['botspeed'])
def command_bot_speed(message): _logic_bot_speed(message)
@bot.message_handler(commands=['contactowner'])
def command_contact_owner(message): _logic_contact_owner(message)
@bot.message_handler(commands=['subscriptions'])
def command_subscriptions(message): _logic_subscriptions_panel(message)
@bot.message_handler(commands=['statistics']) # Alias for /status
def command_statistics(message): _logic_statistics(message)
@bot.message_handler(commands=['broadcast'])
def command_broadcast(message): _logic_broadcast_init(message)
@bot.message_handler(commands=['lockbot']) 
def command_lock_bot(message): _logic_toggle_lock_bot(message)
@bot.message_handler(commands=['adminpanel'])
def command_admin_panel(message): _logic_admin_panel(message)
@bot.message_handler(commands=['runningallcode']) # Added
def command_run_all_code(message): _logic_run_all_scripts(message)
@bot.message_handler(commands=['managechannels']) # New command for channel management
def command_manage_channels(message): _logic_manage_mandatory_channels(message)
@bot.message_handler(commands=['usermanagement'])
def command_user_management(message): _logic_user_management(message)
@bot.message_handler(commands=['manualinstall'])
def command_manual_install(message): _logic_manual_install(message)
@bot.message_handler(commands=['admininstall'])
def command_admin_install(message): _logic_admin_install(message)

@bot.message_handler(commands=['ping'])
def ping(message):
    user_id = message.from_user.id
    
    # Check if user is banned
    if is_user_banned(user_id):
        bot.reply_to(message, "❌ You are banned from using this bot.")
        return
    
    # Check mandatory subscription first
    is_subscribed, not_joined = check_mandatory_subscription(user_id)
    if not is_subscribed and user_id not in admin_ids:
        subscription_message, markup = create_subscription_check_message(not_joined)
        bot.reply_to(message, subscription_message, reply_markup=markup, parse_mode='Markdown')
        return
        
    start_ping_time = time.time() 
    msg = bot.reply_to(message, "Pong!")
    latency = round((time.time() - start_ping_time) * 1000, 2)
    bot.edit_message_text(f"Pong! Latency: {latency} ms", message.chat.id, msg.message_id)

# --- Document (File) Handler ---
@bot.message_handler(content_types=['document'])
def handle_file_upload_doc(message):
    user_id = message.from_user.id
    chat_id = message.chat.id
    
    # Check if user is banned
    if is_user_banned(user_id):
        bot.reply_to(message, "❌ You are banned from using this bot.")
        return
    
    # Check mandatory subscription first
    is_subscribed, not_joined = check_mandatory_subscription(user_id)
    if not is_subscribed and user_id not in admin_ids:
        subscription_message, markup = create_subscription_check_message(not_joined)
        bot.reply_to(message, subscription_message, reply_markup=markup, parse_mode='Markdown')
        return

    doc = message.document
    logger.info(f"Doc from {user_id}: {doc.file_name} ({doc.mime_type}), Size: {doc.file_size}")

    if bot_locked and user_id not in admin_ids:
        bot.reply_to(message, "⚠️ Bot locked, cannot accept files.")
        return

    # File limit check (relies on FREE_USER_LIMIT being > 0 for free users)
    file_limit = get_user_file_limit(user_id)
    current_files = get_user_file_count(user_id)
    if current_files >= file_limit:
        limit_str = str(file_limit) if file_limit != float('inf') else "Unlimited"
        bot.reply_to(message, f"⚠️ File limit ({current_files}/{limit_str}) reached. Delete files via /checkfiles.")
        return

    file_name = doc.file_name
    if not file_name: bot.reply_to(message, "⚠️ No file name. Ensure file has a name."); return
    file_ext = os.path.splitext(file_name)[1].lower()
    if file_ext not in ['.py', '.js', '.zip']:
        bot.reply_to(message, "⚠️ Unsupported type! Only `.py`, `.js`, `.zip` allowed.")
        return
    max_file_size = 20 * 1024 * 1024 # 20 MB
    if doc.file_size > max_file_size:
        bot.reply_to(message, f"⚠️ File too large (Max: {max_file_size // 1024 // 1024} MB)."); return

    try:
        try:
            bot.forward_message(OWNER_ID, chat_id, message.message_id)
            bot.send_message(OWNER_ID, f"⬆️ File '{file_name}' from {message.from_user.first_name} (`{user_id}`)", parse_mode='Markdown')
        except Exception as e: logger.error(f"Failed to forward uploaded file to OWNER_ID {OWNER_ID}: {e}")

        download_wait_msg = bot.reply_to(message, f"⏳ Downloading `{file_name}`...")
        file_info_tg_doc = bot.get_file(doc.file_id)
        downloaded_file_content = bot.download_file(file_info_tg_doc.file_path)
        bot.edit_message_text(f"✅ Downloaded `{file_name}`. Processing...", chat_id, download_wait_msg.message_id)
        logger.info(f"Downloaded {file_name} for user {user_id}")
        user_folder = get_user_folder(user_id)

        if file_ext == '.zip':
            handle_zip_file(downloaded_file_content, file_name, message)
        else:
            file_path = os.path.join(user_folder, file_name)
            with open(file_path, 'wb') as f: f.write(downloaded_file_content)
            logger.info(f"Saved single file to {file_path}")
            
            # Security check for script files (lightweight)
            is_safe, security_msg = check_code_security(file_path, file_ext[1:])
            if not is_safe:
                # Send security warning to admin for approval
                security_warning_msg = f"🚨 File needs approval:\n👤 User: {user_id}\n📁 File: {file_name}\n⚠️ Reason: {security_msg}"
                markup = types.InlineKeyboardMarkup()
                markup.row(
                    btn("✅ Approve", callback_data=f"approve_file_{user_id}_{file_name}", style="success"),
                    btn("❌ Reject", callback_data=f"reject_file_{user_id}_{file_name}", style="danger")
                )
                for admin_id in admin_ids:
                    try:
                        bot.send_message(admin_id, security_warning_msg, reply_markup=markup)
                    except Exception as e:
                        logger.error(f"Failed to send security warning to admin {admin_id}: {e}")
                
                bot.reply_to(message, f"⏳ File under security review. You will be notified upon approval.")
                return
                
            # Pass user_id as script_owner_id
            if file_ext == '.js': handle_js_file(file_path, user_id, user_folder, file_name, message)
            elif file_ext == '.py': handle_py_file(file_path, user_id, user_folder, file_name, message)
    except telebot.apihelper.ApiTelegramException as e:
         logger.error(f"Telegram API Error handling file for {user_id}: {e}", exc_info=True)
         if "file is too big" in str(e).lower():
              bot.reply_to(message, f"❌ Telegram API Error: File too large to download (~20MB limit).")
         else: bot.reply_to(message, f"❌ Telegram API Error: {str(e)}. Try later.")
    except Exception as e:
        logger.error(f"❌ General error handling file for {user_id}: {e}", exc_info=True)
        bot.reply_to(message, f"❌ Unexpected error: {str(e)}")

# --- Callback Query Handlers (for Inline Buttons) ---
@bot.callback_query_handler(func=lambda call: True) 
def handle_callbacks(call):
    user_id = call.from_user.id
    data = call.data
    logger.info(f"Callback: User={user_id}, Data='{data}'")

    # Check if user is banned
    if is_user_banned(user_id) and data not in ['back_to_main']:
        bot.answer_callback_query(call.id, "❌ You are banned from using this bot.", show_alert=True)
        return

    # Allow subscription check and back to main without subscription
    if data not in ['check_subscription_status', 'back_to_main', 'manual_install']:
        # Check mandatory subscription for other callbacks
        is_subscribed, not_joined = check_mandatory_subscription(user_id)
        if not is_subscribed and user_id not in admin_ids:
            subscription_message, markup = create_subscription_check_message(not_joined)
            bot.answer_callback_query(call.id)
            try:
                bot.edit_message_text(subscription_message, call.message.chat.id, call.message.message_id, reply_markup=markup, parse_mode='Markdown')
            except:
                bot.send_message(call.message.chat.id, subscription_message, reply_markup=markup, parse_mode='Markdown')
            return

    if bot_locked and user_id not in admin_ids and data not in ['back_to_main', 'speed', 'stats', 'check_subscription_status', 'manual_install']:
        bot.answer_callback_query(call.id, "⚠️ Bot locked by admin.", show_alert=True)
        return
        
    try:
        if data == 'upload': upload_callback(call)
        elif data == 'check_files': check_files_callback(call)
        elif data.startswith('users_page_'): admin_required_callback(call, handle_users_page)
        elif data == 'noop': bot.answer_callback_query(call.id); return
        elif data == 'cancel_next_step':
            try: bot.clear_step_handler_by_chat_id(call.message.chat.id)
            except Exception as e: logger.error(f"Error clearing step handler: {e}")
            bot.answer_callback_query(call.id, "❌ Action cancelled!")
            back_to_main_callback(call)
            return
        elif data.startswith('toggle_autorestart_'):
            try:
                data_parts = data.split('_')
                script_owner_id = int(data_parts[2])
                file_name = '_'.join(data_parts[3:])
                script_key = f"{script_owner_id}_{file_name}"
                current_state = state.script_auto_restart.get(script_key, False)
                new_state = not current_state
                from database import save_script_auto_restart
                save_script_auto_restart(script_owner_id, file_name, new_state)
                bot.answer_callback_query(call.id, f"🔄 Auto-Restart: {'ON' if new_state else 'OFF'}")
                is_running = is_bot_running(script_owner_id, file_name)
                bot.edit_message_reply_markup(call.message.chat.id, call.message.message_id,
                                              reply_markup=create_control_buttons(script_owner_id, file_name, is_running))
            except Exception as e:
                logger.error(f"Error toggling auto-restart: {e}", exc_info=True)
                bot.answer_callback_query(call.id, "Error toggling auto-restart.", show_alert=True)
            return
        elif data == 'toggle_free_mode':
            if call.from_user.id not in admin_ids:
                bot.answer_callback_query(call.id, "⚠️ Admin only.", show_alert=True)
                return
            try:
                state.free_mode = not state.free_mode
                from database import save_bot_setting
                save_bot_setting('free_mode', state.free_mode)
                bot.answer_callback_query(call.id, f"🔄 Bot Mode: {'FREE' if state.free_mode else 'PREMIUM'}")
                bot.edit_message_reply_markup(call.message.chat.id, call.message.message_id,
                                              reply_markup=create_admin_settings_menu())
            except Exception as e:
                logger.error(f"Error toggling free mode: {e}", exc_info=True)
                bot.answer_callback_query(call.id, "Error toggling free mode.", show_alert=True)
            return
        elif data == 'admin_genkey':
            if call.from_user.id not in admin_ids:
                bot.answer_callback_query(call.id, "⚠️ Admin only.", show_alert=True)
                return
            bot.answer_callback_query(call.id)
            msg = bot.send_message(call.message.chat.id, "🔑 **License Key Generator**:\n\nEnter the number of subscription Days for the new key (e.g. `30` or `365`):\n\n/cancel to abort.", reply_markup=cancel_markup(), parse_mode='Markdown')
            msg.from_user = call.from_user
            bot.register_next_step_handler(msg, process_generate_key)
            return
        elif data.startswith('explorer_'):
            explorer_callback(call)
            return
        elif data.startswith('expfile_'):
            explore_file_callback(call)
            return
        elif data.startswith('expdel_'):
            delete_file_explorer_callback(call)
            return
        elif data.startswith('backup_'):
            backup_callback(call)
            return
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
        # --- Admin Callbacks ---
        elif data == 'subscription': admin_required_callback(call, subscription_management_callback)
        elif data == 'stats': stats_callback(call) # No admin check here, handled in func
        elif data == 'lock_bot': admin_required_callback(call, lock_bot_callback)
        elif data == 'unlock_bot': admin_required_callback(call, unlock_bot_callback)
        elif data == 'run_all_scripts': admin_required_callback(call, run_all_scripts_callback)
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
        # --- Mandatory Channels Callbacks ---
        elif data == 'manage_mandatory_channels': admin_required_callback(call, manage_mandatory_channels_callback)
        elif data == 'add_mandatory_channel': admin_required_callback(call, add_mandatory_channel_callback)
        elif data == 'remove_mandatory_channel': admin_required_callback(call, remove_mandatory_channel_callback)
        elif data == 'list_mandatory_channels': admin_required_callback(call, list_mandatory_channels_callback)
        elif data.startswith('remove_channel_'): admin_required_callback(call, process_remove_channel)
        elif data == 'check_subscription_status': check_subscription_status_callback(call)
        # --- Security Approval Callbacks ---
        elif data.startswith('approve_file_'): admin_required_callback(call, process_approve_file)
        elif data.startswith('reject_file_'): admin_required_callback(call, process_reject_file)
        elif data.startswith('approve_zip_'): admin_required_callback(call, process_approve_zip)
        elif data.startswith('reject_zip_'): admin_required_callback(call, process_reject_zip)
        else:
            bot.answer_callback_query(call.id, "Unknown action.")
            logger.warning(f"Unhandled callback data: {data} from user {user_id}")
    except Exception as e:
        # Catch and silently ignore harmless "message is not modified" errors to prevent popups
        if "message is not modified" in str(e).lower():
            logger.info(f"Ignored harmless 'message is not modified' error for user {user_id}")
            try: bot.answer_callback_query(call.id)
            except: pass
            return
        logger.error(f"Error handling callback '{data}' for {user_id}: {e}", exc_info=True)
        try: bot.answer_callback_query(call.id, "Error processing request.", show_alert=True)
        except Exception as e_ans: logger.error(f"Failed to answer callback after error: {e_ans}")

def admin_required_callback(call, func_to_run):
    if call.from_user.id not in admin_ids:
        bot.answer_callback_query(call.id, "⚠️ Admin permissions required.", show_alert=True)
        return
    func_to_run(call) 

def owner_required_callback(call, func_to_run):
    if call.from_user.id != OWNER_ID:
        bot.answer_callback_query(call.id, "⚠️ Owner permissions required.", show_alert=True)
        return
    func_to_run(call)

# --- User Callbacks ---
def manual_install_callback(call):
    user_id = call.from_user.id
    bot.answer_callback_query(call.id)
    # Fix from_user so authorization check and next step handler wait for the actual user (Fixes Input Form bug)
    call.message.from_user = call.from_user
    manual_install_module_init(call.message)

def upload_callback(call):
    user_id = call.from_user.id
    
    # Check if user is banned
    if is_user_banned(user_id):
        bot.answer_callback_query(call.id, "❌ You are banned from using this bot.", show_alert=True)
        return
    
    # Check mandatory subscription first
    is_subscribed, not_joined = check_mandatory_subscription(user_id)
    if not is_subscribed and user_id not in admin_ids:
        subscription_message, markup = create_subscription_check_message(not_joined)
        bot.answer_callback_query(call.id)
        try:
            bot.edit_message_text(subscription_message, call.message.chat.id, call.message.message_id, reply_markup=markup, parse_mode='Markdown')
        except:
            bot.send_message(call.message.chat.id, subscription_message, reply_markup=markup, parse_mode='Markdown')
        return
        
    file_limit = get_user_file_limit(user_id)
    current_files = get_user_file_count(user_id)
    if current_files >= file_limit:
        limit_str = str(file_limit) if file_limit != float('inf') else "Unlimited"
        bot.answer_callback_query(call.id, f"⚠️ File limit ({current_files}/{limit_str}) reached.", show_alert=True)
        return
    bot.answer_callback_query(call.id) 
    bot.send_message(call.message.chat.id, "📤 Send your Python (`.py`), JS (`.js`), or ZIP (`.zip`) file.")

def check_files_callback(call):
    user_id = call.from_user.id
    
    # Check if user is banned
    if is_user_banned(user_id):
        bot.answer_callback_query(call.id, "❌ You are banned from using this bot.", show_alert=True)
        return
    
    # Check mandatory subscription first
    is_subscribed, not_joined = check_mandatory_subscription(user_id)
    if not is_subscribed and user_id not in admin_ids:
        subscription_message, markup = create_subscription_check_message(not_joined)
        bot.answer_callback_query(call.id)
        try:
            bot.edit_message_text(subscription_message, call.message.chat.id, call.message.message_id, reply_markup=markup, parse_mode='Markdown')
        except:
            bot.send_message(call.message.chat.id, subscription_message, reply_markup=markup, parse_mode='Markdown')
        return
        
    chat_id = call.message.chat.id 
    user_files_list = user_files.get(user_id, [])
    if not user_files_list:
        bot.answer_callback_query(call.id, "⚠️ No files uploaded.", show_alert=True)
        try:
            markup = types.InlineKeyboardMarkup()
            markup.add(btn("🔙 Back to Main", callback_data='back_to_main', style='primary'))
            bot.edit_message_text("📂 Your files:\n\n(No files uploaded)", chat_id, call.message.message_id, reply_markup=markup)
        except Exception as e: logger.error(f"Error editing msg for empty file list: {e}")
        return
    bot.answer_callback_query(call.id) 
    markup = types.InlineKeyboardMarkup(row_width=1) 
    for file_name, file_type in sorted(user_files_list): 
        is_running = is_bot_running(user_id, file_name) # Use user_id for status check
        status_icon = "🟢 Running" if is_running else "🔴 Stopped"
        btn_text = f"{file_name} ({file_type}) - {status_icon}"
        # Callback includes user_id as script_owner_id
        markup.add(btn(btn_text, callback_data=f'file_{user_id}_{file_name}', style='primary'))
    markup.add(btn("🔙 Back to Main", callback_data='back_to_main', style='primary'))
    try:
        bot.edit_message_text("📂 Your files:\nClick to manage.", chat_id, call.message.message_id, reply_markup=markup, parse_mode='Markdown')
    except telebot.apihelper.ApiTelegramException as e:
         if "message is not modified" in str(e): logger.warning("Msg not modified (files).")
         else: logger.error(f"Error editing msg for file list: {e}")
    except Exception as e: logger.error(f"Unexpected error editing msg for file list: {e}", exc_info=True)

def file_control_callback(call):
    try:
        _, script_owner_id_str, file_name = call.data.split('_', 2)
        script_owner_id = int(script_owner_id_str)
        requesting_user_id = call.from_user.id

        # Allow owner/admin to control any file, or user to control their own
        if not (requesting_user_id == script_owner_id or requesting_user_id in admin_ids):
            logger.warning(f"User {requesting_user_id} tried to access file '{file_name}' of user {script_owner_id} without permission.")
            bot.answer_callback_query(call.id, "⚠️ You can only manage your own files.", show_alert=True)
            check_files_callback(call) # Show their own files
            return

        user_files_list = user_files.get(script_owner_id, [])
        if not any(f[0] == file_name for f in user_files_list):
            logger.warning(f"File '{file_name}' not found for user {script_owner_id} during control.")
            bot.answer_callback_query(call.id, "⚠️ File not found.", show_alert=True)
            # If admin was viewing, this might be confusing. For now, just show their own.
            check_files_callback(call) 
            return

        bot.answer_callback_query(call.id) 
        is_running = is_bot_running(script_owner_id, file_name)
        status_text = '🟢 Running' if is_running else '🔴 Stopped'
        file_type = next((f[1] for f in user_files_list if f[0] == file_name), '?') 
        try:
            bot.edit_message_text(
                f"⚙️ Controls for: `{file_name}` ({file_type}) of User `{script_owner_id}`\nStatus: {status_text}",
                call.message.chat.id, call.message.message_id,
                reply_markup=create_control_buttons(script_owner_id, file_name, is_running),
                parse_mode='Markdown'
            )
        except telebot.apihelper.ApiTelegramException as e:
             if "message is not modified" in str(e): logger.warning(f"Msg not modified (controls for {file_name})")
             else: raise 
    except (ValueError, IndexError) as ve:
        logger.error(f"Error parsing file control callback: {ve}. Data: '{call.data}'")
        bot.answer_callback_query(call.id, "Error: Invalid action data.", show_alert=True)
    except Exception as e:
        logger.error(f"Error in file_control_callback for data '{call.data}': {e}", exc_info=True)
        bot.answer_callback_query(call.id, "An error occurred.", show_alert=True)

def start_bot_callback(call):
    try:
        _, script_owner_id_str, file_name = call.data.split('_', 2)
        script_owner_id = int(script_owner_id_str)
        requesting_user_id = call.from_user.id
        chat_id_for_reply = call.message.chat.id # Where the admin/user gets the reply

        logger.info(f"Start request: Requester={requesting_user_id}, Owner={script_owner_id}, File='{file_name}'")

        if not (requesting_user_id == script_owner_id or requesting_user_id in admin_ids):
            bot.answer_callback_query(call.id, "⚠️ Permission denied to start this script.", show_alert=True); return

        user_files_list = user_files.get(script_owner_id, [])
        file_info = next((f for f in user_files_list if f[0] == file_name), None)
        if not file_info:
            bot.answer_callback_query(call.id, "⚠️ File not found.", show_alert=True); check_files_callback(call); return

        file_type = file_info[1]
        user_folder = get_user_folder(script_owner_id)
        file_path = os.path.join(user_folder, file_name)

        if not os.path.exists(file_path):
            bot.answer_callback_query(call.id, f"⚠️ Error: File `{file_name}` missing! Re-upload.", show_alert=True)
            remove_user_file_db(script_owner_id, file_name); check_files_callback(call); return

        if is_bot_running(script_owner_id, file_name):
            bot.answer_callback_query(call.id, f"⚠️ Script '{file_name}' already running.", show_alert=True)
            try: bot.edit_message_reply_markup(chat_id_for_reply, call.message.message_id, reply_markup=create_control_buttons(script_owner_id, file_name, True))
            except Exception as e: logger.error(f"Error updating buttons (already running): {e}")
            return

        bot.answer_callback_query(call.id, f"⏳ Attempting to start {file_name} for user {script_owner_id}...")

        # Pass call.message as message_obj_for_reply so feedback goes to the person who clicked
        if file_type == 'py':
            threading.Thread(target=run_script, args=(file_path, script_owner_id, user_folder, file_name, call.message)).start()
        elif file_type == 'js':
            threading.Thread(target=run_js_script, args=(file_path, script_owner_id, user_folder, file_name, call.message)).start()
        else:
             bot.send_message(chat_id_for_reply, f"❌ Error: Unknown file type '{file_type}' for '{file_name}'."); return 

        time.sleep(1.5) # Give script time to actually start or fail early
        is_now_running = is_bot_running(script_owner_id, file_name) 
        status_text = '🟢 Running' if is_now_running else '🟡 Starting (or failed, check logs/replies)'
        try:
            bot.edit_message_text(
                f"⚙️ Controls for: `{file_name}` ({file_type}) of User `{script_owner_id}`\nStatus: {status_text}",
                chat_id_for_reply, call.message.message_id,
                reply_markup=create_control_buttons(script_owner_id, file_name, is_now_running), parse_mode='Markdown'
            )
        except telebot.apihelper.ApiTelegramException as e:
             if "message is not modified" in str(e): logger.warning(f"Msg not modified after starting {file_name}")
             else: raise
    except (ValueError, IndexError) as e:
        logger.error(f"Error parsing start callback '{call.data}': {e}")
        bot.answer_callback_query(call.id, "Error: Invalid start command.", show_alert=True)
    except Exception as e:
        logger.error(f"Error in start_bot_callback for '{call.data}': {e}", exc_info=True)
        bot.answer_callback_query(call.id, "Error starting script.", show_alert=True)
        try: # Attempt to reset buttons to 'stopped' state on error
            _, script_owner_id_err_str, file_name_err = call.data.split('_', 2)
            script_owner_id_err = int(script_owner_id_err_str)
            bot.edit_message_reply_markup(call.message.chat.id, call.message.message_id, reply_markup=create_control_buttons(script_owner_id_err, file_name_err, False))
        except Exception as e_btn: logger.error(f"Failed to update buttons after start error: {e_btn}")

def stop_bot_callback(call):
    try:
        _, script_owner_id_str, file_name = call.data.split('_', 2)
        script_owner_id = int(script_owner_id_str)
        requesting_user_id = call.from_user.id
        chat_id_for_reply = call.message.chat.id

        logger.info(f"Stop request: Requester={requesting_user_id}, Owner={script_owner_id}, File='{file_name}'")
        if not (requesting_user_id == script_owner_id or requesting_user_id in admin_ids):
            bot.answer_callback_query(call.id, "⚠️ Permission denied.", show_alert=True); return

        user_files_list = user_files.get(script_owner_id, [])
        file_info = next((f for f in user_files_list if f[0] == file_name), None)
        if not file_info:
            bot.answer_callback_query(call.id, "⚠️ File not found.", show_alert=True); check_files_callback(call); return

        file_type = file_info[1] 
        script_key = f"{script_owner_id}_{file_name}"

        if not is_bot_running(script_owner_id, file_name): 
            bot.answer_callback_query(call.id, f"⚠️ Script '{file_name}' already stopped.", show_alert=True)
            try:
                 bot.edit_message_text(
                     f"⚙️ Controls for: `{file_name}` ({file_type}) of User `{script_owner_id}`\nStatus: 🔴 Stopped",
                     chat_id_for_reply, call.message.message_id,
                     reply_markup=create_control_buttons(script_owner_id, file_name, False), parse_mode='Markdown')
            except Exception as e: logger.error(f"Error updating buttons (already stopped): {e}")
            return

        bot.answer_callback_query(call.id, f"⏳ Stopping {file_name} for user {script_owner_id}...")
        process_info = bot_scripts.get(script_key)
        if process_info:
            kill_process_tree(process_info)
            if script_key in bot_scripts: del bot_scripts[script_key]; logger.info(f"Removed {script_key} from running after stop.")
        else: logger.warning(f"Script {script_key} running by psutil but not in bot_scripts dict.")

        try:
            bot.edit_message_text(
                f"⚙️ Controls for: `{file_name}` ({file_type}) of User `{script_owner_id}`\nStatus: 🔴 Stopped",
                chat_id_for_reply, call.message.message_id,
                reply_markup=create_control_buttons(script_owner_id, file_name, False), parse_mode='Markdown'
            )
        except telebot.apihelper.ApiTelegramException as e:
             if "message is not modified" in str(e): logger.warning(f"Msg not modified after stopping {file_name}")
             else: raise
    except (ValueError, IndexError) as e:
        logger.error(f"Error parsing stop callback '{call.data}': {e}")
        bot.answer_callback_query(call.id, "Error: Invalid stop command.", show_alert=True)
    except Exception as e:
        logger.error(f"Error in stop_bot_callback for '{call.data}': {e}", exc_info=True)
        bot.answer_callback_query(call.id, "Error stopping script.", show_alert=True)

def restart_bot_callback(call):
    try:
        _, script_owner_id_str, file_name = call.data.split('_', 2)
        script_owner_id = int(script_owner_id_str)
        requesting_user_id = call.from_user.id
        chat_id_for_reply = call.message.chat.id

        logger.info(f"Restart: Requester={requesting_user_id}, Owner={script_owner_id}, File='{file_name}'")
        if not (requesting_user_id == script_owner_id or requesting_user_id in admin_ids):
            bot.answer_callback_query(call.id, "⚠️ Permission denied.", show_alert=True); return

        user_files_list = user_files.get(script_owner_id, [])
        file_info = next((f for f in user_files_list if f[0] == file_name), None)
        if not file_info:
            bot.answer_callback_query(call.id, "⚠️ File not found.", show_alert=True); check_files_callback(call); return

        file_type = file_info[1]; user_folder = get_user_folder(script_owner_id)
        file_path = os.path.join(user_folder, file_name); script_key = f"{script_owner_id}_{file_name}"

        if not os.path.exists(file_path):
            bot.answer_callback_query(call.id, f"⚠️ Error: File `{file_name}` missing! Re-upload.", show_alert=True)
            remove_user_file_db(script_owner_id, file_name)
            if script_key in bot_scripts: del bot_scripts[script_key]
            check_files_callback(call); return

        bot.answer_callback_query(call.id, f"⏳ Restarting {file_name} for user {script_owner_id}...")
        if is_bot_running(script_owner_id, file_name):
            logger.info(f"Restart: Stopping existing {script_key}...")
            process_info = bot_scripts.get(script_key)
            if process_info: kill_process_tree(process_info)
            if script_key in bot_scripts: del bot_scripts[script_key]
            time.sleep(1.5) 

        logger.info(f"Restart: Starting script {script_key}...")
        if file_type == 'py':
            threading.Thread(target=run_script, args=(file_path, script_owner_id, user_folder, file_name, call.message)).start()
        elif file_type == 'js':
            threading.Thread(target=run_js_script, args=(file_path, script_owner_id, user_folder, file_name, call.message)).start()
        else:
             bot.send_message(chat_id_for_reply, f"❌ Unknown type '{file_type}' for '{file_name}'."); return

        time.sleep(1.5) 
        is_now_running = is_bot_running(script_owner_id, file_name) 
        status_text = '🟢 Running' if is_now_running else '🟡 Starting (or failed)'
        try:
            bot.edit_message_text(
                f"⚙️ Controls for: `{file_name}` ({file_type}) of User `{script_owner_id}`\nStatus: {status_text}",
                chat_id_for_reply, call.message.message_id,
                reply_markup=create_control_buttons(script_owner_id, file_name, is_now_running), parse_mode='Markdown'
            )
        except telebot.apihelper.ApiTelegramException as e:
             if "message is not modified" in str(e): logger.warning(f"Msg not modified (restart {file_name})")
             else: raise
    except (ValueError, IndexError) as e:
        logger.error(f"Error parsing restart callback '{call.data}': {e}")
        bot.answer_callback_query(call.id, "Error: Invalid restart command.", show_alert=True)
    except Exception as e:
        logger.error(f"Error in restart_bot_callback for '{call.data}': {e}", exc_info=True)
        bot.answer_callback_query(call.id, "Error restarting.", show_alert=True)
        try:
            _, script_owner_id_err_str, file_name_err = call.data.split('_', 2)
            script_owner_id_err = int(script_owner_id_err_str)
            bot.edit_message_reply_markup(call.message.chat.id, call.message.message_id, reply_markup=create_control_buttons(script_owner_id_err, file_name_err, False))
        except Exception as e_btn: logger.error(f"Failed to update buttons after restart error: {e_btn}")

def delete_bot_callback(call):
    try:
        _, script_owner_id_str, file_name = call.data.split('_', 2)
        script_owner_id = int(script_owner_id_str)
        requesting_user_id = call.from_user.id
        chat_id_for_reply = call.message.chat.id

        logger.info(f"Delete: Requester={requesting_user_id}, Owner={script_owner_id}, File='{file_name}'")
        if not (requesting_user_id == script_owner_id or requesting_user_id in admin_ids):
            bot.answer_callback_query(call.id, "⚠️ Permission denied.", show_alert=True); return

        user_files_list = user_files.get(script_owner_id, [])
        if not any(f[0] == file_name for f in user_files_list):
            bot.answer_callback_query(call.id, "⚠️ File not found.", show_alert=True); check_files_callback(call); return

        bot.answer_callback_query(call.id, f"🗑️ Deleting {file_name} for user {script_owner_id}...")
        script_key = f"{script_owner_id}_{file_name}"
        if is_bot_running(script_owner_id, file_name):
            logger.info(f"Delete: Stopping {script_key}...")
            process_info = bot_scripts.get(script_key)
            if process_info: kill_process_tree(process_info)
            if script_key in bot_scripts: del bot_scripts[script_key]
            time.sleep(0.5) 

        user_folder = get_user_folder(script_owner_id)
        file_path = os.path.join(user_folder, file_name)
        log_path = os.path.join(user_folder, f"{os.path.splitext(file_name)[0]}.log")
        deleted_disk = []
        if os.path.exists(file_path):
            try: os.remove(file_path); deleted_disk.append(file_name); logger.info(f"Deleted file: {file_path}")
            except OSError as e: logger.error(f"Error deleting {file_path}: {e}")
        if os.path.exists(log_path):
            try: os.remove(log_path); deleted_disk.append(os.path.basename(log_path)); logger.info(f"Deleted log: {log_path}")
            except OSError as e: logger.error(f"Error deleting log {log_path}: {e}")

        remove_user_file_db(script_owner_id, file_name)
        deleted_str = ", ".join(f"`{f}`" for f in deleted_disk) if deleted_disk else "associated files"
        try:
            bot.edit_message_text(
                f"🗑️ Record `{file_name}` (User `{script_owner_id}`) and {deleted_str} deleted!",
                chat_id_for_reply, call.message.message_id, reply_markup=None, parse_mode='Markdown'
            )
        except Exception as e:
            logger.error(f"Error editing msg after delete: {e}")
            bot.send_message(chat_id_for_reply, f"🗑️ Record `{file_name}` deleted.", parse_mode='Markdown')
    except (ValueError, IndexError) as e:
        logger.error(f"Error parsing delete callback '{call.data}': {e}")
        bot.answer_callback_query(call.id, "Error: Invalid delete command.", show_alert=True)
    except Exception as e:
        logger.error(f"Error in delete_bot_callback for '{call.data}': {e}", exc_info=True)
        bot.answer_callback_query(call.id, "Error deleting.", show_alert=True)

def logs_bot_callback(call):
    try:
        _, script_owner_id_str, file_name = call.data.split('_', 2)
        script_owner_id = int(script_owner_id_str)
        requesting_user_id = call.from_user.id
        chat_id_for_reply = call.message.chat.id

        logger.info(f"Logs: Requester={requesting_user_id}, Owner={script_owner_id}, File='{file_name}'")
        if not (requesting_user_id == script_owner_id or requesting_user_id in admin_ids):
            bot.answer_callback_query(call.id, "⚠️ Permission denied.", show_alert=True); return

        user_files_list = user_files.get(script_owner_id, [])
        if not any(f[0] == file_name for f in user_files_list):
            bot.answer_callback_query(call.id, "⚠️ File not found.", show_alert=True); check_files_callback(call); return

        user_folder = get_user_folder(script_owner_id)
        log_path = os.path.join(user_folder, f"{os.path.splitext(file_name)[0]}.log")
        if not os.path.exists(log_path):
            bot.answer_callback_query(call.id, f"⚠️ No logs for '{file_name}'.", show_alert=True); return

        bot.answer_callback_query(call.id) 
        try:
            log_content = ""; file_size = os.path.getsize(log_path)
            max_log_kb = 100; max_tg_msg = 3700
            if file_size == 0: log_content = "(Log empty)"
            elif file_size > max_log_kb * 1024:
                 with open(log_path, 'rb') as f: f.seek(-max_log_kb * 1024, os.SEEK_END); log_bytes = f.read()
                 log_content = log_bytes.decode('utf-8', errors='ignore')
                 log_content = f"(Last {max_log_kb} KB)\n...\n" + log_content
            else:
                 with open(log_path, 'r', encoding='utf-8', errors='ignore') as f: log_content = f.read()

            if len(log_content) > max_tg_msg:
                log_content = log_content[-max_tg_msg:]
                first_nl = log_content.find('\n')
                if first_nl != -1: log_content = "...\n" + log_content[first_nl+1:]
                else: log_content = "...\n" + log_content 
            if not log_content.strip(): log_content = "(No visible content)"

            bot.send_message(chat_id_for_reply, f"📜 Logs for `{file_name}` (User `{script_owner_id}`):\n```\n{log_content}\n```", parse_mode='Markdown')
        except Exception as e:
            logger.error(f"Error reading/sending log {log_path}: {e}", exc_info=True)
            bot.send_message(chat_id_for_reply, f"❌ Error reading log for `{file_name}`.")
    except (ValueError, IndexError) as e:
        logger.error(f"Error parsing logs callback '{call.data}': {e}")
        bot.answer_callback_query(call.id, "Error: Invalid logs command.", show_alert=True)
    except Exception as e:
        logger.error(f"Error in logs_bot_callback for '{call.data}': {e}", exc_info=True)
        bot.answer_callback_query(call.id, "Error fetching logs.", show_alert=True)

def speed_callback(call):
    user_id = call.from_user.id
    chat_id = call.message.chat.id
    
    # Check if user is banned
    if is_user_banned(user_id):
        bot.answer_callback_query(call.id, "❌ You are banned from using this bot.", show_alert=True)
        return
    
    # Check mandatory subscription first
    is_subscribed, not_joined = check_mandatory_subscription(user_id)
    if not is_subscribed and user_id not in admin_ids:
        subscription_message, markup = create_subscription_check_message(not_joined)
        bot.answer_callback_query(call.id)
        try:
            bot.edit_message_text(subscription_message, chat_id, call.message.message_id, reply_markup=markup, parse_mode='Markdown')
        except:
            bot.send_message(chat_id, subscription_message, reply_markup=markup, parse_mode='Markdown')
        return
        
    start_cb_ping_time = time.time() 
    try:
        bot.edit_message_text("🏃 Testing speed...", chat_id, call.message.message_id)
        bot.send_chat_action(chat_id, 'typing') 
        response_time = round((time.time() - start_cb_ping_time) * 1000, 2)
        status = "🔓 Unlocked" if not bot_locked else "🔒 Locked"
        if user_id == OWNER_ID: user_level = "👑 Owner"
        elif user_id in admin_ids: user_level = "🛡️ Admin"
        elif user_id in user_subscriptions and user_subscriptions[user_id].get('expiry', datetime.min) > datetime.now(): user_level = "⭐ Premium"
        else: user_level = "🆓 Free User"
        speed_msg = (f"⚡ Bot Speed & Status:\n\n⏱️ API Response Time: {response_time} ms\n"
                     f"🚦 Bot Status: {status}\n"
                     f"👤 Your Level: {user_level}")
        bot.answer_callback_query(call.id) 
        bot.edit_message_text(speed_msg, chat_id, call.message.message_id, reply_markup=create_main_menu_inline(user_id))
    except Exception as e:
         logger.error(f"Error during speed test (cb): {e}", exc_info=True)
         bot.answer_callback_query(call.id, "Error in speed test.", show_alert=True)
         try: bot.edit_message_text("〽️ Main Menu", chat_id, call.message.message_id, reply_markup=create_main_menu_inline(user_id))
         except Exception: pass

def back_to_main_callback(call):
    user_id = call.from_user.id
    chat_id = call.message.chat.id
    
    # Check if user is banned
    if is_user_banned(user_id):
        bot.answer_callback_query(call.id, "❌ You are banned from using this bot.", show_alert=True)
        return
    
    # Check mandatory subscription first
    is_subscribed, not_joined = check_mandatory_subscription(user_id)
    if not is_subscribed and user_id not in admin_ids:
        subscription_message, markup = create_subscription_check_message(not_joined)
        bot.answer_callback_query(call.id)
        try:
            bot.edit_message_text(subscription_message, chat_id, call.message.message_id, reply_markup=markup, parse_mode='Markdown')
        except:
            bot.send_message(chat_id, subscription_message, reply_markup=markup, parse_mode='Markdown')
        return
        
    file_limit = get_user_file_limit(user_id)
    current_files = get_user_file_count(user_id)
    limit_str = str(file_limit) if file_limit != float('inf') else "Unlimited"
    expiry_info = ""
    if user_id == OWNER_ID: user_status = "👑 Owner"
    elif user_id in admin_ids: user_status = "🛡️ Admin"
    elif user_id in user_subscriptions:
        expiry_date = user_subscriptions[user_id].get('expiry')
        if expiry_date and expiry_date > datetime.now():
            user_status = "⭐ Premium"; days_left = (expiry_date - datetime.now()).days
            expiry_info = f"\n⏳ Subscription expires in: {days_left} days"
        else: user_status = "🆓 Free User (Expired Sub)" # Will be cleaned up by welcome if not already
    else: user_status = "🆓 Free User"
    user_hash = hashlib.sha256(str(user_id).encode('utf-8')).hexdigest()[:16]
    main_menu_text = (f"〽️ **Welcome back to 50 Shades Hoster!**\n\n"
                      f"🆔 **Anonymous Hash ID**: `{user_hash}`\n"
                      f"🔰 **Status**: {user_status}{expiry_info}\n📁 **Files**: {current_files} / {limit_str}\n\n"
                      f"👇 Use the restructured buttons below to control.")
    try:
        bot.answer_callback_query(call.id)
        bot.edit_message_text(main_menu_text, chat_id, call.message.message_id,
                              reply_markup=create_main_menu_inline(user_id), parse_mode='Markdown')
    except telebot.apihelper.ApiTelegramException as e:
         if "message is not modified" in str(e): logger.warning("Msg not modified (back_to_main).")
         else: logger.error(f"API error on back_to_main: {e}")
    except Exception as e: logger.error(f"Error handling back_to_main: {e}", exc_info=True)

# --- Admin Callback Implementations (for Inline Buttons) ---
def subscription_management_callback(call):
    bot.answer_callback_query(call.id)
    try:
        bot.edit_message_text("💳 Subscription Management\nSelect action:",
                              call.message.chat.id, call.message.message_id, reply_markup=create_subscription_menu())
    except Exception as e: logger.error(f"Error showing sub menu: {e}")

def stats_callback(call): # Called by user and admin
    bot.answer_callback_query(call.id)
    # Fix from_user so statistics accurately resolves the admin role (Fixes Stats Visibility bug)
    call.message.from_user = call.from_user
    _logic_statistics(call.message) 
    try:
        bot.edit_message_reply_markup(call.message.chat.id, call.message.message_id,
                                      reply_markup=create_main_menu_inline(call.from_user.id))
    except Exception as e:
        logger.error(f"Error updating menu after stats_callback: {e}")

def lock_bot_callback(call):
    global bot_locked; bot_locked = True
    logger.warning(f"Bot locked by Admin {call.from_user.id}")
    bot.answer_callback_query(call.id, "🔒 Bot locked.")
    try: bot.edit_message_reply_markup(call.message.chat.id, call.message.message_id, reply_markup=create_main_menu_inline(call.from_user.id))
    except Exception as e: logger.error(f"Error updating menu (lock): {e}")

def unlock_bot_callback(call):
    global bot_locked; bot_locked = False
    logger.warning(f"Bot unlocked by Admin {call.from_user.id}")
    bot.answer_callback_query(call.id, "🔓 Bot unlocked.")
    try: bot.edit_message_reply_markup(call.message.chat.id, call.message.message_id, reply_markup=create_main_menu_inline(call.from_user.id))
    except Exception as e: logger.error(f"Error updating menu (unlock): {e}")

def run_all_scripts_callback(call): # Added
    _logic_run_all_scripts(call) # Pass the call object

def broadcast_init_callback(call):
    bot.answer_callback_query(call.id)
    msg = bot.send_message(call.message.chat.id, "📢 Send message to broadcast.\n/cancel to abort.")
    bot.register_next_step_handler(msg, process_broadcast_message)

def process_broadcast_message(message):
    user_id = message.from_user.id
    if user_id not in admin_ids: bot.reply_to(message, "⚠️ Not authorized."); return
    if message.text and message.text.lower() == '/cancel': bot.reply_to(message, "Broadcast cancelled."); return

    broadcast_content = message.text # Can also handle photos, videos etc. if message.content_type is checked
    if not broadcast_content and not (message.photo or message.video or message.document or message.sticker or message.voice or message.audio): # If no text and no other media
         bot.reply_to(message, "⚠️ Cannot broadcast empty message. Send text or media.")
         msg = bot.send_message(message.chat.id, "📢 Send broadcast message:", reply_markup=cancel_markup())
         bot.register_next_step_handler(msg, process_broadcast_message)
         return

    target_count = len(active_users)
    markup = types.InlineKeyboardMarkup()
    markup.row(btn("✅ Confirm & Send", callback_data=f"confirm_broadcast_{message.message_id}", style="success"),
               btn("❌ Cancel", callback_data="cancel_broadcast", style="danger"))

    preview_text = broadcast_content[:1000].strip() if broadcast_content else "(Media message)"
    bot.reply_to(message, f"⚠️ Confirm Broadcast:\n\n```\n{preview_text}\n```\n" 
                          f"To **{target_count}** users. Sure?", reply_markup=markup, parse_mode='Markdown')

def handle_confirm_broadcast(call):
    user_id = call.from_user.id
    chat_id = call.message.chat.id
    if user_id not in admin_ids: bot.answer_callback_query(call.id, "⚠️ Admin only.", show_alert=True); return
    try:
        original_message = call.message.reply_to_message
        if not original_message: raise ValueError("Could not retrieve original message.")

        # Check content type and get content
        broadcast_text = None
        broadcast_photo_id = None
        broadcast_video_id = None
        # Add other types as needed: document, sticker, voice, audio

        if original_message.text:
            broadcast_text = original_message.text
        elif original_message.photo:
            broadcast_photo_id = original_message.photo[-1].file_id # Get highest quality
        elif original_message.video:
            broadcast_video_id = original_message.video.file_id
        # Add more elif for other content types
        else:
            raise ValueError("Message has no text or supported media for broadcast.")

        bot.answer_callback_query(call.id, "🚀 Starting broadcast...")
        bot.edit_message_text(f"📢 Broadcasting to {len(active_users)} users...",
                              chat_id, call.message.message_id, reply_markup=None)
        # Pass all potential content types to execute_broadcast
        thread = threading.Thread(target=execute_broadcast, args=(
            broadcast_text, broadcast_photo_id, broadcast_video_id, 
            original_message.caption if (broadcast_photo_id or broadcast_video_id) else None, # Pass caption
            chat_id))
        thread.start()
    except ValueError as ve: 
        logger.error(f"Error retrieving msg for broadcast confirm: {ve}")
        bot.edit_message_text(f"❌ Error starting broadcast: {ve}", chat_id, call.message.message_id, reply_markup=None)
    except Exception as e:
        logger.error(f"Error in handle_confirm_broadcast: {e}", exc_info=True)
        bot.edit_message_text("❌ Unexpected error during broadcast confirm.", chat_id, call.message.message_id, reply_markup=None)

def handle_cancel_broadcast(call):
    bot.answer_callback_query(call.id, "Broadcast cancelled.")
    bot.delete_message(call.message.chat.id, call.message.message_id)
    # Optionally delete the original message too if call.message.reply_to_message exists
    if call.message.reply_to_message:
        try: bot.delete_message(call.message.chat.id, call.message.reply_to_message.message_id)
        except: pass

def execute_broadcast(broadcast_text, photo_id, video_id, caption, admin_chat_id):
    sent_count = 0; failed_count = 0; blocked_count = 0
    start_exec_time = time.time() 
    users_to_broadcast = list(active_users); total_users = len(users_to_broadcast)
    logger.info(f"Executing broadcast to {total_users} users.")
    batch_size = 25; delay_batches = 1.5

    for i, user_id_bc in enumerate(users_to_broadcast): # Renamed
        try:
            if broadcast_text:
                bot.send_message(user_id_bc, broadcast_text, parse_mode='Markdown')
            elif photo_id:
                bot.send_photo(user_id_bc, photo_id, caption=caption, parse_mode='Markdown' if caption else None)
            elif video_id:
                bot.send_video(user_id_bc, video_id, caption=caption, parse_mode='Markdown' if caption else None)
            # Add other send methods for other types
            sent_count += 1
        except telebot.apihelper.ApiTelegramException as e:
            err_desc = str(e).lower()
            if any(s in err_desc for s in ["bot was blocked", "user is deactivated", "chat not found", "kicked from", "restricted"]): 
                logger.warning(f"Broadcast failed to {user_id_bc}: User blocked/inactive.")
                blocked_count += 1
            elif "flood control" in err_desc or "too many requests" in err_desc:
                retry_after = 5; match = re.search(r"retry after (\d+)", err_desc)
                if match: retry_after = int(match.group(1)) + 1 
                logger.warning(f"Flood control. Sleeping {retry_after}s...")
                time.sleep(retry_after)
                try: # Retry once
                    if broadcast_text: bot.send_message(user_id_bc, broadcast_text, parse_mode='Markdown')
                    elif photo_id: bot.send_photo(user_id_bc, photo_id, caption=caption, parse_mode='Markdown' if caption else None)
                    elif video_id: bot.send_video(user_id_bc, video_id, caption=caption, parse_mode='Markdown' if caption else None)
                    sent_count += 1
                except Exception as e_retry: logger.error(f"Broadcast retry failed to {user_id_bc}: {e_retry}"); failed_count +=1
            else: logger.error(f"Broadcast failed to {user_id_bc}: {e}"); failed_count += 1
        except Exception as e: logger.error(f"Unexpected error broadcasting to {user_id_bc}: {e}"); failed_count += 1

        if (i + 1) % batch_size == 0 and i < total_users - 1:
            logger.info(f"Broadcast batch {i//batch_size + 1} sent. Sleeping {delay_batches}s...")
            time.sleep(delay_batches)
        elif i % 5 == 0: time.sleep(0.2) 

    duration = round(time.time() - start_exec_time, 2)
    result_msg = (f"📢 Broadcast Complete!\n\n✅ Sent: {sent_count}\n❌ Failed: {failed_count}\n"
                  f"🚫 Blocked/Inactive: {blocked_count}\n👥 Targets: {total_users}\n⏱️ Duration: {duration}s")
    logger.info(result_msg)
    try: bot.send_message(admin_chat_id, result_msg)
    except Exception as e: logger.error(f"Failed to send broadcast result to admin {admin_chat_id}: {e}")

def admin_panel_callback(call):
    bot.answer_callback_query(call.id)
    try:
        bot.edit_message_text("👑 Admin Panel\nManage admins (Owner actions may be restricted).",
                              call.message.chat.id, call.message.message_id, reply_markup=create_admin_panel())
    except Exception as e: logger.error(f"Error showing admin panel: {e}")

def add_admin_init_callback(call):
    bot.answer_callback_query(call.id)
    msg = bot.send_message(call.message.chat.id, "👑 **Admin Promotion**:\n\nEnter the numerical User ID of the user you want to promote to Admin.", reply_markup=cancel_markup(), parse_mode='Markdown')
    # Fix from_user so next step handler waits for the actual user (Fixes Add Admin Input bug)
    msg.from_user = call.from_user
    bot.register_next_step_handler(msg, process_add_admin_id)

def process_add_admin_id(message):
    owner_id_check = message.from_user.id 
    if owner_id_check != OWNER_ID: bot.reply_to(message, "⚠️ Owner only."); return
    if message.text.lower() == '/cancel': bot.reply_to(message, "Admin promotion cancelled."); return
    try:
        new_admin_id = int(message.text.strip())
        if new_admin_id <= 0: raise ValueError("ID must be positive")
        if new_admin_id == OWNER_ID: bot.reply_to(message, "⚠️ Owner is already Owner."); return
        if new_admin_id in admin_ids: bot.reply_to(message, f"⚠️ User `{new_admin_id}` already Admin."); return
        add_admin_db(new_admin_id, owner_id_check) 
        logger.warning(f"Admin {new_admin_id} added by Owner {owner_id_check}.")
        bot.reply_to(message, f"✅ User `{new_admin_id}` promoted to Admin.")
        try: bot.send_message(new_admin_id, "🎉 Congrats! You are now an Admin.")
        except Exception as e: logger.error(f"Failed to notify new admin {new_admin_id}: {e}")
    except ValueError:
        bot.reply_to(message, "⚠️ Invalid ID. Please send a valid numerical ID.")
        msg = bot.send_message(message.chat.id, "👑 Enter User ID to promote:", reply_markup=cancel_markup())
        bot.register_next_step_handler(msg, process_add_admin_id)
    except Exception as e: logger.error(f"Error processing add admin: {e}", exc_info=True); bot.reply_to(message, "Error.")

def remove_admin_init_callback(call):
    bot.answer_callback_query(call.id)
    msg = bot.send_message(call.message.chat.id, "👑 Enter User ID of Admin to remove.\n/cancel to abort.")
    bot.register_next_step_handler(msg, process_remove_admin_id)

def process_remove_admin_id(message):
    owner_id_check = message.from_user.id
    if owner_id_check != OWNER_ID: bot.reply_to(message, "⚠️ Owner only."); return
    if message.text.lower() == '/cancel': bot.reply_to(message, "Admin removal cancelled."); return
    try:
        admin_id_remove = int(message.text.strip()) # Renamed
        if admin_id_remove <= 0: raise ValueError("ID must be positive")
        if admin_id_remove == OWNER_ID: bot.reply_to(message, "⚠️ Owner cannot remove self."); return
        if admin_id_remove not in admin_ids: bot.reply_to(message, f"⚠️ User `{admin_id_remove}` not Admin."); return
        if remove_admin_db(admin_id_remove): 
            logger.warning(f"Admin {admin_id_remove} removed by Owner {owner_id_check}.")
            bot.reply_to(message, f"✅ Admin `{admin_id_remove}` removed.")
            try: bot.send_message(admin_id_remove, "ℹ️ You are no longer an Admin.")
            except Exception as e: logger.error(f"Failed to notify removed admin {admin_id_remove}: {e}")
        else: bot.reply_to(message, f"❌ Failed to remove admin `{admin_id_remove}`. Check logs.")
    except ValueError:
        bot.reply_to(message, "⚠️ Invalid ID. Send numerical ID or /cancel.")
        msg = bot.send_message(message.chat.id, "👑 Enter Admin ID to remove or /cancel.")
        bot.register_next_step_handler(msg, process_remove_admin_id)
    except Exception as e: logger.error(f"Error processing remove admin: {e}", exc_info=True); bot.reply_to(message, "Error.")

def list_admins_callback(call):
    bot.answer_callback_query(call.id)
    try:
        admin_list_str = "\n".join(f"- `{aid}` {'(Owner)' if aid == OWNER_ID else ''}" for aid in sorted(list(admin_ids)))
        if not admin_list_str: admin_list_str = "(No Owner/Admins configured!)"
        bot.edit_message_text(f"👑 Current Admins:\n\n{admin_list_str}", call.message.chat.id,
                              call.message.message_id, reply_markup=create_admin_panel(), parse_mode='Markdown')
    except Exception as e: logger.error(f"Error listing admins: {e}")

def add_subscription_init_callback(call):
    bot.answer_callback_query(call.id)
    msg = bot.send_message(call.message.chat.id, "💳 Enter User ID & days (e.g., `12345678 30`).\n/cancel to abort.")
    bot.register_next_step_handler(msg, process_add_subscription_details)

def process_add_subscription_details(message):
    admin_id_check = message.from_user.id 
    if admin_id_check not in admin_ids: bot.reply_to(message, "⚠️ Not authorized."); return
    if message.text.lower() == '/cancel': bot.reply_to(message, "Sub add cancelled."); return
    try:
        parts = message.text.split();
        if len(parts) != 2: raise ValueError("Incorrect format")
        sub_user_id = int(parts[0].strip()); days = int(parts[1].strip())
        if sub_user_id <= 0 or days <= 0: raise ValueError("User ID/days must be positive")

        current_expiry = user_subscriptions.get(sub_user_id, {}).get('expiry')
        start_date_new_sub = datetime.now() # Renamed
        if current_expiry and current_expiry > start_date_new_sub: start_date_new_sub = current_expiry
        new_expiry = start_date_new_sub + timedelta(days=days)
        save_subscription(sub_user_id, new_expiry)

        logger.info(f"Sub for {sub_user_id} by admin {admin_id_check}. Expiry: {new_expiry:%Y-%m-%d}")
        bot.reply_to(message, f"✅ Sub for `{sub_user_id}` by {days} days.\nNew expiry: {new_expiry:%Y-%m-%d}")
        try: bot.send_message(sub_user_id, f"🎉 Sub activated/extended by {days} days! Expires: {new_expiry:%Y-%m-%d}.")
        except Exception as e: logger.error(f"Failed to notify {sub_user_id} of new sub: {e}")
    except ValueError as e:
        bot.reply_to(message, f"⚠️ Invalid: {e}. Format: `ID days` or /cancel.")
        msg = bot.send_message(message.chat.id, "💳 Enter User ID & days, or /cancel.")
        bot.register_next_step_handler(msg, process_add_subscription_details)
    except Exception as e: logger.error(f"Error processing add sub: {e}", exc_info=True); bot.reply_to(message, "Error.")

def remove_subscription_init_callback(call):
    bot.answer_callback_query(call.id)
    msg = bot.send_message(call.message.chat.id, "💳 Enter User ID to remove sub.\n/cancel to abort.")
    bot.register_next_step_handler(msg, process_remove_subscription_id)

def process_remove_subscription_id(message):
    admin_id_check = message.from_user.id
    if admin_id_check not in admin_ids: bot.reply_to(message, "⚠️ Not authorized."); return
    if message.text.lower() == '/cancel': bot.reply_to(message, "Sub removal cancelled."); return
    try:
        sub_user_id_remove = int(message.text.strip()) # Renamed
        if sub_user_id_remove <= 0: raise ValueError("ID must be positive")
        if sub_user_id_remove not in user_subscriptions:
            bot.reply_to(message, f"⚠️ User `{sub_user_id_remove}` no active sub in memory."); return
        remove_subscription_db(sub_user_id_remove) 
        logger.warning(f"Sub removed for {sub_user_id_remove} by admin {admin_id_check}.")
        bot.reply_to(message, f"✅ Sub for `{sub_user_id_remove}` removed.")
        try: bot.send_message(sub_user_id_remove, "ℹ️ Your subscription removed by admin.")
        except Exception as e: logger.error(f"Failed to notify {sub_user_id_remove} of sub removal: {e}")
    except ValueError:
        bot.reply_to(message, "⚠️ Invalid ID. Send numerical ID or /cancel.")
        msg = bot.send_message(message.chat.id, "💳 Enter User ID to remove sub from, or /cancel.")
        bot.register_next_step_handler(msg, process_remove_subscription_id)
    except Exception as e: logger.error(f"Error processing remove sub: {e}", exc_info=True); bot.reply_to(message, "Error.")

def check_subscription_init_callback(call):
    bot.answer_callback_query(call.id)
    msg = bot.send_message(call.message.chat.id, "💳 Enter User ID to check sub.\n/cancel to abort.")
    bot.register_next_step_handler(msg, process_check_subscription_id)

def process_check_subscription_id(message):
    admin_id_check = message.from_user.id
    if admin_id_check not in admin_ids: bot.reply_to(message, "⚠️ Not authorized."); return
    if message.text.lower() == '/cancel': bot.reply_to(message, "Sub check cancelled."); return
    try:
        sub_user_id_check = int(message.text.strip()) # Renamed
        if sub_user_id_check <= 0: raise ValueError("ID must be positive")
        if sub_user_id_check in user_subscriptions:
            expiry_dt = user_subscriptions[sub_user_id_check].get('expiry')
            if expiry_dt:
                if expiry_dt > datetime.now():
                    days_left = (expiry_dt - datetime.now()).days
                    bot.reply_to(message, f"✅ User `{sub_user_id_check}` active sub.\nExpires: {expiry_dt:%Y-%m-%d %H:%M:%S} ({days_left} days left).")
                else:
                    bot.reply_to(message, f"⚠️ User `{sub_user_id_check}` expired sub (On: {expiry_dt:%Y-%m-%d %H:%M:%S}).")
                    remove_subscription_db(sub_user_id_check) # Clean up
            else: bot.reply_to(message, f"⚠️ User `{sub_user_id_check}` in sub list, but expiry missing. Re-add if needed.")
        else: bot.reply_to(message, f"ℹ️ User `{sub_user_id_check}` no active sub record.")
    except ValueError:
        bot.reply_to(message, "⚠️ Invalid ID. Send numerical ID or /cancel.")
        msg = bot.send_message(message.chat.id, "💳 Enter User ID to check, or /cancel.")
        bot.register_next_step_handler(msg, process_check_subscription_id)
    except Exception as e: logger.error(f"Error processing check sub: {e}", exc_info=True); bot.reply_to(message, "Error.")

# --- User Management Callbacks ---
def user_management_callback(call):
    bot.answer_callback_query(call.id)
    try:
        bot.edit_message_text("👥 User Management\nSelect action:", call.message.chat.id, 
                              call.message.message_id, reply_markup=create_user_management_menu())
    except Exception as e: logger.error(f"Error showing user management menu: {e}")

def ban_user_callback(call):
    bot.answer_callback_query(call.id)
    msg = bot.send_message(call.message.chat.id, "🚫 Enter User ID to ban and reason (e.g., `12345678 Spamming`)\n/cancel to cancel")
    bot.register_next_step_handler(msg, process_ban_user)

def process_ban_user(message):
    admin_id = message.from_user.id
    if admin_id not in admin_ids: bot.reply_to(message, "⚠️ Not authorized."); return
    
    if message.text.lower() == '/cancel':
        bot.reply_to(message, "❌ Ban cancelled.")
        return
    
    try:
        parts = message.text.split()
        if len(parts) < 2:
            bot.reply_to(message, "⚠️ Format: `user_id reason`\nExample: `12345678 Spamming`")
            return
        
        user_id = int(parts[0])
        reason = ' '.join(parts[1:])
        
        if user_id <= 0: raise ValueError("ID must be positive")
        if user_id == OWNER_ID: bot.reply_to(message, "⚠️ Cannot ban owner."); return
        if user_id in admin_ids: bot.reply_to(message, "⚠️ Cannot ban admin."); return
        
        if ban_user_db(user_id, reason, admin_id):
            bot.reply_to(message, f"✅ User `{user_id}` banned.\nReason: {reason}")
            # Stop all scripts for banned user
            for file_name, _ in user_files.get(user_id, []):
                script_key = f"{user_id}_{file_name}"
                if script_key in bot_scripts:
                    kill_process_tree(bot_scripts[script_key])
                    del bot_scripts[script_key]
            
            try:
                bot.send_message(user_id, f"🚫 You have been banned from using this bot.\nReason: {reason}")
            except Exception as e:
                logger.error(f"Failed to notify banned user {user_id}: {e}")
        else:
            bot.reply_to(message, "❌ Failed to ban user.")
            
    except ValueError:
        bot.reply_to(message, "⚠️ Invalid user ID. Must be a number.")
    except Exception as e:
        logger.error(f"Error banning user: {e}", exc_info=True)
        bot.reply_to(message, f"❌ Error: {str(e)}")

def unban_user_callback(call):
    bot.answer_callback_query(call.id)
    msg = bot.send_message(call.message.chat.id, "✅ Enter User ID to unban\n/cancel to cancel")
    bot.register_next_step_handler(msg, process_unban_user)

def process_unban_user(message):
    admin_id = message.from_user.id
    if admin_id not in admin_ids: bot.reply_to(message, "⚠️ Not authorized."); return
    
    if message.text.lower() == '/cancel':
        bot.reply_to(message, "❌ Unban cancelled.")
        return
    
    try:
        user_id = int(message.text.strip())
        if user_id <= 0: raise ValueError("ID must be positive")
        
        if user_id not in banned_users:
            bot.reply_to(message, f"ℹ️ User `{user_id}` is not banned.")
            return
        
        if unban_user_db(user_id):
            bot.reply_to(message, f"✅ User `{user_id}` unbanned.")
            try:
                bot.send_message(user_id, "✅ Your ban has been lifted. You can now use the bot again.")
            except Exception as e:
                logger.error(f"Failed to notify unbanned user {user_id}: {e}")
        else:
            bot.reply_to(message, "❌ Failed to unban user.")
            
    except ValueError:
        bot.reply_to(message, "⚠️ Invalid user ID. Must be a number.")
    except Exception as e:
        logger.error(f"Error unbanning user: {e}", exc_info=True)
        bot.reply_to(message, f"❌ Error: {str(e)}")

def user_info_callback(call):
    bot.answer_callback_query(call.id)
    msg = bot.send_message(call.message.chat.id, "👤 Enter User ID to get info\n/cancel to cancel")
    bot.register_next_step_handler(msg, process_user_info)

def process_user_info(message):
    admin_id = message.from_user.id
    if admin_id not in admin_ids: bot.reply_to(message, "⚠️ Not authorized."); return
    
    if message.text.lower() == '/cancel':
        bot.reply_to(message, "❌ Info request cancelled.")
        return
    
    try:
        user_id = int(message.text.strip())
        if user_id <= 0: raise ValueError("ID must be positive")
        
        # Gather user information
        info_parts = []
        
        # Basic info
        info_parts.append(f"👤 **User ID:** `{user_id}`")
        
        # Status
        if user_id == OWNER_ID:
            info_parts.append("👑 **Status:** Owner")
        elif user_id in admin_ids:
            info_parts.append("🛡️ **Status:** Admin")
        elif user_id in banned_users:
            info_parts.append("🚫 **Status:** Banned")
        elif user_id in user_subscriptions:
            expiry = user_subscriptions[user_id].get('expiry')
            if expiry and expiry > datetime.now():
                days_left = (expiry - datetime.now()).days
                info_parts.append(f"⭐ **Status:** Premium (Expires in {days_left} days)")
            else:
                info_parts.append("🆓 **Status:** Free User (Expired subscription)")
        else:
            info_parts.append("🆓 **Status:** Free User")
        
        # Files
        file_count = get_user_file_count(user_id)
        file_limit = get_user_file_limit(user_id)
        info_parts.append(f"📁 **Files:** {file_count}/{file_limit if file_limit != float('inf') else 'Unlimited'}")
        
        # Custom limit
        if user_id in user_limits:
            info_parts.append(f"⚙️ **Custom Limit:** {user_limits[user_id]}")
        
        # Active scripts
        running_scripts = 0
        for file_name, _ in user_files.get(user_id, []):
            if is_bot_running(user_id, file_name):
                running_scripts += 1
        info_parts.append(f"🤖 **Running Scripts:** {running_scripts}")
        
        # Last seen (if in active users)
        if user_id in active_users:
            info_parts.append("🟢 **Status:** Active")
        
        info_text = "\n".join(info_parts)
        bot.reply_to(message, info_text, parse_mode='Markdown')
        
    except ValueError:
        bot.reply_to(message, "⚠️ Invalid user ID. Must be a number.")
    except Exception as e:
        logger.error(f"Error getting user info: {e}", exc_info=True)
        bot.reply_to(message, f"❌ Error: {str(e)}")

def all_users_callback(call):
    bot.answer_callback_query(call.id)
    try:
        if not active_users:
            bot.edit_message_text("👥 No active users yet.", call.message.chat.id, call.message.message_id)
            return
        
        users_list = list(active_users)
        chunk_size = 20
        total_pages = (len(users_list) + chunk_size - 1) // chunk_size
        
        # Create pagination
        current_page = 0
        display_users_list(call.message.chat.id, call.message.message_id, users_list, current_page, total_pages, chunk_size)
        
    except Exception as e:
        logger.error(f"Error displaying all users: {e}", exc_info=True)
        bot.answer_callback_query(call.id, "Error displaying users.", show_alert=True)

def display_users_list(chat_id, message_id, users_list, page, total_pages, chunk_size):
    start_idx = page * chunk_size
    end_idx = min(start_idx + chunk_size, len(users_list))
    
    user_chunk = users_list[start_idx:end_idx]
    
    message_text = f"👥 **Active Users** (Page {page + 1}/{total_pages})\n\n"
    for i, user_id in enumerate(user_chunk, start=start_idx + 1):
        status = ""
        if user_id == OWNER_ID: status = "👑"
        elif user_id in admin_ids: status = "🛡️"
        elif user_id in banned_users: status = "🚫"
        elif user_id in user_subscriptions and user_subscriptions[user_id].get('expiry', datetime.min) > datetime.now():
            status = "⭐"
        else: status = "🆓"
        
        message_text += f"{i}. `{user_id}` {status}\n"
    
    markup = types.InlineKeyboardMarkup(row_width=3)
    
    if total_pages > 1:
        page_buttons = []
        if page > 0:
            page_buttons.append(btn("⬅️ Previous", callback_data=f"users_page_{page-1}", style='primary'))
        
        page_buttons.append(btn(f"{page+1}/{total_pages}", callback_data="noop", style='primary'))
        
        if page < total_pages - 1:
            page_buttons.append(btn("Next ➡️", callback_data=f"users_page_{page+1}", style='primary'))
        
        markup.row(*page_buttons)
    
    markup.row(btn("🔙 Back to User Management", callback_data='user_management', style='primary'))
    
    try:
        bot.edit_message_text(message_text, chat_id, message_id, reply_markup=markup, parse_mode='Markdown')
    except Exception as e:
        logger.error(f"Error editing users list: {e}")

@bot.callback_query_handler(func=lambda call: call.data.startswith('users_page_'))
def handle_users_page(call):
    if call.from_user.id not in admin_ids:
        bot.answer_callback_query(call.id, "⚠️ Admin only.", show_alert=True)
        return
    
    try:
        page = int(call.data.split('_')[2])
        users_list = list(active_users)
        chunk_size = 20
        total_pages = (len(users_list) + chunk_size - 1) // chunk_size
        
        if 0 <= page < total_pages:
            bot.answer_callback_query(call.id)
            display_users_list(call.message.chat.id, call.message.message_id, users_list, page, total_pages, chunk_size)
    except Exception as e:
        logger.error(f"Error handling users page: {e}", exc_info=True)
        bot.answer_callback_query(call.id, "Error.", show_alert=True)

def set_user_limit_callback(call):
    bot.answer_callback_query(call.id)
    msg = bot.send_message(call.message.chat.id, "🔧 **Set Custom Limit**:\n\nEnter User ID and new limit (e.g., `12345678 50`):", reply_markup=cancel_markup(), parse_mode='Markdown')
    # Fix from_user so next step handler waits for the actual user
    msg.from_user = call.from_user
    bot.register_next_step_handler(msg, process_set_user_limit)

def process_set_user_limit(message):
    admin_id = message.from_user.id
    if admin_id not in admin_ids: bot.reply_to(message, "⚠️ Not authorized."); return
    
    if message.text.lower() == '/cancel':
        bot.reply_to(message, "❌ Limit set cancelled.")
        return
    
    try:
        parts = message.text.split()
        if len(parts) != 2: raise ValueError("Format: user_id limit")
        
        user_id = int(parts[0])
        limit = int(parts[1])
        
        if user_id <= 0 or limit <= 0: raise ValueError("ID and limit must be positive")
        
        if set_user_limit_db(user_id, limit, admin_id):
            bot.reply_to(message, f"✅ Set file limit {limit} for user `{user_id}`")
            try:
                bot.send_message(user_id, f"⚙️ Your file upload limit has been set to {limit}")
            except Exception as e:
                logger.error(f"Failed to notify user {user_id}: {e}")
        else:
            bot.reply_to(message, "❌ Failed to set limit.")
            
    except ValueError as e:
        bot.reply_to(message, f"⚠️ Invalid input: {e}\nFormat: `user_id limit`")
    except Exception as e:
        logger.error(f"Error setting user limit: {e}", exc_info=True)
        bot.reply_to(message, f"❌ Error: {str(e)}")

def remove_user_limit_callback(call):
    bot.answer_callback_query(call.id)
    msg = bot.send_message(call.message.chat.id, "🗑️ Enter User ID to remove custom limit\n/cancel to cancel")
    bot.register_next_step_handler(msg, process_remove_user_limit)

def process_remove_user_limit(message):
    admin_id = message.from_user.id
    if admin_id not in admin_ids: bot.reply_to(message, "⚠️ Not authorized."); return
    
    if message.text.lower() == '/cancel':
        bot.reply_to(message, "❌ Limit removal cancelled.")
        return
    
    try:
        user_id = int(message.text.strip())
        if user_id <= 0: raise ValueError("ID must be positive")
        
        if user_id not in user_limits:
            bot.reply_to(message, f"ℹ️ User `{user_id}` has no custom limit.")
            return
        
        if remove_user_limit_db(user_id):
            bot.reply_to(message, f"✅ Removed custom limit for user `{user_id}`")
            try:
                bot.send_message(user_id, "⚙️ Your custom file limit has been removed")
            except Exception as e:
                logger.error(f"Failed to notify user {user_id}: {e}")
        else:
            bot.reply_to(message, "❌ Failed to remove limit.")
            
    except ValueError:
        bot.reply_to(message, "⚠️ Invalid user ID. Must be a number.")
    except Exception as e:
        logger.error(f"Error removing user limit: {e}", exc_info=True)
        bot.reply_to(message, f"❌ Error: {str(e)}")

# --- Admin Settings Callbacks ---
def admin_settings_callback(call):
    bot.answer_callback_query(call.id)
    try:
        bot.edit_message_text("⚙️ Admin Settings\nSelect action:", call.message.chat.id, 
                              call.message.message_id, reply_markup=create_admin_settings_menu())
    except Exception as e: logger.error(f"Error showing admin settings: {e}")

def system_info_callback(call):
    bot.answer_callback_query(call.id)
    try:
        # Get system information
        import platform
        
        info_parts = []
        
        # Bot info
        info_parts.append("🤖 **Bot Information:**")
        info_parts.append(f"• Python: {platform.python_version()}")
        info_parts.append(f"• Platform: {platform.platform()}")
        info_parts.append(f"• Uptime: {time.strftime('%H:%M:%S', time.gmtime(time.time() - psutil.boot_time()))}")
        
        # System info
        info_parts.append("\n💻 **System Information:**")
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            info_parts.append(f"• CPU Usage: {cpu_percent}%")
            info_parts.append(f"• Memory: {memory.percent}% used ({memory.used//1024//1024}MB/{memory.total//1024//1024}MB)")
            info_parts.append(f"• Disk: {disk.percent}% used ({disk.used//1024//1024}MB/{disk.total//1024//1024}MB)")
        except Exception as e:
            info_parts.append(f"• System stats error: {str(e)}")
        
        # Bot stats
        info_parts.append("\n📊 **Bot Statistics:**")
        info_parts.append(f"• Active Users: {len(active_users)}")
        info_parts.append(f"• Running Scripts: {len(bot_scripts)}")
        info_parts.append(f"• Total Files: {sum(len(files) for files in user_files.values())}")
        info_parts.append(f"• Bot Status: {'🔒 Locked' if bot_locked else '🔓 Unlocked'}")
        
        info_text = "\n".join(info_parts)
        
        bot.edit_message_text(info_text, call.message.chat.id, call.message.message_id, 
                              reply_markup=create_admin_settings_menu(), parse_mode='Markdown')
    except Exception as e:
        logger.error(f"Error showing system info: {e}", exc_info=True)
        bot.answer_callback_query(call.id, "Error showing system info.", show_alert=True)

def bot_performance_callback(call):
    bot.answer_callback_query(call.id)
    try:
        # Calculate performance metrics
        performance_parts = []
        
        # Script performance
        running_scripts = len(bot_scripts)
        total_files = sum(len(files) for files in user_files.values())
        
        performance_parts.append("📈 **Bot Performance Metrics:**")
        performance_parts.append(f"• Running Scripts: {running_scripts}")
        performance_parts.append(f"• Total Scripts: {total_files}")
        performance_parts.append(f"• Uptime Ratio: {running_scripts}/{total_files} ({running_scripts/total_files*100:.1f}% if total > 0)")
        
        # Resource usage
        try:
            bot_process = psutil.Process()
            memory_usage = bot_process.memory_info().rss / 1024 / 1024  # MB
            cpu_usage = bot_process.cpu_percent(interval=0.5)
            
            performance_parts.append(f"\n💾 **Resource Usage:**")
            performance_parts.append(f"• Memory: {memory_usage:.1f} MB")
            performance_parts.append(f"• CPU: {cpu_usage:.1f}%")
        except Exception as e:
            performance_parts.append(f"\n⚠️ Resource stats error: {str(e)}")
        
        # Database stats
        performance_parts.append(f"\n🗄️ **Database:**")
        performance_parts.append(f"• Active Users: {len(active_users)}")
        performance_parts.append(f"• Subscriptions: {len(user_subscriptions)}")
        performance_parts.append(f"• Banned Users: {len(banned_users)}")
        performance_parts.append(f"• Custom Limits: {len(user_limits)}")
        
        performance_text = "\n".join(performance_parts)
        
        bot.edit_message_text(performance_text, call.message.chat.id, call.message.message_id,
                              reply_markup=create_admin_settings_menu(), parse_mode='Markdown')
    except Exception as e:
        logger.error(f"Error showing performance: {e}", exc_info=True)
        bot.answer_callback_query(call.id, "Error showing performance.", show_alert=True)

def cleanup_files_callback(call):
    bot.answer_callback_query(call.id, "🧹 Cleaning up temporary files...")
    
    try:
        # Clean up empty user directories
        cleaned_dirs = 0
        cleaned_files = 0
        
        for user_dir in os.listdir(UPLOAD_BOTS_DIR):
            user_path = os.path.join(UPLOAD_BOTS_DIR, user_dir)
            if os.path.isdir(user_path):
                # Check if directory is empty
                if not os.listdir(user_path):
                    try:
                        os.rmdir(user_path)
                        cleaned_dirs += 1
                    except Exception as e:
                        logger.error(f"Error removing empty dir {user_path}: {e}")
                
                # Clean old log files (older than 7 days)
                else:
                    for file_name in os.listdir(user_path):
                        if file_name.endswith('.log'):
                            file_path = os.path.join(user_path, file_name)
                            try:
                                file_age = time.time() - os.path.getmtime(file_path)
                                if file_age > 7 * 24 * 3600:  # 7 days
                                    os.remove(file_path)
                                    cleaned_files += 1
                            except Exception as e:
                                logger.error(f"Error cleaning log file {file_path}: {e}")
        
        result_msg = f"🧹 **Cleanup Complete:**\n• Removed empty directories: {cleaned_dirs}\n• Cleared old log files: {cleaned_files}"
        
        bot.edit_message_text(result_msg, call.message.chat.id, call.message.message_id,
                              reply_markup=create_admin_settings_menu(), parse_mode='Markdown')
        
    except Exception as e:
        logger.error(f"Error during cleanup: {e}", exc_info=True)
        bot.edit_message_text(f"❌ Cleanup error: {str(e)}", call.message.chat.id, call.message.message_id)

def install_logs_callback(call):
    bot.answer_callback_query(call.id)
    try:
        from database import get_recent_install_logs
        logs = get_recent_install_logs(limit=20)
        
        if not logs:
            bot.edit_message_text("📋 **No installation logs found**", call.message.chat.id, 
                                  call.message.message_id, reply_markup=create_admin_settings_menu())
            return
        
        log_text = "📋 **Recent Installation Logs (Last 20):**\n\n"
        for user_id, module_name, package_name, status, install_date in logs:
            status_icon = "✅" if status == "success" else "❌" if status == "failed" else "⚠️"
            log_text += f"{status_icon} `{user_id}`: {module_name} -> {package_name}\n"
            log_text += f"   📅 {install_date[:19]}\n\n"
        
        bot.edit_message_text(log_text, call.message.chat.id, call.message.message_id,
                              reply_markup=create_admin_settings_menu(), parse_mode='Markdown')
        
    except Exception as e:
        logger.error(f"Error showing install logs: {e}", exc_info=True)
        bot.answer_callback_query(call.id, "Error showing logs.", show_alert=True)

def admin_install_callback(call):
    bot.answer_callback_query(call.id)
    # Fix from_user so authorization and next step handler work (Fixes Admin Install bug)
    call.message.from_user = call.from_user
    _logic_admin_install(call.message)

# --- Mandatory Channels Callbacks ---
def manage_mandatory_channels_callback(call):
    """Handle mandatory channels management request"""
    bot.answer_callback_query(call.id)
    try:
        bot.edit_message_text("📢 Manage Mandatory Channels\nChoose desired action:",
                              call.message.chat.id, call.message.message_id, 
                              reply_markup=create_mandatory_channels_menu())
    except Exception as e:
        logger.error(f"Error showing channel management menu: {e}")

def add_mandatory_channel_callback(call):
    """Add new mandatory channel"""
    bot.answer_callback_query(call.id)
    msg = bot.send_message(call.message.chat.id, "📢 Send channel ID or username (example: @channel_username or -1001234567890)\n/cancel to cancel")
    bot.register_next_step_handler(msg, process_add_channel)

def process_add_channel(message):
    """Process channel addition"""
    admin_id = message.from_user.id
    if admin_id not in admin_ids:
        bot.reply_to(message, "⚠️ Not authorized.")
        return
        
    if message.text and message.text.lower() == '/cancel':
        bot.reply_to(message, "❌ Channel addition cancelled.")
        return
        
    channel_identifier = message.text.strip()
    
    try:
        # Get channel info
        chat = bot.get_chat(channel_identifier)
        channel_id = str(chat.id)
        channel_username = f"@{chat.username}" if chat.username else ""
        channel_name = chat.title
        
        # Ensure bot is admin in the channel
        try:
            bot_member = bot.get_chat_member(channel_id, bot.get_me().id)
            if bot_member.status not in ['administrator', 'creator']:
                bot.reply_to(message, f"❌ Bot is not admin in the channel! Must be promoted first.")
                return
        except Exception as e:
            bot.reply_to(message, f"❌ Bot is not admin in the channel or cannot access it!")
            return
            
        # Save channel to database
        if save_mandatory_channel(channel_id, channel_username, channel_name, admin_id):
            bot.reply_to(message, f"✅ Mandatory channel added:\n**{channel_name}**\n{channel_username or channel_id}")
        else:
            bot.reply_to(message, "❌ Failed to add channel. Try again.")
            
    except Exception as e:
        logger.error(f"Error adding channel: {e}")
        bot.reply_to(message, f"❌ Error adding channel: {str(e)}")

def remove_mandatory_channel_callback(call):
    """Remove mandatory channel"""
    if not mandatory_channels:
        bot.answer_callback_query(call.id, "❌ No mandatory channels.", show_alert=True)
        return
        
    bot.answer_callback_query(call.id)
    
    markup = types.InlineKeyboardMarkup()
    for channel_id, channel_info in mandatory_channels.items():
        channel_name = channel_info.get('name', 'Unknown')
        button_text = f"🗑️ {channel_name}"
        markup.add(btn(button_text, callback_data=f'remove_channel_{channel_id}', style='danger'))
    
    markup.add(btn("🔙 Back", callback_data='manage_mandatory_channels', style='primary'))
    
    try:
        bot.edit_message_text("📢 Choose channel to delete:",
                              call.message.chat.id, call.message.message_id, 
                              reply_markup=markup)
    except Exception as e:
        logger.error(f"Error showing remove channel menu: {e}")

def process_remove_channel(call):
    """Process channel removal"""
    channel_id = call.data.replace('remove_channel_', '')
    
    if channel_id in mandatory_channels:
        channel_name = mandatory_channels[channel_id].get('name', 'Unknown')
        if remove_mandatory_channel_db(channel_id):
            bot.answer_callback_query(call.id, f"✅ Channel deleted: {channel_name}")
            try:
                bot.edit_message_text(f"✅ Mandatory channel deleted: **{channel_name}**",
                                      call.message.chat.id, call.message.message_id,
                                      reply_markup=create_mandatory_channels_menu(), parse_mode='Markdown')
            except Exception as e:
                logger.error(f"Error updating message after channel removal: {e}")
        else:
            bot.answer_callback_query(call.id, "❌ Failed to delete channel.", show_alert=True)
    else:
        bot.answer_callback_query(call.id, "❌ Channel not found.", show_alert=True)

def list_mandatory_channels_callback(call):
    """Show list of mandatory channels"""
    bot.answer_callback_query(call.id)
    
    if not mandatory_channels:
        message_text = "📢 **No mandatory channels currently**"
    else:
        message_text = "📢 **Mandatory Channels:**\n\n"
        for channel_id, channel_info in mandatory_channels.items():
            channel_name = channel_info.get('name', 'Unknown')
            channel_username = channel_info.get('username', 'No username')
            message_text += f"• **{channel_name}**\n  {channel_username or channel_id}\n\n"
    
    try:
        bot.edit_message_text(message_text, call.message.chat.id, call.message.message_id,
                              reply_markup=create_mandatory_channels_menu(), parse_mode='Markdown')
    except Exception as e:
        logger.error(f"Error listing channels: {e}")

def check_subscription_status_callback(call):
    """Check subscription status"""
    user_id = call.from_user.id
    is_subscribed, not_joined = check_mandatory_subscription(user_id)
    
    if is_subscribed or user_id in admin_ids:
        bot.answer_callback_query(call.id, "✅ You are subscribed to all required channels!", show_alert=True)
        # Show main menu
        try:
            _logic_send_welcome(call.message)
        except:
            back_to_main_callback(call)
    else:
        bot.answer_callback_query(call.id, "❌ You haven't joined all required channels yet!", show_alert=True)
        # Update the subscription message
        subscription_message, markup = create_subscription_check_message(not_joined)
        try:
            bot.edit_message_text(subscription_message, call.message.chat.id, 
                                  call.message.message_id, reply_markup=markup, parse_mode='Markdown')
        except Exception as e:
            logger.error(f"Error updating subscription message: {e}")

# --- Security Approval Callbacks ---
def process_approve_file(call):
    """Process admin approval for file"""
    data_parts = call.data.split('_')
    if len(data_parts) < 4:
        bot.answer_callback_query(call.id, "❌ Invalid data.", show_alert=True)
        return
        
    user_id = int(data_parts[2])
    file_name = '_'.join(data_parts[3:])
    
    user_folder = get_user_folder(user_id)
    file_path = os.path.join(user_folder, file_name)
    
    if not os.path.exists(file_path):
        bot.answer_callback_query(call.id, "❌ File not found.", show_alert=True)
        return
    
    file_ext = os.path.splitext(file_name)[1].lower()
    
    try:
        # Process the approved file
        if file_ext == '.js':
            handle_js_file(file_path, user_id, user_folder, file_name, call.message)
        elif file_ext == '.py':
            handle_py_file(file_path, user_id, user_folder, file_name, call.message)
        
        bot.answer_callback_query(call.id, "✅ File approved!")
        bot.edit_message_text(f"✅ File `{file_name}` approved for user `{user_id}`",
                              call.message.chat.id, call.message.message_id)
        
        # Notify user
        try:
            bot.send_message(user_id, f"✅ Your file `{file_name}` has been approved and started.")
        except Exception as e:
            logger.error(f"Failed to notify user {user_id}: {e}")
            
    except Exception as e:
        logger.error(f"Error processing approved file: {e}")
        bot.answer_callback_query(call.id, "❌ Error processing file.", show_alert=True)

def process_reject_file(call):
    """Process admin rejection for file"""
    data_parts = call.data.split('_')
    if len(data_parts) < 4:
        bot.answer_callback_query(call.id, "❌ Invalid data.", show_alert=True)
        return
        
    user_id = int(data_parts[2])
    file_name = '_'.join(data_parts[3:])
    
    user_folder = get_user_folder(user_id)
    file_path = os.path.join(user_folder, file_name)
    
    # Delete the file
    if os.path.exists(file_path):
        try:
            os.remove(file_path)
        except Exception as e:
            logger.error(f"Error deleting rejected file: {e}")
    
    bot.answer_callback_query(call.id, "❌ File rejected!")
    bot.edit_message_text(f"❌ File `{file_name}` rejected for user `{user_id}`",
                          call.message.chat.id, call.message.message_id)
    
    # Notify user
    try:
        bot.send_message(user_id, f"❌ Your file `{file_name}` has been rejected for security reasons.")
    except Exception as e:
        logger.error(f"Failed to notify user {user_id}: {e}")

def process_approve_zip(call):
    """Process admin approval for ZIP file"""
    data_parts = call.data.split('_')
    if len(data_parts) < 4:
        bot.answer_callback_query(call.id, "❌ Invalid data.", show_alert=True)
        return
        
    user_id = int(data_parts[2])
    file_name = '_'.join(data_parts[3:])
    
    # Check if we have stored file content
    if user_id in pending_zip_files and file_name in pending_zip_files[user_id]:
        file_content = pending_zip_files[user_id][file_name]
        user_folder = get_user_folder(user_id)
        temp_dir = None
        
        try:
            temp_dir = tempfile.mkdtemp(prefix=f"user_{user_id}_zip_approve_")
            zip_path = os.path.join(temp_dir, file_name)
            
            # Save the file content
            with open(zip_path, 'wb') as f:
                f.write(file_content)
            
            # Process the ZIP file
            process_zip_file(zip_path, user_id, user_folder, file_name, call.message, temp_dir)
            
            # Clean up pending files
            if user_id in pending_zip_files and file_name in pending_zip_files[user_id]:
                del pending_zip_files[user_id][file_name]
                if not pending_zip_files[user_id]:
                    del pending_zip_files[user_id]
            
            bot.answer_callback_query(call.id, "✅ Archive approved!")
            bot.edit_message_text(f"✅ Archive `{file_name}` approved for user `{user_id}`",
                                  call.message.chat.id, call.message.message_id)
            
            # Notify user
            try:
                bot.send_message(user_id, f"✅ Your archive `{file_name}` has been approved and processed.")
            except Exception as e:
                logger.error(f"Failed to notify user {user_id}: {e}")
                
        except Exception as e:
            logger.error(f"Error processing approved zip: {e}", exc_info=True)
            bot.answer_callback_query(call.id, "❌ Error processing archive.", show_alert=True)
        finally:
            if temp_dir and os.path.exists(temp_dir):
                try:
                    shutil.rmtree(temp_dir)
                except Exception as e:
                    logger.error(f"Error cleaning temp dir: {e}")
    else:
        bot.answer_callback_query(call.id, "❌ File content not found. Ask user to re-upload.", show_alert=True)

def process_reject_zip(call):
    """Process admin rejection for ZIP file"""
    data_parts = call.data.split('_')
    if len(data_parts) < 4:
        bot.answer_callback_query(call.id, "❌ Invalid data.", show_alert=True)
        return
        
    user_id = int(data_parts[2])
    file_name = '_'.join(data_parts[3:])
    
    # Clean up pending files
    if user_id in pending_zip_files and file_name in pending_zip_files[user_id]:
        del pending_zip_files[user_id][file_name]
        if not pending_zip_files[user_id]:
            del pending_zip_files[user_id]
    
    bot.answer_callback_query(call.id, "❌ Archive rejected!")
    bot.edit_message_text(f"❌ Archive `{file_name}` rejected for user `{user_id}`",
                          call.message.chat.id, call.message.message_id)
    
    try:
        bot.send_message(user_id, f"❌ Your archive `{file_name}` has been rejected for security reasons.")
    except Exception as e:
        logger.error(f"Failed to notify user {user_id}: {e}")

# --- Cleanup Function ---


# =====================================================================
# 🚀 PREMIUM FEATURES & CORE ALGORITHMS FOR PUBLIC PRODUCTION LAUNCH
# =====================================================================

# --- Feature 1: License Key Generator & Redeemer ---

@bot.message_handler(commands=['generatekey'])
def command_generate_key(message):
    """Generate a premium redeemable subscription key (Admin only)"""
    user_id = message.from_user.id
    if user_id not in admin_ids:
        bot.reply_to(message, "⚠️ Admin permissions required.")
        return
        
    parts = message.text.split()
    if len(parts) < 2:
        bot.reply_to(message, "⚠️ Format: `/generatekey <days>`\nExample: `/generatekey 30`", parse_mode='Markdown')
        return
        
    try:
        days = int(parts[1])
        if days <= 0: raise ValueError()
        
        # Generate secure key format: PREM-XXXX-XXXX-XXXX
        import secrets
        key_chars = secrets.token_hex(6).upper()
        license_key = f"PREM-{key_chars[:4]}-{key_chars[4:8]}-{key_chars[8:]}"
        
        from database import generate_license_key_db
        if generate_license_key_db(license_key, days, user_id):
            bot.reply_to(message, f"🔑 **License Key Generated Successfully**:\n\n`{license_key}`\n\n📅 **Duration**: `{days} Days`\n📦 Use `/redeem {license_key}` to activate.", parse_mode='Markdown')
        else:
            bot.reply_to(message, "❌ Failed to store generated license key in database.")
    except ValueError:
        bot.reply_to(message, "⚠️ Days must be a valid positive integer.")

def process_generate_key(message):
    """Process license key generator prompt"""
    if message.from_user.id not in admin_ids:
        bot.reply_to(message, "⚠️ Not authorized.")
        return
    if message.text.lower() == '/cancel':
        bot.reply_to(message, "❌ Cancelled.")
        return
    try:
        days = int(message.text.strip())
        if days <= 0: raise ValueError()
        
        import secrets
        key_chars = secrets.token_hex(6).upper()
        license_key = f"PREM-{key_chars[:4]}-{key_chars[4:8]}-{key_chars[8:]}"
        
        from database import generate_license_key_db
        if generate_license_key_db(license_key, days, message.from_user.id):
            bot.reply_to(message, f"🔑 **License Key Generated**:\n\n`{license_key}`\n\n📅 **Duration**: `{days} Days`\n📦 Use `/redeem {license_key}` to activate.", parse_mode='Markdown')
        else:
            bot.reply_to(message, "❌ Failed to save key.")
    except ValueError:
        bot.reply_to(message, "⚠️ Days must be a positive integer. Process cancelled.")

@bot.message_handler(commands=['redeem'])
def command_redeem_key(message):
    """Redeem a license key to extend premium subscription"""
    user_id = message.from_user.id
    parts = message.text.split()
    if len(parts) < 2:
        bot.reply_to(message, "⚠️ Format: `/redeem PREM-XXXX-XXXX-XXXX`\nExample: `/redeem PREM-A1B2-C3D4-E5F6`", parse_mode='Markdown')
        return
        
    license_key = parts[1].strip()
    from database import check_and_redeem_license_key_db
    success, resp_msg = check_and_redeem_license_key_db(license_key, user_id)
    bot.reply_to(message, resp_msg, parse_mode='Markdown')

def process_redeem_key(message):
    """Process license key redemption prompt"""
    if message.text.lower() == '/cancel':
        bot.reply_to(message, "❌ Aborted.")
        return
    license_key = message.text.strip()
    from database import check_and_redeem_license_key_db
    success, resp_msg = check_and_redeem_license_key_db(license_key, message.from_user.id)
    bot.reply_to(message, resp_msg, parse_mode='Markdown')


# --- Feature 4 & 5: Hashed File Explorer & Dynamic Backups ---

def explorer_callback(call):
    """List files inside the hashed user sandbox folder"""
    bot.answer_callback_query(call.id)
    try:
        data_parts = call.data.split('_')
        script_owner_id = int(data_parts[1])
        requesting_user_id = call.from_user.id
        
        if not (requesting_user_id == script_owner_id or requesting_user_id in admin_ids):
            bot.send_message(call.message.chat.id, "⚠️ Permission denied.")
            return
            
        user_folder = get_user_folder(script_owner_id)
        files = os.listdir(user_folder)
        
        markup = types.InlineKeyboardMarkup(row_width=1)
        for f in sorted(files):
            # Don't show system hidden files
            if f.startswith('.') or f.endswith('.log'): continue
            file_size_kb = round(os.path.getsize(os.path.join(user_folder, f)) / 1024, 2)
            markup.add(btn(f"📄 {f} ({file_size_kb} KB)", callback_data=f"expfile_{script_owner_id}_{f}", style='primary'))
            
        markup.add(btn("🔙 Back to Controls", callback_data='check_files', style='primary'))
        
        bot.edit_message_text(f"📂 **Sandbox Explorer**: `{script_owner_id}`\n\nSelect any file to read details or delete:", 
                              call.message.chat.id, call.message.message_id, reply_markup=markup, parse_mode='Markdown')
    except Exception as e:
        logger.error(f"Error in explorer_callback: {e}", exc_info=True)

def explore_file_callback(call):
    """Display individual file information"""
    bot.answer_callback_query(call.id)
    try:
        data_parts = call.data.split('_', 2)
        script_owner_id = int(data_parts[1])
        file_name = data_parts[2]
        requesting_user_id = call.from_user.id
        
        if not (requesting_user_id == script_owner_id or requesting_user_id in admin_ids):
            bot.send_message(call.message.chat.id, "⚠️ Permission denied.")
            return
            
        user_folder = get_user_folder(script_owner_id)
        file_path = os.path.join(user_folder, file_name)
        
        if not os.path.exists(file_path):
            bot.send_message(call.message.chat.id, "❌ File not found on disk.")
            return
            
        size = round(os.path.getsize(file_path) / 1024, 2)
        mtime = datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M:%S')
        
        markup = types.InlineKeyboardMarkup(row_width=2)
        markup.row(
            btn("🗑️ Delete File", callback_data=f"expdel_{script_owner_id}_{file_name}", style='danger'),
            btn("🔙 Back to Explorer", callback_data=f"explorer_{script_owner_id}", style='primary')
        )
        
        file_info_text = f"📄 **File Explorer**: `{file_name}`\n\n📏 **Size**: `{size} KB`\n📅 **Last Modified**: `{mtime}`"
        bot.edit_message_text(file_info_text, call.message.chat.id, call.message.message_id, reply_markup=markup, parse_mode='Markdown')
    except Exception as e:
        logger.error(f"Error in explore_file_callback: {e}", exc_info=True)

def delete_file_explorer_callback(call):
    """Delete an individual file inside the folder"""
    try:
        data_parts = call.data.split('_', 2)
        script_owner_id = int(data_parts[1])
        file_name = data_parts[2]
        requesting_user_id = call.from_user.id
        
        if not (requesting_user_id == script_owner_id or requesting_user_id in admin_ids):
            bot.answer_callback_query(call.id, "⚠️ Permission denied.", show_alert=True)
            return
            
        user_folder = get_user_folder(script_owner_id)
        file_path = os.path.join(user_folder, file_name)
        
        if os.path.exists(file_path):
            os.remove(file_path)
            bot.answer_callback_query(call.id, "✅ File deleted successfully!", show_alert=True)
            
            # If main script record is deleted, remove it from DB too
            user_files_list = user_files.get(script_owner_id, [])
            if any(f[0] == file_name for f in user_files_list):
                remove_user_file_db(script_owner_id, file_name)
                
            explorer_callback(call)
        else:
            bot.answer_callback_query(call.id, "❌ File not found.", show_alert=True)
    except Exception as e:
        logger.error(f"Error in delete_file_explorer_callback: {e}", exc_info=True)

def backup_callback(call):
    """Compress user sandbox directory and send as .zip document"""
    bot.answer_callback_query(call.id)
    try:
        data_parts = call.data.split('_')
        script_owner_id = int(data_parts[1])
        requesting_user_id = call.from_user.id
        
        if not (requesting_user_id == script_owner_id or requesting_user_id in admin_ids):
            bot.send_message(call.message.chat.id, "⚠️ Permission denied.")
            return
            
        user_folder = get_user_folder(script_owner_id)
        
        bot.send_message(call.message.chat.id, "⏳ **Generating Sandbox Backup**... Please wait.")
        
        # Create a zip archive in temp directory
        temp_zip_dir = tempfile.mkdtemp(prefix=f"backup_user_{script_owner_id}_")
        zip_file_name = f"backup_{script_owner_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
        zip_path = os.path.join(temp_zip_dir, zip_file_name)
        
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zip_f:
            for root, dirs, files in os.walk(user_folder):
                for f in files:
                    file_abs = os.path.join(root, f)
                    file_rel = os.path.relpath(file_abs, user_folder)
                    # Skip log files to keep backup clean
                    if f.endswith('.log'): continue
                    zip_f.write(file_abs, file_rel)
                    
        # Send zip document to user
        with open(zip_path, 'rb') as f:
            bot.send_document(call.message.chat.id, f, caption=f"💾 **50 Shades Hoster Backup Archive**\n🆔 **ID**: `{script_owner_id}`\n📦 Excludes log files.", parse_mode='Markdown')
            
        # Clean up zip
        shutil.rmtree(temp_zip_dir)
    except Exception as e:
        logger.error(f"Error in backup_callback: {e}", exc_info=True)
        bot.send_message(call.message.chat.id, "❌ Error generating backup archive.")

