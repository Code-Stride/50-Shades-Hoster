# -*- coding: utf-8 -*-
from config import ADMIN_ID, OWNER_ID

# Shared global states
bot_scripts = {}
user_subscriptions = {}
user_files = {}
active_users = set()
admin_ids = {ADMIN_ID, OWNER_ID}
banned_users = set()
user_limits = {}  # Custom limits per user
bot_locked = False

# Manual modules installation system
pending_modules = {}  # {user_id: {module_name: package_name}}
manual_install_requests = {}  # {admin_id: {user_id: {module_name: package_name}}}

# Mandatory channels/groups
mandatory_channels = {}  # {channel_id: {'username': 'channel_username', 'name': 'Channel Name'}}

# Pending ZIP files for approval
pending_zip_files = {}  # {user_id: {file_name: file_content}}
