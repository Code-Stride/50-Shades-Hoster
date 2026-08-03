# -*- coding: utf-8 -*-
import sqlite3
import os
import threading
import logging
from datetime import datetime
from config import DATABASE_PATH, OWNER_ID, ADMIN_ID
import state

logger = logging.getLogger(__name__)

# Single global DB lock to ensure thread safety
DB_LOCK = threading.Lock()

# Support PostgreSQL from Railway if DATABASE_URL is set (Fixes Database Migration)
DATABASE_URL = os.getenv("DATABASE_URL")
if DATABASE_URL:
    try:
        import psycopg2
        logger.info("🔌 Detected DATABASE_URL in environment. Using PostgreSQL!")
    except ImportError:
        logger.error("❌ psycopg2-binary/psycopg2 not installed. Please add it to requirements.txt.")
        DATABASE_URL = None

def get_conn():
    if DATABASE_URL:
        import psycopg2
        return psycopg2.connect(DATABASE_URL)
    else:
        return sqlite3.connect(DATABASE_PATH, check_same_thread=False)

def translate_query(query):
    """Translates standard SQLite syntax to PostgreSQL syntax dynamically if PostgreSQL is used"""
    if not DATABASE_URL:
        return query # No translation needed for SQLite
    
    # Convert '?' placeholders to '%s' for psycopg2
    query = query.replace('?', '%s')
    
    # Convert create table autoincrement
    if 'CREATE TABLE IF NOT EXISTS' in query:
        query = query.replace('INTEGER PRIMARY KEY AUTOINCREMENT', 'SERIAL PRIMARY KEY')
        
    # Translate INSERT OR REPLACE to PostgreSQL INSERT ... ON CONFLICT
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
    
    # Translate INSERT OR IGNORE
    if 'INSERT OR IGNORE INTO admins' in query:
        return "INSERT INTO admins (user_id, added_by, added_date) VALUES (%s, %s, %s) ON CONFLICT (user_id) DO NOTHING"
    
    return query

def init_db():
    """Initialize the database with required tables"""
    logger.info(f"Initializing database...")
    with DB_LOCK:
        try:
            conn = get_conn()
            c = conn.cursor()
            
            q1 = "CREATE TABLE IF NOT EXISTS subscriptions (user_id BIGINT PRIMARY KEY, expiry TEXT)" if DATABASE_URL else "CREATE TABLE IF NOT EXISTS subscriptions (user_id INTEGER PRIMARY KEY, expiry TEXT)"
            q2 = "CREATE TABLE IF NOT EXISTS user_files (user_id BIGINT, file_name TEXT, file_type TEXT, PRIMARY KEY (user_id, file_name))" if DATABASE_URL else "CREATE TABLE IF NOT EXISTS user_files (user_id INTEGER, file_name TEXT, file_type TEXT, PRIMARY KEY (user_id, file_name))"
            q3 = "CREATE TABLE IF NOT EXISTS active_users (user_id BIGINT PRIMARY KEY, join_date TEXT, last_seen TEXT)" if DATABASE_URL else "CREATE TABLE IF NOT EXISTS active_users (user_id INTEGER PRIMARY KEY, join_date TEXT, last_seen TEXT)"
            q4 = "CREATE TABLE IF NOT EXISTS admins (user_id BIGINT PRIMARY KEY, added_by BIGINT, added_date TEXT)" if DATABASE_URL else "CREATE TABLE IF NOT EXISTS admins (user_id INTEGER PRIMARY KEY, added_by INTEGER, added_date TEXT)"
            q5 = "CREATE TABLE IF NOT EXISTS banned_users (user_id BIGINT PRIMARY KEY, reason TEXT, banned_by BIGINT, ban_date TEXT)" if DATABASE_URL else "CREATE TABLE IF NOT EXISTS banned_users (user_id INTEGER PRIMARY KEY, reason TEXT, banned_by INTEGER, ban_date TEXT)"
            q6 = "CREATE TABLE IF NOT EXISTS user_limits (user_id BIGINT PRIMARY KEY, file_limit INTEGER, set_by BIGINT, set_date TEXT)" if DATABASE_URL else "CREATE TABLE IF NOT EXISTS user_limits (user_id INTEGER PRIMARY KEY, file_limit INTEGER, set_by INTEGER, set_date TEXT)"
            
            c.execute(q1)
            c.execute(q2)
            c.execute(q3)
            c.execute(q4)
            c.execute(q5)
            c.execute(q6)
            
            c.execute('''CREATE TABLE IF NOT EXISTS mandatory_channels
                         (channel_id TEXT PRIMARY KEY, 
                          channel_username TEXT,
                          channel_name TEXT,
                          added_by BIGINT,
                          added_date TEXT)''' if DATABASE_URL else '''CREATE TABLE IF NOT EXISTS mandatory_channels
                         (channel_id TEXT PRIMARY KEY, 
                          channel_username TEXT,
                          channel_name TEXT,
                          added_by INTEGER,
                          added_date TEXT)''')
                          
            c.execute(translate_query('CREATE TABLE IF NOT EXISTS install_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id BIGINT, module_name TEXT, package_name TEXT, status TEXT, log TEXT, install_date TEXT)' if DATABASE_URL else 'CREATE TABLE IF NOT EXISTS install_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, module_name TEXT, package_name TEXT, status TEXT, log TEXT, install_date TEXT)'))
            
            # Seed owner and default admin
            seed_q = translate_query('INSERT OR IGNORE INTO admins (user_id, added_by, added_date) VALUES (?, ?, ?)')
            c.execute(seed_q, (OWNER_ID, OWNER_ID, datetime.now().isoformat()))
            if ADMIN_ID != OWNER_ID:
                c.execute(seed_q, (ADMIN_ID, OWNER_ID, datetime.now().isoformat()))
                
            conn.commit()
            conn.close()
            logger.info("Database initialized successfully.")
        except Exception as e:
            logger.error(f"❌ Database initialization error: {e}", exc_info=True)

def load_data():
    """Load data from database into memory state"""
    logger.info("Loading data from database into memory...")
    try:
        conn = get_conn()
        c = conn.cursor()

        # Load subscriptions
        c.execute(translate_query('SELECT user_id, expiry FROM subscriptions'))
        for user_id, expiry in c.fetchall():
            try:
                state.user_subscriptions[user_id] = {'expiry': datetime.fromisoformat(expiry)}
            except ValueError:
                logger.warning(f"⚠️ Invalid expiry date format for user {user_id}: {expiry}. Skipping.")

        # Load user files
        c.execute(translate_query('SELECT user_id, file_name, file_type FROM user_files'))
        for user_id, file_name, file_type in c.fetchall():
            if user_id not in state.user_files:
                state.user_files[user_id] = []
            state.user_files[user_id].append((file_name, file_type))

        # Load active users
        c.execute(translate_query('SELECT user_id FROM active_users'))
        state.active_users.update(user_id for (user_id,) in c.fetchall())

        # Load admins
        c.execute(translate_query('SELECT user_id FROM admins'))
        state.admin_ids.update(user_id for (user_id,) in c.fetchall())

        # Load banned users
        c.execute(translate_query('SELECT user_id FROM banned_users'))
        state.banned_users.update(user_id for (user_id,) in c.fetchall())

        # Load user limits
        c.execute(translate_query('SELECT user_id, file_limit FROM user_limits'))
        for user_id, file_limit in c.fetchall():
            state.user_limits[user_id] = file_limit

        # Load mandatory channels
        c.execute(translate_query('SELECT channel_id, channel_username, channel_name FROM mandatory_channels'))
        for channel_id, channel_username, channel_name in c.fetchall():
            state.mandatory_channels[channel_id] = {
                'username': channel_username,
                'name': channel_name
            }

        conn.close()
        logger.info(f"Data loaded into memory cache successfully.")
    except Exception as e:
        logger.error(f"❌ Error loading data: {e}", exc_info=True)

def is_user_banned(user_id):
    """Check if user is banned"""
    return user_id in state.banned_users

def ban_user_db(user_id, reason, banned_by):
    """Ban a user"""
    with DB_LOCK:
        conn = get_conn()
        c = conn.cursor()
        try:
            ban_date = datetime.now().isoformat()
            query = translate_query('INSERT OR REPLACE INTO banned_users (user_id, reason, banned_by, ban_date) VALUES (?, ?, ?, ?)')
            c.execute(query, (user_id, reason, banned_by, ban_date))
            conn.commit()
            state.banned_users.add(user_id)
            logger.warning(f"User {user_id} banned by {banned_by}. Reason: {reason}")
            return True
        except Exception as e:
            logger.error(f"❌ Error banning user {user_id}: {e}", exc_info=True)
            return False
        finally:
            conn.close()

def unban_user_db(user_id):
    """Unban a user"""
    with DB_LOCK:
        conn = get_conn()
        c = conn.cursor()
        try:
            query = translate_query('DELETE FROM banned_users WHERE user_id = ?')
            c.execute(query, (user_id,))
            conn.commit()
            state.banned_users.discard(user_id)
            logger.info(f"User {user_id} unbanned")
            return True
        except Exception as e:
            logger.error(f"❌ Error unbanning user {user_id}: {e}", exc_info=True)
            return False
        finally:
            conn.close()

def set_user_limit_db(user_id, limit, set_by):
    """Set custom file limit for a user"""
    with DB_LOCK:
        conn = get_conn()
        c = conn.cursor()
        try:
            set_date = datetime.now().isoformat()
            query = translate_query('INSERT OR REPLACE INTO user_limits (user_id, file_limit, set_by, set_date) VALUES (?, ?, ?, ?)')
            c.execute(query, (user_id, limit, set_by, set_date))
            conn.commit()
            state.user_limits[user_id] = limit
            logger.info(f"Set file limit {limit} for user {user_id} by {set_by}")
            return True
        except Exception as e:
            logger.error(f"❌ Error setting limit for user {user_id}: {e}", exc_info=True)
            return False
        finally:
            conn.close()

def remove_user_limit_db(user_id):
    """Remove custom file limit for a user"""
    with DB_LOCK:
        conn = get_conn()
        c = conn.cursor()
        try:
            query = translate_query('DELETE FROM user_limits WHERE user_id = ?')
            c.execute(query, (user_id,))
            conn.commit()
            if user_id in state.user_limits:
                del state.user_limits[user_id]
            logger.info(f"Removed custom limit for user {user_id}")
            return True
        except Exception as e:
            logger.error(f"❌ Error removing limit for user {user_id}: {e}", exc_info=True)
            return False
        finally:
            conn.close()

def save_user_file(user_id, file_name, file_type='py'):
    with DB_LOCK:
        conn = get_conn()
        c = conn.cursor()
        try:
            query = translate_query('INSERT OR REPLACE INTO user_files (user_id, file_name, file_type) VALUES (?, ?, ?)')
            c.execute(query, (user_id, file_name, file_type))
            conn.commit()
            if user_id not in state.user_files: state.user_files[user_id] = []
            state.user_files[user_id] = [(fn, ft) for fn, ft in state.user_files[user_id] if fn != file_name]
            state.user_files[user_id].append((file_name, file_type))
            logger.info(f"Saved file '{file_name}' ({file_type}) for user {user_id}")
        except Exception as e: logger.error(f"❌ Error saving file for user {user_id}, {file_name}: {e}", exc_info=True)
        finally: conn.close()

def remove_user_file_db(user_id, file_name):
    with DB_LOCK:
        conn = get_conn()
        c = conn.cursor()
        try:
            query = translate_query('DELETE FROM user_files WHERE user_id = ? AND file_name = ?')
            c.execute(query, (user_id, file_name))
            conn.commit()
            if user_id in state.user_files:
                state.user_files[user_id] = [f for f in state.user_files[user_id] if f[0] != file_name]
                if not state.user_files[user_id]: del state.user_files[user_id]
            logger.info(f"Removed file '{file_name}' for user {user_id} from DB")
        except Exception as e: logger.error(f"❌ Error removing file for {user_id}, {file_name}: {e}", exc_info=True)
        finally: conn.close()

def add_active_user(user_id):
    state.active_users.add(user_id) 
    with DB_LOCK:
        conn = get_conn()
        c = conn.cursor()
        try:
            join_date = datetime.now().isoformat()
            query = translate_query('INSERT OR REPLACE INTO active_users (user_id, join_date, last_seen) VALUES (?, ?, ?)')
            c.execute(query, (user_id, join_date, join_date))
            conn.commit()
            logger.info(f"Added/Updated active user {user_id} in DB")
        except Exception as e: logger.error(f"❌ Error adding active user {user_id}: {e}", exc_info=True)
        finally: conn.close()

def save_subscription(user_id, expiry):
    with DB_LOCK:
        conn = get_conn()
        c = conn.cursor()
        try:
            expiry_str = expiry.isoformat()
            query = translate_query('INSERT OR REPLACE INTO subscriptions (user_id, expiry) VALUES (?, ?)')
            c.execute(query, (user_id, expiry_str))
            conn.commit()
            state.user_subscriptions[user_id] = {'expiry': expiry}
            logger.info(f"Saved subscription for {user_id}, expiry {expiry_str}")
        except Exception as e: logger.error(f"❌ Error saving subscription for {user_id}: {e}", exc_info=True)
        finally: conn.close()

def remove_subscription_db(user_id):
    with DB_LOCK:
        conn = get_conn()
        c = conn.cursor()
        try:
            query = translate_query('DELETE FROM subscriptions WHERE user_id = ?')
            c.execute(query, (user_id,))
            conn.commit()
            if user_id in state.user_subscriptions: del state.user_subscriptions[user_id]
            logger.info(f"Removed subscription for {user_id} from DB")
        except Exception as e: logger.error(f"❌ Error removing subscription for {user_id}: {e}", exc_info=True)
        finally: conn.close()

def add_admin_db(admin_id, added_by):
    with DB_LOCK:
        conn = get_conn()
        c = conn.cursor()
        try:
            added_date = datetime.now().isoformat()
            query = translate_query('INSERT OR IGNORE INTO admins (user_id, added_by, added_date) VALUES (?, ?, ?)')
            c.execute(query, (admin_id, added_by, added_date))
            conn.commit()
            state.admin_ids.add(admin_id) 
            logger.info(f"Added admin {admin_id} to DB by {added_by}")
        except Exception as e: logger.error(f"❌ Error adding admin {admin_id}: {e}", exc_info=True)
        finally: conn.close()

def remove_admin_db(admin_id):
    if admin_id == OWNER_ID:
        logger.warning("Attempted to remove OWNER_ID from admins.")
        return False 
    with DB_LOCK:
        conn = get_conn()
        c = conn.cursor()
        removed = False
        try:
            query1 = translate_query('SELECT 1 FROM admins WHERE user_id = ?')
            c.execute(query1, (admin_id,))
            if c.fetchone():
                query2 = translate_query('DELETE FROM admins WHERE user_id = ?')
                c.execute(query2, (admin_id,))
                conn.commit()
                removed = c.rowcount > 0 
                if removed: state.admin_ids.discard(admin_id); logger.info(f"Removed admin {admin_id} from DB")
                else: logger.warning(f"Admin {admin_id} found but delete affected 0 rows.")
            else:
                logger.warning(f"Admin {admin_id} not found in DB.")
                state.admin_ids.discard(admin_id)
            return removed
        except Exception as e: logger.error(f"❌ Error removing admin {admin_id}: {e}", exc_info=True); return False
        finally: conn.close()

def save_mandatory_channel(channel_id, channel_username, channel_name, added_by):
    """Save mandatory channel to database"""
    with DB_LOCK:
        conn = get_conn()
        c = conn.cursor()
        try:
            added_date = datetime.now().isoformat()
            query = translate_query('INSERT OR REPLACE INTO mandatory_channels (channel_id, channel_username, channel_name, added_by, added_date) VALUES (?, ?, ?, ?, ?)')
            c.execute(query, (channel_id, channel_username, channel_name, added_by, added_date))
            conn.commit()
            state.mandatory_channels[channel_id] = {
                'username': channel_username,
                'name': channel_name
            }
            logger.info(f"Saved mandatory channel: {channel_name} ({channel_id})")
            return True
        except Exception as e:
            logger.error(f"❌ Error saving channel: {e}", exc_info=True)
            return False
        finally:
            conn.close()

def remove_mandatory_channel_db(channel_id):
    """Remove mandatory channel from database"""
    with DB_LOCK:
        conn = get_conn()
        c = conn.cursor()
        try:
            query = translate_query('DELETE FROM mandatory_channels WHERE channel_id = ?')
            c.execute(query, (channel_id,))
            conn.commit()
            if channel_id in state.mandatory_channels:
                del state.mandatory_channels[channel_id]
            logger.info(f"Removed mandatory channel: {channel_id}")
            return True
        except Exception as e:
            logger.error(f"❌ Error removing channel: {e}", exc_info=True)
            return False
        finally:
            conn.close()

def save_install_log(user_id, module_name, package_name, status, log):
    """Save automated package installation log"""
    with DB_LOCK:
        conn = get_conn()
        c = conn.cursor()
        try:
            install_date = datetime.now().isoformat()
            query = translate_query('INSERT INTO install_logs (user_id, module_name, package_name, status, log, install_date) VALUES (?, ?, ?, ?, ?, ?)')
            c.execute(query, (user_id, module_name, package_name, status, log, install_date))
            conn.commit()
        except Exception as e: logger.error(f"❌ Error saving install log: {e}", exc_info=True)
        finally: conn.close()

def get_recent_install_logs(limit=20):
    """Retrieve recent installation logs, works for both SQLite and PostgreSQL"""
    with DB_LOCK:
        conn = get_conn()
        c = conn.cursor()
        try:
            query = "SELECT user_id, module_name, package_name, status, install_date FROM install_logs ORDER BY install_date DESC LIMIT ?"
            query = translate_query(query)
            c.execute(query, (limit,))
            logs = c.fetchall()
            return logs
        except Exception as e:
            logger.error(f"Error getting install logs: {e}", exc_info=True)
            return []
        finally:
            conn.close()
