# -*- coding: utf-8 -*-
import sys
import time
import logging
import requests
import signal
import atexit
from config import BASE_DIR, UPLOAD_BOTS_DIR, IROTECH_DIR, OWNER_ID, ADMIN_ID
from bot_instance import bot
import state
from database import init_db, load_data, DB_LOCK
from keep_alive import keep_alive
from process_manager import start_watchdog_thread, kill_process_tree

# Pre-setup Logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Import handlers to register all bot decorators/callbacks
import handlers

# --- Cleanup Function on Shutdown ---
def cleanup():
    logger.warning("Shutdown initiated. Cleaning up processes...")
    script_keys_to_stop = list(state.bot_scripts.keys()) 
    if not script_keys_to_stop: 
        logger.info("No running scripts to stop. Exiting.")
        return
    logger.info(f"Stopping {len(script_keys_to_stop)} running scripts...")
    for key in script_keys_to_stop:
        if key in state.bot_scripts: 
            logger.info(f"Stopping script process: {key}")
            kill_process_tree(state.bot_scripts[key])
        else: 
            logger.info(f"Script {key} already removed.")
    logger.warning("Cleanup completed.")

atexit.register(cleanup)

def main():
    logger.info("="*50 + "\n🤖 BLAZE NXT Hosting Bot Starting Up...\n" + f"🐍 Python: {sys.version.split()[0]}\n" +
                f"🔧 Base Dir: {BASE_DIR}\n📁 Upload Dir: {UPLOAD_BOTS_DIR}\n" +
                f"📊 Data Dir: {IROTECH_DIR}\n🔑 Owner ID: {OWNER_ID}\n🛡️ Admins: {len(state.admin_ids)}\n" +
                f"🚫 Banned Users: {len(state.banned_users)}\n📢 Mandatory Channels: {len(state.mandatory_channels)}\n" + "="*50)
    
    # Initialize and load DB data
    init_db()
    load_data()
    
    # Start Active watchdog process monitoring (Zombie/Crash cleanup)
    start_watchdog_thread()
    
    # Start Keep-Alive web server
    keep_alive()
    
    logger.info("🚀 Starting polling...")
    while True:
        try:
            bot.infinity_polling(logger_level=logging.INFO, timeout=60, long_polling_timeout=30)
        except requests.exceptions.ReadTimeout: 
            logger.warning("Polling ReadTimeout. Restarting in 5s...")
            time.sleep(5)
        except requests.exceptions.ConnectionError as ce: 
            logger.error(f"Polling ConnectionError: {ce}. Retrying in 15s...")
            time.sleep(15)
        except Exception as e:
            logger.critical(f"💥 Unrecoverable polling error: {e}", exc_info=True)
            logger.info("Restarting polling in 30s due to critical error...")
            time.sleep(30)
        finally: 
            logger.warning("Polling attempt finished. Restarting loop.")

if __name__ == '__main__':
    main()
