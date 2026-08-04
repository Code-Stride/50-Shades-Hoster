# -*- coding: utf-8 -*-
import subprocess
import os
import sys
import time
import re
import shutil
import psutil
import logging
import threading
from datetime import datetime
from bot_instance import bot
from config import UPLOAD_BOTS_DIR
import state
from database import save_install_log, remove_user_file_db, save_user_file

logger = logging.getLogger(__name__)

import ast

# Standard Python library modules to ignore (Fixes Static Package Auto-Installer)
STD_LIB_MODULES = {
    'sys', 'os', 'time', 'datetime', 'math', 're', 'json', 'subprocess',
    'threading', 'logging', 'hashlib', 'shutil', 'tempfile', 'zipfile',
    'socket', 'sqlite3', 'ast', 'select', 'signal', 'urllib', 'collections',
    'random', 'uuid', 'functools', 'itertools', 'traceback', 'io', 'base64',
    'platform', 'weakref', 'gc', 'atexit', 'ctypes', 'inspect', 'pickle', 'csv',
    'asyncio', 'abc', 'typing', 'string', 'glob', 'pathlib'
}

# Core Node.js modules to ignore (Fixes Static Node Auto-Installer)
JS_CORE_MODULES = {
    'path', 'fs', 'crypto', 'os', 'http', 'https', 'child_process',
    'querystring', 'url', 'util', 'events', 'stream', 'readline', 'process'
}

def extract_imports(file_path):
    """Statically parse a Python file to extract all imported module names"""
    imports = set()
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            tree = ast.parse(f.read(), filename=file_path)
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.name.split('.')[0])
            elif isinstance(node, ast.ImportFrom):
                if node.level == 0 and node.module: # Only absolute imports
                    imports.add(node.module.split('.')[0])
    except Exception as e:
        logger.error(f"Error parsing imports from {file_path}: {e}")
    return imports

def extract_js_imports(file_path):
    """Scan a JS file using regex to extract imported package names"""
    imports = set()
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            code = f.read()
            
        # Match require('package')
        req_matches = re.findall(r"require\s*\(\s*['\x22](.+?)['\x22]\s*\)", code)
        for m in req_matches:
            if not m.startswith('.') and not m.startswith('/'):
                imports.add(m.split('/')[0])
                
        # Match import ... from 'package'
        imp_matches = re.findall(r"from\s*['\x22](.+?)['\x22]", code)
        for m in imp_matches:
            if not m.startswith('.') and not m.startswith('/'):
                imports.add(m.split('/')[0])
    except Exception as e:
        logger.error(f"Error scanning JS imports: {e}")
    return imports


# --- Map Telegram import names to actual PyPI package names ---
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

def resolve_chat_id(reply_target):
    """Safely resolve an integer chat ID or a Message object to a chat ID"""
    if reply_target is None:
        return None
    if hasattr(reply_target, 'chat'):
        return reply_target.chat.id
    if hasattr(reply_target, 'id'): # if it is a user
        return reply_target.id
    return reply_target

def is_bot_running(script_owner_id, file_name):
    """Check if a bot script is currently running for a specific user"""
    script_key = f"{script_owner_id}_{file_name}"
    script_info = state.bot_scripts.get(script_key)
    if script_info and script_info.get('process'):
        try:
            proc = psutil.Process(script_info['process'].pid)
            is_running = proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE
            if not is_running:
                logger.warning(f"Process {script_info['process'].pid} for {script_key} found in memory but not running/zombie. Cleaning up.")
                if 'log_file' in script_info and hasattr(script_info['log_file'], 'close') and not script_info['log_file'].closed:
                    try:
                        script_info['log_file'].close()
                    except Exception as log_e:
                        logger.error(f"Error closing log file during zombie cleanup {script_key}: {log_e}")
                if script_key in state.bot_scripts:
                    del state.bot_scripts[script_key]
            return is_running
        except psutil.NoSuchProcess:
            logger.warning(f"Process for {script_key} not found (NoSuchProcess). Cleaning up.")
            if 'log_file' in script_info and hasattr(script_info['log_file'], 'close') and not script_info['log_file'].closed:
                try:
                     script_info['log_file'].close()
                except Exception as log_e:
                     logger.error(f"Error closing log file during cleanup of non-existent process {script_key}: {log_e}")
            if script_key in state.bot_scripts:
                 del state.bot_scripts[script_key]
            return False
        except Exception as e:
            logger.error(f"Error checking process status for {script_key}: {e}", exc_info=True)
            return False
    return False

def kill_process_tree(process_info):
    """Kill a process and all its children, ensuring log file is closed."""
    pid = None
    log_file_closed = False
    script_key = process_info.get('script_key', 'N/A') 

    try:
        if 'log_file' in process_info and hasattr(process_info['log_file'], 'close') and not process_info['log_file'].closed:
            try:
                process_info['log_file'].close()
                log_file_closed = True
                logger.info(f"Closed log file for {script_key} (PID: {process_info.get('process', {}).pid if hasattr(process_info.get('process'), 'pid') else 'N/A'})")
            except Exception as log_e:
                logger.error(f"Error closing log file during kill for {script_key}: {log_e}")

        process = process_info.get('process')
        if process and hasattr(process, 'pid'):
           pid = process.pid
           if pid: 
                try:
                    parent = psutil.Process(pid)
                    children = parent.children(recursive=True)
                    logger.info(f"Attempting to kill process tree for {script_key} (PID: {pid}, Children: {[c.pid for c in children]})")

                    for child in children:
                        try:
                            child.terminate()
                            logger.info(f"Terminated child process {child.pid} for {script_key}")
                        except psutil.NoSuchProcess:
                            logger.warning(f"Child process {child.pid} for {script_key} already gone.")
                        except Exception as e:
                            logger.error(f"Error terminating child {child.pid} for {script_key}: {e}. Trying kill...")
                            try: child.kill(); logger.info(f"Killed child process {child.pid} for {script_key}")
                            except Exception as e2: logger.error(f"Failed to kill child {child.pid} for {script_key}: {e2}")

                    gone, alive = psutil.wait_procs(children, timeout=1)
                    for p in alive:
                        logger.warning(f"Child process {p.pid} for {script_key} still alive. Killing.")
                        try: p.kill()
                        except Exception as e: logger.error(f"Failed to kill child {p.pid} for {script_key} after wait: {e}")

                    try:
                        parent.terminate()
                        logger.info(f"Terminated parent process {pid} for {script_key}")
                        try: parent.wait(timeout=1)
                        except psutil.TimeoutExpired:
                            logger.warning(f"Parent process {pid} for {script_key} did not terminate. Killing.")
                            parent.kill()
                            logger.info(f"Killed parent process {pid} for {script_key}")
                    except psutil.NoSuchProcess:
                        logger.warning(f"Parent process {pid} for {script_key} already gone.")
                    except Exception as e:
                        logger.error(f"Error terminating parent {pid} for {script_key}: {e}. Trying kill...")
                        try: parent.kill(); logger.info(f"Killed parent process {pid} for {script_key}")
                        except Exception as e2: logger.error(f"Failed to kill parent {pid} for {script_key}: {e2}")

                except psutil.NoSuchProcess:
                    logger.warning(f"Process {pid or 'N/A'} for {script_key} not found during kill. Already terminated?")
           else: logger.error(f"Process PID is None for {script_key}.")
        elif log_file_closed: logger.warning(f"Process object missing for {script_key}, but log file closed.")
        else: logger.error(f"Process object missing for {script_key}, and no log file. Cannot kill.")
    except Exception as e:
        logger.error(f"❌ Unexpected error killing process tree for PID {pid or 'N/A'} ({script_key}): {e}", exc_info=True)

def attempt_install_pip(module_name, reply_target, manual_request=False):
    """Install Python package via pip"""
    package_name = TELEGRAM_MODULES.get(module_name.lower(), module_name) 
    chat_id = resolve_chat_id(reply_target)
    if package_name is None: 
        logger.info(f"Module '{module_name}' is core. Skipping pip install.")
        return False, "Core module - no installation needed"
    
    try:
        if manual_request:
            bot.send_message(chat_id, f"🔄 Manual installation requested for `{module_name}` -> `{package_name}`...", parse_mode='Markdown')
        else:
            bot.send_message(chat_id, f"🐍 Module `{module_name}` not found. Installing `{package_name}`...", parse_mode='Markdown')
        
        command = [sys.executable, '-m', 'pip', 'install', package_name]
        logger.info(f"Running install: {' '.join(command)}")
        result = subprocess.run(command, capture_output=True, text=True, check=False, encoding='utf-8', errors='ignore')
        
        if result.returncode == 0:
            log_msg = f"Installed {package_name}. Output:\n{result.stdout}"
            logger.info(log_msg)
            success_msg = f"✅ Package `{package_name}` (for `{module_name}`) installed successfully."
            bot.send_message(chat_id, success_msg, parse_mode='Markdown')
            save_install_log(chat_id, module_name, package_name, "success", log_msg)
            return True, log_msg
        else:
            error_msg = f"❌ Failed to install `{package_name}` for `{module_name}`.\nLog:\n```\n{result.stderr or result.stdout}\n```"
            logger.error(error_msg)
            if len(error_msg) > 3800: error_msg = error_msg[:3800] + "\n... (Log truncated)"
            bot.send_message(chat_id, error_msg, parse_mode='Markdown')
            save_install_log(chat_id, module_name, package_name, "failed", error_msg)
            return False, error_msg
    except Exception as e:
        error_msg = f"❌ Error installing `{package_name}`: {str(e)}"
        logger.error(error_msg, exc_info=True)
        bot.send_message(chat_id, error_msg)
        save_install_log(chat_id, module_name, package_name, "error", error_msg)
        return False, error_msg

def attempt_install_npm(module_name, user_folder, reply_target, manual_request=False):
    """Install Node package via npm"""
    chat_id = resolve_chat_id(reply_target)
    try:
        if manual_request:
            bot.send_message(chat_id, f"🔄 Manual Node package installation requested for `{module_name}`...", parse_mode='Markdown')
        else:
            bot.send_message(chat_id, f"🟠 Node package `{module_name}` not found. Installing locally...", parse_mode='Markdown')
        
        command = ['npm', 'install', module_name]
        logger.info(f"Running npm install: {' '.join(command)} in {user_folder}")
        result = subprocess.run(command, capture_output=True, text=True, check=False, cwd=user_folder, encoding='utf-8', errors='ignore')
        
        if result.returncode == 0:
            log_msg = f"Installed {module_name}. Output:\n{result.stdout}"
            logger.info(log_msg)
            success_msg = f"✅ Node package `{module_name}` installed locally."
            bot.send_message(chat_id, success_msg, parse_mode='Markdown')
            save_install_log(chat_id, module_name, module_name, "success", log_msg)
            return True, log_msg
        else:
            error_msg = f"❌ Failed to install Node package `{module_name}`.\nLog:\n```\n{result.stderr or result.stdout}\n```"
            logger.error(error_msg)
            if len(error_msg) > 3800: error_msg = error_msg[:3800] + "\n... (Log truncated)"
            bot.send_message(chat_id, error_msg, parse_mode='Markdown')
            save_install_log(chat_id, module_name, module_name, "failed", error_msg)
            return False, error_msg
    except FileNotFoundError:
         error_msg = "❌ Error: 'npm' not found. Ensure Node.js/npm are installed and in PATH."
         logger.error(error_msg)
         bot.send_message(chat_id, error_msg)
         save_install_log(chat_id, module_name, module_name, "error", error_msg)
         return False, error_msg
    except Exception as e:
         error_msg = f"❌ Error installing Node package `{module_name}`: {str(e)}"
         logger.error(error_msg, exc_info=True)
         bot.send_message(chat_id, error_msg)
         save_install_log(chat_id, module_name, module_name, "error", error_msg)
         return False, error_msg

def run_script(script_path, script_owner_id, user_folder, file_name, reply_target, attempt=1):
    """Run Python script. Fixes Bug #4 by directly resolving the owner's chat_id to route outputs correctly."""
    max_attempts = 2 
    if attempt > max_attempts:
        # Route startup messages always to the actual script owner's chat
        bot.send_message(script_owner_id, f"❌ Failed to run '{file_name}' after {max_attempts} attempts. Check logs.")
        return

    script_key = f"{script_owner_id}_{file_name}"
    logger.info(f"Attempt {attempt} to run Python script: {script_path} (Key: {script_key}) for user {script_owner_id}")

    # Always route notifications to the owner's chat_id (Fixes Bug #4)
    target_chat_id = script_owner_id

    try:
        if not os.path.exists(script_path):
             bot.send_message(target_chat_id, f"❌ Error: Script '{file_name}' not found at '{script_path}'!")
             logger.error(f"Script not found: {script_path} for user {script_owner_id}")
             if script_owner_id in state.user_files:
                 state.user_files[script_owner_id] = [f for f in state.user_files.get(script_owner_id, []) if f[0] != file_name]
             remove_user_file_db(script_owner_id, file_name)
             return

        # Auto-install missing Python dependencies statically (Fixes No requirements.txt Dependency Fallback)
        try:
            logger.info(f"Statically scanning {file_name} for Python dependencies...")
            detected_deps = extract_imports(script_path)
            non_core_deps = [d for d in detected_deps if d not in STD_LIB_MODULES]
            if non_core_deps:
                logger.info(f"Found non-core Python dependencies to verify: {non_core_deps}")
                for dep in non_core_deps:
                    attempt_install_pip(dep, target_chat_id)
        except Exception as scan_e:
            logger.error(f"Error statically auto-installing Python deps: {scan_e}")

        if attempt == 1:
            check_command = [sys.executable, script_path]
            logger.info(f"Running Python pre-check: {' '.join(check_command)}")
            check_proc = None
            try:
                check_proc = subprocess.Popen(check_command, cwd=user_folder, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='ignore')
                stdout, stderr = check_proc.communicate(timeout=5)
                return_code = check_proc.returncode
                logger.info(f"Python Pre-check early. RC: {return_code}. Stderr: {stderr[:200]}...")
                if return_code != 0 and stderr:
                    match_py = re.search(r"ModuleNotFoundError: No module named '(.+?)'", stderr)
                    if match_py:
                        module_name = match_py.group(1).strip().strip("'\"")
                        logger.info(f"Detected missing Python module: {module_name}")
                        success, _ = attempt_install_pip(module_name, target_chat_id)
                        if success:
                            logger.info(f"Install OK for {module_name}. Retrying run_script...")
                            bot.send_message(target_chat_id, f"🔄 Install successful. Retrying '{file_name}'...")
                            time.sleep(2)
                            threading.Thread(target=run_script, args=(script_path, script_owner_id, user_folder, file_name, target_chat_id, attempt + 1)).start()
                            return
                        else:
                            bot.send_message(target_chat_id, f"❌ Install failed. Cannot run '{file_name}'.")
                            return
                    else:
                         error_summary = stderr[:500]
                         bot.send_message(target_chat_id, f"❌ Error in script pre-check for '{file_name}':\n```\n{error_summary}\n```\nFix the script.", parse_mode='Markdown')
                         return
            except subprocess.TimeoutExpired:
                logger.info("Python Pre-check timed out (>5s), imports likely OK. Killing check process.")
                if check_proc and check_proc.poll() is None: check_proc.kill(); check_proc.communicate()
                logger.info("Python Check process killed. Proceeding to long run.")
            except FileNotFoundError:
                 logger.error(f"Python interpreter not found: {sys.executable}")
                 bot.send_message(target_chat_id, f"❌ Error: Python interpreter '{sys.executable}' not found.")
                 return
            except Exception as e:
                 logger.error(f"Error in Python pre-check for {script_key}: {e}", exc_info=True)
                 bot.send_message(target_chat_id, f"❌ Unexpected error in script pre-check for '{file_name}': {e}")
                 return
            finally:
                 if check_proc and check_proc.poll() is None:
                     logger.warning(f"Python Check process {check_proc.pid} still running. Killing.")
                     check_proc.kill(); check_proc.communicate()

        logger.info(f"Starting long-running Python process for {script_key}")
        log_file_path = os.path.join(user_folder, f"{os.path.splitext(file_name)[0]}.log")
        log_file = None; process = None
        try: log_file = open(log_file_path, 'w', encoding='utf-8', errors='ignore')
        except Exception as e:
             logger.error(f"Failed to open log file '{log_file_path}' for {script_key}: {e}", exc_info=True)
             bot.send_message(target_chat_id, f"❌ Failed to open log file '{log_file_path}': {e}")
             return
        try:
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
            state.bot_scripts[script_key] = {
                'process': process, 'log_file': log_file, 'file_name': file_name,
                'chat_id': target_chat_id, 
                'script_owner_id': script_owner_id, 
                'start_time': datetime.now(), 'user_folder': user_folder, 'type': 'py', 'script_key': script_key
            }
            bot.send_message(target_chat_id, f"✅ Python script '{file_name}' started! (PID: {process.pid})")
        except FileNotFoundError:
             logger.error(f"Python interpreter {sys.executable} not found for long run {script_key}")
             bot.send_message(target_chat_id, f"❌ Error: Python interpreter '{sys.executable}' not found.")
             if log_file and not log_file.closed: log_file.close()
             if script_key in state.bot_scripts: del state.bot_scripts[script_key]
        except Exception as e:
            if log_file and not log_file.closed: log_file.close()
            error_msg = f"❌ Error starting Python script '{file_name}': {str(e)}"
            logger.error(error_msg, exc_info=True)
            bot.send_message(target_chat_id, error_msg)
            if process and process.poll() is None:
                 logger.warning(f"Killing potentially started Python process {process.pid} for {script_key}")
                 kill_process_tree({'process': process, 'log_file': log_file, 'script_key': script_key})
            if script_key in state.bot_scripts: del state.bot_scripts[script_key]
    except Exception as e:
        error_msg = f"❌ Unexpected error running Python script '{file_name}': {str(e)}"
        logger.error(error_msg, exc_info=True)
        bot.send_message(target_chat_id, error_msg)
        if script_key in state.bot_scripts:
             logger.warning(f"Cleaning up {script_key} due to error in run_script.")
             kill_process_tree(state.bot_scripts[script_key])
             del state.bot_scripts[script_key]

def run_js_script(script_path, script_owner_id, user_folder, file_name, reply_target, attempt=1):
    """Run JS script. Fixes Bug #4 by directly resolving the owner's chat_id to route outputs correctly."""
    max_attempts = 2
    if attempt > max_attempts:
        # Route startup messages always to the actual script owner's chat
        bot.send_message(script_owner_id, f"❌ Failed to run '{file_name}' after {max_attempts} attempts. Check logs.")
        return

    script_key = f"{script_owner_id}_{file_name}"
    logger.info(f"Attempt {attempt} to run JS script: {script_path} (Key: {script_key}) for user {script_owner_id}")

    # Always route notifications to the owner's chat_id (Fixes Bug #4)
    target_chat_id = script_owner_id

    try:
        if not os.path.exists(script_path):
             bot.send_message(target_chat_id, f"❌ Error: Script '{file_name}' not found at '{script_path}'!")
             logger.error(f"JS Script not found: {script_path} for user {script_owner_id}")
             if script_owner_id in state.user_files:
                 state.user_files[script_owner_id] = [f for f in state.user_files.get(script_owner_id, []) if f[0] != file_name]
             remove_user_file_db(script_owner_id, file_name)
             return

        # Auto-install missing JS dependencies statically (Fixes No package.json Dependency Fallback)
        try:
            logger.info(f"Statically scanning {file_name} for Node.js dependencies...")
            detected_deps = extract_js_imports(script_path)
            non_core_deps = [d for d in detected_deps if d not in JS_CORE_MODULES]
            if non_core_deps:
                logger.info(f"Found non-core Node.js dependencies to verify: {non_core_deps}")
                for dep in non_core_deps:
                    attempt_install_npm(dep, user_folder, target_chat_id)
        except Exception as scan_e:
            logger.error(f"Error statically auto-installing JS deps: {scan_e}")

        if attempt == 1:
            check_command = ['node', script_path]
            logger.info(f"Running JS pre-check: {' '.join(check_command)}")
            check_proc = None
            try:
                check_proc = subprocess.Popen(check_command, cwd=user_folder, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='ignore')
                stdout, stderr = check_proc.communicate(timeout=5)
                return_code = check_proc.returncode
                logger.info(f"JS Pre-check early. RC: {return_code}. Stderr: {stderr[:200]}...")
                if return_code != 0 and stderr:
                    match_js = re.search(r"Cannot find module '(.+?)'", stderr)
                    if match_js:
                        module_name = match_js.group(1).strip().strip("'\"")
                        if not module_name.startswith('.') and not module_name.startswith('/'):
                             logger.info(f"Detected missing Node module: {module_name}")
                             success, _ = attempt_install_npm(module_name, user_folder, target_chat_id)
                             if success:
                                 logger.info(f"NPM Install OK for {module_name}. Retrying run_js_script...")
                                 bot.send_message(target_chat_id, f"🔄 NPM Install successful. Retrying '{file_name}'...")
                                 time.sleep(2)
                                 threading.Thread(target=run_js_script, args=(script_path, script_owner_id, user_folder, file_name, target_chat_id, attempt + 1)).start()
                                 return
                             else:
                                 bot.send_message(target_chat_id, f"❌ NPM Install failed. Cannot run '{file_name}'.")
                                 return
                        else: logger.info(f"Skipping npm install for relative/core: {module_name}")
                    error_summary = stderr[:500]
                    bot.send_message(target_chat_id, f"❌ Error in JS script pre-check for '{file_name}':\n```\n{error_summary}\n```\nFix script or install manually.", parse_mode='Markdown')
                    return
            except subprocess.TimeoutExpired:
                logger.info("JS Pre-check timed out (>5s), imports likely OK. Killing check process.")
                if check_proc and check_proc.poll() is None: check_proc.kill(); check_proc.communicate()
                logger.info("JS Check process killed. Proceeding to long run.")
            except FileNotFoundError:
                 error_msg = "❌ Error: 'node' not found. Ensure Node.js is installed for JS files."
                 logger.error(error_msg)
                 bot.send_message(target_chat_id, error_msg)
                 return
            except Exception as e:
                 logger.error(f"Error in JS pre-check for {script_key}: {e}", exc_info=True)
                 bot.send_message(target_chat_id, f"❌ Unexpected error in JS pre-check for '{file_name}': {e}")
                 return
            finally:
                 if check_proc and check_proc.poll() is None:
                     logger.warning(f"JS Check process {check_proc.pid} still running. Killing.")
                     check_proc.kill(); check_proc.communicate()

        logger.info(f"Starting long-running JS process for {script_key}")
        log_file_path = os.path.join(user_folder, f"{os.path.splitext(file_name)[0]}.log")
        log_file = None; process = None
        try: log_file = open(log_file_path, 'w', encoding='utf-8', errors='ignore')
        except Exception as e:
            logger.error(f"Failed to open log file '{log_file_path}' for JS script {script_key}: {e}", exc_info=True)
            bot.send_message(target_chat_id, f"❌ Failed to open log file '{log_file_path}': {e}")
            return
        try:
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
            state.bot_scripts[script_key] = {
                'process': process, 'log_file': log_file, 'file_name': file_name,
                'chat_id': target_chat_id, 
                'script_owner_id': script_owner_id, 
                'start_time': datetime.now(), 'user_folder': user_folder, 'type': 'js', 'script_key': script_key
            }
            bot.send_message(target_chat_id, f"✅ JS script '{file_name}' started! (PID: {process.pid})")
        except FileNotFoundError:
             error_msg = "❌ Error: 'node' not found for long run. Ensure Node.js is installed."
             logger.error(error_msg)
             if log_file and not log_file.closed: log_file.close()
             bot.send_message(target_chat_id, error_msg)
             if script_key in state.bot_scripts: del state.bot_scripts[script_key]
        except Exception as e:
            if log_file and not log_file.closed: log_file.close()
            error_msg = f"❌ Error starting JS script '{file_name}': {str(e)}"
            logger.error(error_msg, exc_info=True)
            bot.send_message(target_chat_id, error_msg)
            if process and process.poll() is None:
                 logger.warning(f"Killing potentially started JS process {process.pid} for {script_key}")
                 kill_process_tree({'process': process, 'log_file': log_file, 'script_key': script_key})
            if script_key in state.bot_scripts: del state.bot_scripts[script_key]
    except Exception as e:
        error_msg = f"❌ Unexpected error running JS script '{file_name}': {str(e)}"
        logger.error(error_msg, exc_info=True)
        bot.send_message(target_chat_id, error_msg)
        if script_key in state.bot_scripts:
             logger.warning(f"Cleaning up {script_key} due to error in run_js_script.")
             kill_process_tree(state.bot_scripts[script_key])
             del state.bot_scripts[script_key]

def process_zip_file(zip_path, user_id, user_folder, file_name_zip, reply_message_obj, temp_dir=None):
    """Process ZIP file extraction and setup"""
    cleanup_temp = False
    if temp_dir is None:
        temp_dir = tempfile.mkdtemp(prefix=f"user_{user_id}_zip_")
        cleanup_temp = True
        
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            # Check for safe paths
            for member in zip_ref.infolist():
                member_path = os.path.abspath(os.path.join(temp_dir, member.filename))
                if not member_path.startswith(os.path.abspath(temp_dir)):
                    raise zipfile.BadZipFile(f"Zip has unsafe path: {member.filename}")
            zip_ref.extractall(temp_dir)
            logger.info(f"Extracted zip to {temp_dir}")

        extracted_items = os.listdir(temp_dir)
        py_files = [f for f in extracted_items if f.endswith('.py')]
        js_files = [f for f in extracted_items if f.endswith('.js')]
        req_file = 'requirements.txt' if 'requirements.txt' in extracted_items else None
        pkg_json = 'package.json' if 'package.json' in extracted_items else None

        # Resolve actual script owner's chat_id
        chat_id = user_id

        if req_file:
            req_path = os.path.join(temp_dir, req_file)
            logger.info(f"requirements.txt found, installing: {req_path}")
            bot.send_message(chat_id, f"🔄 Installing Python deps from `{req_file}`...")
            try:
                command = [sys.executable, '-m', 'pip', 'install', '-r', req_path]
                result = subprocess.run(command, capture_output=True, text=True, check=True, encoding='utf-8', errors='ignore')
                logger.info(f"pip install from requirements.txt OK. Output:\n{result.stdout}")
                bot.send_message(chat_id, f"✅ Python deps from `{req_file}` installed.")
            except subprocess.CalledProcessError as e:
                error_msg = f"❌ Failed to install Python deps from `{req_file}`.\nLog:\n```\n{e.stderr or e.stdout}\n```"
                logger.error(error_msg)
                if len(error_msg) > 3800: error_msg = error_msg[:3800] + "\n... (Log truncated)"
                bot.send_message(chat_id, error_msg, parse_mode='Markdown')
                return
            except Exception as e:
                 error_msg = f"❌ Unexpected error installing Python deps: {e}"
                 logger.error(error_msg, exc_info=True)
                 bot.send_message(chat_id, error_msg)
                 return

        if pkg_json:
            logger.info(f"package.json found, npm install in: {temp_dir}")
            bot.send_message(chat_id, f"🔄 Installing Node deps from `{pkg_json}`...")
            try:
                command = ['npm', 'install']
                result = subprocess.run(command, capture_output=True, text=True, check=True, cwd=temp_dir, encoding='utf-8', errors='ignore')
                logger.info(f"npm install OK. Output:\n{result.stdout}")
                bot.send_message(chat_id, f"✅ Node deps from `{pkg_json}` installed.")
            except FileNotFoundError:
                bot.send_message(chat_id, "❌ 'npm' not found. Cannot install Node deps.")
                return 
            except subprocess.CalledProcessError as e:
                error_msg = f"❌ Failed to install Node deps from `{pkg_json}`.\nLog:\n```\n{e.stderr or e.stdout}\n```"
                logger.error(error_msg)
                if len(error_msg) > 3800: error_msg = error_msg[:3800] + "\n... (Log truncated)"
                bot.send_message(chat_id, error_msg, parse_mode='Markdown')
                return
            except Exception as e:
                 error_msg = f"❌ Unexpected error installing Node deps: {e}"
                 logger.error(error_msg, exc_info=True)
                 bot.send_message(chat_id, error_msg)
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
            bot.send_message(chat_id, "❌ No `.py` or `.js` script found in archive!")
            return

        logger.info(f"Moving extracted files from {temp_dir} to {user_folder}")
        moved_count = 0
        for item_name in os.listdir(temp_dir):
            src_path = os.path.join(temp_dir, item_name)
            dest_path = os.path.join(user_folder, item_name)
            
            # Fix Bug #5: skip moving the original ZIP file itself to avoid wasting storage
            if item_name == file_name_zip:
                continue
                
            if os.path.isdir(dest_path): shutil.rmtree(dest_path)
            elif os.path.exists(dest_path): os.remove(dest_path)
            shutil.move(src_path, dest_path)
            moved_count += 1
        logger.info(f"Moved {moved_count} items to {user_folder}")

        save_user_file(user_id, main_script_name, file_type)
        logger.info(f"Saved main script '{main_script_name}' ({file_type}) for {user_id} from zip.")
        main_script_path = os.path.join(user_folder, main_script_name)
        bot.send_message(chat_id, f"✅ Files extracted. Starting main script: `{main_script_name}`...", parse_mode='Markdown')

        # Use user_id for script key context and reply directly to user
        if file_type == 'py':
             threading.Thread(target=run_script, args=(main_script_path, user_id, user_folder, main_script_name, chat_id)).start()
        elif file_type == 'js':
             threading.Thread(target=run_js_script, args=(main_script_path, user_id, user_folder, main_script_name, chat_id)).start()
             
    except Exception as e:
        logger.error(f"Error processing zip file: {e}", exc_info=True)
        bot.send_message(user_id, f"❌ Error processing zip: {str(e)}")
    finally:
        if cleanup_temp and temp_dir and os.path.exists(temp_dir):
            try: 
                shutil.rmtree(temp_dir)
                logger.info(f"Cleaned temp dir: {temp_dir}")
            except Exception as e: 
                logger.error(f"Failed to clean temp dir {temp_dir}: {e}", exc_info=True)

# --- Active Watchdog Thread for Zombie & Crash Cleanup (Fixes Bug #1 & Auto-Restart Feature) ---
def start_watchdog_thread():
    def watchdog_loop():
        logger.info("👀 Watchdog thread started. Monitoring processes with Auto-Restart functionality...")
        while True:
            try:
                time.sleep(15) # Check every 15 seconds
                for script_key in list(state.bot_scripts.keys()):
                    script_info = state.bot_scripts.get(script_key)
                    if not script_info:
                        continue
                    
                    process = script_info.get('process')
                    if process:
                        # Check if process is dead
                        if process.poll() is not None:
                            logger.info(f"🚨 Watchdog detected stopped process: {script_key} (PID: {process.pid})")
                            
                            # Safely close log file
                            log_file = script_info.get('log_file')
                            if log_file and not log_file.closed:
                                try:
                                    log_file.close()
                                    logger.info(f"Closed log file for terminated script: {script_key}")
                                except Exception as log_e:
                                    logger.error(f"Error closing log file for {script_key}: {log_e}")
                            
                            chat_id = script_info.get('chat_id')
                            file_name = script_info.get('file_name', 'script')
                            script_owner_id = script_info.get('script_owner_id')
                            user_folder = script_info.get('user_folder')
                            script_type = script_info.get('type')
                            restarts = script_info.get('restarts', 0)
                            
                            # Check if Auto-Restart is toggled ON for this script
                            auto_restart_enabled = state.script_auto_restart.get(f"{script_owner_id}_{file_name}", False)
                            
                            if auto_restart_enabled:
                                if restarts < 3:
                                    restarts += 1
                                    script_path = os.path.join(user_folder, file_name)
                                    logger.warning(f"🔄 Auto-Restarting dead process {script_key} (Attempt {restarts}/3)...")
                                    
                                    # Trigger run in a background thread
                                    if script_type == 'py':
                                        threading.Thread(target=run_script, args=(script_path, script_owner_id, user_folder, file_name, chat_id)).start()
                                    elif script_type == 'js':
                                        threading.Thread(target=run_js_script, args=(script_path, script_owner_id, user_folder, file_name, chat_id)).start()
                                        
                                    # Tiny sleep to let it register in bot_scripts
                                    time.sleep(1.0)
                                    if script_key in state.bot_scripts:
                                        state.bot_scripts[script_key]['restarts'] = restarts
                                        
                                    try:
                                        bot.send_message(chat_id, f"🔄 **Auto-Restart (Attempt {restarts}/3)**: Your script `{file_name}` stopped (Exit Code: {process.returncode}) but has been automatically restarted!", parse_mode='Markdown')
                                    except Exception as notify_e:
                                        logger.error(f"Failed to notify user {chat_id} about auto-restart: {notify_e}")
                                    continue
                                else:
                                    logger.warning(f"❌ Auto-Restart failed for {script_key} after 3 attempts.")
                                    try:
                                        bot.send_message(chat_id, f"⚠️ **Auto-Restart Failed**: Your script `{file_name}` crashed 3 consecutive times. Auto-restart disabled for stability. Please fix any bugs and start manually.", parse_mode='Markdown')
                                    except Exception as notify_e:
                                        logger.error(f"Failed to notify user {chat_id} about auto-restart failure: {notify_e}")
                            else:
                                # Normal notification without restart
                                try:
                                    bot.send_message(chat_id, f"⚠️ **Alert**: Your script `{file_name}` has stopped running (Exit Code: {process.returncode}).", parse_mode='Markdown')
                                except Exception as notify_e:
                                    logger.error(f"Failed to notify user {chat_id} about stop: {notify_e}")
                                
                            # Delete from running cache
                            if script_key in state.bot_scripts:
                                del state.bot_scripts[script_key]
            except Exception as e:
                logger.error(f"Error in watchdog loop: {e}", exc_info=True)
                
    watchdog = threading.Thread(target=watchdog_loop)
    watchdog.daemon = True
    watchdog.start()
