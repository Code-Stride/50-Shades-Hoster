# -*- coding: utf-8 -*-
import os
import logging
from flask import Flask
from threading import Thread

logger = logging.getLogger(__name__)

app = Flask('')

@app.route('/')
def home():
    return "POWERED-BY BLAZE NXT 🚀"

def run_flask():
    try:
        port = int(os.environ.get("PORT", 8080))
        app.run(host='0.0.0.0', port=port)
    except OSError as e:
        logger.error(f"Flask Keep-Alive port bind error: {e}. Check if port 8080 is already in use.")
    except Exception as e:
        logger.error(f"Flask Keep-Alive unexpected error: {e}")

def keep_alive():
    t = Thread(target=run_flask)
    t.daemon = True
    t.start()
    logger.info("Flask Keep-Alive server started in a background daemon thread.")
