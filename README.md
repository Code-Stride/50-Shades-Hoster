# 🚀 50 Shades Hoster

A highly optimized, modular, and robust Telegram Bot Hosting Platform built using Python (`pyTelegramBotAPI`). It allows users to upload, host, and run Python (`.py`) and Node.js (`.js`) scripts directly on your server with automatic dependency installations, real-time logging, active background watchdog monitoring, and cutting-edge **Telegram Bot API 9.4** colored action buttons!

---

## ✨ Features

- ⚙️ **Multi-Language Support**: Host Python (`.py`) and JavaScript (`.js` via Node.js) scripts seamlessly.
- 📦 **Auto Dependency Installer**: Automatically detects missing imports and runs `pip install` or `npm install` on the fly.
- 🚨 **Zombie/Crash Watchdog**: Background watchdog thread monitors running processes. If a script stops or crashes, it automatically frees up resources (closes log file descriptors, reaps zombie PIDs) and sends a proactive alert to the script owner's private chat.
- 🎨 **Bot API 9.4 Button Styles**: Uses the latest Telegram styles (`danger`, `success`, `primary`) for highly polished, visual interfaces.
- 🔒 **Resilient Security Scanning**: Safe, double-checked, and non-redundant scanning of single script files and ZIP archives.
- 🛡️ **Bypassing Mandatory Lockouts**: Bypasses mandatory sub check if the bot lacks admin permissions in a configured channel—keeping users active and preventing system lockout.
- 💾 **No Storage Waste**: Deletes temporary ZIP archives once extraction is successfully completed.
- 🔌 **Web Dashboard & IDE**: A fully featured, highly secure, and gorgeous dark-mode Web Portal. Log in anonymously using your User ID and Hash Key to manage files, upload codes via drag-and-drop, view/edit script logs, and edit code in real-time with an in-browser IDE!
- 🔌 **Flask Keep-Alive**: Included keep-alive endpoint for cloud platforms to ensure 24/7 uptime.

---

## 🛠️ Configuration Parameters

Rename `example.env` to `.env` and configure the following:

| Variable | Required | Description |
| :--- | :---: | :--- |
| `BOT_TOKEN` | **Yes** | Your Telegram Bot token from [@BotFather](https://t.me/BotFather). |
| `OWNER_ID` | **Yes** | Your Telegram User ID (Get from [@userinfobot](https://t.me/userinfobot)). |
| `ADMIN_ID` | No | Optional Admin User ID (Defaults to `OWNER_ID` if empty). |
| `YOUR_USERNAME` | No | Optional. Your Telegram Username without `@` (e.g. `BlazeNXT`). |
| `UPDATE_CHANNEL` | No | Optional. Channel Username for mandatory subscription check without `@`. |
| `PORT` | No | Keep-Alive server port (defaults to `8080`). |

---

## 🚀 One-Click Cloud Deployments

We provide pre-configured templates for seamless deployment to your favorite cloud platforms:

### 1. 🚄 Railway Deployment
Railway will automatically detect our `railway.json` and `Procfile`.
- Connect your GitHub repository to [Railway](https://railway.app/).
- Add your variables (`BOT_TOKEN`, `OWNER_ID`) in the Railway variables tab.
- Click **Deploy**!

### 2. 🌌 Render Deployment
Render will use our `render.yaml` Blueprint definition.
- Go to [Render](https://render.com/) and create a **Blueprints** service.
- Connect this GitHub repository.
- Provide values for the environment variables and deploy.

### 3. 🟣 Heroku Deployment
Heroku uses our `app.json` and `Procfile`.
- Create a new app on Heroku.
- Add the required config vars in the **Settings** tab.
- Connect your GitHub repo and click **Deploy Branch**.

---

## 💻 Local Run Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/Code-Stride/50-Shades-Hoster.git
   cd 50-Shades-Hoster
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Set up environment:
   ```bash
   cp example.env .env
   # Edit .env with your favorite editor and configure values.
   ```
4. Start the bot:
   ```bash
   python test.py
   ```

---

## 📂 Codebase Architecture (Modular Breakdown)

- `test.py`: Backwards-compatible startup wrapper.
- `main.py`: Main entry point that sets up, initializes, and spins up the bot.
- `config.py`: Environment loader and centralized constant settings.
- `state.py`: Centralized in-memory shared caches across different threads.
- `bot_instance.py`: Singleton bot initialization to prevent circular imports.
- `database.py`: Fully locked and thread-safe database handling routines.
- `security.py`: Consolidated, highly polished code and ZIP malware checking rules.
- `process_manager.py`: Runs and stops scripts, installs packages, and runs the Watchdog thread.
- `handlers.py`: Controls reply keyboards, inline queries, and button actions.

---

### 🛡️ Contribution Credits
All optimizations and refactoring contributions are designed and maintained with care.
Designed for **BlazeNXT** as part of open source contribution.
