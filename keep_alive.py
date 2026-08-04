# -*- coding: utf-8 -*-
import os
import sys
import hashlib
import shutil
import logging
from datetime import datetime
from flask import Flask, request, redirect, url_for, render_template_string, session, jsonify, send_from_directory, Response

logger = logging.getLogger(__name__)

app = Flask('')
# Secret key for encrypting Flask session cookies (Fixes Session Persistence)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "50_shades_hoster_ultimate_secret_key_123456789")

# Directory configurations
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_BOTS_DIR = os.path.join(BASE_DIR, 'upload_bots')

# --- Anonymity Hashing Logic ---
def get_user_hash(user_id):
    return hashlib.sha256(str(user_id).encode('utf-8')).hexdigest()[:16]

def get_user_folder_by_id(user_id):
    user_hash = get_user_hash(user_id)
    folder = os.path.join(UPLOAD_BOTS_DIR, user_hash)
    os.makedirs(folder, exist_ok=True)
    return folder

# --- Security Path Verification ---
def is_safe_path(base_dir, path):
    return os.path.abspath(path).startswith(os.path.abspath(base_dir))

# =====================================================================
# 🎭 HTML/CSS/JS WEBPAGE TEMPLATES (EMBEDDED FOR 100% PRODUCTION RELIABILITY)
# =====================================================================

LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🎭 50 Shades Hoster - Web Login</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        body {
            background-color: #0f172a;
            background-image: radial-gradient(at 50% 50%, rgba(16, 185, 129, 0.05) 0, transparent 50%);
        }
        .neon-shadow {
            box-shadow: 0 0 20px rgba(16, 185, 129, 0.2);
        }
    </style>
</head>
<body class="min-h-screen flex items-center justify-center text-slate-100 p-4">
    <div class="w-full max-w-md bg-slate-900 border border-emerald-500/20 rounded-2xl p-8 neon-shadow">
        <div class="text-center mb-8">
            <h1 class="text-3xl font-extrabold text-emerald-400 mb-2 tracking-tight">🎭 50 Shades Hoster</h1>
            <p class="text-slate-400 text-sm">Secure & Anonymous Web File Manager</p>
        </div>

        {% if error %}
        <div class="mb-6 bg-red-950/40 border border-red-500/30 text-red-300 text-sm rounded-lg p-4 flex items-center gap-3">
            <i class="fa-solid fa-triangle-exclamation"></i>
            <span>{{ error }}</span>
        </div>
        {% endif %}

        <form action="/login" method="POST" class="space-y-6">
            <div>
                <label class="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">Telegram User ID</label>
                <div class="relative">
                    <span class="absolute inset-y-0 left-0 pl-3 flex items-center text-slate-500">
                        <i class="fa-solid fa-user"></i>
                    </span>
                    <input type="number" name="user_id" required placeholder="e.g. 12345678"
                        class="w-full pl-10 pr-4 py-3 bg-slate-950 border border-slate-800 rounded-xl focus:outline-none focus:border-emerald-500 text-slate-100 transition-colors">
                </div>
            </div>

            <div>
                <label class="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">Anonymous Hash Key</label>
                <div class="relative">
                    <span class="absolute inset-y-0 left-0 pl-3 flex items-center text-slate-500">
                        <i class="fa-solid fa-key"></i>
                    </span>
                    <input type="text" name="hash_key" required placeholder="16-character key from /start"
                        class="w-full pl-10 pr-4 py-3 bg-slate-950 border border-slate-800 rounded-xl focus:outline-none focus:border-emerald-500 text-slate-100 transition-colors">
                </div>
            </div>

            <button type="submit"
                class="w-full bg-emerald-500 hover:bg-emerald-600 active:scale-[0.98] text-slate-950 font-bold py-3 px-4 rounded-xl transition-all duration-150 shadow-lg shadow-emerald-500/20 flex items-center justify-center gap-2">
                <i class="fa-solid fa-arrow-right-to-bracket"></i>
                <span>Sign In To Sandbox</span>
            </button>
        </form>

        <div class="mt-8 text-center border-t border-slate-800/60 pt-6">
            <p class="text-xs text-slate-500">Get your credentials by running <code class="bg-slate-950 text-emerald-400 px-2 py-1 rounded">/start</code> inside the Telegram Bot.</p>
        </div>
    </div>
</body>
</html>
"""

DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🎭 50 Shades Hoster - Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        body {
            background-color: #0b0f19;
        }
        ::-webkit-scrollbar {
            width: 8px;
        }
        ::-webkit-scrollbar-track {
            background: #0f172a;
        }
        ::-webkit-scrollbar-thumb {
            background: #1e293b;
            border-radius: 4px;
        }
        ::-webkit-scrollbar-thumb:hover {
            background: #334155;
        }
    </style>
</head>
<body class="min-h-screen text-slate-100 flex flex-col font-sans">
    <!-- Navbar -->
    <nav class="bg-slate-900/90 border-b border-slate-800/80 sticky top-0 backdrop-blur-md z-40">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div class="flex items-center justify-between h-16">
                <div class="flex items-center gap-3">
                    <span class="text-emerald-400 text-2xl"><i class="fa-solid fa-server"></i></span>
                    <span class="font-extrabold text-xl tracking-tight text-slate-100">50 Shades Hoster</span>
                    <span class="bg-emerald-500/10 text-emerald-400 text-xs px-2 py-0.5 rounded font-mono border border-emerald-400/20">Active</span>
                </div>
                <div class="flex items-center gap-6">
                    <div class="text-right hidden sm:block">
                        <p class="text-xs text-slate-400 font-mono">HASH PATH</p>
                        <p class="text-sm font-bold text-slate-200 font-mono">{{ user_hash }}</p>
                    </div>
                    <a href="/logout" class="bg-slate-800 hover:bg-red-950/40 border border-slate-700/50 hover:border-red-500/30 text-slate-200 hover:text-red-300 px-4 py-2 rounded-xl text-sm font-semibold transition-all flex items-center gap-2">
                        <i class="fa-solid fa-power-off"></i>
                        <span>Log Out</span>
                    </a>
                </div>
            </div>
        </div>
    </nav>

    <!-- Content -->
    <main class="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 lg:p-8 space-y-6">
        <!-- Explorer Header -->
        <div class="bg-slate-900 border border-slate-800/80 rounded-2xl p-6 flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
                <h1 class="text-2xl font-bold text-slate-100">📂 Hashed Sandbox Explorer</h1>
                <p class="text-slate-400 text-sm mt-1">Manage files, upload new codes, download backups, or edit in real-time.</p>
            </div>
            
            <div class="flex flex-wrap items-center gap-3">
                <!-- Backup Download Button -->
                <a href="/api/backup" class="bg-emerald-500 hover:bg-emerald-600 text-slate-950 font-bold px-4 py-2.5 rounded-xl text-sm transition-all shadow-lg shadow-emerald-500/10 flex items-center gap-2">
                    <i class="fa-solid fa-file-zipper"></i>
                    <span>Download Backup (.zip)</span>
                </a>
            </div>
        </div>

        <!-- Main Workspace Grid -->
        <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <!-- Left 2 Columns: File List -->
            <div class="lg:col-span-2 space-y-6">
                <!-- File Manager Table Card -->
                <div class="bg-slate-900 border border-slate-800/80 rounded-2xl overflow-hidden">
                    <div class="px-6 py-4 border-b border-slate-800/80 flex items-center justify-between">
                        <h2 class="font-bold text-slate-200 flex items-center gap-2">
                            <i class="fa-solid fa-folder-open text-emerald-400"></i>
                            <span>Workspace Files</span>
                        </h2>
                        <span class="bg-slate-800 text-slate-400 text-xs px-2.5 py-1 rounded-full font-mono">{{ files|length }} files</span>
                    </div>

                    {% if files %}
                    <div class="overflow-x-auto">
                        <table class="w-full text-left border-collapse">
                            <thead>
                                <tr class="border-b border-slate-800/40 text-slate-400 text-xs font-semibold uppercase tracking-wider bg-slate-950/20">
                                    <th class="py-4 px-6">Name</th>
                                    <th class="py-4 px-6">Size</th>
                                    <th class="py-4 px-6">Last Modified</th>
                                    <th class="py-4 px-6 text-right">Actions</th>
                                </tr>
                            </thead>
                            <tbody class="divide-y divide-slate-800/40">
                                {% for f in files %}
                                <tr class="hover:bg-slate-800/20 transition-colors">
                                    <td class="py-4 px-6 font-semibold flex items-center gap-3">
                                        {% if f.name.endswith('.py') %}
                                        <i class="fa-brands fa-python text-yellow-500 text-lg"></i>
                                        {% elif f.name.endswith('.js') %}
                                        <i class="fa-brands fa-node-js text-emerald-500 text-lg"></i>
                                        {% else %}
                                        <i class="fa-solid fa-file text-slate-400 text-lg"></i>
                                        {% endif %}
                                        <span class="text-slate-200 tracking-tight truncate font-mono max-w-[200px]">{{ f.name }}</span>
                                    </td>
                                    <td class="py-4 px-6 text-sm text-slate-400 font-mono">{{ f.size_kb }} KB</td>
                                    <td class="py-4 px-6 text-sm text-slate-400 font-mono">{{ f.mtime }}</td>
                                    <td class="py-4 px-6 text-right">
                                        <div class="flex items-center justify-end gap-2">
                                            {% if f.name.endswith(('.py', '.js', '.txt', '.json', '.log')) %}
                                            <a href="/edit/{{ f.name }}" class="bg-slate-800 hover:bg-emerald-500/10 border border-slate-700/50 hover:border-emerald-500/30 text-slate-300 hover:text-emerald-400 p-2 rounded-lg text-xs font-semibold transition-all" title="Edit File">
                                                <i class="fa-solid fa-code"></i>
                                            </a>
                                            {% endif %}
                                            <a href="/api/download/{{ f.name }}" class="bg-slate-800 hover:bg-slate-700 p-2 rounded-lg text-xs text-slate-300 transition-all" title="Download">
                                                <i class="fa-solid fa-download"></i>
                                            </a>
                                            <button onclick="deleteFile('{{ f.name }}')" class="bg-slate-800 hover:bg-red-500/10 border border-slate-700/50 hover:border-red-500/30 text-slate-300 hover:text-red-400 p-2 rounded-lg text-xs font-semibold transition-all" title="Delete">
                                                <i class="fa-solid fa-trash-can"></i>
                                            </button>
                                        </div>
                                    </td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                    {% else %}
                    <div class="py-16 text-center text-slate-500">
                        <span class="text-5xl block mb-4"><i class="fa-solid fa-folder-open"></i></span>
                        <p class="text-sm">This hashed sandbox is currently empty.</p>
                        <p class="text-xs text-slate-600 mt-1">Upload a script or zip below to start hosting!</p>
                    </div>
                    {% endif %}
                </div>

                <!-- Live Log Monitor Terminal -->
                <div class="bg-slate-900 border border-slate-800/80 rounded-2xl overflow-hidden flex flex-col">
                    <div class="px-6 py-4 border-b border-slate-800/80 flex items-center justify-between bg-slate-950/20">
                        <h2 class="font-bold text-slate-200 flex items-center gap-2">
                            <i class="fa-solid fa-terminal text-emerald-400"></i>
                            <span>Live Script Log Monitor</span>
                        </h2>
                        <select id="log-selector" onchange="loadLog()" class="bg-slate-800 border border-slate-700/50 text-slate-300 rounded-lg px-3 py-1.5 text-xs font-mono focus:outline-none focus:border-emerald-500">
                            <option value="">-- Select log file --</option>
                            {% for f in files %}
                                {% if f.name.endswith('.log') %}
                                <option value="{{ f.name }}">{{ f.name }}</option>
                                {% endif %}
                            {% endfor %}
                        </select>
                    </div>
                    <div class="p-6 bg-slate-950 font-mono text-xs text-emerald-400 min-h-[220px] max-h-[350px] overflow-y-auto leading-relaxed" id="terminal-screen">
                        <p class="text-slate-500"># Click on the selector above to monitor running script logs in real-time...</p>
                    </div>
                </div>
            </div>

            <!-- Right Column: Drag & Drop Upload -->
            <div class="lg:col-span-1 space-y-6">
                <!-- Upload Box -->
                <div class="bg-slate-900 border border-slate-800/80 rounded-2xl p-6">
                    <h2 class="font-bold text-slate-200 mb-4 flex items-center gap-2">
                        <i class="fa-solid fa-cloud-arrow-up text-emerald-400"></i>
                        <span>Upload Script / Zip</span>
                    </h2>
                    
                    <div id="drop-zone" class="border-2 border-dashed border-slate-800 hover:border-emerald-500/50 rounded-2xl p-8 text-center transition-all bg-slate-950/25 flex flex-col items-center justify-center min-h-[200px]">
                        <span class="text-4xl text-slate-600 mb-3"><i class="fa-solid fa-cloud-arrow-up"></i></span>
                        <p class="text-sm font-semibold text-slate-300">Drag & Drop file here</p>
                        <p class="text-xs text-slate-500 mt-1">or click below to browse</p>
                        
                        <input type="file" id="file-input" class="hidden" onchange="handleFileSelect()">
                        <button onclick="document.getElementById('file-input').click()" class="bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold px-4 py-2 rounded-lg mt-4 transition-all border border-slate-700/50">
                            Browse Files
                        </button>
                    </div>
                </div>

                <!-- Help Box -->
                <div class="bg-slate-900 border border-slate-800/80 rounded-2xl p-6 space-y-4 text-sm text-slate-400">
                    <h3 class="font-bold text-slate-200 flex items-center gap-2">
                        <i class="fa-solid fa-shield-halved text-emerald-400"></i>
                        <span>Sandbox Security Info</span>
                    </h3>
                    <p>🎭 Your absolute privacy is our core parameter. Hashed sandbox routes isolate your data completely from raw Telegram user credentials.</p>
                    <p>🔒 Standard path traversal checkers operate on the backend. Files uploaded outside the sandboxed region will be auto-deleted.</p>
                </div>
            </div>
        </div>
    </main>

    <script>
        function deleteFile(filename) {
            if (confirm("Are you sure you want to permanently delete '" + filename + "'?")) {
                fetch('/api/delete/' + filename, { method: 'POST' })
                    .then(res => res.json())
                    .then(data => {
                        if (data.success) {
                            location.reload();
                        } else {
                            alert("Error: " + data.message);
                        }
                    });
            }
        }

        function handleFileSelect() {
            const input = document.getElementById('file-input');
            if (input.files.length > 0) {
                uploadFile(input.files[0]);
            }
        }

        function uploadFile(file) {
            const formData = new FormData();
            formData.append('file', file);

            const dropZone = document.getElementById('drop-zone');
            dropZone.innerHTML = '<span class="text-4xl text-emerald-400 animate-pulse block mb-3"><i class="fa-solid fa-spinner animate-spin"></i></span><p class="text-sm font-semibold text-slate-300">Uploading ' + file.name + '...</p>';

            fetch('/api/upload', {
                method: 'POST',
                body: formData
            })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    location.reload();
                } else {
                    alert("Upload error: " + data.message);
                    location.reload();
                }
            });
        }

        function loadLog() {
            const selector = document.getElementById('log-selector');
            const screen = document.getElementById('terminal-screen');
            const filename = selector.value;

            if (!filename) {
                screen.innerHTML = '<p class="text-slate-500"># Click on the selector above to monitor running script logs in real-time...</p>';
                return;
            }

            fetch('/api/log/' + filename)
                .then(res => res.json())
                .then(data => {
                    if (data.success) {
                        screen.innerHTML = '<pre class="whitespace-pre-wrap">' + escapeHtml(data.content) + '</pre>';
                        screen.scrollTop = screen.scrollHeight;
                    } else {
                        screen.innerHTML = '<p class="text-red-400">❌ Error reading logs: ' + data.message + '</p>';
                    }
                });
        }

        function escapeHtml(text) {
            return text
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#039;");
        }

        // Set up drag and drop
        const dropZone = document.getElementById('drop-zone');
        
        ['dragenter', 'dragover'].forEach(eventName => {
            dropZone.addEventListener(eventName, e => {
                e.preventDefault();
                dropZone.classList.add('border-emerald-500', 'bg-emerald-500/5');
            }, false);
        });

        ['dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, e => {
                e.preventDefault();
                dropZone.classList.remove('border-emerald-500', 'bg-emerald-500/5');
            }, false);
        });

        dropZone.addEventListener('drop', e => {
            const dt = e.dataTransfer;
            const files = dt.files;
            if (files.length > 0) {
                uploadFile(files[0]);
            }
        });
    </script>
</body>
</html>
"""

EDIT_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🎭 Web IDE - Editing {{ filename }}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        body {
            background-color: #0b0f19;
        }
        .code-area {
            font-family: 'Fira Code', 'Courier New', Courier, monospace;
            background-color: #030712;
            color: #10b981;
        }
    </style>
</head>
<body class="min-h-screen text-slate-100 flex flex-col font-sans">
    <!-- Navbar -->
    <nav class="bg-slate-900 border-b border-slate-800 sticky top-0 z-40">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div class="flex items-center justify-between h-16">
                <div class="flex items-center gap-3">
                    <a href="/dashboard" class="text-slate-400 hover:text-slate-100 transition-colors text-lg" title="Back to Workspace">
                        <i class="fa-solid fa-arrow-left"></i>
                    </a>
                    <span class="text-slate-500">/</span>
                    <span class="font-mono text-sm font-bold text-slate-200">{{ filename }}</span>
                </div>
                <div class="flex items-center gap-3">
                    <button onclick="saveCode()" class="bg-emerald-500 hover:bg-emerald-600 text-slate-950 font-bold px-4 py-2 rounded-xl text-sm transition-all shadow-lg shadow-emerald-500/10 flex items-center gap-2">
                        <i class="fa-solid fa-floppy-disk"></i>
                        <span>Save Code</span>
                    </button>
                    <a href="/dashboard" class="bg-slate-800 hover:bg-slate-700 text-slate-200 px-4 py-2 rounded-xl text-sm font-semibold transition-all">
                        Cancel
                    </a>
                </div>
            </div>
        </div>
    </nav>

    <!-- Editor Workspace -->
    <main class="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 lg:p-8 flex flex-col">
        <div class="bg-slate-900 border border-slate-800/80 rounded-2xl overflow-hidden flex-1 flex flex-col">
            <div class="px-6 py-3 border-b border-slate-800/80 bg-slate-950/20 flex items-center justify-between text-xs text-slate-400">
                <span>Real-Time Code Editor (In-browser IDE)</span>
                <span id="save-status" class="text-slate-500">Unsaved changes...</span>
            </div>
            
            <textarea id="editor" class="flex-1 w-full code-area p-6 focus:outline-none resize-none leading-relaxed font-mono text-sm focus:ring-1 focus:ring-emerald-500" spellcheck="false">{{ content }}</textarea>
        </div>
    </main>

    <script>
        function saveCode() {
            const code = document.getElementById('editor').value;
            const status = document.getElementById('save-status');
            status.innerHTML = '<i class="fa-solid fa-spinner animate-spin"></i> Saving...';
            status.className = 'text-emerald-400';

            fetch('/api/save/{{ filename }}', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ code: code })
            })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    status.innerHTML = '💾 All changes saved!';
                    status.className = 'text-emerald-500 font-semibold';
                    setTimeout(() => {
                        status.innerHTML = 'Synced with server';
                        status.className = 'text-slate-500';
                    }, 2000);
                } else {
                    status.innerHTML = '❌ Error: ' + data.message;
                    status.className = 'text-red-400 font-semibold';
                }
            })
            .catch(err => {
                status.innerHTML = '❌ Network error';
                status.className = 'text-red-400 font-semibold';
            });
        }

        // Add support for Tab indent inside textarea
        document.getElementById('editor').addEventListener('keydown', function(e) {
            if (e.key === 'Tab') {
                e.preventDefault();
                var start = this.selectionStart;
                var end = this.selectionEnd;

                // set textarea value to: text before caret + tab + text after caret
                this.value = this.value.substring(0, start) + "    " + this.value.substring(end);

                // put caret at right position
                this.selectionStart = this.selectionEnd = start + 4;
            }
        });
    </script>
</body>
</html>
"""

# =====================================================================
# 🛠️ FLASK CONTROLLERS & SERVER ENDPOINTS
# =====================================================================

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user_id_str = request.form.get('user_id', '').strip()
        hash_key = request.form.get('hash_key', '').strip()
        
        if not user_id_str or not hash_key:
            return render_template_string(LOGIN_TEMPLATE, error="Both User ID and Hash Key are required!")
            
        try:
            user_id = int(user_id_str)
            # Verify the anonymous hash key
            expected_hash = get_user_hash(user_id)
            if hash_key == expected_hash:
                session['user_id'] = user_id
                session['user_hash'] = hash_key
                logger.info(f"Web Login successful for user_id {user_id}")
                return redirect(url_for('dashboard'))
            else:
                return render_template_string(LOGIN_TEMPLATE, error="❌ Incorrect credentials! Make sure to copy Hash Key exactly.")
        except ValueError:
            return render_template_string(LOGIN_TEMPLATE, error="❌ User ID must be a numeric integer!")
            
    return render_template_string(LOGIN_TEMPLATE, error=None)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    user_id = session['user_id']
    user_hash = session['user_hash']
    
    user_folder = get_user_folder_by_id(user_id)
    files_list = []
    
    for f in os.listdir(user_folder):
        file_path = os.path.join(user_folder, f)
        if os.path.isfile(file_path):
            size_kb = round(os.path.getsize(file_path) / 1024, 2)
            mtime = datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M')
            files_list.append({
                'name': f,
                'size_kb': size_kb,
                'mtime': mtime
            })
            
    return render_template_string(DASHBOARD_TEMPLATE, user_hash=user_hash, files=files_list)

@app.route('/edit/<filename>')
def edit_file(filename):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    user_id = session['user_id']
    user_folder = get_user_folder_by_id(user_id)
    file_path = os.path.join(user_folder, filename)
    
    if not is_safe_path(user_folder, file_path) or not os.path.exists(file_path):
        return "❌ Security Block: Access denied.", 403
        
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
        
    return render_template_string(EDIT_TEMPLATE, filename=filename, content=content)

# --- WEB PANEL JSON API CONTROLLERS ---

@app.route('/api/save/<filename>', methods=['POST'])
def api_save_file(filename):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Session expired!'}), 401
        
    user_id = session['user_id']
    user_folder = get_user_folder_by_id(user_id)
    file_path = os.path.join(user_folder, filename)
    
    if not is_safe_path(user_folder, file_path):
        return jsonify({'success': False, 'message': 'Path Traversal Blocked!'}), 403
        
    try:
        data = request.get_json()
        code_content = data.get('code', '')
        
        # Save edited content to disk
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(code_content)
            
        logger.warning(f"Web IDE: Saved file '{filename}' for user_id {user_id}")
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error saving file in Web IDE: {e}", exc_info=True)
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/delete/<filename>', methods=['POST'])
def api_delete_file(filename):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Session expired!'}), 401
        
    user_id = session['user_id']
    user_folder = get_user_folder_by_id(user_id)
    file_path = os.path.join(user_folder, filename)
    
    if not is_safe_path(user_folder, file_path) or not os.path.exists(file_path):
        return jsonify({'success': False, 'message': 'Access Denied!'}), 403
        
    try:
        os.remove(file_path)
        logger.info(f"Web IDE: Deleted file '{filename}' for user_id {user_id}")
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error deleting file in Web IDE: {e}", exc_info=True)
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/upload', methods=['POST'])
def api_upload_file():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Session expired!'}), 401
        
    user_id = session['user_id']
    user_folder = get_user_folder_by_id(user_id)
    
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file segment found!'}), 400
        
    uploaded_file = request.files['file']
    if uploaded_file.filename == '':
        return jsonify({'success': False, 'message': 'Empty filename!'}), 400
        
    try:
        file_path = os.path.join(user_folder, uploaded_file.filename)
        if not is_safe_path(user_folder, file_path):
            return jsonify({'success': False, 'message': 'Path Traversal Blocked!'}), 403
            
        uploaded_file.save(file_path)
        logger.info(f"Web IDE: Uploaded file '{uploaded_file.filename}' for user_id {user_id}")
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error uploading file in Web IDE: {e}", exc_info=True)
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/download/<filename>')
def api_download_file(filename):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    user_id = session['user_id']
    user_folder = get_user_folder_by_id(user_id)
    file_path = os.path.join(user_folder, filename)
    
    if not is_safe_path(user_folder, file_path) or not os.path.exists(file_path):
        return "Access Denied", 403
        
    return send_from_directory(user_folder, filename, as_attachment=True)

@app.route('/api/backup')
def api_download_backup():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    import zipfile
    import tempfile
    
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
                    
        # Send zip and register clean up on completion
        def generate_file():
            with open(zip_path, 'rb') as f:
                yield from f
            try:
                shutil.rmtree(temp_dir)
            except Exception as e:
                logger.error(f"Failed to delete temp web backup: {e}")
                
        return Response(generate_file(), mimetype='application/zip',
                        headers={'Content-Disposition': f'attachment; filename={zip_name}'})
    except Exception as e:
        logger.error(f"Error serving web zip backup: {e}", exc_info=True)
        return "Internal Error", 500

@app.route('/api/log/<filename>')
def api_view_log(filename):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Session expired!'}), 401
        
    user_id = session['user_id']
    user_folder = get_user_folder_by_id(user_id)
    file_path = os.path.join(user_folder, filename)
    
    if not is_safe_path(user_folder, file_path) or not os.path.exists(file_path):
        return jsonify({'success': False, 'message': 'Access Denied!'}), 403
        
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            # Read last 150 lines of logs
            lines = f.readlines()[-150:]
            content = "".join(lines)
            
        return jsonify({'success': True, 'content': content if content.strip() else "(Log empty)"})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# --- Flask Keep-Alive Server Thread Starter ---
def run_flask():
    try:
        port = int(os.environ.get("PORT", 8080))
        app.run(host='0.0.0.0', port=port)
    except OSError as e:
        logger.error(f"Flask Web Server bind error: {e}. Check port usage.")
    except Exception as e:
        logger.error(f"Flask Web Server error: {e}")

def keep_alive():
    from threading import Thread
    t = Thread(target=run_flask)
    t.daemon = True
    t.start()
    logger.info("🎭 Web IDE Panel & Keep-Alive Server initialized on background thread.")
