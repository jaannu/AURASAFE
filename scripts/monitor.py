import time
import threading
import joblib
import numpy as np
import scapy.all as scapy
import xgboost as xgb
import pandas as pd
import self_heal
import sys
import os
import logging
import telebot

# 🔹 BotFather Telegram Bot Token
BOT_TOKEN = "7263544374:AAGDBQCjAPWruUpSDHlfUNP9nTdefyA4xnU"
bot = telebot.TeleBot(BOT_TOKEN)

# 🔹 Intrusion log file
LOG_FILE = "intrusion_logs.txt"

# 🔹 Set up logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s - %(message)s")

# 🔹 Load trained XGBoost model
MODEL_PATH = os.path.abspath("models/xgboost_intrusion_detection.json")

if os.path.exists(MODEL_PATH):
    model = xgb.XGBClassifier()
    model.load_model(MODEL_PATH)
    print("✅ Model Loaded Successfully!")
else:
    print(f"❌ Model file not found at {MODEL_PATH}")
    sys.exit(1)

# 🔹 Escape MarkdownV2 special characters
def escape_markdown(text):
    escape_chars = "_*[]()~`>#+-=|{}.!"
    return "".join(f"\\{char}" if char in escape_chars else char for char in text)

# 🔹 Extract network features
def extract_features(packet):
    return {
        "duration": 0,  # Placeholder (packet timing can be added)
        "protocol_type": packet.proto,
        "service": 1 if packet.haslayer(scapy.TCP) else 2 if packet.haslayer(scapy.UDP) else 3,
        "flag": 1 if packet.haslayer(scapy.IP) else 0,
        "src_bytes": len(packet),
        "dst_bytes": len(packet.payload),
        "land": 0,  # Placeholder (requires TCP session tracking)
        "wrong_fragment": 0,  # Placeholder (requires fragmentation analysis)
        "urgent": 0,  # Placeholder (check TCP urgent flag)
        "hot": 0,  # Placeholder
        "num_failed_logins": 0,
        "logged_in": 0,  
        "num_compromised": 0,
        "root_shell": 0,
        "su_attempted": 0,
        "num_root": 0,
        "num_file_creations": 0,
        "num_shells": 0,
        "num_access_files": 0,
        "num_outbound_cmds": 0,
        "is_host_login": 0,
        "is_guest_login": 0,
        "count": 0,  # Placeholder (requires windowed packet counting)
        "srv_count": 0,  
        "serror_rate": 0,  
        "srv_serror_rate": 0,  
        "rerror_rate": 0,  
        "srv_rerror_rate": 0,  
        "same_srv_rate": 0,  
        "diff_srv_rate": 0,  
        "srv_diff_host_rate": 0,  
        "dst_host_count": 0,  
        "dst_host_srv_count": 0,  
        "dst_host_same_srv_rate": 0,  
        "dst_host_diff_srv_rate": 0,  
        "dst_host_same_src_port_rate": 0,  
        "dst_host_srv_diff_host_rate": 0,  
        "dst_host_serror_rate": 0,  
        "dst_host_srv_serror_rate": 0,  
        "dst_host_rerror_rate": 0,  
        "dst_host_srv_rerror_rate": 0
    }



# 🔹 Admin Chat ID (Replace with your ID)
ADMIN_CHAT_ID = 6838941898

# 🔹 Process incoming packets
def process_packet(packet):
    print(f"📡 Captured Packet: {packet.summary()}")

    features = extract_features(packet)
    df = pd.DataFrame([features])
    prediction = model.predict(df)[0]

    if prediction == 1:
        print("🚨 Malicious Packet Detected!")
        alert_msg = f"🚨 *Attack Detected at* `{time.strftime('%Y-%m-%d %H:%M:%S')}`"
        logging.info(alert_msg)

        try:
            bot.send_message(ADMIN_CHAT_ID, escape_markdown(alert_msg), parse_mode="MarkdownV2")
        except Exception as e:
            print(f"⚠ Telegram Bot Error: {e}")

        # Self-heal mechanism
        self_heal.isolate_threat(packet)

# 🔹 Telegram Bot Commands
@bot.message_handler(commands=["start"])
def start(message):
    bot.send_message(message.chat.id, escape_markdown("🤖 *A_ura_bot Activated!* Use /help for commands"), parse_mode="MarkdownV2")

@bot.message_handler(commands=["status"])
def status(message):
    bot.send_message(message.chat.id, escape_markdown("✅ *IDS System is Running!*"), parse_mode="MarkdownV2")

@bot.message_handler(commands=["logs"])
def logs(message):
    try:
        with open(LOG_FILE, "r") as f:
            lines = f.readlines()[-10:]  
            if not lines:
                bot.send_message(message.chat.id, escape_markdown("📜 *No logs available.*"), parse_mode="MarkdownV2")
                return
            bot.send_message(message.chat.id, escape_markdown("📜 *Recent Logs:* \n" + "".join(lines)), parse_mode="MarkdownV2")
    except Exception as e:
        bot.send_message(message.chat.id, escape_markdown(f"❌ *Error Reading Logs:* {e}"), parse_mode="MarkdownV2")

@bot.message_handler(commands=["full_logs"])
def full_logs(message):
    try:
        with open(LOG_FILE, "r") as f:
            logs = f.readlines()

        if not logs:
            bot.send_message(message.chat.id, escape_markdown("📜 *No logs available.*"), parse_mode="MarkdownV2")
            return

        # Split logs into chunks of 4000 characters (to fit within Telegram's limit)
        log_chunks = []
        chunk = ""

        for log in logs:
            if len(chunk) + len(log) > 4000:  # If chunk is too large, store it and start a new one
                log_chunks.append(chunk)
                chunk = ""
            chunk += log  # Add log line to the chunk
        
        if chunk:  # Add the last remaining chunk
            log_chunks.append(chunk)

        # Send each chunk separately
        for i, chunk in enumerate(log_chunks):
            bot.send_message(message.chat.id, escape_markdown(f"📜 *Logs Part {i+1}:*\n\n{chunk}"), parse_mode="MarkdownV2")

    except Exception as e:
        bot.send_message(message.chat.id, escape_markdown(f"❌ *Error Reading Logs:* {e}"), parse_mode="MarkdownV2")

@bot.message_handler(commands=["ban_ip"])
def ban_ip(message):
    try:
        ip = message.text.split()[1]
        if os.name == "nt":
            bot.send_message(message.chat.id, escape_markdown("❌ *Windows does not support iptables commands.*"), parse_mode="MarkdownV2")
        else:
            os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
            bot.send_message(message.chat.id, escape_markdown(f"🚫 *IP `{ip}` Banned!*"), parse_mode="MarkdownV2")
    except IndexError:
        bot.send_message(message.chat.id, escape_markdown("❌ *Please provide an IP to ban:* `/ban_ip <IP>`"), parse_mode="MarkdownV2")

@bot.message_handler(commands=["help"])
def help(message):
    commands = """
🤖 *A_ura_bot Commands:*
🔹 [/start](https://t.me/A_ura_bot) - Start the bot
🔹 [/status](https://t.me/A_ura_bot) - Check IDS system status
🔹 [/logs](https://t.me/A_ura_bot) - Get last 10 logs
🔹 [/full_logs](https://t.me/A_ura_bot) - Get all logs
🔹 `/ban_ip <IP>` - Ban an IP
🔹 `/unban_ip <IP>` - Unban an IP
🔹 `/live_monitor` - Start live monitoring
🔹 `/stop_monitor` - Stop live monitoring
🔹 `/self_heal_status` - Check self-healing status
🔹 [/help](https://t.me/A_ura_bot) - Show this menu
"""
    bot.send_message(message.chat.id, escape_markdown(commands), parse_mode="MarkdownV2", disable_web_page_preview=True)

# 🔹 Function to Start the Bot
def start_bot():
    print("🤖 A_ura_bot is now active!")
    try:
        bot.infinity_polling(timeout=10, long_polling_timeout=5)
    except Exception as e:
        print(f"⚠ Telegram Bot Error: {e}")

# 🔹 Function to Start Network Monitoring
def start_sniffer():
    print("🔍 Monitoring Network Traffic in Real Time...")
    scapy.sniff(iface="Wi-Fi", filter="ip", prn=process_packet, store=0)

# 🔹 Run bot & sniffer in separate threads
bot_thread = threading.Thread(target=start_bot, daemon=True)
sniff_thread = threading.Thread(target=start_sniffer, daemon=True)

bot_thread.start()
sniff_thread.start()

bot_thread.join()  # Keep the bot running
