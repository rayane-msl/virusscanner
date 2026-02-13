# 🛡️ Telescan - Telegram Security Bot

A powerful Telegram bot that scans websites and files for viruses, malware, and suspicious content.

![Telescan Banner](https://via.placeholder.com/800x200?text=Telescan+Security+Bot)

## 🌟 Features

### File Scanning
- **Multi-Engine Detection**: Uses YARA rules, ClamAV, and heuristic analysis
- **Wide File Support**: Scans documents, images, archives, executables, and more
- **Real-time Analysis**: Immediate threat detection and reporting
- **Quarantine System**: Safely isolates detected threats

### Website Scanning  
- **Phishing Detection**: Identifies phishing attempts and fake sites
- **Content Analysis**: Scans for malicious code and suspicious patterns
- **SSL/TLS Check**: Verifies certificate security
- **External API Integration**: Uses VirusTotal and Google Safe Browsing

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Telegram Bot Token
- Optional: ClamAV, VirusTotal API Key, Google Safe Browsing API Key

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/telescan.git
cd telescan
```

2. **Create virtual environment**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Configure environment**
```bash
cp .env.example .env
# Edit .env with your configuration
```

5. **Run the bot**
```bash
python main.py
```

## 📱 Bot Commands

| Command | Description |
|---------|-------------|
| `/start` | Start the bot and show welcome message |
| `/help` | Display help information |
| `/scan_file` | Upload a file to scan |
| `/scan_url [url]` | Scan a website URL |
| `/status` | Check scanner status |

## 📁 Project Structure

```
telescan/
├── main.py                 # Main bot application
├── config.py              # Configuration settings
├── requirements.txt       # Python dependencies
├── .env.example          # Environment template
├── README.md             # Documentation
├── scanners/
│   ├── __init__.py
│   ├── file_scanner.py   # File scanning logic
│   └── website_scanner.py # Website scanning logic
├── utils/
│   ├── __init__.py
│   └── helpers.py        # Utility functions
├── rules/                # YARA rules directory
├── temp/                 # Temporary files
└── quarantine/          # Quarantined files
```

## 🔧 Configuration

### Telegram Bot Token
1. Message [@BotFather](https://t.me/BotFather) on Telegram
2. Create a new bot with `/newbot`
3. Copy the token to your `.env` file

### ClamAV (Optional)
```bash
# Ubuntu/Debian
sudo apt-get install clamav clamav-daemon

# Start daemon
sudo systemctl start clamav-daemon
```

### VirusTotal API (Optional)
1. Create account at [VirusTotal](https://www.virustotal.com/)
2. Get API key from Settings → API Key
3. Add to `.env` file

### Google Safe Browsing (Optional)
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Enable Safe Browsing API
3. Create API credentials
4. Add to `.env` file

## 🛡️ Supported File Types

| Category | Extensions |
|----------|-----------|
| Documents | PDF, DOC, DOCX, TXT, RTF, ODT |
| Spreadsheets | XLS, XLSX, CSV, ODS |
| Code | Python, JavaScript, Java, C, C++, PHP, HTML, CSS |
| Images | JPG, PNG, GIF, BMP, SVG, ICO |
| Archives | ZIP, RAR, 7Z, TAR, GZ |
| Executables | EXE, DLL, APK, JAR, SH |

## 📊 Security Features

### File Scanning
- YARA signature matching
- ClamAV integration
- Heuristic pattern detection
- MD5/SHA256 hash checking
- Obfuscated code detection

### Website Scanning
- Phishing URL detection
- Suspicious TLD blocking
- Content pattern analysis
- SSL certificate validation
- External threat intelligence

## ⚠️ Disclaimer

This tool is for educational and security purposes only. Always:
- Verify scan results with additional tools
- Don't rely solely on automated scanning
- Keep your own security software updated
- Report suspicious files to appropriate authorities

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [python-telegram-bot](https://github.com/python-telegram-bot/python-telegram-bot)
- [YARA](https://virustotal.github.io/yara/)
- [ClamAV](https://www.clamav.net/)
- [VirusTotal](https://www.virustotal.com/)
- [Google Safe Browsing](https://developers.google.com/safe-browsing)

---

## ☁️ Deploy 24/7 (Keep Bot Running)

To keep your bot running 24/7 even when your PC is off, you can deploy it to a cloud service. Here are free options:

### Option 1: Render.com (Recommended)

1. **Create account** at [Render.com](https://render.com/) (free tier)

2. **Connect your GitHub** repository containing this bot

3. **Create a Web Service**:
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `python main.py`

4. **Add Environment Variables**:
   - Go to Environment section
   - Add `BOT_TOKEN` with your Telegram bot token
   - Add `VIRUSTOTAL_API_KEY` (optional)

5. **Deploy** - Your bot will run 24/7 for free

### Option 2: Railway.app

1. **Create account** at [Railway.app](https://railway.app/)

2. **Deploy from GitHub** repository

3. **Add Environment Variables** in the Variables tab:
   - `BOT_TOKEN` = your Telegram bot token
   - `VIRUSTOTAL_API_KEY` = your API key (optional)

4. **Start Command**: `python main.py`

### Option 3: PythonAnywhere

1. **Create account** at [PythonAnywhere.com](https://www.pythonanywhere.com/) (free tier)

2. **Upload your files** via the Files tab or from GitHub

3. **Open a Bash console** and run:
   ```bash
   pip install -r requirements.txt
   ```

4. **Schedule the bot** using PythonAnywhere's task scheduler:
   - Go to Tasks tab
   - Set time (e.g., every minute)
   - Command: `python /path/to/main.py`

### Option 4: VPS (DigitalOcean/Raspberry Pi)

If you have a VPS or Raspberry Pi:

```bash
# SSH into your server
cd telescan
pip install -r requirements.txt

# Create systemd service
sudo nano /etc/systemd/system/telescan-bot.service
```

Add this content:
```ini
[Unit]
Description=Telescan Telegram Bot
After=network.target

[Service]
Type=simple
User=your_user
WorkingDirectory=/path/to/telescan
ExecStart=/usr/bin/python3 main.py
Restart=always

[Install]
WantedBy=multi-user.target
```

Then enable:
```bash
sudo systemctl enable telescan-bot
sudo systemctl start telescan-bot
sudo systemctl status telescan-bot
```

### ⚠️ Important Notes

- **Free tiers** have some limitations (sleep after inactivity, limited hours)
- **Keep your `.env` file** secure - never commit it to GitHub
- **Monitor your bot** logs for any errors
- **Restart the bot** if it crashes (auto-restart is enabled on most platforms)

---

**Stay Safe! 🛡️**
