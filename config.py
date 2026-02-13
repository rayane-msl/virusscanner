"""
Telescan Configuration
"""

import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Telegram Bot Token
BOT_TOKEN = os.getenv("BOT_TOKEN", "")

# Maximum file size (50MB)
MAX_FILE_SIZE = 50 * 1024 * 1024

# ClamAV Configuration (optional - requires ClamAV daemon)
CLAMD_HOST = os.getenv("CLAMD_HOST", "localhost")
CLAMD_PORT = int(os.getenv("CLAMD_PORT", "3310"))

# Website Scanning Configuration
SCAN_TIMEOUT = 30  # seconds
MAX_URL_LENGTH = 2048
ALLOWED_PROTOCOLS = ["http://", "https://"]

# File Type Restrictions
ALLOWED_EXTENSIONS = [
    # Documents
    '.pdf', '.doc', '.docx', '.txt', '.rtf', '.odt',
    # Spreadsheets
    '.xls', '.xlsx', '.csv', '.ods',
    # Code
    '.py', '.js', '.java', '.c', '.cpp', '.h', '.php', '.html', '.css', '.xml', '.json',
    # Images
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico',
    # Archives
    '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2',
    # Executables
    '.exe', '.dll', '.apk', '.jar', '.sh', '.bat'
]

# Dangerous Extensions (require extra caution)
DANGEROUS_EXTENSIONS = [
    '.exe', '.dll', '.bat', '.sh', '.cmd', '.com', '.pif', '.msi', '.scr', '.jar'
]

# Malicious URL Patterns
SUSPICIOUS_PATTERNS = [
    r'(?i)(virus|malware|trojan|spyware|adware|rootkit|worm|bot)',
    r'(?i)(free.?money|lottery|winner|prize|milliondollar)',
    r'(?i)(login|signin|account.?update|password.?reset)',
    r'(?i)(bank|credit.?card|social.?security|ssn)',
    r'(?i)(bitcoin|crypto|wallet|mining)',
    r'(?i)(phishing|fake|scam|fraud)',
    r'(?i)(download|install|update.?now)',
    r'(?i)(click.?here|limited.?time|act.?now)',
    r'(?i)(.*?)\.(tk|ml|ga|cf|gq|xyz|top|loan|download|stream)',
]

# API Keys for external services (optional)
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")

# Rate Limiting
RATE_LIMIT_PER_USER = 10  # scans per minute
RATE_LIMIT_WINDOW = 60  # seconds

# Logging Configuration
LOG_LEVEL = "INFO"
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

# Base directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
