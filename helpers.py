"""
Utility Helper Functions
"""

import os
from typing import Dict, Any
from datetime import datetime

# File signature mappings
FILE_SIGNATURES = {
    b'MZ': 'application/x-msdownload',
    b'%PDF': 'application/pdf',
    b'PK\x03\x04': 'application/zip',
    b'PK\x05\x06': 'application/zip',
    b'Rar!\x1a\x07': 'application/x-rar-compressed',
    b'\x89PNG\r\n\x1a\n': 'image/png',
    b'\xff\xd8\xff': 'image/jpeg',
    b'GIF87a': 'image/gif',
    b'GIF89a': 'image/gif',
    b'BM': 'image/bmp',
    b'II\x2a\x00': 'image/tiff',
    b'MM\x00\x2a': 'image/tiff',
    b'<!DOCTYPE': 'text/html',
    b'<html': 'text/html',
    b'<?xml': 'application/xml',
    b'\x1f\x8b': 'application/gzip',
}

def detect_mime_type(file_path: str) -> str:
    """Detect file MIME type based on signature"""
    try:
        with open(file_path, 'rb') as f:
            header = f.read(16)
            
            for signature, mime_type in FILE_SIGNATURES.items():
                if header.startswith(signature):
                    return mime_type
            
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    f.read(1024)
                    return 'text/plain'
            except UnicodeDecodeError:
                pass
            
            return 'application/octet-stream'
            
    except Exception:
        return 'application/octet-stream'

def get_file_info(file_path: str) -> Dict[str, Any]:
    """Get detailed file information"""
    if not os.path.exists(file_path):
        return {"error": "File not found"}
    
    stat = os.stat(file_path)
    mime_type = detect_mime_type(file_path)
    
    return {
        "name": os.path.basename(file_path),
        "size": stat.st_size,
        "size_human": human_readable_size(stat.st_size),
        "mime_type": mime_type,
        "extension": os.path.splitext(file_path)[1].lower(),
        "created": datetime.fromtimestamp(stat.st_ctime).strftime("%Y-%m-%d %H:%M:%S"),
        "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
    }

def human_readable_size(size: int) -> str:
    """Convert bytes to human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} TB"

def format_scan_result(scan_type: str, item_info: Dict, result: Dict) -> str:
    """Format scan results for Telegram message"""
    
    if scan_type == "file":
        filename = result.get("filename", "Unknown")
        file_info = item_info
        vt_result = result.get("details", {}).get("virustotal", {})
        
        if result.get("clean", True) and not result.get("threats"):
            message = f"✅ *Scan Complete - No Threats Detected*\n\n"
            message += f"📄 *File:* `{filename}`\n"
            message += f"📊 *Size:* {file_info.get('size_human', 'Unknown')}\n"
            message += f"🏷️ *Type:* {file_info.get('mime_type', 'Unknown')}\n"
            message += f"🔐 *MD5:* `{result.get('details', {}).get('md5', 'N/A')[:16]}...`\n"
            
            # Show VirusTotal stats
            if vt_result:
                stats = vt_result.get("stats", {})
                if stats:
                    message += f"\n🔍 *VirusTotal Results:*\n"
                    message += f"🟢 Safe: {stats.get('harmless', 0)}\n"
                    message += f"🔴 Malicious: {stats.get('malicious', 0)}\n"
                    message += f"🟡 Suspicious: {stats.get('suspicious', 0)}\n"
                    message += f"⏱️ Undetected: {stats.get('undetected', 0)}\n"
            
            message += f"\n🛡️ *Result:* No malicious content detected by VirusTotal."
        else:
            threat_count = len(result.get("threats", []))
            warning_count = len(result.get("warnings", []))
            
            message = f"⚠️ *Scan Complete - Threats Detected*\n\n"
            message += f"📄 *File:* `{filename}`\n"
            message += f"🚨 *Threats:* {threat_count}\n"
            message += f"⚠️ *Warnings:* {warning_count}\n\n"
            
            # Show VirusTotal stats
            if vt_result:
                stats = vt_result.get("stats", {})
                if stats:
                    message += f"🔍 *VirusTotal Analysis:*\n"
                    message += f"🟢 Safe: {stats.get('harmless', 0)}\n"
                    message += f"🔴 Malicious: {stats.get('malicious', 0)}\n"
                    message += f"🟡 Suspicious: {stats.get('suspicious', 0)}\n\n"
            
            message += "*🔍 Threat Details:*\n"
            for i, threat in enumerate(result.get("threats", []), 1):
                message += f"{i}. *{threat.get('type', 'Unknown')}*\n"
                message += f"   📛 Name: {threat.get('name', 'Unknown')}\n"
                message += f"   📍 Source: {threat.get('source', 'Unknown')}\n\n"
            
            if result.get("warnings"):
                message += "*⚠️ Warnings:*\n"
                for warning in result.get("warnings", []):
                    message += f"• {warning.get('description', 'Unknown')}\n"
    
    elif scan_type == "website":
        url = item_info.get("url", "Unknown")
        site_info = result.get("details", {}).get("site_info", {})
        
        if result.get("clean", True) and not result.get("threats"):
            message = f"✅ *Website Scan Complete*\n\n"
            message += f"🔗 *URL:* `{url}`\n"
            
            if site_info.get("title"):
                message += f"📑 *Title:* {site_info.get('title')}\n"
            if site_info.get("response_time"):
                message += f"⏱️ *Response Time:* {site_info.get('response_time')}s\n"
            if site_info.get("ip_address"):
                message += f"🌐 *IP:* {site_info.get('ip_address')}\n"
            
            message += f"\n🛡️ *Result:* No malicious content detected."
        else:
            threat_count = len(result.get("threats", []))
            warning_count = len(result.get("warnings", []))
            
            message = f"⚠️ *Website Scan Complete - Threats Detected*\n\n"
            message += f"🔗 *URL:* `{url}`\n"
            message += f"🚨 *Threats:* {threat_count}\n"
            message += f"⚠️ *Warnings:* {warning_count}\n\n"
            
            message += "*🔍 Threat Details:*\n"
            for i, threat in enumerate(result.get("threats", []), 1):
                message += f"{i}. *{threat.get('type', 'Unknown')}*\n"
                message += f"   📝 Description: {threat.get('description', 'Unknown')}\n"
                message += f"   📍 Source: {threat.get('source', 'Unknown')}\n"
                message += f"   ⚡ Severity: {threat.get('severity', 'Unknown')}\n\n"
            
            if result.get("warnings"):
                message += "*⚠️ Warnings:*\n"
                for warning in result.get("warnings", []):
                    message += f"• {warning.get('type', 'Warning')}: {warning.get('description', 'Unknown')}\n"
    
    message += f"\n📅 *Scan Time:* {result.get('scan_time', 'Unknown')}"
    message += f"\n🔒 *Powered by Telescan*"
    
    return message

def validate_file_extension(filename: str, allowed_extensions: list) -> bool:
    """Check if file extension is allowed"""
    ext = os.path.splitext(filename)[1].lower()
    return ext in allowed_extensions

def sanitize_filename(filename: str) -> str:
    """Sanitize filename to prevent path traversal"""
    filename = os.path.basename(filename)
    dangerous_chars = ['/', '\\', '..', '.', '*', '?', '[', ']', '{', '}', '<', '>', '|', '\0']
    for char in dangerous_chars:
        filename = filename.replace(char, '_')
    return filename

def truncate_text(text: str, max_length: int = 100) -> str:
    """Truncate text with ellipsis"""
    if len(text) <= max_length:
        return text
    return text[:max_length - 3] + "..."

def get_risk_level(threats: list) -> str:
    """Determine risk level based on threats"""
    critical = sum(1 for t in threats if t.get('severity') == 'critical')
    high = sum(1 for t in threats if t.get('severity') == 'high')
    medium = sum(1 for t in threats if t.get('severity') == 'medium')
    
    if critical > 0:
        return "🔴 CRITICAL"
    elif high > 0:
        return "🟠 HIGH"
    elif medium > 0:
        return "🟡 MEDIUM"
    else:
        return "🟢 LOW"
