"""
File Scanner Module
Handles scanning of files for viruses and malicious content
"""

import os
import hashlib
import asyncio
import re
import tempfile
import aiohttp
from datetime import datetime
from typing import Dict, Any, Optional, List
from pathlib import Path

from config import VIRUSTOTAL_API_KEY

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

class FileScanner:
    """Scanner for files with VirusTotal integration"""
    
    def __init__(self):
        self.scanner_name = "Telescan File Scanner"
        self.version = "1.0.0"
        self.active = True
        self._create_directories()
        print(f"[INFO] File scanner initialized with VirusTotal integration")
    
    def _create_directories(self):
        """Create necessary directories"""
        base_dir = os.path.dirname(os.path.dirname(__file__))
        self.quarantine_dir = os.path.join(base_dir, "quarantine")
        self.temp_dir = os.path.join(base_dir, "temp")
        os.makedirs(self.quarantine_dir, exist_ok=True)
        os.makedirs(self.temp_dir, exist_ok=True)
    
    def get_status(self) -> Dict[str, Any]:
        """Get scanner status"""
        return {
            "name": self.scanner_name,
            "version": self.version,
            "engine": "VirusTotal API + Heuristic Analysis",
            "active": self.active,
            "signatures": "VirusTotal Database",
            "last_update": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "python_version": f"{os.sys.version_info.major}.{os.sys.version_info.minor}",
            "website_apis": ["VirusTotal"]
        }
    
    async def scan_file(self, file_path: str) -> Dict[str, Any]:
        """
        Scan a file for viruses using VirusTotal
        
        Args:
            file_path: Path to the file to scan
            
        Returns:
            Dictionary with scan results
        """
        result = {
            "filename": os.path.basename(file_path),
            "filepath": file_path,
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "threats": [],
            "warnings": [],
            "clean": True,
            "details": {}
        }
        
        if not os.path.exists(file_path):
            result["error"] = "File not found"
            result["clean"] = False
            return result
        
        try:
            # Get file information
            file_info = self._get_file_info(file_path)
            result["details"]["file_info"] = file_info
            
            # Calculate file hash
            file_hash = self._calculate_file_hash(file_path)
            result["details"]["md5"] = file_hash["md5"]
            result["details"]["sha256"] = file_hash["sha256"]
            
            # Upload to VirusTotal and get analysis
            vt_result = await self._scan_with_virustotal(file_path)
            result["details"]["virustotal"] = vt_result
            
            if vt_result.get("infected"):
                result["threats"].extend(vt_result["threats"])
                result["clean"] = False
            
            # Heuristic analysis
            heuristic_results = self._heuristic_analysis(file_path, file_info)
            if heuristic_results["suspicious"]:
                result["warnings"].extend(heuristic_results["details"])
            
        except Exception as e:
            result["error"] = str(e)
            result["clean"] = False
        
        return result
    
    def _get_file_info(self, file_path: str) -> Dict[str, Any]:
        """Get detailed file information"""
        stat = os.stat(file_path)
        mime_type = detect_mime_type(file_path)
        
        return {
            "size": stat.st_size,
            "size_human": self._human_readable_size(stat.st_size),
            "mime_type": mime_type,
            "extension": os.path.splitext(file_path)[1].lower(),
            "created": datetime.fromtimestamp(stat.st_ctime).strftime("%Y-%m-%d %H:%M:%S"),
            "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        }
    
    def _human_readable_size(self, size: int) -> str:
        """Convert bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} TB"
    
    def _calculate_file_hash(self, file_path: str) -> Dict[str, str]:
        """Calculate file hashes"""
        md5_hash = hashlib.md5()
        sha256_hash = hashlib.sha256()
        
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                md5_hash.update(chunk)
                sha256_hash.update(chunk)
        
        return {
            "md5": md5_hash.hexdigest(),
            "sha256": sha256_hash.hexdigest()
        }
    
    async def _scan_with_virustotal(self, file_path: str) -> Dict[str, Any]:
        """
        Upload file to VirusTotal and get analysis
        """
        result = {"infected": False, "threats": [], "error": None}
        
        if not VIRUSTOTAL_API_KEY:
            result["error"] = "VirusTotal API key not configured"
            return result
        
        try:
            headers = {"x-apikey": VIRUSTOTAL_API_KEY}
            
            # First, check if file was already analyzed
            file_hash = self._calculate_file_hash(file_path)
            
            async with aiohttp.ClientSession() as session:
                # Check file by hash first
                async with session.get(
                    f"https://www.virustotal.com/api/v3/files/{file_hash['sha256']}",
                    headers=headers
                ) as response:
                    if response.status == 200:
                        # File already analyzed
                        data = await response.json()
                        attributes = data.get("data", {}).get("attributes", {})
                        stats = attributes.get("last_analysis_stats", {})
                        
                        if stats.get("malicious", 0) > 0:
                            result["infected"] = True
                            
                            # Get detection names
                            results = attributes.get("last_analysis_results", {})
                            for engine, analysis in results.items():
                                if analysis.get("category") == "malicious":
                                    result["threats"].append({
                                        "type": "VirusTotal Detection",
                                        "name": analysis.get("result", "Unknown"),
                                        "source": f"VirusTotal ({engine})",
                                        "severity": "critical",
                                        "method": analysis.get("method", "Unknown")
                                    })
                        
                        result["stats"] = stats
                        result["analysis_date"] = attributes.get("last_analysis_date", "Unknown")
                        return result
                
                # If not found, upload the file
                form = aiohttp.FormData()
                form.add_field('file',
                              open(file_path, 'rb'),
                              filename=os.path.basename(file_path),
                              content_type='application/octet-stream')
                
                async with session.post(
                    "https://www.virustotal.com/api/v3/files",
                    headers=headers,
                    data=form
                ) as upload_response:
                    if upload_response.status == 200:
                        upload_data = await upload_response.json()
                        analysis_id = upload_data.get("data", {}).get("id")
                        
                        # Wait for analysis
                        await asyncio.sleep(5)
                        
                        # Get analysis results
                        async with session.get(
                            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                            headers=headers
                        ) as analysis_response:
                            if analysis_response.status == 200:
                                analysis_data = await analysis_response.json()
                                attributes = analysis_data.get("data", {}).get("attributes", {})
                                stats = attributes.get("stats", {})
                                
                                if stats.get("malicious", 0) > 0:
                                    result["infected"] = True
                                    
                                    results = attributes.get("results", {})
                                    for engine, analysis in results.items():
                                        if analysis.get("category") == "malicious":
                                            result["threats"].append({
                                                "type": "VirusTotal Detection",
                                                "name": analysis.get("result", "Unknown"),
                                                "source": f"VirusTotal ({engine})",
                                                "severity": "critical"
                                            })
                                
                                result["stats"] = stats
                                return result
                    
                    elif upload_response.status == 400:
                        # File too large (VirusTotal limit is 32MB)
                        result["error"] = "File too large for VirusTotal (max 32MB)"
                        return result
                    
        except Exception as e:
            result["error"] = str(e)
            print(f"[WARNING] VirusTotal API error: {e}")
        
        return result
    
    def _heuristic_analysis(self, file_path: str, file_info: Dict) -> Dict[str, Any]:
        """Perform heuristic analysis on file"""
        import time
        start_time = time.time()
        
        results = {"suspicious": False, "details": [], "duration": 0}
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read(50000)
                content_str = content.decode('latin-1', errors='ignore')
            
            # Check for suspicious patterns
            suspicious_patterns = [
                (r'eval\s*\(\s*base64', "Obfuscated code detected"),
                (r'\$_(?:GET|POST|REQUEST)\s*\[', "Suspicious input usage"),
                (r'exec\s*\(', "Command execution detected"),
                (r'system\s*\(', "System command usage"),
                (r'passthru\s*\(', "Command execution detected"),
                (r'shell_exec\s*\(', "Shell command usage"),
                (r'assert\s*\(\s*[\'"]', "Code assertion detected"),
            ]
            
            for pattern, description in suspicious_patterns:
                if re.search(pattern, content_str, re.IGNORECASE):
                    results["details"].append({
                        "type": "Heuristic",
                        "description": description,
                        "source": "Heuristic Analysis"
                    })
                    results["suspicious"] = True
            
        except Exception as e:
            results["details"].append({"error": str(e)})
        
        results["duration"] = time.time() - start_time
        return results
    
    async def quarantine_file(self, file_path: str, reason: str = "") -> Dict[str, Any]:
        """Move a file to quarantine"""
        result = {"success": False, "quarantine_path": None}
        
        try:
            if not os.path.exists(file_path):
                result["error"] = "File not found"
                return result
            
            filename = os.path.basename(file_path)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            quarantine_name = f"{timestamp}_{filename}"
            quarantine_path = os.path.join(self.quarantine_dir, quarantine_name)
            
            os.rename(file_path, quarantine_path)
            
            result["success"] = True
            result["quarantine_path"] = quarantine_path
            
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def cleanup_temp_files(self):
        """Clean up temporary files"""
        try:
            for file in os.listdir(self.temp_dir):
                file_path = os.path.join(self.temp_dir, file)
                if os.path.isfile(file_path):
                    os.remove(file_path)
            return True
        except Exception:
            return False
