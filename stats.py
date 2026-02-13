"""
Statistics Tracker
Tracks bot usage statistics
"""

import json
import os
from datetime import datetime
from typing import Dict, Any

class StatsTracker:
    """Track bot usage statistics"""
    
    def __init__(self):
        self.stats_file = "bot_stats.json"
        self.stats = self._load_stats()
    
    def _load_stats(self) -> Dict[str, Any]:
        """Load statistics from file"""
        if os.path.exists(self.stats_file):
            try:
                with open(self.stats_file, 'r') as f:
                    return json.load(f)
            except Exception:
                pass
        return {
            "files_scanned": 0,
            "urls_scanned": 0,
            "threats_detected": 0,
            "clean_files": 0,
            "clean_urls": 0,
            "start_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "last_scan": None
        }
    
    def _save_stats(self):
        """Save statistics to file"""
        try:
            with open(self.stats_file, 'w') as f:
                json.dump(self.stats, f, indent=2)
        except Exception as e:
            print(f"[WARNING] Failed to save stats: {e}")
    
    def increment_files_scanned(self, clean: bool = False):
        """Increment file scan counter"""
        self.stats["files_scanned"] += 1
        if clean:
            self.stats["clean_files"] += 1
        else:
            self.stats["threats_detected"] += 1
        self.stats["last_scan"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._save_stats()
    
    def increment_urls_scanned(self, clean: bool = False):
        """Increment URL scan counter"""
        self.stats["urls_scanned"] += 1
        if clean:
            self.stats["clean_urls"] += 1
        else:
            self.stats["threats_detected"] += 1
        self.stats["last_scan"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._save_stats()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current statistics"""
        return self.stats.copy()
    
    def reset_stats(self):
        """Reset all statistics"""
        self.stats = {
            "files_scanned": 0,
            "urls_scanned": 0,
            "threats_detected": 0,
            "clean_files": 0,
            "clean_urls": 0,
            "start_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "last_scan": None
        }
        self._save_stats()

# Global stats tracker instance
stats_tracker = StatsTracker()
