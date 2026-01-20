import subprocess
import json
import logging
import tempfile
import os
import sys
from django.conf import settings

logger = logging.getLogger(__name__)

class SQLMapService:
    @staticmethod
    def get_sqlmap_path():
        """Get absolute path to sqlmap.py"""
        # Assuming backend/tools/sqlmap/sqlmap.py
        base_dir = settings.BASE_DIR
        path = os.path.join(base_dir, 'tools', 'sqlmap', 'sqlmap.py')
        if os.path.exists(path):
            return path
        return None

    @staticmethod
    def run_scan(target_url, params=None):
        """
        Runs a SQLMap scan on the target.
        """
        sqlmap_path = SQLMapService.get_sqlmap_path()
        if not sqlmap_path:
            return {
                "error": "SQLMap not found",
                "details": "Please clone sqlmap into backend/tools/sqlmap"
            }

        try:
            # Create a temp file for output directory (batch mode writes to folder)
            # Actually sqlmap writes to ~/.sqlmap/output... or custom dir.
            # We'll use --output-dir
            temp_dir = tempfile.mkdtemp()

            cmd = [
                sys.executable, # python
                sqlmap_path,
                "-u", target_url,
                "--batch", # Non-interactive
                "--output-dir", temp_dir,
                "--smart", # Only test if it looks heuristic
                "--forms", # Parse forms
                "--dbs",   # Enumerate DBs if found
                "--random-agent"
            ]
            
            # Simple Quick Scan options
            if params:
                 # TODO: Add custom params support safely
                 pass

            logger.info(f"Starting SQLMap on {target_url}")
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600 # 10 minutes
            )

            # Read execution log
            stdout = process.stdout
            stderr = process.stderr
            
            # Check output dir for results
            # SQLMap creates a folder per domain.
            # We need to find the CSV or content.
            # For simplicity, we'll return the stdout for now (it shows the "Snippet" of vuln).
            
            # Extract basic info from stdout
            is_vulnerable = "is vulnerable" in stdout
            
            return {
                "status": "success",
                "vulnerable": is_vulnerable,
                "stdout": stdout,
                "stderr": stderr,
                "output_dir": temp_dir
            }

        except subprocess.TimeoutExpired:
            return {"error": "Scan timed out (10m limit)"}
        except Exception as e:
            logger.error(f"SQLMap error: {e}")
            return {"error": str(e)}
