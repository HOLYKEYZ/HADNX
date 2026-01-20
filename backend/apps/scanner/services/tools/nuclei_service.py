import subprocess
import shutil
import json
import logging
import tempfile
import os

logger = logging.getLogger(__name__)

class NucleiService:
    @staticmethod
    def is_available():
        """Check if nuclei is in PATH."""
        return shutil.which("nuclei") is not None

    @staticmethod
    def run_scan(target_url):
        """
        Runs a quick nuclei scan on the target.
        Returns a list of findings (dicts) or error dict.
        """
        if not NucleiService.is_available():
            return {
                "error": "Nuclei CLI not found",
                "details": "Please install Nuclei: 'go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest' or download the binary and add to PATH."
            }

        try:
            # Create a temp file for output
            fd, temp_path = tempfile.mkstemp(suffix=".json")
            os.close(fd)

            # Run Nuclei
            # -u: Target
            # -json-output: Output file
            # -nc: No color
            # -silent: Less stdout noise
            cmd = [
                "nuclei",
                "-u", target_url,
                "-json-output", temp_path,
                "-nc",
                "-silent"
            ]

            logger.info(f"Starting Nuclei scan on {target_url}")
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300 # 5 minute timeout for 'quick' tool scan
            )

            # Read execution logs from stderr if needed
            debug_log = process.stderr

            if process.returncode != 0 and not os.path.getsize(temp_path):
                # If command failed and wrote nothing
                os.remove(temp_path)
                return {
                    "error": "Nuclei Execution Failed",
                    "details": debug_log or "Unknown error"
                }

            # Parse Results
            results = []
            if os.path.exists(temp_path):
                with open(temp_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        if line.strip():
                            try:
                                results.append(json.loads(line))
                            except json.JSONDecodeError:
                                pass
                os.remove(temp_path)

            return {
                "status": "success",
                "findings": results,
                "count": len(results),
                "raw_log": debug_log
            }

        except subprocess.TimeoutExpired:
            return {"error": "Scan timed out (5m limit)"}
        except Exception as e:
            logger.error(f"Nuclei scan error: {e}")
            return {"error": str(e)}
