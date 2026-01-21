import subprocess
import tempfile
import os
import shutil
import logging
from django.conf import settings

logger = logging.getLogger(__name__)

class WiresharkService:
    # Windows default installation path
    TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"
    
    @staticmethod
    def is_available():
        """Check if tshark is installed."""
        # First try PATH, then check default install location
        if shutil.which("tshark"):
            return True
        return os.path.exists(WiresharkService.TSHARK_PATH)
    
    @staticmethod
    def get_tshark_cmd():
        """Returns the tshark command (path or just 'tshark' if in PATH)."""
        if shutil.which("tshark"):
            return "tshark"
        if os.path.exists(WiresharkService.TSHARK_PATH):
            return WiresharkService.TSHARK_PATH
        return None

    @staticmethod
    def capture(interface: str = "eth0", duration: int = 10, filename: str = None):
        """
        Capture packets for a given duration.
        Returns the path to the .pcap file.
        """
        if not WiresharkService.is_available():
            return {
                "error": "Tshark not found",
                "details": "Please install Wireshark/Tshark (e.g., 'winget install Wireshark.Wireshark')."
            }

        try:
            # Generate temp file path if not provided
            if not filename:
                temp_dir = os.path.join(settings.BASE_DIR, 'captures')
                os.makedirs(temp_dir, exist_ok=True)
                filename = os.path.join(temp_dir, f"capture_{os.getpid()}.pcap")

            cmd = [
                WiresharkService.get_tshark_cmd(),
                "-i", interface,
                "-a", f"duration:{duration}",
                "-w", filename
            ]

            logger.info(f"Starting tshark capture on {interface} for {duration}s -> {filename}")
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=duration + 10 # Buffer
            )

            if process.returncode != 0:
                return {"error": f"Capture failed: {process.stderr}"}

            return {
                "status": "success",
                "file": filename,
                "duration": duration
            }

        except subprocess.TimeoutExpired:
            return {"error": "Capture timed out"}
        except Exception as e:
            logger.error(f"Tshark error: {e}")
            return {"error": str(e)}

    @staticmethod
    def list_interfaces():
        """Lists available network interfaces."""
        if not WiresharkService.is_available():
            return {"error": "Tshark not found"}

        try:
            tshark_cmd = WiresharkService.get_tshark_cmd()
            process = subprocess.run(
                [tshark_cmd, "-D"],
                capture_output=True,
                text=True,
                timeout=5
            )
            lines = process.stdout.strip().split("\n")
            interfaces = []
            for line in lines:
                if ". " in line:
                    parts = line.split(". ", 1)
                    interfaces.append({"id": parts[0], "name": parts[1] if len(parts) > 1 else parts[0]})
            return {"interfaces": interfaces}
        except Exception as e:
            return {"error": str(e)}
