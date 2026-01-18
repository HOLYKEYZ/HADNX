import os
import sys
import dotenv
import requests

def test_keys():
    print("--- DIAGNOSTIC: Checking AI Keys ---")
    
    # 1. Check if .env exists
    env_path = os.path.join(os.path.dirname(__file__), '.env')
    if os.path.exists(env_path):
        print(f"[OK] .env file found at: {env_path}")
    else:
        print(f"[FAIL] .env file NOT found at: {env_path}")
        return

    # 2. Load .env
    dotenv.load_dotenv(env_path)
    print("Loading .env file...")

    # 3. Check Keys
    groq_key = os.environ.get('GROQ_KEY')
    gemini_key = os.environ.get('GEMINI_KEY')

    if groq_key:
        print(f"[OK] GROQ_KEY found: {groq_key[:5]}...{groq_key[-4:] if len(groq_key)>8 else ''}")
    else:
        print("[FAIL] GROQ_KEY is missing or empty")

    if gemini_key:
        print(f"[OK] GEMINI_KEY found: {gemini_key[:5]}...{gemini_key[-4:] if len(gemini_key)>8 else ''}")
    else:
        print("[FAIL] GEMINI_KEY is missing or empty")

    # 4. Test API Call if key exists
    if groq_key:
        print("\n--- Testing Groq API Connection ---")
        try:
            resp = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {groq_key}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": "llama-3.3-70b-versatile",
                    "messages": [{"role": "user", "content": "Hello"}],
                    "max_tokens": 10
                },
                timeout=10
            )
            if resp.status_code == 200:
                print("[OK] Groq API connection SUCCESS!")
            else:
                print(f"[FAIL] Groq API Error: {resp.status_code} - {resp.text}")
        except Exception as e:
            print(f"[FAIL] Groq Connection Failed: {e}")

if __name__ == "__main__":
    test_keys()
