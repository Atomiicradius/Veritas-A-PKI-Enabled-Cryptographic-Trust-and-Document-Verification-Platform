"""Run once to pre-generate RSA keypairs for User A and User B."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from crypto.keygen import generate_keys, save_keys

KEYS_DIR = os.path.join(os.path.dirname(__file__), "keys")


def main():
    for user, size in [("userA", 2048), ("userB", 2048)]:
        priv_path = os.path.join(KEYS_DIR, f"{user}_private.pem")
        if os.path.exists(priv_path):
            print(f"Keys for {user} already exist, skipping.")
            continue
        print(f"Generating {size}-bit RSA keypair for {user}...")
        priv, pub = generate_keys(size)
        save_keys(priv, pub, user, KEYS_DIR)
        print(f"  Saved to keys/{user}_private.pem and keys/{user}_public.pem")
    print("Done.")


if __name__ == "__main__":
    main()
