from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def generate_keys(key_size: int):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    public_key = private_key.public_key()
    return private_key, public_key


def save_keys(private_key, public_key, name: str, keys_dir: str = "keys"):
    import os
    os.makedirs(keys_dir, exist_ok=True)

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    with open(os.path.join(keys_dir, f"{name}_private.pem"), "wb") as f:
        f.write(priv_pem)
    with open(os.path.join(keys_dir, f"{name}_public.pem"), "wb") as f:
        f.write(pub_pem)


def load_private_key(name: str, keys_dir: str = "keys"):
    import os
    path = os.path.join(keys_dir, f"{name}_private.pem")
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_public_key(name: str, keys_dir: str = "keys"):
    import os
    path = os.path.join(keys_dir, f"{name}_public.pem")
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())
