import os
import json
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from datetime import datetime, timedelta
import base64

class KeyManagementSystem:
    def __init__(self, master_key_env_var='MASTER_KEY', key_store_file='master_keys.json'):
        self.key_store_file = key_store_file
        self.master_key_env_var = master_key_env_var
        self.backend = default_backend()
        self.master_keys = self._load_master_keys()

    def _load_master_keys(self):
        """Load master keys from file, structure: {tenant_id: {version: key, created_at: datetime}}"""
        if os.path.exists(self.key_store_file):
            with open(self.key_store_file, 'r') as f:
                data = json.load(f)
                # Convert created_at back to datetime
                for tenant, versions in data.items():
                    for version, info in versions.items():
                        info['created_at'] = datetime.fromisoformat(info['created_at'])
                return data
        return {}

    def _save_master_keys(self):
        """Save master keys to file"""
        data = {}
        for tenant, versions in self.master_keys.items():
            data[tenant] = {}
            for version, info in versions.items():
                data[tenant][version] = {
                    'key': info['key'],
                    'created_at': info['created_at'].isoformat()
                }
        with open(self.key_store_file, 'w') as f:
            json.dump(data, f, indent=2)

    def _get_or_create_master_key(self, tenant_id):
        """Get active master key for tenant, create if not exists"""
        if tenant_id not in self.master_keys:
            self.master_keys[tenant_id] = {}

        if not self.master_keys[tenant_id]:
            # Create first master key
            master_key = self._generate_master_key()
            version = 'v1'
            self.master_keys[tenant_id][version] = {
                'key': base64.b64encode(master_key).decode(),
                'created_at': datetime.utcnow()
            }
            self._save_master_keys()

        # Return the latest (active) version
        latest_version = max(self.master_keys[tenant_id].keys(), key=lambda v: int(v[1:]))
        return base64.b64decode(self.master_keys[tenant_id][latest_version]['key']), latest_version

    def _generate_master_key(self):
        """Generate a new master key"""
        return secrets.token_bytes(32)  # 256-bit key

    def _derive_key(self, password, salt):
        """Derive key from password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=self.backend
        )
        return kdf.derive(password.encode())

    def generate_dek(self):
        """Generate a data encryption key"""
        return secrets.token_bytes(32)

    def encrypt_dek(self, tenant_id, dek):
        """Encrypt DEK with master key, return encrypted_dek and version"""
        master_key, version = self._get_or_create_master_key(tenant_id)
        salt = secrets.token_bytes(16)
        key = self._derive_key(base64.b64encode(master_key).decode(), salt)

        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(dek) + padder.finalize()

        encrypted_dek = encryptor.update(padded_data) + encryptor.finalize()

        # Return base64 encoded encrypted_dek, salt, iv, and version
        return {
            'encrypted_dek': base64.b64encode(encrypted_dek).decode(),
            'salt': base64.b64encode(salt).decode(),
            'iv': base64.b64encode(iv).decode(),
            'version': version
        }

    def decrypt_dek(self, tenant_id, encrypted_data):
        """Decrypt DEK using appropriate master key version"""
        version = encrypted_data['version']
        if tenant_id not in self.master_keys or version not in self.master_keys[tenant_id]:
            raise ValueError("Invalid tenant or key version")

        master_key_b64 = self.master_keys[tenant_id][version]['key']
        master_key = base64.b64decode(master_key_b64)

        salt = base64.b64decode(encrypted_data['salt'])
        key = self._derive_key(base64.b64encode(master_key).decode(), salt)

        iv = base64.b64decode(encrypted_data['iv'])
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()

        encrypted_dek = base64.b64decode(encrypted_data['encrypted_dek'])
        padded_data = decryptor.update(encrypted_dek) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        dek = unpadder.update(padded_data) + unpadder.finalize()

        return dek

    def encrypt_document(self, dek, data):
        """Encrypt document data with DEK"""
        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(dek), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()

        if isinstance(data, str):
            data = data.encode()

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()

        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        return {
            'encrypted_data': base64.b64encode(encrypted_data).decode(),
            'iv': base64.b64encode(iv).decode()
        }

    def decrypt_document(self, dek, encrypted_data):
        """Decrypt document data with DEK"""
        iv = base64.b64decode(encrypted_data['iv'])
        cipher = Cipher(algorithms.AES(dek), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()

        encrypted = base64.b64decode(encrypted_data['encrypted_data'])
        padded_data = decryptor.update(encrypted) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()

        return data

    def rotate_keys(self, tenant_id):
        """Rotate master key for tenant - create new version"""
        if tenant_id not in self.master_keys:
            self.master_keys[tenant_id] = {}

        current_versions = [int(v[1:]) for v in self.master_keys[tenant_id].keys()]
        next_version_num = max(current_versions) + 1 if current_versions else 1
        next_version = f'v{next_version_num}'

        master_key = self._generate_master_key()
        self.master_keys[tenant_id][next_version] = {
            'key': base64.b64encode(master_key).decode(),
            'created_at': datetime.utcnow()
        }
        self._save_master_keys()
        return next_version

    def get_key_age(self, tenant_id, version):
        """Get age of a key in days"""
        if tenant_id in self.master_keys and version in self.master_keys[tenant_id]:
            created_at = self.master_keys[tenant_id][version]['created_at']
            return (datetime.utcnow() - created_at).days
        return None

    def should_rotate_keys(self, tenant_id, max_age_days=90):
        """Check if keys should be rotated"""
        if tenant_id not in self.master_keys:
            return True
        latest_version = max(self.master_keys[tenant_id].keys(), key=lambda v: int(v[1:]))
        age = self.get_key_age(tenant_id, latest_version)
        return age is None or age >= max_age_days

# Example usage
if __name__ == '__main__':
    kms = KeyManagementSystem()

    tenant_id = 'tenant1'

    # Check if rotation needed
    if kms.should_rotate_keys(tenant_id):
        print(f"Rotating keys for {tenant_id}")
        new_version = kms.rotate_keys(tenant_id)
        print(f"New key version: {new_version}")

    # Generate DEK and encrypt document
    dek = kms.generate_dek()
    document = "This is a sample policy document for compliance analysis."

    encrypted_dek_data = kms.encrypt_dek(tenant_id, dek)
    encrypted_doc_data = kms.encrypt_document(dek, document)

    print("Encrypted DEK data:", encrypted_dek_data)
    print("Encrypted document data:", encrypted_doc_data)

    # Decrypt
    decrypted_dek = kms.decrypt_dek(tenant_id, encrypted_dek_data)
    decrypted_doc = kms.decrypt_document(decrypted_dek, encrypted_doc_data)

    print("Decrypted document:", decrypted_doc.decode())