import cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# Function to generate RSA key pair
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Function to encrypt data using public key
def encrypt_with_public_key(public_key, data):
    encrypted_data = public_key.encrypt(
        data.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_data

# Function to decrypt data using private key
def decrypt_with_private_key(private_key, encrypted_data):
    decrypted_data = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_data.decode()

# Function to generate a SHA-256 hash of data
def hash_data(data):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data.encode())
    return digest.finalize()

# Generate RSA key pairs for cloud server and robot
cloud_private_key, cloud_public_key = generate_rsa_key_pair()
robot_private_key, robot_public_key = generate_rsa_key_pair()

# Take user input for health data
health_data = input("Enter health data (e.g., 'Temperature: 36.6, Heartbeat: 72'): ")

# Encrypt health data using cloud server's public key
encrypted_data = encrypt_with_public_key(cloud_public_key, health_data)

# Hash the health data for integrity verification
data_hash = hash_data(health_data)

# Decrypt the data using cloud server's private key
decrypted_data = decrypt_with_private_key(cloud_private_key, encrypted_data)

# Verify that decrypted data matches original data
is_data_intact = health_data == decrypted_data
is_hash_same = data_hash == hash_data(decrypted_data)

print("\nOriginal Data:", health_data)
print("Encrypted Data (in bytes):", encrypted_data)
print("Decrypted Data:", decrypted_data)
print("Is Data Intact:", is_data_intact)
print("Is Hash Same:", is_hash_same)
