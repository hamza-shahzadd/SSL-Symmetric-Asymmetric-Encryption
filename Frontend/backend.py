from flask import Flask, request, render_template, session, redirect, url_for
import socket
import base64
import hashlib
import ssl
from cryptography import x509
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.hashes import SHA256



app = Flask(__name__)
app.secret_key = 'your_secret_key'


@app.route('/')
def index():
    
    # Create a socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server (replace 'localhost' and 12345 with your server's hostname and port)
    server_hostname = '127.0.0.1'
    server_port = 12369
    client_socket.connect((server_hostname, server_port))

    # Load the client private key from file
    with open('client-key.pem', 'rb') as key_file:
        client_private_key = serialization.load_pem_private_key(key_file.read(), password=None)

    with open('server-cert.pem', 'rb') as cert_file:
        server_cert = x509.load_pem_x509_certificate(cert_file.read())
        server_public_key = server_cert.public_key()




    # Wrap the client socket in an SSL context with certificate verification disabled
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

    # Disable certificate verification (not recommended for production)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    secure_socket = context.wrap_socket(client_socket, server_hostname=server_hostname)

    # Secure communication example
    data = b'SSL Certification Completed'
    encrypted_data = server_public_key.encrypt(data, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    secure_socket.send(encrypted_data)


    secure_socket.close()
    client_socket.close()
    return render_template('index.html')



@app.route('/Symmetric', methods=['POST'])
def Symmetric():
    data = request.get_json()
    message = data['message']

    # Create a socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost', 12341)
    client_socket.connect(server_address)

    # Define hardcoded public keys for the client and server
    client_public_key = 7  # Replace with a real public key
    server_public_key = 5  # Replace with a real public key

    # Send the client's public key to the server
    client_socket.send(str(client_public_key).encode())

    print("Waiting for the server to send the secret...")

    # Receive the server's public key
    server_public_key_received = int(client_socket.recv(1024).decode())

    # Calculate the shared secret
    shared_secret = (server_public_key_received * client_public_key) % 23  # Replace 23 with your prime number

    print("Shared Secret:", shared_secret)

    if shared_secret == 12:  # Replace 12 with the expected shared secret
        print("Key exchange successful. Secrets match.")
        print("Sending an encrypted message to the server...")

        # Derive an encryption key from the shared secret using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            iterations=100000,
            salt=b'',
            length=32,
        )
        encryption_key = base64.urlsafe_b64encode(kdf.derive(shared_secret.to_bytes(32, byteorder='big')))

        # Calculate the SHA-256 hash of the message
        message_hash = hashlib.sha256(message.encode()).digest()
        print("Message Hash: ", message_hash)

        # Append the hash to the message
        message_with_hash = message.encode() + message_hash

        # Encrypt the message with the hash
        cipher = Fernet(encryption_key)
        encrypted_message = cipher.encrypt(message_with_hash)
        print("Encrypted Message: ", encrypted_message)
        client_socket.send(encrypted_message)

    else:
        print("Key exchange failed. Secrets do not match.")

    return redirect(url_for('index'))


@app.route('/Asymmetric', methods=['POST'])
def Asymmetric():
    data2 = request.get_json()
    message = data2['message']
    message=message.encode('utf-8')

    # Function to encrypt data using the RSA public key
    def encrypt_data(data, public_key):
        encrypted_data = public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_data

    # Function to hash data using SHA-256
    def hash_data(data):
        digest = hashes.Hash(SHA256())
        digest.update(data)
        return digest.finalize()

    # Create an RSA key pair for the client
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Serialize the public key
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Create a socket and connect to the server
    host = 'localhost'
    port = 12339
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))

    # Send the client's public key to the server
    client_socket.send(public_key_pem)

    # Receive the server's public key
    server_public_key_pem = client_socket.recv(2048)

    # Load the server's public key
    server_public_key = serialization.load_pem_public_key(server_public_key_pem)

    # Wait for the key exchange to complete
    print("Key exchange completed. Sending encrypted and hashed message...")

    # Message to be hashed, concatenated, and encrypted
    hash_value = hash_data(message)

    # Concatenate the message and the hash
    message_to_send = message + b'\n' + hash_value

    # Encrypt the message using the server's public key
    encrypted_message = encrypt_data(message_to_send, server_public_key)
    print(encrypted_message)
    # Send the encrypted message to the server
    client_socket.send(encrypted_message)

    # Close the socket
    client_socket.close()

    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)
