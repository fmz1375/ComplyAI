import os
import ssl
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
from datetime import timedelta
import secrets

app = Flask(__name__)

# Configure JWT
app.config['JWT_SECRET_KEY'] = secrets.token_hex(32)  # Generate a random secret key
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)  # Token expires in 1 hour
jwt = JWTManager(app)

# Generate self-signed certificate if not exists
CERT_FILE = 'cert.pem'
KEY_FILE = 'key.pem'

def generate_self_signed_cert():
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    import datetime

    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Create certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "UAE"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Test"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Test"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        ]),
        critical=False,
    ).sign(private_key, hashes.SHA256(), default_backend())

    # Write certificate and key
    with open(CERT_FILE, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    with open(KEY_FILE, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

if not os.path.exists(CERT_FILE) or not os.path.exists(KEY_FILE):
    try:
        import cryptography
        import ipaddress
        generate_self_signed_cert()
    except ImportError:
        print("Cryptography library not installed. Please install with: pip install cryptography")
        exit(1)

# Create SSL context with TLS 1.3 support
ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
ssl_context.load_cert_chain(CERT_FILE, KEY_FILE)
ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3
ssl_context.maximum_version = ssl.TLSVersion.TLSv1_3

# In-memory user store per tenant (for demo purposes)
# Structure: {tenant_id: {username: password}}
users = {
    "tenant1": {"admin": "password", "user1": "pass1"},
    "tenant2": {"admin": "password", "user2": "pass2"},
}

@app.route('/login', methods=['POST'])
def login():
    tenant_id = request.headers.get('X-Tenant-ID')
    if not tenant_id:
        return jsonify({"msg": "Tenant ID required in X-Tenant-ID header"}), 400

    username = request.json.get('username')
    password = request.json.get('password')

    tenant_users = users.get(tenant_id)
    if not tenant_users:
        return jsonify({"msg": "Invalid tenant"}), 401

    if username in tenant_users and tenant_users[username] == password:
        access_token = create_access_token(identity=username, additional_claims={"tenant_id": tenant_id})
        return jsonify(access_token=access_token, tenant_id=tenant_id), 200
    else:
        return jsonify({"msg": "Bad username or password"}), 401

@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    claims = get_jwt()
    tenant_id = claims.get('tenant_id')
    return jsonify(logged_in_as=current_user, tenant_id=tenant_id), 200

@app.route('/generate_token', methods=['POST'])
@jwt_required()
def generate_token():
    # This endpoint allows generating a new token for another user or purpose
    # For demo, just regenerate for current user
    current_user = get_jwt_identity()
    claims = get_jwt()
    tenant_id = claims.get('tenant_id')
    new_token = create_access_token(identity=current_user, additional_claims={"tenant_id": tenant_id})
    return jsonify(new_token=new_token, tenant_id=tenant_id), 200

@app.route('/validate_token', methods=['POST'])
@jwt_required()
def validate_token():
    current_user = get_jwt_identity()
    claims = get_jwt()
    tenant_id = claims.get('tenant_id')
    return jsonify(valid=True, user=current_user, tenant_id=tenant_id), 200

@app.route('/tenant_info', methods=['GET'])
@jwt_required()
def tenant_info():
    claims = get_jwt()
    tenant_id = claims.get('tenant_id')
    tenant_users = users.get(tenant_id, {})
    return jsonify(tenant_id=tenant_id, users=list(tenant_users.keys())), 200

if __name__ == '__main__':
    print("Starting multi-tenant server with TLS 1.3...")
    print("Certificate files:", CERT_FILE, KEY_FILE)
    print("Note: Browser will show security warning for self-signed certificate.")
    print("Use X-Tenant-ID header to specify tenant (e.g., tenant1 or tenant2)")
    app.run(host='127.0.0.1', port=5000, ssl_context=ssl_context, debug=True)
<parameter name="filePath">c:\ssl_session_script.py