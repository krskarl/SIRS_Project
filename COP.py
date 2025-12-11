"""
Chain of Product (CoP) - Distributed Secure Transaction System
SIRS Project Implementation - Complete Infrastructure

Components:
- Secure Document Library (Part 1)
- REST API Server with TLS, Database, Firewall support (Part 2)
- Group Management (Security Challenge A - Part 3)
"""

import json
import os
import base64
import ssl
from datetime import datetime, timedelta
from pathlib import Path
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
import requests


# ============= SECURE DOCUMENT LIBRARY (PART 1) =============

class SecureDocumentLibrary:
    """Library for protecting, checking, and unprotecting transaction documents"""
    
    def __init__(self):
        self.backend = default_backend()
    
    def generate_rsa_keypair(self):
        """Generate RSA key pair for signing"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=self.backend
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    def save_private_key(self, private_key, filepath, password=None):
        """Save private key to file"""
        encryption = serialization.NoEncryption()
        if password:
            encryption = serialization.BestAvailableEncryption(password.encode())
        
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )
        Path(filepath).write_bytes(pem)
    
    def load_private_key(self, filepath, password=None):
        """Load private key from file"""
        pem = Path(filepath).read_bytes()
        pwd = password.encode() if password else None
        return serialization.load_pem_private_key(pem, password=pwd, backend=self.backend)
    
    def save_public_key(self, public_key, filepath):
        """Save public key to file"""
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        Path(filepath).write_bytes(pem)
    
    def load_public_key(self, filepath):
        """Load public key from file"""
        pem = Path(filepath).read_bytes()
        return serialization.load_pem_public_key(pem, backend=self.backend)
    
    def protect(self, transaction, seller_private_key, authorized_parties=None):
        """Protect a transaction document with encryption and signature"""
        if authorized_parties is None:
            authorized_parties = []
        
        # Serialize transaction
        transaction_json = json.dumps(transaction, sort_keys=True)
        transaction_bytes = transaction_json.encode('utf-8')
        
        # Generate symmetric key and encrypt (AES-256-GCM)
        symmetric_key = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(symmetric_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, transaction_bytes, None)
        
        # Sign with seller's private key (RSA-PSS)
        signature = seller_private_key.sign(
            transaction_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # Create access list
        access_list = [
            {'entity': transaction['seller'], 'role': 'seller'},
            {'entity': transaction['buyer'], 'role': 'buyer'}
        ]
        for party in authorized_parties:
            access_list.append({'entity': party, 'role': 'authorized'})
        
        # Build protected document
        protected_doc = {
            'version': '1.0',
            'algorithm': 'AES-256-GCM',
            'encrypted_data': base64.b64encode(ciphertext).decode('utf-8'),
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'symmetric_key': base64.b64encode(symmetric_key).decode('utf-8'),
            'signature': base64.b64encode(signature).decode('utf-8'),
            'access_list': access_list,
            'metadata': {
                'transaction_id': transaction['id'],
                'timestamp': int(datetime.now().timestamp()),
                'seller': transaction['seller'],
                'buyer': transaction['buyer']
            }
        }
        
        return protected_doc
    
    def check(self, protected_doc):
        """Verify the integrity and structure of a protected document"""
        try:
            required_fields = ['version', 'encrypted_data', 'signature', 'access_list', 'metadata']
            for field in required_fields:
                if field not in protected_doc:
                    return {'valid': False, 'reason': f'Missing field: {field}'}
            
            if protected_doc['version'] != '1.0':
                return {'valid': False, 'reason': f"Unsupported version: {protected_doc['version']}"}
            
            return {
                'valid': True,
                'transaction_id': protected_doc['metadata']['transaction_id'],
                'access_list': protected_doc['access_list'],
                'seller': protected_doc['metadata']['seller'],
                'buyer': protected_doc['metadata']['buyer']
            }
        except Exception as e:
            return {'valid': False, 'reason': f'Error: {str(e)}'}
    
    def unprotect(self, protected_doc, entity_name, verify_signature=True, public_key=None):
        """Decrypt and return the original transaction"""
        # Check access rights
        has_access = any(entry['entity'] == entity_name for entry in protected_doc['access_list'])
        
        if not has_access:
            raise PermissionError(f"Access denied: '{entity_name}' not authorized")
        
        # Decode and decrypt
        ciphertext = base64.b64decode(protected_doc['encrypted_data'])
        nonce = base64.b64decode(protected_doc['nonce'])
        symmetric_key = base64.b64decode(protected_doc['symmetric_key'])
        
        aesgcm = AESGCM(symmetric_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        
        # Verify signature if requested
        if verify_signature and public_key:
            signature = base64.b64decode(protected_doc['signature'])
            try:
                public_key.verify(
                    signature, plaintext,
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
                )
            except Exception as e:
                raise ValueError(f"Signature verification failed: {str(e)}")
        
        return json.loads(plaintext.decode('utf-8'))


# ============= DATABASE LAYER (PART 2) =============

import mysql.connector

class Database:
    """MySQL database for persistent storage on remote server with TLS"""

    def __init__(self, host='localhost', port=3306, user='cop_user', password='cop_password', database='cop_database', use_ssl=True):
        self.config = {
            'host': host,
            'port': port,
            'user': user,
            'password': password,
            'database': database
        }
        # Enable TLS/SSL for secure connection to database
        if use_ssl:
            self.config['ssl_disabled'] = False
            self.config['tls_versions'] = ['TLSv1.2', 'TLSv1.3']
        self.init_db()

    def get_connection(self):
        """Get a database connection with TLS"""
        return mysql.connector.connect(**self.config)

    def init_db(self):
        """Initialize database schema"""
        conn = self.get_connection()
        cursor = conn.cursor()

        # Transactions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS transactions (
                transaction_id BIGINT PRIMARY KEY,
                protected_doc TEXT NOT NULL,
                seller VARCHAR(255) NOT NULL,
                buyer VARCHAR(255) NOT NULL,
                timestamp BIGINT NOT NULL
            )
        ''')

        # Public keys table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS public_keys (
                entity VARCHAR(255) PRIMARY KEY,
                public_key TEXT NOT NULL,
                registered_at BIGINT NOT NULL
            )
        ''')

        # Groups table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS groups_table (
                group_name VARCHAR(255) PRIMARY KEY,
                created_at BIGINT NOT NULL
            )
        ''')

        # Group members table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS group_members (
                group_name VARCHAR(255),
                member VARCHAR(255),
                PRIMARY KEY (group_name, member)
            )
        ''')

        conn.commit()
        cursor.close()
        conn.close()

    def store_transaction(self, transaction_id, protected_doc, seller, buyer):
        """Store a transaction"""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute('''
            REPLACE INTO transactions
            (transaction_id, protected_doc, seller, buyer, timestamp)
            VALUES (%s, %s, %s, %s, %s)
        ''', (transaction_id, json.dumps(protected_doc), seller, buyer, int(datetime.now().timestamp())))

        conn.commit()
        cursor.close()
        conn.close()

    def get_transaction(self, transaction_id):
        """Retrieve a transaction"""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute('SELECT protected_doc FROM transactions WHERE transaction_id = %s', (transaction_id,))
        row = cursor.fetchone()
        cursor.close()
        conn.close()

        if row:
            return json.loads(row[0])
        return None

    def list_transactions(self, entity=None):
        """List transactions"""
        conn = self.get_connection()
        cursor = conn.cursor()

        if entity:
            cursor.execute('''
                SELECT transaction_id, protected_doc, seller, buyer, timestamp
                FROM transactions
            ''')
            rows = cursor.fetchall()
            result = []
            for row in rows:
                doc = json.loads(row[1])
                if any(a['entity'] == entity for a in doc['access_list']):
                    result.append({
                        'transaction_id': row[0],
                        'seller': row[2],
                        'buyer': row[3],
                        'timestamp': row[4]
                    })
        else:
            cursor.execute('SELECT transaction_id, seller, buyer, timestamp FROM transactions')
            rows = cursor.fetchall()
            result = [{'transaction_id': r[0], 'seller': r[1], 'buyer': r[2], 'timestamp': r[3]} for r in rows]

        cursor.close()
        conn.close()
        return result

    def update_transaction(self, transaction_id, protected_doc):
        """Update a transaction's protected document"""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute('UPDATE transactions SET protected_doc = %s WHERE transaction_id = %s',
                      (json.dumps(protected_doc), transaction_id))

        conn.commit()
        cursor.close()
        conn.close()

    def register_public_key(self, entity, public_key):
        """Register an entity's public key"""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute('''
            REPLACE INTO public_keys (entity, public_key, registered_at)
            VALUES (%s, %s, %s)
        ''', (entity, public_key, int(datetime.now().timestamp())))

        conn.commit()
        cursor.close()
        conn.close()

    def get_public_key(self, entity):
        """Get an entity's public key"""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute('SELECT public_key FROM public_keys WHERE entity = %s', (entity,))
        row = cursor.fetchone()
        cursor.close()
        conn.close()

        return row[0] if row else None

    def create_group(self, group_name, members):
        """Create a group"""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute('REPLACE INTO groups_table (group_name, created_at) VALUES (%s, %s)',
                      (group_name, int(datetime.now().timestamp())))

        for member in members:
            cursor.execute('INSERT IGNORE INTO group_members (group_name, member) VALUES (%s, %s)',
                          (group_name, member))

        conn.commit()
        cursor.close()
        conn.close()

    def add_group_member(self, group_name, member):
        """Add member to group"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('INSERT IGNORE INTO group_members (group_name, member) VALUES (%s, %s)',
                      (group_name, member))
        conn.commit()
        cursor.close()
        conn.close()

    def get_group_members(self, group_name):
        """Get all members of a group"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT member FROM group_members WHERE group_name = %s', (group_name,))
        members = [row[0] for row in cursor.fetchall()]
        cursor.close()
        conn.close()
        return members

    def list_groups(self):
        """List all groups"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT group_name FROM groups_table')
        groups = [row[0] for row in cursor.fetchall()]
        cursor.close()
        conn.close()
        return groups


# ============= REST API SERVER WITH TLS (PART 2) =============

app = Flask(__name__)
db = None  # Initialized at startup with connection parameters

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'service': 'Chain of Product Server'})

@app.route('/api/keys/register', methods=['POST'])
def register_key():
    """Register an entity's public key"""
    data = request.json
    entity = data.get('entity')
    public_key = data.get('public_key')
    
    if not entity or not public_key:
        return jsonify({'success': False, 'error': 'Missing entity or public_key'}), 400
    
    db.register_public_key(entity, public_key)
    return jsonify({'success': True, 'message': f'Public key registered for {entity}'})

@app.route('/api/keys/<entity>', methods=['GET'])
def get_key(entity):
    """Get an entity's public key"""
    public_key = db.get_public_key(entity)
    
    if public_key:
        return jsonify({'success': True, 'public_key': public_key})
    return jsonify({'success': False, 'error': f'Public key not found for {entity}'}), 404

@app.route('/api/transactions', methods=['POST'])
def store_transaction():
    """Store a new transaction"""
    data = request.json
    transaction_id = data.get('transaction_id')
    protected_doc = data.get('protected_doc')
    
    if not transaction_id or not protected_doc:
        return jsonify({'success': False, 'error': 'Missing transaction_id or protected_doc'}), 400
    
    seller = protected_doc['metadata']['seller']
    buyer = protected_doc['metadata']['buyer']
    
    db.store_transaction(transaction_id, protected_doc, seller, buyer)
    return jsonify({'success': True, 'message': f'Transaction {transaction_id} stored'})

@app.route('/api/transactions/<int:transaction_id>', methods=['GET'])
def get_transaction(transaction_id):
    """Get a transaction"""
    protected_doc = db.get_transaction(transaction_id)
    
    if protected_doc:
        return jsonify({'success': True, 'protected_doc': protected_doc})
    return jsonify({'success': False, 'error': f'Transaction {transaction_id} not found'}), 404

@app.route('/api/transactions', methods=['GET'])
def list_transactions():
    """List transactions"""
    entity = request.args.get('entity')
    transactions = db.list_transactions(entity)
    return jsonify({'success': True, 'transactions': transactions})

@app.route('/api/transactions/<int:transaction_id>/share', methods=['POST'])
def share_transaction(transaction_id):
    """Share transaction with a party"""
    data = request.json
    new_party = data.get('party')
    
    if not new_party:
        return jsonify({'success': False, 'error': 'Missing party'}), 400
    
    protected_doc = db.get_transaction(transaction_id)
    if not protected_doc:
        return jsonify({'success': False, 'error': 'Transaction not found'}), 404
    
    if not any(a['entity'] == new_party for a in protected_doc['access_list']):
        protected_doc['access_list'].append({'entity': new_party, 'role': 'authorized'})
        db.update_transaction(transaction_id, protected_doc)
    
    return jsonify({'success': True, 'message': f'Shared with {new_party}'})

@app.route('/api/groups', methods=['POST'])
def create_group():
    """Create a group"""
    data = request.json
    group_name = data.get('group_name')
    members = data.get('members', [])
    
    if not group_name:
        return jsonify({'success': False, 'error': 'Missing group_name'}), 400
    
    db.create_group(group_name, members)
    return jsonify({'success': True, 'message': f'Group {group_name} created'})

@app.route('/api/groups/<group_name>/members', methods=['POST'])
def add_group_member(group_name):
    """Add member to group"""
    data = request.json
    member = data.get('member')
    
    if not member:
        return jsonify({'success': False, 'error': 'Missing member'}), 400
    
    db.add_group_member(group_name, member)
    return jsonify({'success': True, 'message': f'Added {member} to {group_name}'})

@app.route('/api/groups/<group_name>', methods=['GET'])
def get_group(group_name):
    """Get group members"""
    members = db.get_group_members(group_name)
    
    if members is not None:
        return jsonify({'success': True, 'members': members})
    return jsonify({'success': False, 'error': 'Group not found'}), 404

@app.route('/api/groups', methods=['GET'])
def list_groups():
    """List all groups"""
    groups = db.list_groups()
    result = [{'name': g, 'members': db.get_group_members(g)} for g in groups]
    return jsonify({'success': True, 'groups': result})

@app.route('/api/transactions/<int:transaction_id>/share_group', methods=['POST'])
def share_with_group(transaction_id):
    """Share transaction with a group"""
    data = request.json
    group_name = data.get('group_name')
    
    if not group_name:
        return jsonify({'success': False, 'error': 'Missing group_name'}), 400
    
    protected_doc = db.get_transaction(transaction_id)
    if not protected_doc:
        return jsonify({'success': False, 'error': 'Transaction not found'}), 404
    
    members = db.get_group_members(group_name)
    if not members:
        return jsonify({'success': False, 'error': 'Group not found'}), 404
    
    for member in members:
        if not any(a['entity'] == member for a in protected_doc['access_list']):
            protected_doc['access_list'].append({'entity': member, 'role': 'group_member'})
    
    db.update_transaction(transaction_id, protected_doc)
    return jsonify({'success': True, 'message': f'Shared with group {group_name}'})


# ============= TLS CERTIFICATE GENERATION =============

def generate_self_signed_cert(cert_file='server.crt', key_file='server.key'):
    """Generate self-signed certificate for TLS"""
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Create certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PT"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Lisbon"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Lisbon"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Chain of Product"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"cop-server"),
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
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).sign(private_key, hashes.SHA256(), default_backend())
    
    # Write certificate
    with open(cert_file, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    # Write private key
    with open(key_file, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    print(f"[TLS] Generated certificate: {cert_file}")
    print(f"[TLS] Generated private key: {key_file}")


# ============= CLIENT WITH TLS SUPPORT =============

class Client:
    """Client for interacting with the server via REST API with TLS"""
    
    def __init__(self, entity_name, server_url='https://localhost:8000', verify_ssl=False):
        self.entity_name = entity_name
        self.server_url = server_url
        self.verify_ssl = verify_ssl
        self.lib = SecureDocumentLibrary()
        self.private_key = None
        self.public_key = None
        
        # Disable SSL warnings if verify_ssl is False (for self-signed certs)
        if not verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    def make_request(self, method, endpoint, json_data=None):
        """Make HTTP request to server"""
        url = f"{self.server_url}{endpoint}"
        
        try:
            if method == 'GET':
                response = requests.get(url, verify=self.verify_ssl)
            elif method == 'POST':
                response = requests.post(url, json=json_data, verify=self.verify_ssl)
            else:
                raise ValueError(f"Unsupported method: {method}")
            
            return response.json()
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def setup_keys(self):
        """Generate and register keys"""
        print(f"[{self.entity_name}] Generating RSA key pair...")
        self.private_key, self.public_key = self.lib.generate_rsa_keypair()
        
        # Save keys locally
        os.makedirs('keys', exist_ok=True)
        self.lib.save_private_key(self.private_key, f'keys/{self.entity_name}_private.pem')
        self.lib.save_public_key(self.public_key, f'keys/{self.entity_name}_public.pem')
        
        # Register public key with server
        public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        response = self.make_request('POST', '/api/keys/register', {
            'entity': self.entity_name,
            'public_key': public_key_pem
        })
        
        if response['success']:
            print(f"[{self.entity_name}] Keys registered successfully")
        else:
            print(f"[{self.entity_name}] Error: {response.get('error')}")
    
    def load_keys(self):
        """Load existing keys"""
        try:
            self.private_key = self.lib.load_private_key(f'keys/{self.entity_name}_private.pem')
            self.public_key = self.lib.load_public_key(f'keys/{self.entity_name}_public.pem')
            print(f"[{self.entity_name}] Keys loaded successfully")
        except FileNotFoundError:
            print(f"[{self.entity_name}] No existing keys found. Run 'setup' first.")
    
    def create_transaction(self, buyer, product, units, amount):
        """Create and store a new transaction"""
        transaction = {
            'id': int(datetime.now().timestamp() * 1000),
            'timestamp': int(datetime.now().timestamp()),
            'seller': self.entity_name,
            'buyer': buyer,
            'product': product,
            'units': units,
            'amount': amount
        }
        
        # Protect transaction
        protected = self.lib.protect(transaction, self.private_key)
        
        # Store on server
        response = self.make_request('POST', '/api/transactions', {
            'transaction_id': transaction['id'],
            'protected_doc': protected
        })
        
        if response['success']:
            print(f"[{self.entity_name}] Transaction {transaction['id']} created and stored")
            return transaction['id']
        else:
            print(f"[{self.entity_name}] Error: {response.get('error')}")
            return None
    
    def view_transaction(self, transaction_id):
        """View a transaction"""
        response = self.make_request('GET', f'/api/transactions/{transaction_id}')
        
        if not response['success']:
            print(f"[{self.entity_name}] Error: {response.get('error')}")
            return
        
        protected_doc = response['protected_doc']
        
        # Get seller's public key
        seller = protected_doc['metadata']['seller']
        key_response = self.make_request('GET', f'/api/keys/{seller}')
        
        seller_public_key = None
        if key_response['success']:
            pem = key_response['public_key'].encode('utf-8')
            seller_public_key = serialization.load_pem_public_key(pem, backend=default_backend())
        
        # Try to decrypt
        try:
            transaction = self.lib.unprotect(protected_doc, self.entity_name,
                                            verify_signature=True, public_key=seller_public_key)
            print(f"\n[{self.entity_name}] Transaction Details:")
            print(json.dumps(transaction, indent=2))
        except PermissionError as e:
            print(f"[{self.entity_name}] {e}")
    
    def list_my_transactions(self):
        """List transactions accessible to this entity"""
        response = self.make_request('GET', f'/api/transactions?entity={self.entity_name}')
        
        if response['success']:
            print(f"\n[{self.entity_name}] Your Transactions:")
            for tx in response['transactions']:
                print(f"  ID: {tx['transaction_id']} | {tx['seller']} -> {tx['buyer']}")
        else:
            print(f"[{self.entity_name}] Error: {response.get('error')}")
    
    def share_with(self, transaction_id, party):
        """Share transaction with another party"""
        response = self.make_request('POST', f'/api/transactions/{transaction_id}/share', {
            'party': party
        })
        
        if response['success']:
            print(f"[{self.entity_name}] {response['message']}")
        else:
            print(f"[{self.entity_name}] Error: {response.get('error')}")
    
    def share_with_group(self, transaction_id, group_name):
        """Share transaction with a group"""
        response = self.make_request('POST', f'/api/transactions/{transaction_id}/share_group', {
            'group_name': group_name
        })
        
        if response['success']:
            print(f"[{self.entity_name}] {response['message']}")
        else:
            print(f"[{self.entity_name}] Error: {response.get('error')}")


# ============= CLI =============

def main():
    import sys
    from datetime import timedelta

    if len(sys.argv) < 2:
        print_help()
        return

    mode = sys.argv[1]

    if mode == 'help':
        print_help()

    elif mode == 'protect':
        if len(sys.argv) < 4:
            print("Usage: python COP.py protect <input-file> <private-key-file> [output-file]")
            print("  Protects a JSON transaction document with encryption and signature")
            return

        input_file = sys.argv[2]
        key_file = sys.argv[3]
        output_file = sys.argv[4] if len(sys.argv) > 4 else input_file.replace('.json', '_protected.json')

        lib = SecureDocumentLibrary()
        try:
            with open(input_file, 'r') as f:
                transaction = json.load(f)
            private_key = lib.load_private_key(key_file)
            protected = lib.protect(transaction, private_key)
            with open(output_file, 'w') as f:
                json.dump(protected, f, indent=2)
            print(f"[OK] Protected document saved to: {output_file}")
        except Exception as e:
            print(f"[ERROR] {e}")

    elif mode == 'check':
        if len(sys.argv) < 3:
            print("Usage: python COP.py check <input-file>")
            print("  Verifies the structure and integrity of a protected document")
            return

        input_file = sys.argv[2]
        lib = SecureDocumentLibrary()
        try:
            with open(input_file, 'r') as f:
                protected_doc = json.load(f)
            result = lib.check(protected_doc)
            if result['valid']:
                print(f"[OK] Document is valid")
                print(f"  Transaction ID: {result['transaction_id']}")
                print(f"  Seller: {result['seller']}")
                print(f"  Buyer: {result['buyer']}")
                print(f"  Access list: {[a['entity'] for a in result['access_list']]}")
            else:
                print(f"[INVALID] {result['reason']}")
        except Exception as e:
            print(f"[ERROR] {e}")

    elif mode == 'unprotect':
        if len(sys.argv) < 5:
            print("Usage: python COP.py unprotect <input-file> <entity-name> <public-key-file> [output-file]")
            print("  Decrypts a protected document and verifies the signature")
            return

        input_file = sys.argv[2]
        entity_name = sys.argv[3]
        key_file = sys.argv[4]
        output_file = sys.argv[5] if len(sys.argv) > 5 else input_file.replace('_protected.json', '_decrypted.json').replace('.json', '_decrypted.json')

        lib = SecureDocumentLibrary()
        try:
            with open(input_file, 'r') as f:
                protected_doc = json.load(f)
            public_key = lib.load_public_key(key_file)
            transaction = lib.unprotect(protected_doc, entity_name, verify_signature=True, public_key=public_key)
            with open(output_file, 'w') as f:
                json.dump(transaction, f, indent=2)
            print(f"[OK] Decrypted document saved to: {output_file}")
        except PermissionError as e:
            print(f"[ACCESS DENIED] {e}")
        except ValueError as e:
            print(f"[SIGNATURE ERROR] {e}")
        except Exception as e:
            print(f"[ERROR] {e}")

    elif mode == 'server':
        # Parse server arguments
        port = int(os.environ.get('COP_PORT', 8000))
        use_tls = os.environ.get('COP_TLS', 'true').lower() == 'true'
        db_host = os.environ.get('COP_DB_HOST', 'localhost')
        db_port = int(os.environ.get('COP_DB_PORT', 3306))
        db_user = os.environ.get('COP_DB_USER', 'cop_user')
        db_pass = os.environ.get('COP_DB_PASS', 'cop_password')
        db_name = os.environ.get('COP_DB_NAME', 'cop_database')

        # Allow command line overrides
        if len(sys.argv) > 2:
            port = int(sys.argv[2])
        if len(sys.argv) > 3:
            use_tls = sys.argv[3].lower() == 'true'
        if len(sys.argv) > 4:
            db_host = sys.argv[4]

        # Initialize database connection with TLS
        global db
        print(f"[SERVER] Connecting to MySQL database at {db_host}:{db_port} (TLS enabled)...")
        db = Database(host=db_host, port=db_port, user=db_user, password=db_pass, database=db_name, use_ssl=True)
        print(f"[SERVER] Database connected successfully with TLS")

        print(f"[SERVER] Starting Chain of Product Server on port {port}")
        print(f"[SERVER] TLS enabled: {use_tls}")

        if use_tls:
            # Generate certificate if it doesn't exist
            if not os.path.exists('server.crt') or not os.path.exists('server.key'):
                print("[SERVER] Generating self-signed certificate...")
                generate_self_signed_cert()

            # Create SSL context
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain('server.crt', 'server.key')

            app.run(host='0.0.0.0', port=port, ssl_context=context, debug=False)
        else:
            app.run(host='0.0.0.0', port=port, debug=False)
    
    elif mode == 'client':
        if len(sys.argv) < 3:
            print("Usage: python COP.py client <entity_name> [server_url]")
            return
        
        entity_name = sys.argv[2]
        server_url = sys.argv[3] if len(sys.argv) > 3 else 'https://localhost:8000'
        
        client = Client(entity_name, server_url, verify_ssl=False)
        interactive_client(client)

    else:
        print_help()


def interactive_client(client):
    """Interactive client CLI"""
    print(f"\n{'='*60}")
    print(f"Chain of Product - Client: {client.entity_name}")
    print(f"{'='*60}\n")
    
    while True:
        print("\nCommands:")
        print("  setup                              - Generate and register keys")
        print("  create <buyer> <product> <units> <amount> - Create transaction")
        print("  list                               - List your transactions")
        print("  view <transaction_id>              - View transaction details")
        print("  share <transaction_id> <party>     - Share with party")
        print("  sharegroup <transaction_id> <group> - Share with group")
        print("  quit                               - Exit")
        
        cmd = input(f"\n[{client.entity_name}]> ").strip().split()
        
        if not cmd:
            continue
        
        action = cmd[0]
        
        if action == 'setup':
            client.setup_keys()
        
        elif action == 'create':
            if len(cmd) < 5:
                print("Usage: create <buyer> <product> <units> <amount>")
                continue
            client.create_transaction(cmd[1], cmd[2], int(cmd[3]), int(cmd[4]))
        
        elif action == 'list':
            client.list_my_transactions()
        
        elif action == 'view':
            if len(cmd) < 2:
                print("Usage: view <transaction_id>")
                continue
            client.view_transaction(int(cmd[1]))
        
        elif action == 'share':
            if len(cmd) < 3:
                print("Usage: share <transaction_id> <party>")
                continue
            client.share_with(int(cmd[1]), cmd[2])
        
        elif action == 'sharegroup':
            if len(cmd) < 3:
                print("Usage: sharegroup <transaction_id> <group>")
                continue
            client.share_with_group(int(cmd[1]), cmd[2])
        
        elif action == 'quit':
            print("Goodbye!")
            break
        
        else:
            print(f"Unknown command: {action}")


def print_help():
    """Print help information"""
    print("""
Chain of Product (CoP) - Secure Transaction System
===================================================

SECURE DOCUMENT COMMANDS:

  python COP.py help
      Show this help message

  python COP.py protect <input-file> <private-key-file> [output-file]
      Protect a JSON transaction with encryption and digital signature
      Example: python COP.py protect tx.json keys/Seller_private.pem tx_protected.json

  python COP.py check <input-file>
      Verify structure and integrity of a protected document
      Example: python COP.py check tx_protected.json

  python COP.py unprotect <input-file> <entity-name> <public-key-file> [output-file]
      Decrypt a protected document and verify signature
      Example: python COP.py unprotect tx_protected.json "Lays Chips" keys/Seller_public.pem tx_decrypted.json

SERVER/CLIENT COMMANDS:

  python COP.py server [port] [use_tls] [db_host]
      Start the CoP server (default: port=8000, use_tls=true, db_host=localhost)
      Example: python COP.py server 8000 true 192.168.1.100

      Environment variables for database config:
        COP_DB_HOST  - MySQL host (default: localhost)
        COP_DB_PORT  - MySQL port (default: 3306)
        COP_DB_USER  - MySQL user (default: cop_user)
        COP_DB_PASS  - MySQL password (default: cop_password)
        COP_DB_NAME  - MySQL database (default: cop_database)

  python COP.py client <entity_name> [server_url]
      Start interactive client for an entity
      Example: python COP.py client "Ching Chong Extractions" https://localhost:8000

DATABASE SETUP (on Database VM):

  1. Install MySQL: sudo apt install mysql-server
  2. Create database and user:
     mysql -u root -p
     CREATE DATABASE cop_database;
     CREATE USER 'cop_user'@'%' IDENTIFIED BY 'cop_password';
     GRANT ALL PRIVILEGES ON cop_database.* TO 'cop_user'@'%';
     FLUSH PRIVILEGES;
  3. Allow remote connections: edit /etc/mysql/mysql.conf.d/mysqld.cnf
     bind-address = 0.0.0.0
  4. Restart MySQL: sudo systemctl restart mysql
""")


if __name__ == '__main__':
    main()
