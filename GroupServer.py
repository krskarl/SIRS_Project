"""
Group Management Server - Security Challenge A
Separate server that dynamically tracks groups and members.
"""

import json
import os
import ssl
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
import mysql.connector

app = Flask(__name__)
db_config = None


def get_connection():
    """Get database connection with TLS"""
    config = db_config.copy()
    config['ssl_disabled'] = False
    config['tls_versions'] = ['TLSv1.2', 'TLSv1.3']
    return mysql.connector.connect(**config)


def init_db():
    """Initialize group tables"""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS groups_table (
            group_name VARCHAR(255) PRIMARY KEY,
            created_at BIGINT NOT NULL
        )
    ''')

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


@app.route('/health', methods=['GET'])
def health():
    """Health check"""
    return jsonify({'status': 'healthy', 'service': 'Group Management Server'})


@app.route('/api/groups', methods=['POST'])
def create_group():
    """Create a new group"""
    data = request.json
    group_name = data.get('group_name')
    members = data.get('members', [])

    if not group_name:
        return jsonify({'success': False, 'error': 'Missing group_name'}), 400

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute('REPLACE INTO groups_table (group_name, created_at) VALUES (%s, %s)',
                  (group_name, int(datetime.now().timestamp())))

    for member in members:
        cursor.execute('INSERT IGNORE INTO group_members (group_name, member) VALUES (%s, %s)',
                      (group_name, member))

    conn.commit()
    cursor.close()
    conn.close()

    print(f"[GROUP SERVER] Created group '{group_name}' with members: {members}")
    return jsonify({'success': True, 'message': f'Group {group_name} created'})


@app.route('/api/groups/<group_name>/members', methods=['POST'])
def add_member(group_name):
    """Add member to group"""
    data = request.json
    member = data.get('member')

    if not member:
        return jsonify({'success': False, 'error': 'Missing member'}), 400

    conn = get_connection()
    cursor = conn.cursor()

    # Check if group exists
    cursor.execute('SELECT group_name FROM groups_table WHERE group_name = %s', (group_name,))
    if not cursor.fetchone():
        cursor.close()
        conn.close()
        return jsonify({'success': False, 'error': 'Group not found'}), 404

    cursor.execute('INSERT IGNORE INTO group_members (group_name, member) VALUES (%s, %s)',
                  (group_name, member))

    conn.commit()
    cursor.close()
    conn.close()

    print(f"[GROUP SERVER] Added '{member}' to group '{group_name}'")
    return jsonify({'success': True, 'message': f'Added {member} to {group_name}'})


@app.route('/api/groups/<group_name>/members', methods=['DELETE'])
def remove_member(group_name):
    """Remove member from group"""
    data = request.json
    member = data.get('member')

    if not member:
        return jsonify({'success': False, 'error': 'Missing member'}), 400

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute('DELETE FROM group_members WHERE group_name = %s AND member = %s',
                  (group_name, member))

    conn.commit()
    cursor.close()
    conn.close()

    print(f"[GROUP SERVER] Removed '{member}' from group '{group_name}'")
    return jsonify({'success': True, 'message': f'Removed {member} from {group_name}'})


@app.route('/api/groups/<group_name>', methods=['GET'])
def get_group(group_name):
    """Get group members - called by main server when sharing"""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT group_name FROM groups_table WHERE group_name = %s', (group_name,))
    if not cursor.fetchone():
        cursor.close()
        conn.close()
        return jsonify({'success': False, 'error': 'Group not found'}), 404

    cursor.execute('SELECT member FROM group_members WHERE group_name = %s', (group_name,))
    members = [row[0] for row in cursor.fetchall()]

    cursor.close()
    conn.close()

    print(f"[GROUP SERVER] Queried group '{group_name}': {members}")
    return jsonify({'success': True, 'group_name': group_name, 'members': members})


@app.route('/api/groups/<group_name>', methods=['DELETE'])
def delete_group(group_name):
    """Delete a group"""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute('DELETE FROM group_members WHERE group_name = %s', (group_name,))
    cursor.execute('DELETE FROM groups_table WHERE group_name = %s', (group_name,))

    conn.commit()
    cursor.close()
    conn.close()

    print(f"[GROUP SERVER] Deleted group '{group_name}'")
    return jsonify({'success': True, 'message': f'Group {group_name} deleted'})


@app.route('/api/groups', methods=['GET'])
def list_groups():
    """List all groups"""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT group_name FROM groups_table')
    groups = []
    for row in cursor.fetchall():
        group_name = row[0]
        cursor.execute('SELECT member FROM group_members WHERE group_name = %s', (group_name,))
        members = [m[0] for m in cursor.fetchall()]
        groups.append({'name': group_name, 'members': members})

    cursor.close()
    conn.close()

    return jsonify({'success': True, 'groups': groups})


def generate_self_signed_cert(cert_file='group_server.crt', key_file='group_server.key'):
    """Generate self-signed certificate for TLS"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PT"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Lisbon"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Lisbon"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Chain of Product"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"group-server"),
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

    with open(cert_file, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    with open(key_file, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    print(f"[TLS] Generated certificate: {cert_file}")
    print(f"[TLS] Generated private key: {key_file}")


def main():
    import sys
    global db_config

    # Default configuration
    port = int(os.environ.get('GROUP_SERVER_PORT', 8001))
    use_tls = os.environ.get('GROUP_SERVER_TLS', 'true').lower() == 'true'
    db_host = os.environ.get('COP_DB_HOST', 'localhost')
    db_port = int(os.environ.get('COP_DB_PORT', 3306))
    db_user = os.environ.get('COP_DB_USER', 'cop_user')
    db_pass = os.environ.get('COP_DB_PASS', 'cop_password')
    db_name = os.environ.get('COP_DB_NAME', 'cop_database')

    # Command line overrides
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    if len(sys.argv) > 2:
        use_tls = sys.argv[2].lower() == 'true'
    if len(sys.argv) > 3:
        db_host = sys.argv[3]

    db_config = {
        'host': db_host,
        'port': db_port,
        'user': db_user,
        'password': db_pass,
        'database': db_name
    }

    print(f"[GROUP SERVER] Connecting to MySQL database at {db_host}:{db_port}...")
    init_db()
    print(f"[GROUP SERVER] Database connected successfully")

    print(f"[GROUP SERVER] Starting Group Management Server on port {port}")
    print(f"[GROUP SERVER] TLS enabled: {use_tls}")

    if use_tls:
        if not os.path.exists('group_server.crt') or not os.path.exists('group_server.key'):
            print("[GROUP SERVER] Generating self-signed certificate...")
            generate_self_signed_cert()

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain('group_server.crt', 'group_server.key')

        app.run(host='0.0.0.0', port=port, ssl_context=context, debug=False)
    else:
        app.run(host='0.0.0.0', port=port, debug=False)


if __name__ == '__main__':
    main()
