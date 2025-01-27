from flask import Flask, jsonify, request, render_template, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta, timezone
import logging
from logging.handlers import RotatingFileHandler
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet
import secrets

app = Flask(__name__)
app.secret_key = 'votre_clé_secrète_ici'

# Configuration des bases de données
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///packets_logs.db'
app.config['SQLALCHEMY_BINDS'] = {
    'alerts': 'sqlite:///alerts.db'
}
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Configuration avancée des logs avec rotation
log_formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s', 
                                datefmt='%Y-%m-%d %H:%M:%S')
log_handler = RotatingFileHandler('/app/logs/server.log', maxBytes=10485760, backupCount=3)
log_handler.setFormatter(log_formatter)
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
logger.addHandler(log_handler)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now(timezone.utc))
    last_login = db.Column(db.DateTime)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class PacketLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    agent_name = db.Column(db.String(100), nullable=False)
    source_ip = db.Column(db.String(50), nullable=True)
    source_mac = db.Column(db.String(50), nullable=True)
    destination_ip = db.Column(db.String(50), nullable=True)
    destination_mac = db.Column(db.String(50), nullable=True)
    packet_type = db.Column(db.String(50), nullable=True)
    timestamp = db.Column(db.DateTime, nullable=False)
    summary = db.Column(db.String(200), nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'agent_name': self.agent_name,
            'source_ip': self.source_ip,
            'source_mac': self.source_mac,
            'destination_ip': self.destination_ip,
            'destination_mac': self.destination_mac,
            'packet_type': self.packet_type,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'summary': self.summary
        }

class Alert(db.Model):
    __bind_key__ = 'alerts'
    id = db.Column(db.Integer, primary_key=True)
    alert_type = db.Column(db.String(50), nullable=False)
    agent_name = db.Column(db.String(100), nullable=False)
    packet_ids = db.Column(db.String, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.now(timezone.utc))

    def to_dict(self):
        packet_count = len(self.packet_ids.split(',')) if self.packet_ids else 0
        return {
            'id': self.id,
            'alert_type': self.alert_type,
            'agent_name': self.agent_name,
            'packet_count': packet_count,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
        }

def init_db():
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='scp').first():
            user = User(username='scp')
            user.set_password('test')
            user.created_at = datetime.now(timezone.utc)
            db.session.add(user)
            db.session.commit()
            logger.info("Utilisateur 'scp' créé avec succès")

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def analyze_packets():
    analysis_window = timedelta(seconds=1)
    current_time = datetime.now(timezone.utc)

    recent_packets = PacketLog.query.filter(
        PacketLog.timestamp >= current_time - analysis_window,
        PacketLog.packet_type == 'ARP'
    ).all()

    arp_counts = {}
    for packet in recent_packets:
        key = packet.source_ip
        arp_counts[key] = arp_counts.get(key, 0) + 1

    for source_ip, count in arp_counts.items():
        if count > 100:
            reference_packet = next((p for p in recent_packets if p.source_ip == source_ip), None)
            if reference_packet:
                alert = Alert(
                    alert_type='arp_flood',
                    agent_name=reference_packet.agent_name,
                    packet_ids=','.join(str(packet.id) for packet in recent_packets if packet.source_ip == source_ip),
                    timestamp=current_time
                )
                db.session.add(alert)
                logger.warning(f"ARP Flood détecté par l'agent {reference_packet.agent_name} pour {source_ip} avec {count} paquets/s")

    mac_to_ip = {}
    for packet in recent_packets:
        if packet.source_mac not in mac_to_ip:
            mac_to_ip[packet.source_mac] = set()
        mac_to_ip[packet.source_mac].add(packet.source_ip)

    for mac, ips in mac_to_ip.items():
        if len(ips) > 1:
            reference_packet = next((p for p in recent_packets if p.source_mac == mac), None)
            if reference_packet:
                alert = Alert(
                    alert_type='mitm',
                    agent_name=reference_packet.agent_name,
                    packet_ids=','.join(str(packet.id) for packet in recent_packets if packet.source_mac == mac),
                    timestamp=current_time
                )
                db.session.add(alert)
                logger.warning(f"Man in the Middle détecté par l'agent {reference_packet.agent_name} pour MAC {mac} avec IPs {ips}")

    db.session.commit()

class AgentRegistration(db.Model):
    __bind_key__ = 'alerts'  # Utilisation de la même base que les alertes
    id = db.Column(db.Integer, primary_key=True)
    agent_name = db.Column(db.String(100), unique=True, nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='pending')
    registration_date = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    approval_date = db.Column(db.DateTime)
    api_key = db.Column(db.String(64), unique=True)

    def generate_api_key(self):
        self.api_key = secrets.token_urlsafe(32)
        return self.api_key

    def encrypt_api_key(self):
        try:
            public_key = serialization.load_pem_public_key(self.public_key.encode())
            encrypted_key = public_key.encrypt(
                self.api_key.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return encrypted_key
        except Exception as e:
            logger.error(f"Erreur lors du chiffrement de la clé API: {e}")
            return None

# Routes de l'application

@app.route('/api/register', methods=['POST'])
def register_agent():
    try:
        data = request.json
        agent_name = data.get('agent_name')
        public_key = data.get('public_key')

        if not agent_name or not public_key:
            logger.warning("Tentative d'enregistrement avec données manquantes")
            return jsonify({'error': 'Données manquantes'}), 400

        existing_agent = AgentRegistration.query.filter_by(agent_name=agent_name).first()
        if existing_agent:
            logger.warning(f"Tentative de réenregistrement pour l'agent: {agent_name}")
            return jsonify({'error': 'Agent déjà enregistré'}), 409

        new_registration = AgentRegistration(
            agent_name=agent_name,
            public_key=public_key
        )
        db.session.add(new_registration)
        db.session.commit()

        logger.info(f"Nouvelle demande d'enregistrement pour l'agent: {agent_name}")
        return jsonify({'message': 'Demande d'enregistrement en attente de validation'})

    except Exception as e:
        logger.error(f"Erreur lors de l'enregistrement: {str(e)}")
        return jsonify({'error': 'Erreur interne'}), 500

@app.route('/api/approve-registration/<int:registration_id>', methods=['POST'])
@login_required
def approve_registration(registration_id):
    try:
        registration = AgentRegistration.query.get_or_404(registration_id)
        
        if registration.status != 'pending':
            return jsonify({'error': 'Demande déjà traitée'}), 400

        api_key = registration.generate_api_key()
        encrypted_key = registration.encrypt_api_key()
        
        if not encrypted_key:
            return jsonify({'error': 'Erreur lors du chiffrement de la clé'}), 500

        registration.status = 'approved'
        registration.approval_date = datetime.now(timezone.utc)
        db.session.commit()

        logger.info(f"Agent approuvé: {registration.agent_name}")
        return jsonify({
            'encrypted_key': encrypted_key.hex(),
            'agent_name': registration.agent_name
        })

    except Exception as e:
        logger.error(f"Erreur lors de l'approbation: {str(e)}")
        return jsonify({'error': 'Erreur interne'}), 500

@app.route('/api/registrations', methods=['GET'])
@login_required
def list_registrations():
    registrations = AgentRegistration.query.all()
    return jsonify([{
        'id': r.id,
        'agent_name': r.agent_name,
        'status': r.status,
        'registration_date': r.registration_date.strftime('%Y-%m-%d %H:%M:%S'),
        'approval_date': r.approval_date.strftime('%Y-%m-%d %H:%M:%S') if r.approval_date else None
    } for r in registrations])


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.json
        user = User.query.filter_by(username=data.get('username')).first()
        
        if user and user.check_password(data.get('password')):
            session['user_id'] = user.id
            user.last_login = datetime.now(timezone.utc)
            db.session.commit()
            return jsonify({'success': True})
        return jsonify({'error': 'Identifiants invalides'}), 401
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(10).all()
    agent_query = db.session.query(
        PacketLog.agent_name,
        db.func.max(PacketLog.timestamp).label('last_seen')
    ).group_by(PacketLog.agent_name).all()
    
    current_time = datetime.now(timezone.utc)
    agents = []
    for agent_name, last_seen in agent_query:
        is_active = (current_time - last_seen.replace(tzinfo=timezone.utc)).total_seconds() < 3600
        agents.append({
            'agent_name': agent_name,
            'last_seen': last_seen.strftime('%Y-%m-%d %H:%M:%S'),
            'is_active': is_active
        })
    return render_template('index.html', alerts=alerts, agents=agents)

@app.route('/trafic')
@login_required
def trafic():
    page = request.args.get('page', 1, type=int)
    ip_filter = request.args.get('ip', '')
    packet_type = request.args.get('type', '')
    per_page = 100

    query = PacketLog.query.order_by(PacketLog.timestamp.desc())

    if ip_filter:
        query = query.filter(
            (PacketLog.source_ip.contains(ip_filter)) |
            (PacketLog.destination_ip.contains(ip_filter))
        )
    if packet_type:
        query = query.filter(PacketLog.packet_type == packet_type)

    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    logs = pagination.items

    packet_types = db.session.query(PacketLog.packet_type).distinct().all()
    packet_types = [pt[0] for pt in packet_types if pt[0]]

    return render_template(
        'trafic.html',
        logs=logs,
        pagination=pagination,
        ip_filter=ip_filter,
        packet_type=packet_type,
        packet_types=packet_types
    )

@app.route('/statistiques')
@login_required
def statistics_page():
    return render_template('statistiques.html')

@app.route('/api/statistics')
@login_required
def get_statistics():
    one_day_ago = datetime.now(timezone.utc) - timedelta(days=1)
    
    packets_by_type = db.session.query(
        PacketLog.packet_type,
        db.func.count(PacketLog.id).label('count')
    ).group_by(PacketLog.packet_type).all()
    
    io_stats = db.session.query(
        PacketLog.agent_name,
        db.func.count(PacketLog.id).label('count')
    ).filter(PacketLog.timestamp >= one_day_ago)\
     .group_by(PacketLog.agent_name).all()
    
    top_ip_sources = db.session.query(
        PacketLog.source_ip,
        db.func.count(PacketLog.id).label('count')
    ).filter(PacketLog.source_ip.isnot(None))\
     .group_by(PacketLog.source_ip)\
     .order_by(db.func.count(PacketLog.id).desc())\
     .limit(10).all()
    
    packets_over_time = db.session.query(
        db.func.strftime('%H:%M', PacketLog.timestamp).label('time_slice'),
        db.func.count(PacketLog.id).label('count')
    ).filter(PacketLog.timestamp >= one_day_ago)\
     .group_by('time_slice')\
     .order_by('time_slice').all()

    return jsonify({
        'packets_by_type': [{'type': t[0], 'count': t[1]} for t in packets_by_type],
        'io_stats': [{'agent': s[0], 'count': s[1]} for s in io_stats],
        'top_ip_sources': [{'address': s[0], 'count': s[1]} for s in top_ip_sources],
        'packets_over_time': [{'timestamp': t[0], 'count': t[1]} for t in packets_over_time]
    })

@app.route('/api/packets_by_hour')
@login_required
def get_packets_by_hour():
    one_day_ago = datetime.now(timezone.utc) - timedelta(days=1)
    
    packets_by_hour = db.session.query(
        db.func.strftime('%H', PacketLog.timestamp).label('hour'),
        db.func.count(PacketLog.id).label('count')
    ).filter(PacketLog.timestamp >= one_day_ago)\
     .group_by('hour')\
     .order_by('hour').all()
    
    return jsonify([{'hour': h[0], 'count': h[1]} for h in packets_by_hour])

@app.route('/api/alerts', methods=['GET'])
@login_required
def get_alerts():
    alerts = Alert.query.order_by(Alert.timestamp.desc()).all()
    return jsonify([alert.to_dict() for alert in alerts])

@app.route('/api/packet_logs', methods=['GET'])
def get_packet_logs():
    logs = PacketLog.query.all()
    return jsonify([log.to_dict() for log in logs])

@app.route('/api/packet_logs', methods=['POST'])
def add_packet_logs():
    try:
        data = request.json
        agent_name = data.get('agent_name')
        
        if not agent_name:
            logger.warning("Agent name missing in request")
            return jsonify({'error': 'Agent name required'}), 400

        agent_registration = AgentRegistration.query.filter_by(
            agent_name=agent_name,
            status='approved'
        ).first()
        
        if not agent_registration:
            logger.warning(f"Unauthorized agent attempt: {agent_name}")
            return jsonify({'error': 'Agent non autorisé'}), 401
        for packet in data['packets']:
            new_log = PacketLog(
                agent_name=packet.get('agent_name'),
                source_ip=packet.get('source_ip'),
                source_mac=packet.get('source_mac'),
                destination_ip=packet.get('destination_ip'),
                destination_mac=packet.get('destination_mac'),
                packet_type=packet.get('type'),
                timestamp=datetime.fromisoformat(packet['timestamp']) if 'timestamp' in packet else datetime.now(timezone.utc),
                summary=packet.get('summary')
            )
            db.session.add(new_log)

        db.session.commit()
        analyze_packets()
        
        logger.info(f"{len(data['packets'])} packets logged successfully")
        return jsonify({'message': 'Packets logged successfully!'}), 201
    except Exception as e:
        logger.error(f"Error processing request: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/trafic/update')
def update_trafic():
    logs = PacketLog.query.order_by(PacketLog.timestamp.desc()).all()
    return jsonify([log.to_dict() for log in logs])

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)