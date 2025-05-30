import os
from dotenv import load_dotenv
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_jwt_identity, get_jwt
from sqlalchemy.exc import IntegrityError
from sqlalchemy import text
from datetime import datetime, timedelta
from functools import wraps
from flasgger import Swagger
from flask_cors import CORS
import sys
import logging

# Load environment variables
load_dotenv()
# Ensure required environment variables are set
if not os.getenv('SECRET_KEY') or not os.getenv('JWT_SECRET_KEY'):
    raise ValueError("Environment variables SECRET_KEY and JWT_SECRET_KEY must be set")
# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/iot_portal'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)

# Validate configuration
def validate_config():
    required_configs = [
        'SECRET_KEY',
        'JWT_SECRET_KEY',
        'SQLALCHEMY_DATABASE_URI'
    ]
    for config in required_configs:
        if not app.config.get(config):
            raise ValueError(f"Missing required config: {config}")

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
swagger = Swagger(app)

# Logging configuration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Models
class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), default='user')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    admins = db.relationship('Admin', backref='creator', lazy=True)
    
    def __repr__(self):
        return f'<User {self.username}>'

class Admin(db.Model):
    __tablename__ = 'admins'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20))
    access_level = db.Column(db.Enum('super', 'regular'), default='regular', nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Admin {self.name}>'

# Custom decorators
def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        jwt_data = get_jwt()
        if jwt_data.get('role') != 'admin':
            return jsonify({"msg": "Admin privileges required"}), 403
        return fn(*args, **kwargs)
    return wrapper

def create_app():
    with app.app_context():
        db.create_all()
    return app
    

# Routes
@app.route('/api/register', methods=['POST'])
def register():
    print("Registration attempt received")  # Debug print
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Missing username or password'}), 400
        
    try:
        # Hash the password
        hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
        
        # Create new user
        new_user = User(
            username=data['username'],
            password_hash=hashed_password
        )
        
        # Add to database
        db.session.add(new_user)
        db.session.commit()
        
        print(f"User {data['username']} registered successfully")  # Debug print
        return jsonify({'message': 'User registered successfully'}), 201
        
    except IntegrityError:
        db.session.rollback()
        return jsonify({'message': 'Username already exists'}), 409
    except Exception as e:
        db.session.rollback()
        print(f"Error during registration: {str(e)}")  # Debug print
        return jsonify({'message': 'Registration failed'}), 500

@app.route('/api/login', methods=['POST'])
def login():
    """
    User login
    ---
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            username:
              type: string
              description: Username
            password:
              type: string
              description: Password
    responses:
      200:
        description: Login successful
      401:
        description: Invalid credentials
    """
    data = request.get_json()
    print(f"Login attempt received: {data}")  # Debug print
    
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'success': False, 'message': 'Missing username or password'}), 400
    
    user = User.query.filter_by(username=data.get('username')).first()
    
    if user and bcrypt.check_password_hash(user.password_hash, data.get('password')):
        access_token = create_access_token(
            identity=user.id,
            additional_claims={'username': user.username, 'role': user.role}
        )
        return jsonify({
            'success': True,
            'message': 'Login successful',
            'token': access_token,
            'username': user.username,
            'role': user.role
        }), 200
    else:
        return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

@app.route('/api/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """
    Refresh access token
    ---
    security:
      - JWT: []
    responses:
      200:
        description: New access token generated
      401:
        description: Invalid refresh token
    """
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    # Create a new access token
    access_token = create_access_token(
        identity=user.id,
        additional_claims={'username': user.username, 'role': user.role}
    )
    
    return jsonify({'access_token': access_token}), 200


@app.route('/api/admins', methods=['GET'])
@jwt_required()
@admin_required
def get_admins():
    """
    Get all admins
    ---
    security:
      - JWT: []
    responses:
      200:
        description: List of admins
      403:
        description: Admin privileges required
    """
    admins = Admin.query.filter_by(is_active=True).all()
    result = []
    
    for admin in admins:
        result.append({
            'id': admin.id,
            'name': admin.name,
            'email': admin.email,
            'phone': admin.phone,
            'access_level': admin.access_level,
            'created_by': admin.created_by,
            'is_active': admin.is_active,
            'created_at': admin.created_at.isoformat()
        })
    
    return jsonify({'admins': result}), 200

@app.route('/api/admins', methods=['POST'])
@jwt_required()
@admin_required
def create_admin():
    """
    Create a new admin (super admin only)
    ---
    security:
      - JWT: []
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            name:
              type: string
              description: Admin name
            email:
              type: string
              description: Admin email
            phone:
              type: string
              description: Admin phone number
            access_level:
              type: string
              enum: [super, regular]
              description: Admin access level
    responses:
      201:
        description: Admin created successfully
      400:
        description: Bad request
      403:
        description: Super admin privileges required
    """
    data = request.get_json()
    current_user_id = get_jwt_identity()
    
    if not data or not data.get('name') or not data.get('email'):
        return jsonify({'message': 'Name and email are required'}), 400
    
    new_admin = Admin(
        name=data.get('name'),
        email=data.get('email'),
        phone=data.get('phone', ''),
        access_level=data.get('access_level', 'regular'),
        created_by=current_user_id
    )
    
    try:
        db.session.add(new_admin)
        db.session.commit()
        
        return jsonify({
            'message': 'Admin created successfully',
            'admin_id': new_admin.id,
            'name': new_admin.name
        }), 201
    except IntegrityError:
        db.session.rollback()
        return jsonify({'message': 'Email already exists'}), 409
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': str(e)}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """
    Health check endpoint
    ---
    responses:
      200:
        description: Server is healthy
    """
    return jsonify({'status': 'healthy'}), 200

# Error handlers
@app.errorhandler(404)
def handle_not_found(error):
    return jsonify({'message': 'Resource not found'}), 404

@app.errorhandler(500)
def handle_internal_error(error):
    return jsonify({'message': 'Internal server error'}), 500

# JWT error handlers
@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({
        'message': 'The token has expired',
        'error': 'token_expired'
    }), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({
        'message': 'Signature verification failed',
        'error': 'invalid_token'
    }), 401

@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({
        'message': 'Request does not contain an access token',
        'error': 'authorization_required'
    }), 401

def test_db_connection():
    with app.app_context():
        try:
            db.session.execute(text('SELECT 1'))
            print("Database connection successful")
        except Exception as e:
            print(f"Database connection failed: {e}")
            sys.exit(1)

if __name__ == '__main__':
    try:
        # Initialize the app
        app = create_app()
        # Test database connection
        test_db_connection()
        # Log network info
        import socket
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        print(f"Server hostname: {hostname}")
        print(f"Local IP: {local_ip}")
        # Run the Flask application
        app.run(debug=True, host='0.0.0.0', port=5000)
    except Exception as e:
        print(f"Application failed to start: {e}")
        sys.exit(1)