import builtins
try:
    builtins.unicode
except AttributeError:
    builtins.unicode = str

import os
import random
from datetime import datetime
from flask import session, request, jsonify, render_template, redirect, url_for, flash, abort, Response
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import or_, desc, func
from dotenv import load_dotenv
from flask_migrate import Migrate
from slugify import slugify

# Local imports
from database import db
from forms import ProjectForm
from models import Project, Rating, User, AuditLog, Comment
from config import NHS_TRUSTS, MEDICAL_SPECIALTIES, SECRET_KEY, RECAPTCHA_PUBLIC_KEY, RECAPTCHA_PRIVATE_KEY

# Load environment variables
load_dotenv()

# Initialize Flask
app = Flask(__name__)
app.config.update({
    'SQLALCHEMY_DATABASE_URI': os.environ.get('DATABASE_URL', 'sqlite:///audits.db'),
    'SECRET_KEY': SECRET_KEY,
    'JWT_SECRET_KEY': os.environ.get('JWT_SECRET_KEY'),
    'RECAPTCHA_PUBLIC_KEY': RECAPTCHA_PUBLIC_KEY,
    'RECAPTCHA_PRIVATE_KEY': RECAPTCHA_PRIVATE_KEY,
    'JWT_TOKEN_LOCATION': ['headers', 'cookies'],
    'JWT_ACCESS_COOKIE_NAME': 'access_token',
    'JWT_COOKIE_CSRF_PROTECT': False,
    'JWT_ACCESS_CSRF_HEADER_NAME': 'X-CSRF-TOKEN',
    'JWT_ERROR_MESSAGE_KEY': 'error',
    'JWT_SESSION_COOKIE': False,
    'JWT_ACCESS_COOKIE_PATH': '/admin',
    'JWT_COOKIE_SECURE': True,
    'JWT_COOKIE_SAMESITE': 'Lax',
})

# Extensions
csrf = CSRFProtect(app)
db.init_app(app)
jwt = JWTManager(app)
migrate = Migrate(app, db)

# Template helper
TRUSTS_DICT = {code: name for code, name in NHS_TRUSTS}
@app.template_global()
def get_trust_name(code):
    return TRUSTS_DICT.get(code, code)

# JWT callbacks
@jwt.user_identity_loader
def user_identity_lookup(user):
    return user

@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data['sub']
    return User.query.filter_by(username=identity).first()

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({'msg': 'Token has expired'}), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({'msg': 'Invalid token'}), 401

@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({'msg': 'Missing authorization token'}), 401

# Helpers
def generate_unique_slug(project):
    base_slug = slugify(project.project_name)
    slug = base_slug
    suffix = 2
    while Project.query.filter_by(project_type=project.project_type, slug=slug).first():
        slug = f"{base_slug}-{suffix}"
        suffix += 1
    return slug

def initialize_admin():
    with app.app_context():
        admin_username = os.environ.get('ADMIN_USERNAME')
        admin_password = os.environ.get('ADMIN_PASSWORD')
        if not admin_username or not admin_password:
            raise ValueError('Missing admin credentials in environment variables')
        if not User.query.filter_by(username=admin_username).first():
            new_admin = User(
                username=admin_username,
                password=generate_password_hash(admin_password, method='pbkdf2:sha256:600000'),
                role='admin',
                created_at=datetime.utcnow(),
                active=True
            )
            db.session.add(new_admin)
            db.session.commit()

def record_audit(project, admin_user, action):
    project.last_modified_by = admin_user
    project.last_modified_at = datetime.utcnow()
    db.session.add(AuditLog(
        project_id=project.id,
        admin_username=admin_user,
        action=action
    ))

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/<project_type>/<slug>')
def view_project_slug(project_type, slug):
    if project_type not in ['audit', 'qip']:
        abort(404)
    project = Project.query.filter_by(project_type=project_type, slug=slug).first_or_404()
    return render_template('project.html', project=project)

@app.route('/admin', methods=['GET', 'POST'])
@jwt_required()
def admin_portal():
    try:
        username = get_jwt_identity()
        user = User.query.filter_by(username=username).first()
        if not user or user.role != 'admin':
            return jsonify({'error': 'Admin privileges required'}), 403

        # Handle project deletion if POST
        if request.method == 'POST' and request.form.get('project_id'):
            project = Project.query.get_or_404(request.form['project_id'])
            record_audit(project, username, 'delete')
            db.session.delete(project)
            db.session.commit()
            flash('Project successfully deleted', 'success')

        # Get comment and project data
        pending_comments = Comment.query.filter_by(approved=False).count()
        projects_with_pending = db.session.query(
            Project.id,
            Project.project_name,
            func.count(Comment.id).label('pending_count')
        ).join(Comment).filter(
            Comment.approved == False
        ).group_by(Project.id).all()
        
        projects = Project.query.order_by(Project.date_added.desc()).all()

        return render_template(
            'admin.html',
            projects=projects,
            pending_comments=pending_comments,
            projects_with_pending=projects_with_pending,
            current_user=user
        )
    except Exception as e:
        app.logger.error(f"Admin portal error: {e}")
        return jsonify({'error': 'Server error loading admin portal'}), 500

@app.route('/admin/pending-comments')
@jwt_required()
def pending_comments():
    try:
        user = User.query.filter_by(username=get_jwt_identity()).first()
        if not user or user.role != 'admin':
            return jsonify({'error': 'Admin privileges required'}), 403

        pending = db.session.query(
            Comment,
            Project.project_name,
            Project.id.label('project_id')
        ).join(Project).filter(
            Comment.approved == False
        ).order_by(Comment.created_at.desc()).all()

        return render_template('admin_pending_comments.html', pending_comments=pending)
    except Exception as e:
        app.logger.error(f"Pending comments error: {e}")
        return jsonify({'error': 'Server error loading pending comments'}), 500

@app.route('/admin/comment/<int:comment_id>/approve', methods=['POST'])
@jwt_required()
def approve_single_comment(comment_id):
    try:
        user = User.query.filter_by(username=get_jwt_identity()).first()
        if not user or user.role != 'admin':
            return jsonify({'error': 'Admin privileges required'}), 403

        comment = Comment.query.get_or_404(comment_id)
        comment.approved = True
        db.session.commit()
        
        db.session.add(AuditLog(
            project_id=comment.project_id,
            admin_username=user.username,
            action=f'approve_comment:{comment_id}'
        ))
        db.session.commit()
        
        return jsonify({'success': True}), 200
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error approving comment: {e}")
        return jsonify({'error': 'Server error approving comment'}), 500

# ... [Keep all your other existing routes exactly as they were]

if __name__ == '__main__':
    required = ['ADMIN_USERNAME','ADMIN_PASSWORD','JWT_SECRET_KEY']
    missing = [v for v in required if not os.getenv(v)]
    if missing:
        raise EnvironmentError(f"Missing environment vars: {', '.join(missing)}")
    with app.app_context():
        db.create_all()
        initialize_admin()
    app.run(debug=True)