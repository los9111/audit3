import builtins
try:
    builtins.unicode
except AttributeError:
    builtins.unicode = str
    
    
import os
import random
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt_identity,
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import or_, desc
from dotenv import load_dotenv
from flask_migrate import Migrate
from slugify import slugify  # Make sure to install via: pip install python-slugify

# Local imports
from database import db
from forms import ProjectForm
from models import Project, Rating, User
from config import NHS_TRUSTS, MEDICAL_SPECIALTIES, SECRET_KEY, RECAPTCHA_PUBLIC_KEY, RECAPTCHA_PRIVATE_KEY

# Load environment variables
load_dotenv()

# Initialize Flask application
app = Flask(__name__)
app.config.update({
    'SQLALCHEMY_DATABASE_URI': os.environ.get('DATABASE_URL', 'sqlite:///audits.db'),
    'SECRET_KEY': SECRET_KEY,
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

# Initialize extensions
csrf = CSRFProtect(app)
db.init_app(app)
jwt = JWTManager(app)
migrate = Migrate(app, db)

TRUSTS_DICT = { code: name for code, name in NHS_TRUSTS }
@app.template_global()
def get_trust_name(code):
    return TRUSTS_DICT.get(code, code)

# JWT Configuration
@jwt.user_identity_loader
def user_identity_lookup(user):
    return user

@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return User.query.filter_by(username=identity).first()

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({"msg": "Token has expired"}), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({"msg": "Invalid token"}), 401

@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({"msg": "Missing authorization token"}), 401

# Helper function to generate a unique slug for a project
def generate_unique_slug(project):
    # Create a base slug from the project name
    base_slug = slugify(project.project_name)
    slug = base_slug
    suffix = 2

    # Query for an existing project with the same type and slug
    while Project.query.filter_by(project_type=project.project_type, slug=slug).first() is not None:
        slug = f"{base_slug}-{suffix}"
        suffix += 1
    return slug

# Admin setup function: creates the admin user if not already present
def initialize_admin():
    with app.app_context():
        admin_username = os.environ.get('ADMIN_USERNAME')
        admin_password = os.environ.get('ADMIN_PASSWORD')
        
        if not admin_username or not admin_password:
            raise ValueError("Missing admin credentials in environment variables")
        
        existing_admin = User.query.filter_by(username=admin_username).first()
        if not existing_admin:
            new_admin = User(
                username=admin_username,
                password=generate_password_hash(admin_password, method='pbkdf2:sha256:600000'),
                role='admin',
                created_at=datetime.utcnow(),
                active=True
            )
            db.session.add(new_admin)
            db.session.commit()

# Public route for homepage
@app.route('/')
def index():
    return render_template('index.html')

# New route for viewing a project by slug and project type
@app.route('/<project_type>/<slug>')
def view_project_slug(project_type, slug):
    if project_type not in ['audit', 'qip']:
        abort(404)
    project = Project.query.filter_by(project_type=project_type, slug=slug).first_or_404()
    return render_template('project.html', project=project)

# Admin portal route
@app.route('/admin', methods=['GET', 'POST'])
@jwt_required()
def admin_portal():
    try:
        username = get_jwt_identity()
        user = User.query.filter_by(username=username).first()
        if not user or user.role != 'admin':
            return jsonify({"error": "Admin privileges required"}), 403

        if request.method == 'POST':
            project_id = request.form.get('project_id')
            if project_id:
                try:
                    project = Project.query.get_or_404(project_id)
                    db.session.delete(project)
                    db.session.commit()
                    flash('Project successfully deleted', 'success')
                except SQLAlchemyError as e:
                    db.session.rollback()
                    flash('Database error during deletion', 'danger')
                    app.logger.error(f"Delete error: {str(e)}")

        projects = Project.query.order_by(Project.date_added.desc()).all()
        return render_template('admin.html', projects=projects, current_user=user)
    except Exception as e:
        app.logger.error(f"Admin portal error: {str(e)}")
        return jsonify({"error": "Server error loading admin portal"}), 500

# Admin login route
@app.route('/admin/login', methods=['GET', 'POST'])
@csrf.exempt
def admin_login():
    if request.method == 'GET':
        return render_template('admin_login.html')
    try:
        if not request.is_json:
            return jsonify({"msg": "Missing JSON in request"}), 400
            
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()

        if not username or not password:
            return jsonify({"msg": "Username and password required"}), 400

        user = User.query.filter_by(username=username).first()
        if user and user.role == 'admin' and check_password_hash(user.password, password):
            access_token = create_access_token(identity=username)
            response = jsonify({
                "access_token": access_token,
                "user": {"username": user.username, "role": user.role}
            })
            response.set_cookie(
                'access_token',
                value=access_token,
                httponly=True,
                secure=True,
                samesite='Lax',
                path='/admin'
            )
            return response, 200

        return jsonify({"msg": "Invalid credentials"}), 401

    except Exception as e:
        app.logger.error(f"Login error: {str(e)}")
        return jsonify({"msg": "Server error"}), 500

# Submission route that generates and assigns a unique slug before committing
@app.route('/submit', methods=['GET', 'POST'])
def submit_project():
    form = ProjectForm()
    form.hospital.choices = NHS_TRUSTS
    form.specialty.choices = MEDICAL_SPECIALTIES

    if form.validate_on_submit():
        try:
            clean_keywords = [k.strip() for k in form.keywords.data.split(',') if k.strip()]
            
            # Create a new project instance using form data
            new_project = Project(
                project_name = form.project_name.data.strip(),
                project_type = form.project_type.data,  # 'audit' or 'qip'
                hospital = form.hospital.data,
                year = int(form.year.data),
                specialty = form.specialty.data,
                guidelines = form.guidelines.data.strip(),
                background = form.background.data.strip(),
                aims = form.aims.data.strip(),
                objectives = form.objectives.data.strip(),
                keywords = ','.join(clean_keywords),
                submitter_email_hash = "",  # Use set_submitter_email() if desired to hash email
                data_protection_compliant = form.data_protection.data,
                data_classification = 'RESTRICTED'
            )

            # Generate and assign a unique slug using the helper function
            new_project.slug = generate_unique_slug(new_project)

            db.session.add(new_project)
            db.session.commit()
            flash('Project submitted successfully!', 'success')
            return redirect(url_for('index'))
            
        except SQLAlchemyError as error:
            db.session.rollback()
            flash('Database error occurred. Please try again.', 'danger')
            app.logger.error(f'Submission error: {str(error)}')

    return render_template('submit.html', form=form)

# Data protection policy route
@app.route('/data-protection-policy')
def data_protection_policy():
    return render_template('data_policy.html')

# Search route that builds links with project type and slug
@app.route('/search')
def search():
    query = request.args.get('query', '').strip().lower()
    if not query:
        return redirect(url_for('index'))
    
    search_terms = [term.strip() for term in query.split(',') if term.strip()]
    filters = []
    for term in search_terms:
        term_filter = or_(
            Project.project_name.ilike(f'%{term}%'),
            Project.keywords.ilike(f'%{term}%'),
            Project.specialty.ilike(f'%{term}%'),
            Project.hospital.ilike(f'%{term}%')
        )
        filters.append(term_filter)
    
    results = Project.query.filter(or_(*filters)).order_by(desc(Project.date_added)).all()
    return render_template('search_results.html', results=results, query=query, search_terms=search_terms)

# Random project route that redirects to the new slug-based URL
@app.route('/random')
def random_project():
    projects = Project.query.all()
    if not projects:
        flash('No projects available yet')
        return redirect(url_for('index'))
    chosen = random.choice(projects)
    return redirect(url_for('view_project_slug', project_type=chosen.project_type, slug=chosen.slug))

# Optional legacy route using project ID for backward compatibility (can be removed)
@app.route('/project/<int:project_id>')
def view_project_by_id(project_id):
    project = Project.query.get_or_404(project_id)
    return redirect(url_for('view_project_slug', project_type=project.project_type, slug=project.slug))

if __name__ == '__main__':
    required_vars = ['ADMIN_USERNAME', 'ADMIN_PASSWORD', 'JWT_SECRET_KEY']
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    
    if missing_vars:
        raise EnvironmentError(f"""
        Missing required environment variables: {', '.join(missing_vars)}
        Your .env file should contain:
        ADMIN_USERNAME=your-admin-name
        ADMIN_PASSWORD=your-admin-password
        JWT_SECRET_KEY=your-random-secret-key
        """)
    
    with app.app_context():
        db.create_all()
        initialize_admin()

    try:
        app.run(debug=True)
    except Exception as e:
        print(f"Server failed to start: {e}")
