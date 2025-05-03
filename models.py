from datetime import datetime
from database import db
from slugify import slugify  # Ensure you installed this using: pip install python-slugify
from werkzeug.security import generate_password_hash, check_password_hash

# User model
class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='user')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    active = db.Column(db.Boolean, default=True)
    mfa_secret = db.Column(db.String(16))
    
    def set_password(self, password):
        self.password = generate_password_hash(
            password,
            method='pbkdf2:sha256:600000'
        )
    
    def check_password(self, password):
        return check_password_hash(self.password, password)

# Project model
class Project(db.Model):
    __tablename__ = 'projects'
    
    id = db.Column(db.Integer, primary_key=True)
    project_name = db.Column(db.String(200), nullable=False)
    project_type = db.Column(db.String(50))  # expect values like 'audit' or 'qip'
    hospital = db.Column(db.String(150))
    year = db.Column(db.Integer)
    specialty = db.Column(db.String(100))
    guidelines = db.Column(db.String(500))
    background = db.Column(db.Text)
    aims = db.Column(db.Text)
    objectives = db.Column(db.Text)
    keywords = db.Column(db.String(300))
    submitter_email_hash = db.Column(db.String(256))
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    data_protection_compliant = db.Column(db.Boolean, nullable=False)
    data_classification = db.Column(db.String(20), default='RESTRICTED')
    ratings = db.relationship('Rating', backref='project', lazy=True)
    slug = db.Column(db.String(255), unique=True)
    approved = db.Column(db.Boolean, default=False, nullable=False)
    archived = db.Column(db.Boolean, default=False, nullable=False)
    last_modified_by = db.Column(db.String(80), nullable=True)
    last_modified_at = db.Column(db.DateTime, nullable=True)
    audit_logs = db.relationship('AuditLog', backref='project', lazy=True)
    
    def average_rating(self):
        if not self.ratings:
            return 0.0
        total = sum(r.rating for r in self.ratings)
        return round(total / len(self.ratings), 1)
    
    def set_submitter_email(self, email):
        self.submitter_email_hash = generate_password_hash(
            email.strip().lower(),
            method='pbkdf2:sha256:600000'
        )
    
    def generate_unique_slug(self):
        base_slug = slugify(self.project_name)
        candidate = base_slug
        counter = 2
        # Ensure uniqueness for this project type
        while Project.query.filter_by(project_type=self.project_type, slug=candidate).first():
            candidate = f"{base_slug}-{counter}"
            counter += 1
        return candidate
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Do not set the slug in __init__ because the project ID might not be available.
        # Instead, set it right before commit (e.g. in your submission route).

# Rating model
class Rating(db.Model):
    __tablename__ = 'ratings'
    
    id = db.Column(db.Integer, primary_key=True)
    rating = db.Column(db.Integer, nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=False)

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=False)
    admin_username = db.Column(db.String(80), nullable=False)
    action = db.Column(db.String(20), nullable=False)   # e.g. 'edit', 'delete', 'approve'
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

