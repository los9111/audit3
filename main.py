import builtins
try:
    builtins.unicode
except AttributeError:
    builtins.unicode = str

import os
import random
from datetime import datetime
from flask import session
from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, jsonify, abort, Response
)
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import or_, desc, func
from dotenv import load_dotenv
from flask_migrate import Migrate
from slugify import slugify  # pip install python-slugify

# Local imports
from database import db
from forms import ProjectForm
from models import Project, Rating, User, AuditLog, Comment
from config import (
    NHS_TRUSTS, MEDICAL_SPECIALTIES,
    SECRET_KEY, RECAPTCHA_PUBLIC_KEY, RECAPTCHA_PRIVATE_KEY
)

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
    while Project.query.filter_by(
        project_type=project.project_type, slug=slug
    ).first():
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

@app.context_processor
def inject_current_year():
    return {'current_year': datetime.now().year}

@app.route('/')
def index():
    return render_template('index.html', now=datetime.now())

@app.route('/<project_type>/<slug>')
def view_project_slug(project_type, slug):
    if project_type not in ['audit', 'qip']:
        abort(404)
    project = Project.query.filter_by(
        project_type=project_type, slug=slug
    ).first_or_404()
    return render_template('project.html', project=project)

@app.route('/admin', methods=['GET', 'POST'])
@jwt_required()
def admin_portal():
    try:
        username = get_jwt_identity()
        user = User.query.filter_by(username=username).first()
        if not user or user.role != 'admin':
            return jsonify({'error': 'Admin privileges required'}), 403

        # Handle POST requests (deletions)
        if request.method == 'POST' and request.form.get('project_id'):
            project = Project.query.get_or_404(request.form['project_id'])
            record_audit(project, username, 'delete')
            db.session.delete(project)
            db.session.commit()
            flash('Project successfully deleted', 'success')

        # Get count of pending comments
        pending_comments = Comment.query.filter_by(approved=False).count()

        # Get all projects with pending comments detail
        projects_with_pending = db.session.query(
            Project.id,
            Project.project_name,
            func.count(Comment.id).label('pending_count')
        ).join(Comment).filter(
            Comment.approved == False
        ).group_by(Project.id).all()

        # Get all projects ordered by date
        projects = Project.query.order_by(desc(Project.date_added)).all()

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

        # Get all pending comments with project information
        pending = db.session.query(
            Comment,
            Project.project_name,
            Project.id.label('project_id')
        ).join(Project).filter(
            Comment.approved == False
        ).order_by(desc(Comment.created_at)).all()

        return render_template(
            'admin_pending_comments.html',
            pending_comments=pending
        )
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

        # Record audit log
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

@app.route('/admin/login', methods=['GET','POST'])
@csrf.exempt
def admin_login():
    if request.method == 'GET':
        return render_template('admin_login.html')
    data = request.get_json(force=True)
    username = data.get('username','').strip()
    password = data.get('password','').strip()
    if not username or not password:
        return jsonify({'msg': 'Username and password required'}), 400
    user = User.query.filter_by(username=username).first()
    if user and user.role=='admin' and check_password_hash(user.password, password):
        token = create_access_token(identity=username)
        resp = jsonify({'access_token': token, 'user': {'username': username, 'role': user.role}})
        resp.set_cookie('access_token', token,
                        httponly=True, secure=True, samesite='Lax', path='/admin')
        return resp, 200
    return jsonify({'msg': 'Invalid credentials'}), 401

@app.route('/admin/project/<int:id>/edit', methods=['GET','POST'])
@jwt_required()
def edit_project(id):
    proj = Project.query.get_or_404(id)
    form = ProjectForm(obj=proj)
    form.hospital.choices = NHS_TRUSTS
    form.specialty.choices = MEDICAL_SPECIALTIES
    if form.validate_on_submit():
        form.populate_obj(proj)
        proj.slug = generate_unique_slug(proj)
        record_audit(proj, get_jwt_identity(), 'edit')
        db.session.commit()
        flash('Project updated successfully', 'success')
        return redirect(url_for('admin_portal'))
    return render_template('admin_edit.html', form=form, project=proj)

@app.route('/admin/project/<int:id>/approve', methods=['POST'])
@jwt_required()
def approve_project(id):
    proj = Project.query.get_or_404(id)
    proj.approved = True
    record_audit(proj, get_jwt_identity(), 'approve')
    db.session.commit()
    flash('Project approved', 'success')
    return redirect(url_for('admin_portal'))

@app.route('/admin/bulk-action', methods=['POST'])
@jwt_required()
def bulk_action():
    user = User.query.filter_by(username=get_jwt_identity()).first()
    if not user or user.role != 'admin':
        return jsonify({'error': 'Admin privileges required'}), 403

    data = request.get_json() or {}
    action = data.get('action')
    ids = data.get('ids', [])
    if not action or not isinstance(ids, list):
        return jsonify({'error': 'Invalid request'}), 400

    projects = Project.query.filter(Project.id.in_(ids)).all()

    if action == 'approve':
        for p in projects:
            p.approved = True
            record_audit(p, user.username, 'approve')
    elif action == 'delete':
        for p in projects:
            record_audit(p, user.username, 'delete')
            db.session.delete(p)
    elif action == 'export':
        from io import StringIO
        import csv
        si = StringIO()
        w = csv.writer(si)
        w.writerow([
            'ID', 'Name', 'Type', 'Hospital', 'Year',
            'Specialty', 'Approved', 'Modified By', 'Modified At'
        ])
        for p in projects:
            w.writerow([
                p.id, p.project_name, p.project_type,
                get_trust_name(p.hospital), p.year, p.specialty,
                'Yes' if p.approved else 'No',
                p.last_modified_by or '',
                p.last_modified_at.strftime('%Y-%m-%d %H:%M') if p.last_modified_at else ''
            ])
        return Response(
            si.getvalue(), mimetype='text/csv',
            headers={'Content-Disposition': 'attachment;filename=projects_export.csv'}
        )
    else:
        return jsonify({'error': 'Unknown action'}), 400

    db.session.commit()
    flash(f"{len(projects)} project(s) {action}d", 'success')
    return ('', 204)

@app.route('/admin/metrics')
@jwt_required()
def metrics():
    user = User.query.filter_by(username=get_jwt_identity()).first()
    if not user or user.role != 'admin':
        return jsonify({'error': 'Admin privileges required'}), 403

    total = Project.query.count()
    approved = Project.query.filter_by(approved=True).count()
    pending = total - approved

    trust_counts = db.session.query(
        Project.hospital, func.count(Project.id)
    ).group_by(Project.hospital).all()

    spec_counts = db.session.query(
        Project.specialty, func.count(Project.id)
    ).group_by(Project.specialty).all()

    return render_template(
        'metrics.html',
        total=total,
        approved=approved,
        pending=pending,
        trust_counts=trust_counts,
        spec_counts=spec_counts
    )

@app.route('/admin/metrics/export')
@jwt_required()
def metrics_export():
    user = User.query.filter_by(username=get_jwt_identity()).first()
    if not user or user.role != 'admin':
        return jsonify({'error': 'Admin privileges required'}), 403

    from io import StringIO
    import csv
    si = StringIO()
    w = csv.writer(si)
    w.writerow(['Metric', 'Value'])
    w.writerow(['Total Projects', Project.query.count()])
    w.writerow(['Approved', Project.query.filter_by(approved=True).count()])
    w.writerow(['Pending', Project.query.filter_by(approved=False).count()])
    w.writerow([])
    w.writerow(['Trust', 'Count'])
    for trust, cnt in db.session.query(Project.hospital, func.count(Project.id)).group_by(Project.hospital):
        w.writerow([get_trust_name(trust), cnt])
    w.writerow([])
    w.writerow(['Specialty', 'Count'])
    for spec, cnt in db.session.query(Project.specialty, func.count(Project.id)).group_by(Project.specialty):
        w.writerow([spec, cnt])

    return Response(
        si.getvalue(), mimetype='text/csv',
        headers={'Content-Disposition': 'attachment;filename=metrics_export.csv'}
    )

@app.route('/admin/feedback/<int:project_id>')
@jwt_required()
def feedback_panel(project_id):
    project = Project.query.get_or_404(project_id)
    show_pending = request.args.get('filter') == 'pending'

    if show_pending:
        comments = Comment.query.filter_by(
            project_id=project.id,
            approved=False
        ).order_by(Comment.created_at.desc()).all()
    else:
        comments = Comment.query.filter_by(
            project_id=project.id,
            approved=True
        ).order_by(Comment.created_at.desc()).all()

    return render_template(
        'admin_feedback.html',
        project=project,
        comments=comments,
        show_pending=show_pending
    )

@app.route('/admin/feedback/<int:rating_id>', methods=['DELETE'])
@jwt_required()
def delete_feedback(rating_id):
    user = User.query.filter_by(username=get_jwt_identity()).first()
    if not user or user.role != 'admin':
        return jsonify({'error': 'Admin privileges required'}), 403
    r = Rating.query.get_or_404(rating_id)
    db.session.delete(r)
    db.session.commit()
    return ('', 204)

@app.route('/admin/feedback/<int:comment_id>/approve', methods=['POST'])
@jwt_required()
def approve_comment(comment_id):
    user = User.query.filter_by(username=get_jwt_identity()).first()
    if not user or user.role != 'admin':
        return jsonify({'error': 'Admin privileges required'}), 403

    comment = Comment.query.get_or_404(comment_id)
    comment.approved = True
    db.session.commit()

    # Record audit log
    db.session.add(AuditLog(
        project_id=comment.project_id,
        admin_username=user.username,
        action=f'approve_comment:{comment_id}'
    ))
    db.session.commit()

    return ('', 204)

@app.route('/submit', methods=['GET','POST'])
def submit_project():
    form = ProjectForm()
    form.hospital.choices = NHS_TRUSTS
    form.specialty.choices = MEDICAL_SPECIALTIES
    if form.validate_on_submit():
        clean_keywords = [k.strip() for k in form.keywords.data.split(',') if k.strip()]
        p = Project(
            project_name=form.project_name.data.strip(),
            project_type=form.project_type.data,
            hospital=form.hospital.data,
            year=int(form.year.data),
            specialty=form.specialty.data,
            guidelines=form.guidelines.data.strip(),
            background=form.background.data.strip(),
            aims=form.aims.data.strip(),
            objectives=form.objectives.data.strip(),
            keywords=','.join(clean_keywords),
            submitter_email_hash='',
            data_protection_compliant=form.data_protection.data,
            data_classification='RESTRICTED'
        )
        p.slug = generate_unique_slug(p)
        db.session.add(p)
        db.session.commit()
        flash('Project submitted successfully!', 'success')
        return redirect(url_for('index'))
    return render_template('submit.html', form=form)

@app.route('/data-protection-policy')
def data_protection_policy():
    return render_template('data_policy.html')

@app.route('/comment/<int:project_id>', methods=['POST'])
@csrf.exempt
def post_comment(project_id):
    data = request.get_json() or {}
    text = data.get('comment', '').strip()
    if len(text) < 10:
        return jsonify(error="Comment too short"), 400

    new_comment = Comment(
        text=text,
        project_id=project_id,
        approved=False
    )
    db.session.add(new_comment)
    db.session.commit()
    return jsonify(success=True), 201

@app.route('/admin/feedback/<int:rating_id>/approve', methods=['POST'])
@jwt_required()
def approve_feedback(rating_id):
    user = User.query.filter_by(username=get_jwt_identity()).first()
    if not user or user.role != 'admin':
        return jsonify({'error': 'Admin privileges required'}), 403
    r = Rating.query.get_or_404(rating_id)
    r.approved = True
    db.session.commit()
    return ('', 204)

@app.route('/search')
def search():
    query = request.args.get('query', '').strip().lower()
    if not query:
        return redirect(url_for('index'))
    terms = [t.strip() for t in query.split(',') if t.strip()]
    filters = []
    for t in terms:
        filters.append(or_(
            Project.project_name.ilike(f'%{t}%'),
            Project.keywords.ilike(f'%{t}%'),
            Project.specialty.ilike(f'%{t}%'),
            Project.hospital.ilike(f'%{t}%')
        ))
    results = Project.query.filter(or_(*filters)).order_by(desc(Project.date_added)).all()
    return render_template(
        'search_results.html',
        results=results,
        query=query,
        search_terms=terms
    )

@app.errorhandler(404)
def not_found_error(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(e):
    db.session.rollback()
    return render_template('500.html'), 500

@app.route('/random')
def random_project():
    projects = Project.query.all()
    if not projects:
        flash('No projects available yet', 'warning')
        return redirect(url_for('index'))
    chosen = random.choice(projects)
    return redirect(url_for(
        'view_project_slug',
        project_type=chosen.project_type,
        slug=chosen.slug
    ))

@app.route('/project/<int:project_id>')
def view_project_by_id(project_id):
    proj = Project.query.get_or_404(project_id)
    return redirect(url_for(
        'view_project_slug',
        project_type=proj.project_type,
        slug=proj.slug
    ))

@app.route('/rate/<int:project_id>', methods=['POST'])
def rate_project(project_id):
    try:
        if session.get(f'rated_{project_id}'):
            return jsonify({'success': False, 'error': 'You have already rated this project'}), 400

        rating_value = int(request.json.get('rating'))
        if not 1 <= rating_value <= 5:
            return jsonify({'success': False, 'error': 'Invalid rating value'}), 400

        project = Project.query.get_or_404(project_id)
        new_rating = Rating(rating=rating_value, project=project)
        db.session.add(new_rating)
        db.session.commit()

        session[f'rated_{project_id}'] = True

        return jsonify({
            'success': True,
            'new_average': project.average_rating(),
            'total_ratings': len(project.ratings)
        })

    except Exception as error:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(error)}), 500

if __name__ == '__main__':
    required = ['ADMIN_USERNAME','ADMIN_PASSWORD','JWT_SECRET_KEY']
    missing = [v for v in required if not os.getenv(v)]
    if missing:
        raise EnvironmentError(f"Missing environment vars: {', '.join(missing)}")
    with app.app_context():
        db.create_all()
        initialize_admin()
    app.run(debug=True)
