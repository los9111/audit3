
})

# Initialize extensions
csrf = CSRFProtect(app)
db.init_app(app)
jwt = JWTManager(app)  # Must come before JWT decorators

# JWT Configuration
@jwt.user_identity_loader
def user_identity_lookup(user):
    # User is the username string here
    return user  # Directly return the username

@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]  # Get the username from JWT
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

# Admin setup function
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

# Routes
@app.route('/admin', methods=['GET', 'POST'])
@jwt_required()
def admin_portal():
    try:
        # Get username from JWT
        username = get_jwt_identity()
        
        # Fetch user from database
        user = User.query.filter_by(username=username).first()
        
        # Validate admin status
        if not user or user.role != 'admin':
            return jsonify({"error": "Admin privileges required"}), 403

        # Handle POST requests (deletions)
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

        # Get all projects ordered by date
        projects = Project.query.order_by(Project.date_added.desc()).all()
        
        return render_template(
            'admin.html',
            projects=projects,
            current_user={
                'username': user.username,
                'role': user.role
            }
        )

    except Exception as e:
        app.logger.error(f"Admin portal error: {str(e)}")
        return jsonify({"error": "Server error loading admin portal"}), 500

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
            # Identity is just the username string
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

@app.route('/admin/project/<int:project_id>', methods=['DELETE'])
@jwt_required()
def delete_project(project_id):
    current_user = get_jwt_identity()
    if current_user['role'] != 'admin':
        return jsonify({"error": "Unauthorized"}), 403
    
    project = Project.query.get_or_404(project_id)
    db.session.delete(project)
    db.session.commit()
    return jsonify({"message": "Project deleted"}), 200

@app.route('/')
def index():
    return render_template('index.html')

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

@app.route('/random')
def random_project():
    projects = Project.query.all()
    if not projects:
        flash('No projects available yet')
        return redirect(url_for('index'))
    return redirect(url_for('view_project', project_id=random.choice(projects).id))

@app.route('/submit', methods=['GET', 'POST'])
def submit_project():
    form = ProjectForm()
    form.hospital.choices = NHS_TRUSTS
    form.specialty.choices = MEDICAL_SPECIALTIES

    if form.validate_on_submit():
        try:
            clean_keywords = [k.strip() for k in form.keywords.data.split(',') if k.strip()]
            
            new_project = Project(
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
                submitter_email=form.email.data.strip(),
                data_protection_compliant=form.data_protection.data,
                data_classification='RESTRICTED'
            )
            
            db.session.add(new_project)
            db.session.commit()
            flash('Project submitted successfully!')
            return redirect(url_for('index'))
            
        except SQLAlchemyError as error:
            db.session.rollback()
            flash('Database error occurred. Please try again.')
            app.logger.error(f'Submission error: {str(error)}')

    return render_template('submit.html', form=form)

@app.route('/project/<int:project_id>')
def view_project(project_id):
    project = Project.query.get_or_404(project_id)
    return render_template('project.html', project=project)

@app.route('/rate/<int:project_id>', methods=['POST'])
def rate_project(project_id):
    try:
        rating_value = int(request.json.get('rating'))
        if not 1 <= rating_value <= 5:
            return jsonify({'success': False, 'error': 'Rating must be between 1-5'}), 400
            
        project = Project.query.get_or_404(project_id)
        new_rating = Rating(rating=rating_value, project=project)
        db.session.add(new_rating)
        db.session.commit()
        return jsonify({'success': True, 'new_average': project.average_rating()})
    
    except Exception as error:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(error)}), 500

if __name__ == '__main__':
    # Add these lines
    if not os.getenv('ADMIN_USERNAME') or not os.getenv('ADMIN_PASSWORD'):
        raise Exception("""
        ERROR: Missing admin credentials!
        Did you create the .env file?
        It needs:
        ADMIN_USERNAME=your-username
        ADMIN_PASSWORD=your-password
        """)
    
@app.route('/data-protection-policy')
def data_protection_policy():
    return render_template('data_policy.html')    
    
# Add these at the bottom of your routes
@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({"msg": "Token has expired"}), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({"msg": "Invalid token"}), 401

@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({"msg": "Missing authorization token"}), 401    
    
# START THE APPLICATION PROPERLY
# Add this import at the top with other imports
from datetime import datetime

# ... [keep all other imports and configuration]

# Fix the single __main__ block at the bottom
if __name__ == '__main__':
    # Check environment variables first
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

    # Initialize database and admin user
    with app.app_context():
        db.create_all()
        initialize_admin()

    # Start the server
    try:
        port = int(os.environ.get('PORT', 8081))
        app.run(host='0.0.0.0', port=port, debug=False)
        print(f"\n➜ Access URL: https://{os.environ.get('CODESPACE_NAME', 'localhost')}-{port}.githubpreview.dev")
    except KeyError:
        print("\n➜ Local access: http://localhost:8080")