import os
import base64

# Define project name
project_name = 'microblog'

# Define the folder structure
folders = [
    project_name,
    os.path.join(project_name, 'templates'),
    os.path.join(project_name, 'static', 'css'),
    os.path.join(project_name, 'static', 'uploads')
]

# Create directories
for folder in folders:
    os.makedirs(folder, exist_ok=True)
    print(f"Created directory: {folder}")

# Define the content for app.py
app_py_content = """\
import os
import uuid
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user,
    login_required, logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret_key')  # Use environment variable in production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'  # Directory to save profile pictures
app.config['SESSION_COOKIE_SECURE'] = True  # Ensure cookies are sent over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to cookies

# Initialize Extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
csrf = CSRFProtect(app)
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Association table for likes
likes = db.Table('likes',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('post_id', db.Integer, db.ForeignKey('post.id'), primary_key=True)
)

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    profile_photo = db.Column(db.String(150), default='default.jpg')  # Default profile photo
    bio = db.Column(db.String(500), nullable=True)
    posts = db.relationship('Post', backref='author', lazy=True)
    comments = db.relationship('Comment', backref='author', lazy=True)
    liked = db.relationship('Post', secondary=likes, backref=db.backref('liked_by', lazy='dynamic'))

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(250), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    views = db.Column(db.Integer, default=0)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comments = db.relationship('Comment', backref='post', lazy=True)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(250), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# User loader callback
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes

@app.route('/')
@login_required
def index():
    posts = Post.query.order_by(Post.timestamp.desc()).all()
    return render_template('index.html', posts=posts)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password').strip()
        # Validate input
        if not username or not password:
            flash('Username and password are required.', 'danger')
            return redirect(url_for('signup'))
        if len(username) > 150 or len(password) > 150:
            flash('Username and password must be under 150 characters.', 'danger')
            return redirect(url_for('signup'))
        # Check if user exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose another one.', 'danger')
            return redirect(url_for('signup'))
        # Create new user
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")  # Rate limit to prevent brute-force
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password').strip()
        # Validate input
        if not username or not password:
            flash('Username and password are required.', 'danger')
            return redirect(url_for('login'))
        # Authenticate user
        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password, password):
            flash('Invalid username or password.', 'danger')
            return redirect(url_for('login'))
        login_user(user)
        flash('Logged in successfully!', 'success')
        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# Route to render the Post Creation Page
@app.route('/create_post_page')
@login_required
def create_post_page():
    return render_template('create_post.html')

# Route to handle the Post Creation form submission
@app.route('/create_post', methods=['POST'])
@login_required
def create_post():
    content = request.form.get('content').strip()
    if not content:
        flash('Post content cannot be empty.', 'danger')
        return redirect(url_for('create_post_page'))
    if len(content) > 250:
        flash('Post must be 250 characters or fewer.', 'danger')
        return redirect(url_for('create_post_page'))
    new_post = Post(content=content, author=current_user)
    db.session.add(new_post)
    db.session.commit()
    flash('Post created successfully!', 'success')
    return redirect(url_for('index'))

# Profile Management Route
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        bio = request.form.get('bio').strip()
        current_user.bio = bio

        # Handle profile photo upload
        if 'profile_photo' in request.files:
            file = request.files['profile_photo']
            if file and file.filename:
                # Validate file extension
                ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
                def allowed_file(filename):
                    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

                if allowed_file(file.filename):
                    # Secure filename by generating a unique name
                    filename = f"{uuid.uuid4().hex}.{file.filename.rsplit('.', 1)[1].lower()}"
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(file_path)
                    current_user.profile_photo = filename
                else:
                    flash('Invalid file type. Allowed types: png, jpg, jpeg, gif.', 'danger')
                    return redirect(url_for('profile'))

        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))

    # Set a default profile photo if none exists
    profile_photo = current_user.profile_photo if current_user.profile_photo else 'default.jpg'

    return render_template('profile.html', user=current_user, profile_photo=profile_photo)

@app.route('/post/<int:post_id>', methods=['GET', 'POST'])
@login_required
def post_detail(post_id):
    post = Post.query.get_or_404(post_id)
    post.views += 1
    db.session.commit()

    # Fetch and sort comments by timestamp in descending order
    sorted_comments = Comment.query.filter_by(post_id=post.id).order_by(Comment.timestamp.desc()).all()

    if request.method == 'POST':
        comment_content = request.form.get('comment').strip()
        if not comment_content:
            flash('Comment cannot be empty.', 'danger')
            return redirect(url_for('post_detail', post_id=post_id))
        if len(comment_content) > 250:
            flash('Comment must be 250 characters or fewer.', 'danger')
            return redirect(url_for('post_detail', post_id=post_id))
        new_comment = Comment(content=comment_content, author=current_user, post=post)
        db.session.add(new_comment)
        db.session.commit()
        flash('Comment added successfully!', 'success')
        return redirect(url_for('post_detail', post_id=post_id))

    return render_template('post.html', post=post, comments=sorted_comments)

# Like/Unlike Route
@app.route('/like/<int:post_id>', methods=['POST'])
@login_required
def like(post_id):
    post = Post.query.get_or_404(post_id)
    if post in current_user.liked:
        current_user.liked.remove(post)
        db.session.commit()
        return jsonify({'status': 'unliked', 'likes': post.liked_by.count()})
    else:
        current_user.liked.append(post)
        db.session.commit()
        return jsonify({'status': 'liked', 'likes': post.liked_by.count()})

# API Route to Get Likes Count
@app.route('/get_likes/<int:post_id>')
def get_likes(post_id):
    post = Post.query.get_or_404(post_id)
    return jsonify({'likes': post.liked_by.count()})

# API Route to Get Comments
@app.route('/get_comments/<int:post_id>')
def get_comments(post_id):
    post = Post.query.get_or_404(post_id)
    comments = [
        {
            'author': comment.author.username,
            'content': comment.content,
            'timestamp': comment.timestamp.strftime('%Y-%m-%d %H:%M')
        } for comment in Comment.query.filter_by(post_id=post.id).order_by(Comment.timestamp.desc()).all()
    ]
    return jsonify({'comments': comments})

if __name__ == '__main__':
    app.run(debug=True)
"""

# Define the content for requirements.txt
requirements_txt_content = """\
Flask==2.3.2
Flask-Login==0.6.2
Flask-Migrate==4.0.4
Flask-SQLAlchemy==3.0.5
Werkzeug==2.3.4
Flask-WTF==1.1.1
Flask-Limiter==2.8.0
"""

# Define the content for styles.css
styles_css_content = """\
/* styles.css */

/* Circular Profile Picture */
.profile-pic {
    width: 100px;
    height: 100px;
    border-radius: 50%;
    object-fit: cover;
}

/* Bottom Navigation Styling */
.bottom-nav a {
    text-decoration: none;
    color: white;
}

.bottom-nav a:hover {
    color: #f0f0f0;
}

.bottom-nav i {
    font-size: 1.5rem;
}
"""

# Define the content for base.html
base_html_content = """\
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MicroBlog</title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Bootstrap Icons -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons/font/bootstrap-icons.css" rel="stylesheet">
    <!-- Custom CSS -->
    <link rel="stylesheet" href="{{ url_for('static', filename='css/styles.css') }}">
</head>
<body>
    <!-- Main Navigation Bar -->
    <nav class="navbar navbar-expand-lg navbar-light bg-warning shadow">
        <div class="container-fluid">
            <a class="navbar-brand" href="{{ url_for('index') }}">MicroBlog</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarSupportedContent" 
                aria-controls="navbarSupportedContent" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarSupportedContent">
                <ul class="navbar-nav ms-auto">
                    {% if current_user.is_authenticated %}
                        <li class="nav-item">
                            <a class="nav-link" href="#">Hello, {{ current_user.username }}!</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="{{ url_for('logout') }}">Logout</a>
                        </li>
                    {% else %}
                        <li class="nav-item">
                            <a class="nav-link" href="{{ url_for('login') }}">Login</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="{{ url_for('signup') }}">Sign Up</a>
                        </li>
                    {% endif %}
                </ul>
            </div>
        </div>
    </nav>

    <!-- Main Content Area -->
    <div class="container mt-4">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }} alert-dismissible fade show" role="alert">
                        {{ message }}
                        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        {% block content %}{% endblock %}
    </div>

    <!-- Bottom Navbar for Mobile View -->
    <nav class="navbar fixed-bottom bg-dark d-lg-none bottom-nav">
        <div class="container-fluid d-flex justify-content-around">
            <a href="{{ url_for('index') }}" class="text-center">
                <i class="bi bi-house-door-fill"></i>
                <p class="mb-0">Home</p>
            </a>
            <a href="{{ url_for('create_post_page') }}" class="text-center">
                <i class="bi bi-pencil-square"></i>
                <p class="mb-0">Post</p>
            </a>
            <a href="{{ url_for('index') }}" class="text-center">
                <i class="bi bi-globe"></i>
                <p class="mb-0">Explore</p>
            </a>
            <a href="{{ url_for('profile') }}" class="text-center">
                <i class="bi bi-person-circle"></i>
                <p class="mb-0">Profile</p>
            </a>
            <a href="{{ url_for('profile') }}" class="text-center">
                <i class="bi bi-gear"></i>
                <p class="mb-0">Settings</p>
            </a>
        </div>
    </nav>

    <!-- Bootstrap JS Bundle with Popper -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <!-- jQuery (for AJAX) -->
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    {% block scripts %}{% endblock %}
</body>
</html>
"""

# Define the content for signup.html
signup_html_content = """\
{% extends "base.html" %}

{% block content %}
<div class="row justify-content-center">
    <div class="col-md-6">
        <h2>Sign Up</h2>
        <form method="POST" action="{{ url_for('signup') }}">
            {{ csrf_token() }}
            <div class="mb-3">
                <label for="username" class="form-label">Username</label>
                <input type="text" class="form-control" id="username" name="username" required maxlength="150">
            </div>
            <div class="mb-3">
                <label for="password" class="form-label">Password</label>
                <input type="password" class="form-control" id="password" name="password" required maxlength="150">
            </div>
            <button type="submit" class="btn btn-warning">Sign Up</button>
        </form>
        <p class="mt-3">Already have an account? <a href="{{ url_for('login') }}">Login here</a>.</p>
    </div>
</div>
{% endblock %}
"""

# Define the content for login.html
login_html_content = """\
{% extends "base.html" %}

{% block content %}
<div class="row justify-content-center">
    <div class="col-md-6">
        <h2>Login</h2>
        <form method="POST" action="{{ url_for('login') }}">
            {{ csrf_token() }}
            <div class="mb-3">
                <label for="username" class="form-label">Username</label>
                <input type="text" class="form-control" id="username" name="username" required maxlength="150">
            </div>
            <div class="mb-3">
                <label for="password" class="form-label">Password</label>
                <input type="password" class="form-control" id="password" name="password" required maxlength="150">
            </div>
            <button type="submit" class="btn btn-warning">Login</button>
        </form>
        <p class="mt-3">Don't have an account? <a href="{{ url_for('signup') }}">Sign up here</a>.</p>
    </div>
</div>
{% endblock %}
"""

# Define the content for index.html
index_html_content = """\
{% extends "base.html" %}

{% block content %}
<div class="row justify-content-center">
    <div class="col-md-8">
        <h2>Create a New Post</h2>
        <form method="POST" action="{{ url_for('create_post') }}">
            {{ csrf_token() }}
            <div class="mb-3">
                <textarea class="form-control" name="content" rows="3" maxlength="250" placeholder="What's on your mind?" required></textarea>
            </div>
            <button type="submit" class="btn btn-warning">Post</button>
        </form>
        <hr>
        <h2>Recent Posts</h2>
        {% for post in posts %}
            <div class="card mb-3 shadow-sm">
                <div class="card-body">
                    <h5 class="card-title">{{ post.author.username }}</h5>
                    <h6 class="card-subtitle mb-2 text-muted">{{ post.timestamp.strftime('%Y-%m-%d %H:%M') }}</h6>
                    <p class="card-text">{{ post.content }}</p>
                    <p class="card-text">
                        <small class="text-muted">Views: {{ post.views }}</small>
                    </p>
                    <a href="{{ url_for('post_detail', post_id=post.id) }}" class="card-link">View Details</a>
                    <button class="btn btn-link like-button" data-post-id="{{ post.id }}">
                        {% if post in current_user.liked %}
                            Unlike
                        {% else %}
                            Like
                        {% endif %}
                    </button>
                    <span id="like-count-{{ post.id }}">{{ post.liked_by.count() }}</span> Likes
                </div>
            </div>
        {% else %}
            <p>No posts yet. Start by creating one!</p>
        {% endfor %}
    </div>
</div>
{% endblock %}

{% block scripts %}
<script>
$(document).ready(function(){
    $('.like-button').click(function(){
        var postId = $(this).data('post-id');
        var button = $(this);
        $.ajax({
            url: '/like/' + postId,
            type: 'POST',
            headers: {
                'X-CSRFToken': '{{ csrf_token() }}'
            },
            success: function(response){
                $('#like-count-' + postId).text(response.likes);
                if(response.status === 'liked'){
                    button.text('Unlike');
                } else {
                    button.text('Like');
                }
            }
        });
    });
});
</script>
{% endblock %}
"""

# Define the content for post.html
post_html_content = """\
{% extends "base.html" %}

{% block content %}
<div class="row justify-content-center">
    <div class="col-md-8">
        <div class="card shadow-sm">
            <div class="card-body">
                <h5 class="card-title">{{ post.author.username }}</h5>
                <h6 class="card-subtitle mb-2 text-muted">{{ post.timestamp.strftime('%Y-%m-%d %H:%M') }}</h6>
                <p class="card-text">{{ post.content }}</p>
                <p class="card-text">
                    <small class="text-muted">Views: {{ post.views }}</small> |
                    <small class="text-muted">{{ post.liked_by.count() }} Likes</small>
                </p>
                <button class="btn btn-link like-button" data-post-id="{{ post.id }}">
                    {% if post in current_user.liked %}
                        Unlike
                    {% else %}
                        Like
                    {% endif %}
                </button>
                <span id="like-count-{{ post.id }}">{{ post.liked_by.count() }}</span> Likes
            </div>
        </div>
        <hr>
        <h4>Comments</h4>
        {% for comment in comments %}
            <div class="mb-3">
                <strong>{{ comment.author.username }}</strong> 
                <small class="text-muted">{{ comment.timestamp.strftime('%Y-%m-%d %H:%M') }}</small>
                <p>{{ comment.content }}</p>
            </div>
        {% else %}
            <p>No comments yet. Be the first to comment!</p>
        {% endfor %}
        <form method="POST" action="{{ url_for('post_detail', post_id=post.id) }}">
            {{ csrf_token() }}
            <div class="mb-3">
                <textarea class="form-control" name="comment" rows="2" maxlength="250" placeholder="Add a comment..." required></textarea>
            </div>
            <button type="submit" class="btn btn-warning">Comment</button>
        </form>
    </div>
</div>
{% endblock %}

{% block scripts %}
<script>
$(document).ready(function(){
    $('.like-button').click(function(){
        var postId = $(this).data('post-id');
        var button = $(this);
        $.ajax({
            url: '/like/' + postId,
            type: 'POST',
            headers: {
                'X-CSRFToken': '{{ csrf_token() }}'
            },
            success: function(response){
                $('#like-count-' + postId).text(response.likes);
                if(response.status === 'liked'){
                    button.text('Unlike');
                } else {
                    button.text('Like');
                }
            }
        });
    });
});
</script>
{% endblock %}
"""

# Define the content for create_post.html
create_post_html_content = """\
{% extends "base.html" %}
{% block content %}
<div class="container mt-4">
    <h2>Create a New Post</h2>
    <form method="POST" action="{{ url_for('create_post') }}">
        {{ csrf_token() }}
        <div class="mb-3">
            <textarea class="form-control" name="content" rows="3" maxlength="250" placeholder="What's on your mind?" required></textarea>
        </div>
        <button type="submit" class="btn btn-warning">Post</button>
    </form>
</div>
{% endblock %}
"""

# Define the content for profile.html
profile_html_content = """\
{% extends "base.html" %}
{% block content %}
<div class="container mt-4">
    <h2>Profile</h2>
    <!-- Display profile photo in a small circle -->
    <img src="{{ url_for('static', filename='uploads/' + profile_photo) }}" alt="Profile Photo" class="profile-pic mb-3">
    
    <form method="POST" enctype="multipart/form-data" action="{{ url_for('profile') }}">
        {{ csrf_token() }}
        <div class="mb-3">
            <label for="bio" class="form-label">Bio</label>
            <textarea class="form-control" id="bio" name="bio" rows="3">{{ user.bio }}</textarea>
        </div>
        <div class="mb-3">
            <label for="profile_photo" class="form-label">Profile Photo</label>
            <input class="form-control" type="file" id="profile_photo" name="profile_photo" accept=".png, .jpg, .jpeg, .gif">
        </div>
        <button type="submit" class="btn btn-warning">Update Profile</button>
    </form>
</div>
{% endblock %}
"""

# Define a simple default profile picture as a base64 string (a small gray circle)
default_jpg_base64 = (
    "/9j/4AAQSkZJRgABAQEAYABgAAD/4QBARXhpZgAATU0AKgAAAAgABAE7AAIAAAAGAAAISodpAAQA"
    "AAABAAAAJgAAAAAAAqACAAQAAAABAAAAUKADAAQAAAABAAAAUgAAAAD/2wBDAAYEBQYFBAYGBQYH"
    "CgkKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCv/wAARCAAQ"
    "ABADASIAAhEBAxEB/8QAFQABAQAAAAAAAAAAAAAAAAAAAAb/xAAgEAACAQQCAwAAAAAAAAAAAAABAgMEAAUGBxITIVFB/8QAFQEBAQAAAAAAAAAAAAAAAAAAAwT/xAAXEQEBAQEAAAAAAAAAAAAAAAABAgAD/9oADAMBAAIRAxEAPwDkA//Z"
)

# Function to write a file with given content
def write_file(path, content, mode='w'):
    with open(path, mode) as f:
        f.write(content)
    print(f"Created file: {path}")

# Write app.py
write_file(os.path.join(project_name, 'app.py'), app_py_content)

# Write requirements.txt
write_file(os.path.join(project_name, 'requirements.txt'), requirements_txt_content)

# Write styles.css
write_file(os.path.join(project_name, 'static', 'css', 'styles.css'), styles_css_content)

# Write templates
templates = {
    'base.html': base_html_content,
    'signup.html': signup_html_content,
    'login.html': login_html_content,
    'index.html': index_html_content,
    'post.html': post_html_content,
    'create_post.html': create_post_html_content,
    'profile.html': profile_html_content
}

for filename, content in templates.items():
    write_file(os.path.join(project_name, 'templates', filename), content)

# Decode and write default.jpg
default_jpg_bytes = base64.b64decode(default_jpg_base64)
default_jpg_path = os.path.join(project_name, 'static', 'uploads', 'default.jpg')
with open(default_jpg_path, 'wb') as f:
    f.write(default_jpg_bytes)
print(f"Created file: {default_jpg_path}")

print("\nProject setup completed successfully!")
print(f"Navigate to the '{project_name}' directory to start working on your project.")
print("\nNext Steps:")
print("1. Navigate to the project directory:")
print(f"   cd {project_name}")
print("2. (Optional) Create and activate a virtual environment:")
print("   python -m venv venv")
print("   # On Windows:")
print("   venv\\Scripts\\activate")
print("   # On macOS/Linux:")
print("   source venv/bin/activate")
print("3. Install the dependencies:")
print("   pip install -r requirements.txt")
print("4. Initialize the database with Flask-Migrate:")
print("   flask db init")
print("   flask db migrate -m \"Initial migration.\"")
print("   flask db upgrade")
print("5. Run the application:")
print("   python app.py")
print("\nAccess the application by navigating to http://127.0.0.1:5000/ in your web browser.")
