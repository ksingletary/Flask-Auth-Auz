from flask import Flask, render_template, redirect, session, url_for, flash
from flask_wtf import FlaskForm
from models import db, User, Feedback, connect_db
from forms import RegistrationForm, LoginForm, FeedbackForm
from flask_bcrypt import Bcrypt
from functools import wraps

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql:///auth-auz'
app.config['SECRET_KEY'] = 'secret_key_here'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = True

connect_db(app)
with app.app_context():
    db.create_all()

bcrypt = Bcrypt(app)

def require_login(f):
    """wrapper function to require login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        
        session_username = session.get('username')
        route_username = kwargs.get('username', None)

        if session_username is None:
            return redirect('/login')
        
        if route_username is not None and session_username != route_username:
            return redirect('/login')
        
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def home():
    return redirect('/register')

@app.route('/register', methods=["GET", "POST"])
def register():
    """registering a user"""
    form = RegistrationForm()
    if form.validate_on_submit():

        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')

        new_user = User(
            username=form.username.data,
            password=hashed_password,
            email=form.email.data,
            first_name=form.first_name.data,
            last_name=form.last_name.data
        )
        db.session.add(new_user)
        db.session.commit()

        session['username'] = form.username.data

        return redirect(url_for('user_detail', username=form.username.data))
    return render_template('register.html', form=form)

@app.route('/users/<username>')
@require_login
def user_detail(username):  
    """details about a user"""  
    user = User.query.filter_by(username=username).first_or_404()
    feedbacks = Feedback.query.filter_by(username=username).all()
    return render_template('user_detail.html', user=user, feedbacks=feedbacks)


@app.route('/login', methods=["GET", "POST"])
def login():
    """loggin in a user"""
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            session['username'] = user.username
            return redirect(url_for('user_detail', username=user.username))
        else:
            flash('Invalid username/password', 'danger')
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    """logout a user"""
    session.pop('username', None)
    return redirect('/')

@app.route('/users/<username>/delete', methods=["POST"])
@require_login
def delete_user(username):
    """deleting a user"""
    user = User.query.filter_by(username=username).first_or_404()
    db.session.delete(user)
    db.session.commit()
    session.pop('username', None)
    return redirect('/')

@app.route('/users/<username>/feedback/add', methods=["GET", "POST"])
@require_login
def add_feedback(username):    
    """add feedback to some user"""
    form = FeedbackForm()
    if form.validate_on_submit():
        new_feedback = Feedback(
            title=form.title.data,
            content=form.content.data,
            username=username
        )
        db.session.add(new_feedback)
        db.session.commit()
        return redirect(url_for('user_detail', username=username))
    return render_template('feedback_form.html', form=form)

@app.route('/feedback/<int:feedback_id>/update', methods=["GET", "POST"])
@require_login
def update_feedback(feedback_id):
    """update feedback"""
    feedback = Feedback.query.get_or_404(feedback_id)
    form = FeedbackForm(obj=feedback)
    if form.validate_on_submit():
        feedback.title = form.title.data
        feedback.content = form.content.data
        db.session.commit()
        return redirect(url_for('user_detail', username=feedback.username))
    return render_template('update_feedback_form.html', form=form)

@app.route('/feedback/<int:feedback_id>/delete', methods=["POST"])
@require_login
def delete_feedback(feedback_id):
    """delete feedback"""
    feedback = Feedback.query.get_or_404(feedback_id)
    db.session.delete(feedback)
    db.session.commit()
    return redirect(url_for('user_detail', username=feedback.username))

