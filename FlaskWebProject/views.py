"""
Routes and views for the Flask application.
"""

from datetime import datetime
from flask import render_template, flash, redirect, request, session, url_for
from werkzeug.urls import url_parse
from config import Config
from FlaskWebProject import app, db
from FlaskWebProject.forms import LoginForm, PostForm
from flask_login import current_user, login_user, logout_user, login_required
from FlaskWebProject.models import User, Post
import msal
import uuid

# Construct the image source URL for blob storage
imageSourceUrl = f"https://{app.config['BLOB_ACCOUNT']}.blob.core.windows.net/{app.config['BLOB_CONTAINER']}/"

@app.route('/')
@app.route('/home')
@login_required
def home():
    user = User.query.filter_by(username=current_user.username).first_or_404()
    posts = Post.query.all()
    return render_template('index.html', title='Home Page', posts=posts)

@app.route('/new_post', methods=['GET', 'POST'])
@login_required
def new_post():
    form = PostForm(request.form)
    if form.validate_on_submit():
        post = Post()
        post.save_changes(form, request.files['image_path'], current_user.id, new=True)
        flash('Post created successfully!', 'success')
        return redirect(url_for('home'))
    return render_template('post.html', title='Create Post', imageSource=imageSourceUrl, form=form)

@app.route('/post/<int:id>', methods=['GET', 'POST'])
@login_required
def post(id):
    post = Post.query.get_or_404(id)
    form = PostForm(formdata=request.form, obj=post)
    if form.validate_on_submit():
        post.save_changes(form, request.files.get('image_path'), current_user.id)
        flash('Post updated successfully!', 'success')
        return redirect(url_for('home'))
    return render_template('post.html', title='Edit Post', imageSource=imageSourceUrl, form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            app.logger.warning('Invalid login attempt for user: %s', form.username.data)
            flash('Invalid username or password', 'danger')
                   login_user(user, remember=form.remember_me.data)
        app.logger.info('User %s logged in successfully', form.username.data)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('home')
        return redirect(next_page)
    
    # Generate a unique state for OAuth
    session["state"] = str(uuid.uuid4())
    auth_url = _build_auth_url(scopes=Config.SCOPE, state=session["state"])
    return render_template('login.html', title='Sign In', form=form, auth_url=auth_url)

@app.route(Config.REDIRECT_PATH)  # Ensure this matches your app's redirect_uri in Azure AD
def authorized():
    if request.args.get('state') != session.get("state"):
        return redirect(url_for("home"))  # No-OP. Goes back to Index page
    if "error" in request.args:  # Authentication/Authorization failure
        return render_template("auth_error.html", result=request.args)

    # Handle token acquisition
    if request.args.get('code'):
        cache = _load_cache()
        result = _build_msal_app(cache).acquire_token_by_authorization_code(
            request.args['code'],
            scopes=Config.SCOPE,
            redirect_uri=url_for('authorized', _external=True)
        )
        
        # Check if the result contains an error
        if "error" in result:
            return render_template("auth_error.html", result=result)

        # If successful, save user info and log in
        session["user"] = result.get("id_token_claims")
        user = User.query.filter_by(username=session["user"]["preferred_username"]).first()  # Adjust as needed
        if user:
            login_user(user)
        _save_cache(cache)

    return redirect(url_for('home'))

@app.route('/logout')
def logout():
    logout_user()
    session.clear()  # Clear session data
    return redirect(url_for('login'))

def _load_cache():
    cache = msal.SerializableTokenCache()
    if session.get('token_cache'):
        cache.deserialize(session['token_cache'])
    return cache

def _save_cache(cache):
    if cache.has_state_changed:
        session['token_cache'] = cache.serialize()

def _build_msal_app(cache=None, authority=None):
    return msal.ConfidentialClientApplication(
        app.config['CLIENT_ID'],
        authority=authority or Config.AUTHORITY,
        client_credential=app.config['CLIENT_SECRET'],
        token_cache=cache
    )

def _build_auth_url(authority=None, scopes=None, state=None):
    return f"{(authority or Config.AUTHORITY)}/oauth2/v2.0/authorize?" + \
           f"client_id={app.config['CLIENT_ID']}&" + \
           f"response_type=code&" + \
           f"redirect_uri={url_for('authorized', _external=True)}&" + \
           f"scope={' '.join(scopes)}&" + \
           f"state={state}"
