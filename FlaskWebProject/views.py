@app.route(Config.REDIRECT_PATH)  # Its absolute URL must match your app's redirect_uri set in AAD
def authorized():
    if request.args.get('state') != session.get("state"):
        return redirect(url_for("home"))  # No-OP. Goes back to Index page
    if "error" in request.args:  # Authentication/Authorization failure
        return render_template("auth_error.html", result=request.args)
    
    if request.args.get('code'):
        cache = _load_cache()
        # Acquire a token from a built msal app
        result = _build_msal_app(cache).acquire_token_by_authorization_code(
            request.args['code'],
            scopes=Config.SCOPE,
            redirect_uri=url_for('authorized', _external=True)
        )
        
        # Check if the result contains an error
        if "error" in result:
            return render_template("auth_error.html", result=result)
        
        session["user"] = result.get("id_token_claims")
        user = User.query.filter_by(username="admin").first()  # Adjust as needed
        if user:
            login_user(user)
        _save_cache(cache)
    
    return redirect(url_for('home'))

def _build_auth_url(authority=None, scopes=None, state=None):
    return _build_msal_app(authority=authority).get_authorization_request_url(
        scopes or [],
        state=state or str(uuid.uuid4()),
        redirect_uri=url_for('authorized', _external=True, _scheme='https')
    )
