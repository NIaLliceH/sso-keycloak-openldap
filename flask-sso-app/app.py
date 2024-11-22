import jwt
import json
from flask import Flask, redirect, url_for, render_template, jsonify, session
from flask_oidc import OpenIDConnect
from datetime import datetime
import pytz
import requests

with open('client_secrets.json') as f:
    client_secrets = json.load(f)

app = Flask(__name__)
app.config.update({
    'SECRET_KEY': 'EubEJ8O3SF3beBGYzIQpRnx1yqyK339C',
    'OIDC_CLIENT_SECRETS': client_secrets,
    'OIDC_SCOPES': ['openid', 'email', 'profile', 'roles'],
    'OIDC_INTROSPECTION_AUTH_METHOD': 'client_secret_post',
    'OIDC_USER_INFO_ENABLED': True,
})
oidc = OpenIDConnect(app)

@app.template_filter('timestamp_to_date')
def timestamp_to_date(timestamp):
    if timestamp:
        vietnam_tz = pytz.timezone('Asia/Ho_Chi_Minh')
        dt = datetime.fromtimestamp(timestamp, tz=pytz.utc)  # Convert timestamp to UTC
        vietnam_time = dt.astimezone(vietnam_tz)
        return vietnam_time.strftime('%Y-%m-%d %H:%M:%S')
    
    return "Unknown"

@app.route('/')
def home():
    if oidc.user_loggedin:
        print("User is logged in")
    else:
        print("User is not logged in")
    return render_template('home.html', oidc=oidc)

@app.route('/profile')
@oidc.require_login
def profile():
    # Get user information
    info = session.get('oidc_auth_profile', {})
    
    # Access the access token using the OIDC helper method
    access_token = oidc.get_access_token()

    # Decode the access token and get the expiration time (exp)
    if access_token:
        token_data = jwt.decode(access_token, options={"verify_signature": False})
        token_expiry = token_data.get('exp')  # Expiry time is in the 'exp' field (in seconds)
    else:
        token_expiry = None

    return render_template('profile.html', info=info, token_expiry=token_expiry, access_token=access_token)

@app.route('/refresh_token')
@oidc.require_login
def refresh_token():
    refresh_token = oidc.get_refresh_token()
    
    if not refresh_token:
        return jsonify({'error': 'No refresh token available'}), 400

    # Get the client credentials from the loaded client secrets
    client_id = app.config['OIDC_CLIENT_SECRETS']['web']['client_id']
    client_secret = app.config['OIDC_CLIENT_SECRETS']['web']['client_secret']
    token_uri = app.config['OIDC_CLIENT_SECRETS']['web']['token_uri']
    
    data = {
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token,
        'client_id': client_id,
        'client_secret': client_secret
    }
    
    response = requests.post(token_uri, data=data)

    if response.status_code == 200:
        refreshed_token = response.json().get('access_token')
        token_data = jwt.decode(refreshed_token, options={"verify_signature": False})
        new_token_expiry = timestamp_to_date(token_data.get('exp'))
        print(f"Token refreshed successfully. New expiry time: {new_token_expiry}")
        return jsonify({'token_expiry': new_token_expiry, 'access_token': refreshed_token}), 200
    else:
        return jsonify({'error': 'Failed to refresh the token', 'details': response.json()}), 400


@app.route('/logout_sso')
def logout_sso():
    keycloak_logout_url = app.config['OIDC_CLIENT_SECRETS']['web']['logout_uri']
    cliend_id = app.config['OIDC_CLIENT_SECRETS']['web']['client_id']
    return redirect(f"{keycloak_logout_url}?client_id={cliend_id}&post_logout_redirect_uri={url_for('home', _external=True)}")


if __name__ == '__main__':
    app.run(debug=True, port=5000)
