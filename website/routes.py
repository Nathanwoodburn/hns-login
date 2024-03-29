import time
from .varo_auth import flask_login as varo_auth_flask_login
from flask import Blueprint, request, session, url_for
from flask import render_template, redirect, jsonify, send_from_directory
from werkzeug.security import gen_salt
from authlib.integrations.flask_oauth2 import current_token
from authlib.oauth2 import OAuth2Error
from .models import db, User, OAuth2Client
from .oauth2 import authorization, require_oauth


bp = Blueprint('home', __name__)


def current_user():
    if 'id' in session:
        uid = session['id']
        return User.query.get(uid)
    return None


def split_by_crlf(s):
    return [v for v in s.splitlines() if v]


@bp.route('/', methods=('GET', 'POST'))
def home():
    next_page = request.args.get('next')
    if request.method == 'POST':
        auth = varo_auth_flask_login(request)
        if auth == False:
            return redirect('/?error=login_failed')
        print(auth)
        user = User.query.filter_by(username=auth).first()
        if not user:
            user = User(username=auth)
            db.session.add(user)
            db.session.commit()
        session['id'] = user.id
        # if user is not just to log in, but need to head back to the auth page, then go for it
        if next_page:
            return redirect(next_page)
        return redirect('/')
    user = current_user()
    if user:
        clients = OAuth2Client.query.filter_by(user_id=user.id).all()
        if next_page:
            return redirect(next_page)
    else:
        clients = []
    
    return render_template('home.html', user=user, clients=clients)


@bp.route('/logout')
def logout():
    del session['id']
    next = request.args.get('next')
    if next:
        return redirect(url_for('home.home', next=next))

    return redirect('/')


@bp.route('/create_client', methods=('GET', 'POST'))
def create_client():
    user = current_user()
    if not user:
        return redirect('/')
    if request.method == 'GET':
        return render_template('create_client.html')

    client_id = gen_salt(24)
    client_id_issued_at = int(time.time())
    client = OAuth2Client(
        client_id=client_id,
        client_id_issued_at=client_id_issued_at,
        user_id=user.id,
    )

    form = request.form
    client_metadata = {
        "client_name": form["client_name"],
        "client_uri": form["client_uri"],
        "grant_types": split_by_crlf(form["grant_type"]),
        "redirect_uris": split_by_crlf(form["redirect_uri"]),
        "response_types": split_by_crlf(form["response_type"]),
        "scope": form["scope"],
        "token_endpoint_auth_method": form["token_endpoint_auth_method"]
    }
    client.set_client_metadata(client_metadata)

    if form['token_endpoint_auth_method'] == 'none':
        client.client_secret = ''
    else:
        client.client_secret = gen_salt(48)

    db.session.add(client)
    db.session.commit()
    return redirect('/')

@bp.route('/delete_client')
def delete_client():
    user = current_user()
    if not user:
        return redirect('/')
    if user.id != 1:
        return redirect('/')

    client_id = request.args.get('client_id')
    client = OAuth2Client.query.filter_by(client_id=client_id).first()
    if client:
        db.session.delete(client)
        db.session.commit()
    return redirect('/')


@bp.route('/oauth/authorize', methods=['GET', 'POST'])
def authorize():
    user = current_user()
    # if user log status is not true (Auth server), then to log it in
    if not user:
        return redirect(url_for('home.home', next=request.url))
    if request.method == 'GET':
        try:
            grant = authorization.get_consent_grant(end_user=user)
        except OAuth2Error as error:
            return error.error
        return render_template('authorize.html', user=user, grant=grant)
    
    grant_user = user
    
    return authorization.create_authorization_response(grant_user=grant_user)


@bp.route('/oauth/token', methods=['POST'])
def issue_token():
    return authorization.create_token_response()


@bp.route('/oauth/revoke', methods=['POST'])
def revoke_token():
    return authorization.create_endpoint_response('revocation')


@bp.route('/api/me')
@require_oauth('profile')
def api_me():
    user = current_token.user
    print(user.id, user.username)
    return jsonify(id=user.id, username=user.username,
                   email= f'{user.username}@login.hns.au',
                   displayName=user.username+"/")

@bp.route('/discovery')
def autodiscovery():
    host = request.host
    discovery = {
    "issuer": f"https://{host}/",
    "authorization_endpoint": f"https://{host}/oauth/authorize",
    "token_endpoint": f"https://{host}/oauth/token",
    "userinfo_endpoint": f"https://{host}/api/me",
    "revocation_endpoint": f"https://{host}/oauth/revoke",
    "response_types_supported": [
        "code"
    ],
    "subject_types_supported": [
        "public"
    ],
    "id_token_signing_alg_values_supported": [
        "RS256"
    ],
    "scopes_supported": [
        "openid",
        "email",
        "profile"
    ],
    "token_endpoint_auth_methods_supported": [
        "client_secret_basic",
        "client_secret_post",
    ],
    "grant_types_supported": [
        "authorization_code"
    ]
}


    return jsonify(discovery)



@bp.route('/favicon.png')
def favicon():
    return send_from_directory('templates', 'favicon.png', mimetype='image/png')