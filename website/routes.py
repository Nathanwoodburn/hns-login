import time
from .varo_auth import flask_login as varo_auth_flask_login
from flask import Blueprint, request, session, url_for, make_response
from flask import render_template, redirect, jsonify, send_from_directory
from werkzeug.security import gen_salt
from authlib.integrations.flask_oauth2 import current_token
from authlib.oauth2 import OAuth2Error
from .models import db, User, OAuth2Client
from .oauth2 import authorization, require_oauth
import os
import requests
import dns.message
import dns.query
import dns.rdatatype
from requests_doh import DNSOverHTTPSSession, add_dns_provider
from datetime import timedelta
from eth_account.messages import encode_defunct
from eth_account import Account
import json



bp = Blueprint("home", __name__)
openSeaAPIKey = os.getenv("OPENSEA_API_KEY")

restricted_keys = [
    "id",
    "uid",
    "username",
    "sub",
    "email_verified",
    "roles",
    "role",
    "admin"
]

if not os.path.exists("website/avatars"):
    os.makedirs("website/avatars")

def current_user():
    if "id" in session:
        uid = session["id"]
        return User.query.get(uid)
    return None


def split_by_crlf(s):
    return [v for v in s.splitlines() if v]

def get_idns_records(domain:str) -> list:
    query = dns.message.make_query(domain, dns.rdatatype.TXT)
    dns_request = query.to_wire()
    # Send the DNS query over HTTPS
    response = requests.post('https://hnsdoh.com/dns-query', data=dns_request, headers={'Content-Type': 'application/dns-message'})
    # Parse the DNS response
    dns_response = dns.message.from_wire(response.content)
    # Loop over TXT records and look for profile 
    idns_records = []
    for record in dns_response.answer:
        if record.rdtype == dns.rdatatype.TXT:
            for txt in record:
                txt_value:str = txt.to_text().strip('"')
                if txt_value.startswith("IDNS1"):
                    print(txt_value)
                    idns = txt_value.removeprefix("IDNS1 ")
                    idns = idns.split(" ")
                    for r in idns:
                        idns_records.append(r)
    return idns_records

def get_user_info(user:User) -> dict:
    picture = f"https://login.hns.au/u/{user.username}/avatar.png"

    if user.profile_picture:
        picture = user.profile_picture

    userInfo = {
        "id": user.id,
        "uid": user.id,
        "username": user.username,
        "email": f"{user.username}@login.hns.au",
        "displayName": user.username + "/",
        "sub": user.id,
        "name": user.username,
        "given_name": user.username,
        "family_name": user.username,
        "nickname": user.username,
        "preferred_username": user.username,
        "profile": f"https://login.hns.au/u/{user.username}",
        "picture": picture,
        "website": f"https://{user.username}",
        "email_verified": True
    }

    idns_info = get_idns_records(user.username)
    for record in idns_info:
        type = record.split(":")[0]
        content = record.split(":")
        if len(content) > 2:
            content = ":".join(content[1:])
        else:
            content = content[1]
        key = content.split("=")[0].lower()
        value = content.split("=")[1]
        if type == "profile":
            if key == "avatar":
                userInfo["picture"] = value
            elif key == "email":
                userInfo["email"] = value
                userInfo["email_verified"] = False
            elif key == "name":
                userInfo["name"] = value
                userInfo["nickname"] = value
                userInfo["displayName"] = value
            else:
                if key in restricted_keys:
                    continue
                userInfo[key] = value
    
    return userInfo

@bp.route("/", methods=("GET", "POST"))
def home():
    next_page = request.args.get("next")

    # Check if session exists
    if "uuid" not in session:
        session["uuid"] = gen_salt(24)
        session.permanent = True

    uuid = session["uuid"]

    if request.method == "POST":
        auth = varo_auth_flask_login(request)
        if auth == False:
            return redirect("/?error=login_failed")
        print(auth)
        user = User.query.filter_by(username=auth).first()
        if not user:
            user = User(username=auth)
            db.session.add(user)
            db.session.commit()
        session["id"] = user.id
        # Make sure the session is permanent
        session.permanent = True
        # if user is not just to log in, but need to head back to the auth page, then go for it
        if next_page:
            return redirect(next_page)
        return redirect("/")
    user = current_user()
    users = []
    if user:
        clients = OAuth2Client.query.filter_by(user_id=user.id).all()

        if user.id == 1:
            clients = OAuth2Client.query.all()
            users = User.query.all()
            users = [{"id": user.id, "username": user.username} for user in users]

        if next_page:
            return redirect(next_page)
    else:
        clients = []

    # Check if the user has signed in with HNS ID
    hnsid=''
    address=''
    if "address" in session:
        address = session["address"]
        openseaInfo = requests.get(f"https://api.opensea.io/api/v2/chain/optimism/account/{address}/nfts?collection=handshake-slds",
            headers={"Accept": "application/json",
                     "x-api-key":openSeaAPIKey})
        if openseaInfo.status_code == 200:
            hnsid = openseaInfo.json()

    domains = []
    if 'domains' in session:
        domains = session['domains']

    

    return render_template("home.html", user=user, clients=clients,
                           address=address, hnsid=hnsid, users=users,
                           uuid=uuid, next=next_page, domains=domains)

@bp.route("/hnsid", methods=["POST"])
def hnsid():
    # Get address and signature from the request
    address = request.json.get("address")
    signature = request.json.get("signature")
    message = request.json.get("message")
    # Verify the signature
    msg = encode_defunct(text=message)
    signer = Account.recover_message(msg, signature=signature).lower()
    if signer != address:
        print("Signature verification failed")
        print(signer, address)
        return jsonify({"success": False})

    # Save the address in the session
    session["address"] = address
    session.permanent = True

    return jsonify({"success": True})

@bp.route("/hnsid/<domain>")
def hnsid_domain(domain):
    # Get the address from the session
    address = session.get("address")
    if not address:
        return jsonify({"error": "No address found in session"})
    
    # Get domain info from Opensea
    openseaInfo = requests.get(f"https://api.opensea.io/api/v2/chain/optimism/account/{address}/nfts?collection=handshake-slds",
        headers={"Accept": "application/json",
                 "x-api-key":openSeaAPIKey})
    if openseaInfo.status_code != 200:
        return jsonify({"error": "Failed to get domain info from Opensea"})
    hnsid = openseaInfo.json()
    for nft in hnsid["nfts"]:
        if nft["name"] == domain:
            # Add domain to the session
            user = User.query.filter_by(username=domain).first()
            if not user:
                # Create user with username and profile picture
                user = User(username=domain, profile_picture=nft["image_url"])
                db.session.add(user)
                db.session.commit()
            session["id"] = user.id
            session.permanent = True

            # Check if next page is specified
            next_page = request.args.get("next")
            if next_page:
                return redirect(next_page)

            return redirect("/")

    return jsonify({"success": False, "error": "Domain not found"})


@bp.route("/txt", methods=["POST"])
def txtLogin():
    # Get domain from form
    domain = request.form.get("domain")
    # Get uuid
    uuid = session["uuid"]

    query = dns.message.make_query(domain, dns.rdatatype.TXT)
    dns_request = query.to_wire()

    # Send the DNS query over HTTPS
    response = requests.post('https://hnsdoh.com/dns-query', data=dns_request, headers={'Content-Type': 'application/dns-message'})

    # Parse the DNS response
    dns_response = dns.message.from_wire(response.content)

    # Loop over TXT records and look for profile avatar
    idns_records = []
    for record in dns_response.answer:
        if record.rdtype == dns.rdatatype.TXT:
            for txt in record:
                txt_value:str = txt.to_text().strip('"')
                if txt_value.startswith("IDNS1"):
                    print(txt_value)
                    idns = txt_value.removeprefix("IDNS1 ")
                    idns = idns.split(" ")
                    for r in idns:
                        idns_records.append(r)

    for record in idns_records:
        print(record)
        type = record.split(":")[0]
        content = record.split(":")[1]
        key = content.split("=")[0]
        value = content.split("=")[1]
        print(f"Type: {type}, Key: {key}, Value: {value}")
        if type == "auth" and key == "login.hns.au":
            if value == uuid:
                # Add domain to user
                user = User.query.filter_by(username=domain).first()
                if not user:
                    # Create user with username and profile picture
                    user = User(username=domain)
                    db.session.add(user)
                    db.session.commit()
                session["id"] = user.id
                session.permanent = True
                if "domains" not in session:
                    session["domains"] = []

                if domain not in session["domains"]:
                    session["domains"].append(domain)
                print("User logged in with TXT")

                # Check if next page is specified
                next_page = request.args.get("next")
                print(next_page)
                if next_page and next_page != "None":
                    return redirect(next_page)
                return redirect("/")

    return render_template("error.html",error="The domain wasn't able to be authenticated.",
                           message="<br>Double check the TXT record and try again",
                           custom="<button onclick='window.location.reload();'>Try again</button>"), 200
        
@bp.route("/txt/<domain>")
def txtLoginDomain(domain):
    # Get uuid
    uuid = session["uuid"]

    idns_records = get_idns_records(domain)
    

    for record in idns_records:
        print(record)
        type = record.split(":")[0]
        content = record.split(":")[1]
        key = content.split("=")[0]
        value = content.split("=")[1]
        print(f"Type: {type}, Key: {key}, Value: {value}")
        if type == "auth" and key == "login.hns.au":
            if value == uuid:
                # Add domain to user
                user = User.query.filter_by(username=domain).first()
                if not user:
                    # Create user with username and profile picture
                    user = User(username=domain)
                    db.session.add(user)
                    db.session.commit()
                session["id"] = user.id
                session.permanent = True
                if "domains" not in session:
                    session["domains"] = []

                if domain not in session["domains"]:
                    session["domains"].append(domain)
                print("User logged in with TXT")

                # Check if next page is specified
                next_page = request.args.get("next")
                print(next_page)
                if next_page and next_page != "None":
                    return redirect(next_page)
                return redirect("/")

    return render_template("error.html",error="The domain wasn't able to be authenticated.",
                           message="<br>Double check the TXT record and try again",
                           custom="<button onclick='window.location.reload();'>Try again</button>"), 200

@bp.route("/logout")
def logout():
    del session["id"]
    next = request.args.get("next")
    if next:
        return redirect(url_for("home.home", next=next))

    return redirect("/")


@bp.route("/create_client", methods=("GET", "POST"))
def create_client():
    user = current_user()
    if not user:
        return redirect("/")
    if request.method == "GET":
        return render_template("create_client.html")

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
        "scope": " ".join(form.getlist("scope")),
        "token_endpoint_auth_method": form["token_endpoint_auth_method"],
    }
    client.set_client_metadata(client_metadata)

    if form["token_endpoint_auth_method"] == "none":
        client.client_secret = ""
    else:
        client.client_secret = gen_salt(48)

    db.session.add(client)
    db.session.commit()
    return redirect("/client/" + client_id)

@bp.route("/client/<client_id>")
def client(client_id):
    user = current_user()
    if not user:
        return redirect("/")
    
    client:OAuth2Client = OAuth2Client.query.filter_by(client_id=client_id).first()
    if not client:
        return redirect("/")
    
    if client.user_id != user.id and user.id != 1:
        return redirect("/")
    
    metadata = client.client_metadata
    # Convert metadata to json
    metadata = json.dumps(metadata, indent=4)

    return render_template("client.html", client=metadata,id=client_id,
                           secret=client.client_secret)


@bp.route("/delete_client")
def delete_client():
    user = current_user()
    if not user:
        return redirect("/")

    client_id = request.args.get("client_id")
    client:OAuth2Client = OAuth2Client.query.filter_by(client_id=client_id).first()

    if not client:
        return redirect("/")
    
    if client.user_id != user.id and user.id != 1:
        return redirect("/")
    
    db.session.delete(client)
    db.session.commit()
    return redirect("/")


@bp.route("/oauth/authorize", methods=["GET", "POST"])
def authorize():
    user = current_user()
    # if user log status is not true (Auth server), then to log it in
    if not user:
        return redirect(url_for("home.home", next=request.url))
    if request.method == "GET":
        try:
            grant = authorization.get_consent_grant(end_user=user)
        except OAuth2Error as error:
            return error.error
        return render_template("authorize.html", user=user, grant=grant)

    grant_user = user

    return authorization.create_authorization_response(grant_user=grant_user)


@bp.route("/oauth/token", methods=["POST"])
def issue_token():
    return authorization.create_token_response()


@bp.route("/oauth/revoke", methods=["POST"])
def revoke_token():
    return authorization.create_endpoint_response("revocation")


@bp.route("/discovery")
def autodiscovery():
    host = request.host
    discovery = {
        "issuer": f"https://{host}/",
        "authorization_endpoint": f"https://{host}/oauth/authorize",
        "token_endpoint": f"https://{host}/oauth/token",
        "userinfo_endpoint": f"https://{host}/api/me",
        "revocation_endpoint": f"https://{host}/oauth/revoke",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "email", "profile"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
        ],
        "grant_types_supported": ["authorization_code"],
    }

    return jsonify(discovery)

@bp.route("/api/me")
@require_oauth(["profile", "openid"])
def api_me():
    user = current_token.user
    return jsonify(get_user_info(user))
    

@bp.route("/u/<username>")
def profile(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": "User not found"})
    
    return jsonify(get_user_info(user))

@bp.route("/u/<username>/avatar.png")
def avatar(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        print("User not found")
        return send_from_directory("templates", "favicon.png", mimetype="image/png")
    
    # Check if file exists
    if os.path.exists(f"website/avatars/{username}.png"):
        return send_from_directory("avatars", f"{username}.png", mimetype="image/png")
    # If not, download from HNS info
    query = dns.message.make_query(username, dns.rdatatype.TXT)
    dns_request = query.to_wire()

    # Send the DNS query over HTTPS
    response = requests.post('https://hnsdoh.com/dns-query', data=dns_request, headers={'Content-Type': 'application/dns-message'})

    # Parse the DNS response
    dns_response = dns.message.from_wire(response.content)

    # Loop over TXT records and look for profile avatar
    avatar_url=""
    for record in dns_response.answer:
        if record.rdtype == dns.rdatatype.TXT:
            for txt in record:
                txt_value = txt.to_text().strip('"')
                if txt_value.startswith("profile avatar="):
                    avatar_url = txt_value.split("profile avatar=")[1]
                    break
    
    if avatar_url != "":
        # Download the avatar using DNS-over-HTTPS
        add_dns_provider("hns", "https://hnsdoh.com/dns-query")
        session = DNSOverHTTPSSession(provider="hns")
        response = session.get(avatar_url)
        with open(f"website/avatars/{username}.png", "wb") as f:
            f.write(response.content)
        return send_from_directory("avatars", f"{username}.png", mimetype="image/png")

    return send_from_directory("templates", "favicon.png", mimetype="image/png")
    
@bp.route("/favicon.png")
def favicon():
    return send_from_directory("templates", "favicon.png", mimetype="image/png")


@bp.errorhandler(404)
@bp.app_errorhandler(404)
def page_not_found(e):
    return render_template("error.html",error="404 - Page Not Found"), 404
