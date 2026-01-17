import base64
from typing import Any
import azure.functions as func
import functools
import jwt
import logging
import re
import requests
import os
import secrets
import hashlib

from azure.functions import HttpRequest,HttpResponse
from http.cookies import SimpleCookie
from config import cfg
from http_utils import http_error, login_redirect

def get_session_id_and_data_from_req(req: HttpRequest) -> tuple[str, Any] | None:
    """
    Returns session_id and session_data
    """
    cookie_header = req.headers.get("cookie")
    if cookie_header:
        cookie = SimpleCookie()
        cookie.load(cookie_header)

        if "session_id" not in cookie:
            return None
    else:
        return None

    session_id = cookie["session_id"].value

    if not session_id:
        return None

    session_data = get_session_data(session_id)

    if not session_data:
        return None

    return session_id, session_data

# Simple decorator that does some login handling
def auth(token=False):
    def decorator(func):
        def wrapper(req: HttpRequest):
            res = get_session_id_and_data_from_req(req)
            if not res:
                logging.info("user data from session not found, redirecting to login...")
                # Invalid session, or session expired
                return login_redirect()

            session_id, session_data = res

            if token:
                print("TOKEN TRUE")

            # Ignore lint errors
            req.session_data = session_data
            req.session_id = session_id

            result = func(req)
            return result

        return wrapper
    return decorator

def generate_code_challenge_pair() -> tuple[str, str]:
    """
    Used for submitting the request to retrieve an access token
    returns tuple[code_verifier, code_challenge]
    """
    code_verifier = base64.urlsafe_b64encode(os.urandom(40)).decode('utf-8')
    code_verifier = re.sub('[^a-zA-Z0-9]+', '', code_verifier)

    code_challenge = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge).decode('utf-8')
    code_challenge = code_challenge.replace('=', '')

    return (code_verifier, code_challenge)

def get_session_data(session_id_from_cookie: str):
    # Hash the incoming cookie value
    incoming_hash = hashlib.sha256(session_id_from_cookie.encode()).hexdigest()
    
    # Look it up in your "database"
    session_data = cfg["sessions"].get(incoming_hash)
    
    if not session_data:
        return None # Session is invalid or expired
        
    return session_data

def revoke_session(session_id_from_cookie: str):
    # Hash the incoming cookie value
    incoming_hash = hashlib.sha256(session_id_from_cookie.encode()).hexdigest()

    del cfg["sessions"][incoming_hash]

def generate_session_id_and_hash() -> tuple[str,str]:
    session_id = secrets.token_urlsafe(32)

    session_hash = hashlib.sha256(session_id.encode("utf-8")).hexdigest()

    return session_id, session_hash

def set_new_access_token_session(req: HttpRequest, access_token_json):
    """
    Uses the authorization code to request a new access token.
    Stores the access token in a session and requests.
    Validates access_token
    """
    res = get_session_id_and_data_from_req(req)
    if not res:
        raise Exception("session_id not found in user who must be logged in. Fatal!")

    _, session_data = res
    session_data["access_token"] = access_token_json

def create_new_id_session(id_token: str):
    """
    Returns a cookie string for an id_token. Validates id_token.
    """
    payload, header = validate_id_token(id_token)

    session_id, session_hash = generate_session_id_and_hash()

    #print(payload)
    #print(header)

    cfg["sessions"][session_hash] = {
        "payload": payload,
        "header": header,
        "id_token": id_token,
    }

    # HttpOnly: Prevents JS access (XSS protection)
    # Secure: Only sent over HTTPS
    # SameSite=Lax: Modern browser standard for CSRF protection
    cookie_string = (
        f"session_id={session_id}; "
        "Path=/; "
        "HttpOnly; "
        "Secure; "
        "SameSite=Lax; "
        "Max-Age=86400"  # Valid for 24 hours
    )

    # Return the cookie as a string
    return cookie_string

# Since we're getting the access_token through backchannel for now, 
# we don't have to validate it 
#def validate_access_token(access_token: str|bytes, session_data):
#    if not session_data:
#        raise Exception("session_data object empty. Fatal!")
#
#    print(session_data)
#    payload, header = session_data["payload"], session_data["header"]
#    alg_obj = jwt.get_algorithm_by_name(header["alg"])
#
#    # compute at_hash, then validate / assert
#    if isinstance(access_token, str):
#        access_token = access_token.encode("utf-8")
#    digest = alg_obj.compute_hash_digest(access_token)
#    digest = digest[:(len(digest) // 2)]
#    at_hash = base64.urlsafe_b64encode(digest).rstrip(b"=")
#    for key in payload:
#        print(key)
#    assert at_hash == payload["at_hash"]

# TODO 
# Validate the nonce
def validate_id_token(id_token: str, access_token: str|bytes|None = None):
    client_id = os.getenv("CLIENT_ID")
    oidc_server = os.getenv("AUTHORITY")
    if not oidc_server:
        raise Exception("`validate_id_token` error, env vars not found")

    oidc_config = requests.get(
        f"{oidc_server}/.well-known/openid-configuration"
    ).json()

    signing_algos = oidc_config["id_token_signing_alg_values_supported"]

    # setup a PyJWKClient to get the appropriate signing key
    jwks_client = jwt.PyJWKClient(oidc_config["jwks_uri"])

    # Part 2: login / authorization
    # when a user completes an OIDC login flow, there will be a well-formed
    # response object to parse/handle

    # data from the login flow
    # see: https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
    #access_token = token_response["access_token"]

    # Part 3: decode and validate at_hash
    # after the login is complete, the id_token needs to be decoded
    # this is the stage at which an OIDC client must verify the at_hash

    # get signing_key from id_token
    signing_key = jwks_client.get_signing_key_from_jwt(id_token)

    # now, decode_complete to get payload + header
    data = jwt.decode_complete(
        id_token,
        key=signing_key,
        audience=client_id,
        algorithms=signing_algos,
    )
    payload, header = data["payload"], data["header"]


    return payload, header
