import base64
import azure.functions as func
import functools
import jwt
import requests
import os
import secrets
import hashlib

from azure.functions import HttpRequest,HttpResponse
from http.cookies import SimpleCookie
from config import cfg
from http_utils import http_error, login_redirect

# Simple decorator that does some login handling
def auth(func):
    @functools.wraps(func)
    def wrapper(req: HttpRequest):
#        req = kwargs.get('req') or (args[0] if args else None)
#        assert isinstance(req, HttpRequest)
        print("req headers", dict(req.headers.items()))
        cookie_header = req.headers.get("cookie")

        if cookie_header:
            cookie = SimpleCookie()
            cookie.load(cookie_header)

            if "session_id" not in cookie:
                return login_redirect()

            user_session_id = cookie["session_id"].value

            user_data = get_session_data(user_session_id)
            if not user_data:
                # Invalid session, or session expired
                return login_redirect()

            req.user_data = user_data
            req.session_id = user_session_id

            result = func(req)
            return result

        else:
            return login_redirect()

    return wrapper

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

def create_new_id_session(id_token: str):
    payload, header = validate_tokens(id_token)

    session_id, session_hash = generate_session_id_and_hash()

    print(payload)
    print(header)

    cfg["sessions"][session_hash] = payload

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

    # 4. Return the response with the header
    return func.HttpResponse(
        "Logged in successfully",
        status_code=200,
        headers={
            "Set-Cookie": cookie_string
        }
    )

def validate_tokens(id_token: str, access_token: str|bytes|None = None):
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

    # get the pyjwt algorithm object
    alg_obj = jwt.get_algorithm_by_name(header["alg"])

    # compute at_hash, then validate / assert
    if access_token:
        if isinstance(access_token, str):
            access_token = access_token.encode("utf-8")
        digest = alg_obj.compute_hash_digest(access_token)
        at_hash = base64.urlsafe_b64encode(digest[: (len(digest) // 2)]).rstrip("=")
        assert at_hash == payload["at_hash"]

    return payload, header
