from types import TracebackType
from typing import Any
from oauth_utils import *
import azure.functions as func
import traceback
import logging
import base64
import requests
import dotenv
import os
import json

from urllib.parse import urlencode, parse_qs
from http_utils import http_error, login_redirect

from auth import auth, set_new_access_token_session, create_new_id_session, generate_code_challenge_pair, get_session_id_and_data_from_req, revoke_session
from config import cfg

"""
This application demonstrates two distinct authentication/authorization flows:

1. OIDC AUTHENTICATION (/api/login):
   - Uses implicit grant to obtain an id_token ONLY
   - The id_token proves the user's identity (authentication)
   - Delivered via form_post (not URL fragment) for security
   - This is NOT the deprecated "implicit flow for access tokens"

2. OAUTH AUTHORIZATION (/api/token):
   - Uses Authorization Code flow with PKCE (Proof Key for Code Exchange)
   - Obtains an access_token to call Microsoft Graph API
   - PKCE protects against authorization code interception attacks
   - Client secret is also used (defense in depth for confidential clients)
   - Token exchange happens server-to-server (backchannel), never exposed to browser

WHY NOT USE IMPLICIT FLOW FOR ACCESS TOKENS?
Even though Azure AD supports returning access tokens via implicit flow 
(response_type=token) with form_post delivery, this is discouraged because:
- Access tokens in browser memory are vulnerable to XSS attacks
- No client authentication possible on the token request
- Refresh tokens cannot be issued
- OAuth 2.1 formally deprecates implicit flow for access tokens

These steps are intentionally separated for educational purposes. In production,
you might combine them or use libraries like MSAL that handle this for you.

For more information, see:
- OIDC: https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc
- OAuth 2.0 Auth Code: https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow
- Why implicit is dead: https://blog.logto.io/implicit-flow-is-dead
"""

app = func.FunctionApp()
dotenv.load_dotenv()
access_token_scope = "email"

@app.route(route="people", auth_level=func.AuthLevel.FUNCTION, methods=["GET"])
@auth(token=True)
def people(req: func.HttpRequest) -> func.HttpResponse:

    response_message = "People:\n"
    access_token = req.session_data["access_token"]["access_token"]
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json" # Optional: specify desired response format
    }

    response = requests.get(
        "https://graph.microsoft.com/v1.0/me/people",
        headers=headers,
    )
    
    data = response.json()

    for person in data['value']:
        response_message += f"{person}"

    return func.HttpResponse(
        response_message, 
        status_code=200,
    )

@app.route(route="login", auth_level=func.AuthLevel.FUNCTION, methods=["GET"])
def login(req: func.HttpRequest) -> func.HttpResponse:
    """
    Logs the user in, storing their id_token in a session and 
    return the session_id as an http only cookie to the client
    """
    try:
        logging.info('Login function triggered')
        authority_uri = os.getenv("AUTHORITY")
        client_id = os.getenv("CLIENT_ID")
        client_secret = os.getenv("CLIENT_SECRET")
        host = os.getenv("HOST")
        if not authority_uri or not client_id or not client_secret or not host:
            return http_error("`login error`, issue acquiring env vars")

        endpoint = get_authorization_endpoint()

        params = {
            "client_id": client_id,
            "response_type": "id_token",
            "redirect_uri": f"{host}/api/auth-response",
            "response_mode": "form_post",
            "scope": "openid",
            "state": "12345",  # In production, make this a random string
            "nonce": "678910"   # In production, make this a random string
        }

        full_url = f"{endpoint}?{urlencode(params)}"

        return func.HttpResponse(
            "Redirecting to microsoft login...",
            status_code=302,
            headers={
                "Location": full_url
            }
        )

    except Exception as e:
        return http_error(f"{e}")

@app.route(route="logout", auth_level=func.AuthLevel.FUNCTION)
@auth() # This isn't ideal, but works for now
def logout(req: func.HttpRequest) -> func.HttpResponse:
    authority_uri = os.getenv("AUTHORITY")
    host = os.getenv("HOST")
    if not authority_uri or not host: 
        return http_error("issue acquiring env vars")

    endpoint = get_end_session_endpoint()

    params = {
        "post_logout_redirect_uri": f"{host}/api/home",
    }

    # Ignore lint error
    revoke_session(req.session_id)

    return func.HttpResponse(
        "Redirecting to logout",
        status_code=302,
        headers={
            "Location": f"{endpoint}?{urlencode(params)}"
        }
    )

@app.route(route="home", auth_level=func.AuthLevel.FUNCTION)
def home(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Home function triggered')
    print(req.headers)
    return func.HttpResponse(
"""
Home page

Routes:
/api/login - acquire id_token and session initialization
/api/logout
/api/session - displays users current session_data
/api/sessions - displays all sessions data
/api/token - acquire an access_token
/api/auth-response - callback_uri
/api/people - Lists people you work with

""",
         status_code=200
    )


@app.route(route="session", auth_level=func.AuthLevel.FUNCTION)
@auth()
def get_user_session_data(req: func.HttpRequest) -> func.HttpResponse:

    data = {
        "session_id" : req.session_id,
        "session_data": req.session_data,
    }
    # We're providing this from auth
    return func.HttpResponse(
         f"{data}",
         status_code=200
    )

"""
Need to send a GET request:
https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize?
client_id=00001111-aaaa-2222-bbbb-3333cccc4444
&response_type=code
&redirect_uri=http%3A%2F%2Flocalhost%2Fmyapp%2F
&response_mode=query
&scope=https%3A%2F%2Fgraph.microsoft.com%2Fmail
&state=12345
&code_challenge=YTFjNjI1OWYzMzA3MTI4ZDY2Njg5M2RkNmVjNDE5YmEyZGRhOGYyM2IzNjdmZWFhMTQ1ODg3NDcxY2Nl
&code_challenge_method=S256
"""

@app.route(route="token", auth_level=func.AuthLevel.FUNCTION)
@auth()
def get_access_token(req: func.HttpRequest) -> func.HttpResponse:
    try:
        logging.info('Login function triggered')
        authority_uri = os.getenv("AUTHORITY")
        client_id = os.getenv("CLIENT_ID")
        client_secret = os.getenv("CLIENT_SECRET")
        host = os.getenv("HOST")
        if not authority_uri or not client_id or not client_secret or not host:
            return http_error("`login error`, issue acquiring env vars")

        endpoint = get_authorization_endpoint()

        code_verifier, code_challenge = generate_code_challenge_pair()
        res = get_session_id_and_data_from_req(req)
        if not res:
            return http_error("`get_access_token` session couldn't be found in memory")

        _, session_data = res
        session_data["code_verifier"], session_data["code_challenge"] = code_verifier, code_challenge

        params = {
            "client_id": client_id,
            "response_type": "code",
            "redirect_uri": f"{host}/api/auth-response",
            "response_mode": "query",
            "scope": access_token_scope,
            "state": "12345",  # In production, make this a random string
            "code_challenge": code_challenge, 
            "code_challenge_method": "S256"
        }

        full_url = f"{endpoint}?{urlencode(params)}"

        return func.HttpResponse(
            "Redirecting to microsoft login...",
            status_code=302,
            headers={
                "Location": full_url
            }
        )

    except Exception as e:
        return http_error(str(e))

@app.route(route="sessions", auth_level=func.AuthLevel.FUNCTION)
@auth()
def get_sessions(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Get sessions function triggered')

    return func.HttpResponse(
         f"{cfg}",
         status_code=200
    )

# id_token will be returned here, as this is the redirect URI
@app.route(route="auth-response", auth_level=func.AuthLevel.FUNCTION)
def auth_response(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Auth-response function triggered')
    try:
        
        data = {}
        title = "Auth-Response:\n"
        response_message = ""
        headers = []

        # --- ID TOKEN
        try:
            data = parse_qs(req.get_body().decode('utf-8'))
        except ValueError as _:
            pass

        id_token = data.get('id_token')
        if id_token:
            id_cookie_string = create_new_id_session(id_token[0])
            headers.append(("Set-Cookie", id_cookie_string))
            response_message += "\nSuccessfully set id_token"
        # ---

        # --- AUTHZ CODE
        if req.params:
            authz_code = req.params.get('code')
            if authz_code:
                authority_uri = os.getenv("AUTHORITY")
                client_id = os.getenv("CLIENT_ID")
                client_secret = os.getenv("CLIENT_SECRET")
                host = os.getenv("HOST")
                if not authority_uri or not client_id or not client_secret or not host:
                    return http_error("`login error`, issue acquiring env vars")

                endpoint = get_token_endpoint()

                res = get_session_id_and_data_from_req(req)
                if not res:
                    return http_error("`auth_response` session couldn't be found in memory")

                _, session_data = res

                params = {
                    "client_id": client_id,
                    "grant_type": "authorization_code",
                    "redirect_uri": f"{host}/api/auth-response",
                    "scope": access_token_scope,
                    "client_secret": client_secret,
                    "code": authz_code,
                    "code_verifier": session_data["code_verifier"],
                }

                full_url = f"{endpoint}"
                resp: requests.Response = requests.post(
                    url=full_url,
                    data=params
                )

                access_token_json = resp.json()
                set_new_access_token_session(req, access_token_json)
                response_message += "\nSuccessfully set access_token"
        # ---

        if not response_message:
            response_message = f"No tokens have been delivered. Is the scope(s) {access_token_scope} correct?"
            error_msg = data.get("error_description")
            if error_msg: 
                response_message += f"\n{error_msg}"

        title += response_message
        response = func.HttpResponse(
            title,
            status_code=200,
        )

        for header in headers:
            response.headers.add(header[0], header[1])

        return response

    except Exception as e:
        error_details = traceback.format_exc()
        return http_error(error_details)
