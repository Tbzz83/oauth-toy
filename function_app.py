from typing import Any
import azure.functions as func
import logging
import dotenv
import os

from urllib.parse import urlencode, parse_qs
from http_utils import http_error, login_redirect

from auth import auth, create_new_id_session, revoke_session
from config import cfg

app = func.FunctionApp()
dotenv.load_dotenv()

@app.route(route="login", auth_level=func.AuthLevel.FUNCTION, methods=["GET"])
def login(req: func.HttpRequest) -> func.HttpResponse:
    try:
        logging.info('Login function triggered')
        authority_uri = os.getenv("AUTHORITY")
        client_id = os.getenv("CLIENT_ID")
        client_secret = os.getenv("CLIENT_SECRET")
        host = os.getenv("HOST")
        if not authority_uri or not client_id or not client_secret or not host:
            return http_error("`login error`, issue acquiring env vars")

        endpoint = f"{authority_uri}/oauth2/v2.0/authorize"

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

        return login_redirect()

    except Exception as e:
        return http_error(f"{e}")

@app.route(route="logout", auth_level=func.AuthLevel.FUNCTION)
@auth
def logout(req: func.HttpRequest) -> func.HttpResponse:
    authority_uri = os.getenv("AUTHORITY")
    host = os.getenv("HOST")
    if not authority_uri or not host: 
        return http_error("issue acquiring env vars")

    endpoint = f"{authority_uri}/oauth2/v2.0/logout"

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
         "Home page",
         status_code=200
    )

@app.route(route="session", auth_level=func.AuthLevel.FUNCTION)
@auth
def get_user_session_data(req: func.HttpRequest) -> func.HttpResponse:
    # We're providing this from auth
    return func.HttpResponse(
         f"{req.user_data}",
         status_code=200
    )


@app.route(route="sessions", auth_level=func.AuthLevel.FUNCTION)
def get_sessions(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Get sessions function triggered')

    return func.HttpResponse(
         f"{cfg}",
         status_code=200
    )

# id_token will be returned here, as this is the redirect URI
@app.route(route="auth-response", auth_level=func.AuthLevel.FUNCTION)
def auth_response(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Home function triggered')
    
    data = {}
    try:
        data = parse_qs(req.get_body().decode('utf-8'))
    except ValueError as _:
        pass

    id_token = data.get('id_token')
    print(id_token)
    if not id_token:
        return http_error('id_token not set')

    try:
        response = create_new_id_session(id_token[0])

        return response

    except Exception as e:
        return http_error(e.__str__())
