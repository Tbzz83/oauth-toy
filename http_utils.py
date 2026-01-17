from azure.functions import HttpResponse 

def http_error(e: str) -> HttpResponse:
    return HttpResponse(
        f"Error: {e}",
        status_code=500
    )

def token_redirect() -> HttpResponse:
    return HttpResponse(
        "Redirecting to acquire token",
        status_code=302,
        headers={
            "Location": "/api/token",
        }
    )

def login_redirect() -> HttpResponse:
    return HttpResponse(
        "Redirecting to login",
        status_code=302,
        headers={
            "Location": "/api/login",
        }
    )
