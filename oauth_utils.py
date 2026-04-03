from typing import Any
import requests
import os

def get_openid_config_json() -> Any:
    openid_config_endpoint = os.getenv("OPENID_CONFIG_ENDPOINT")
    if not openid_config_endpoint:
        raise Exception("OPENID_CONFIG_ENDPOINT env var not set")

    return requests.get(openid_config_endpoint).json()

def get_authorization_endpoint() -> str:
    """
    Gets the authorization endpoint uri from .well-known/openid-configuration
    """
    return get_openid_config_json()["authorization_endpoint"]

def get_token_endpoint() -> str:
    """
    Gets the token endpoint uri from .well-known/openid-configuration
    """
    return get_openid_config_json()["token_endpoint"]

def get_end_session_endpoint() -> str:
    """
    Gets the end session endpoint uri from .well-known/openid-configuration
    """
    return get_openid_config_json()["end_session_endpoint"]

