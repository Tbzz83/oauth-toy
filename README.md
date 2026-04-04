# OIDC Toy Application (Python)

This project is a minimal, educational OIDC implementation built as an **Azure Function App**. It demonstrates how to acquire both an `id_token` and an `access_token` in a single Authorization Code flow with PKCE.

---

## 🚀 Routes & Educational Flow

### Discovery & State

* **`/api/home`**: The main dashboard. Lists all available routes and their purposes.
* **`/api/session`**: Displays the data stored in **your** current active session (e.g., tokens, claims).
* **`/api/sessions`**: A "god-mode" view that lists **all** active sessions currently stored by the app. Useful for debugging local state.

*NOTE*: Sessions are stored in-memory, so if you make changes to the app, log in again after restarting.

### Authentication & Authorization

* **`/api/login`**: Initiates the **Authorization Code Flow with PKCE**. Redirects to Azure AD, and on callback, exchanges the authorization code for both an `id_token` and an `access_token` simultaneously via the backchannel.
* **`/api/auth-response`**: The OAuth2 redirect URI / callback. Handles the authorization code exchange—validates the `id_token` and stores both tokens in the session.
* **`/api/logout`**: Revokes the local session and redirects to Azure AD's end-session endpoint.

---

## Understanding the Authentication Flow

This app uses a single **Authorization Code + PKCE** flow to obtain both tokens in one round trip. There is no separate implicit flow for the `id_token` and no separate `/api/token` step.

### How It Works

1. **`/api/login`** generates a PKCE `code_verifier`/`code_challenge` pair and stores them in a new server-side session. It then redirects the user to Azure AD with `response_type=code`, `scope=openid`, and the `code_challenge`.

2. **Azure AD** authenticates the user and redirects back to `/api/auth-response` with an authorization code.

3. **`/api/auth-response`** retrieves the `code_verifier` from the session and makes a server-to-server (backchannel) POST to the token endpoint, exchanging the authorization code for tokens. Azure AD returns both an `id_token` and an `access_token` in a single response because the `openid` scope was requested.

4. Both tokens are validated and stored in the session. The user is now fully authenticated and authorized in one flow.

### Why Authorization Code + PKCE (Not Implicit)?

| Aspect | Authorization Code + PKCE |
|--------|--------------------------|
| **Tokens received** | `id_token` + `access_token` simultaneously |
| **Grant type** | `response_type=code` |
| **PKCE** | Yes — `code_challenge` + `code_verifier` (S256) |
| **Client secret** | Yes — defense in depth for confidential clients |
| **Token delivery** | Backchannel (server-to-server), never exposed to browser |
| **Refresh tokens** | Supported |

Implicit flow (returning tokens directly in the redirect) is formally deprecated by OAuth 2.1. Even when used with `response_mode=form_post`, access tokens end up in browser memory, making them vulnerable to XSS. Authorization Code + PKCE avoids this entirely—the token exchange happens server-to-server and tokens are stored only in the server-side session.

See [Why Implicit Flow is Dead](https://blog.logto.io/implicit-flow-is-dead) for more background.

### Best Practices (OAuth 2.1)

1. **Use Authorization Code + PKCE for all clients** — even public clients (SPAs, mobile) should use auth code + PKCE.
2. **Confidential clients should use PKCE + client secret** — defense in depth. If PKCE is somehow compromised, the attacker still needs the client secret.
3. **Keep tokens server-side** — for server-rendered apps like this one, tokens stay on the server and never touch the browser.

---

### Data Retrieval

* **`/api/people`**: Uses the `access_token` from your session to call the **Microsoft Graph API** (`/me/people`) and returns a list of your coworkers.

---

## 🛠 Local Development

### Prerequisites

* [Azure Functions Core Tools](https://learn.microsoft.com/en-us/azure/azure-functions/functions-run-local)
* Python 3.9+

### Running the App

1. **Environment Variables**: Create a `.env` file in the root directory:
```
CLIENT_SECRET=<client_secret>
CLIENT_ID=<client_id>
AUTHORITY=https://login.microsoftonline.com/<appstate_azure_tenant_id>
HOST=http://localhost:7071
```

To get `CLIENT_SECRET` and `CLIENT_ID`, find the app registration in Azure. The client secret is only shown once. Ask azeezoe@appstate.edu if the infra already exists. The tenant ID can be found in your Azure account settings.

2. **Install Dependencies**:
```bash
pip install -r requirements.txt
```

3. **Start the Function App**:
```bash
func start
```

The app will typically be available at `http://localhost:7071`.
