# OIDC Toy Application (Python)

This project is a minimal, educational OIDC implementation built as an **Azure Function App**. Its primary purpose is to decouple the OIDC/OAuth2 handshake steps, allowing you to observe how `id_tokens` and `access_tokens` are acquired and stored independently.

### NOTE
Since the id_token and access_token steps are decoupled, you will be redirected twice. This means for trying
to access routes that require login and access_tokens (like `/api/people` or `/api/token`), each time you try
to access the endpoint, you will be first redirected to login, then next time you try you'll be redirected to 
acquire a token, *then* the next time you try it will work. This ain't perfect I admit, so apologies, but it's 
educational!

---

## 🚀 Routes & Educational Flow

### Discovery & State

* **`/api/home`**: The main dashboard. Lists all available routes and their purposes.
* **`/api/session`**: Displays the data stored in **your** current active session (e.g., tokens, claims).
* **`/api/sessions`**: A "god-mode" view that lists **all** active sessions currently stored by the app. Useful for debugging local state.

*NOTE*
sessions are just crudely stored in-memory for now, so if you are making changes to the 
app, be sure to login again after changes.

### Authentication vs. Authorization

* **`/api/login`**: Intentionally requests **only an `id_token`**. This demonstrates the "Authentication" layer—proving who you are without necessarily gaining permission to call downstream APIs.
* **`/api/token`**: Initiates the **Authorization Code Flow with PKCE**. It redirects to Azure AD to request permissions, processes the callback, and saves the resulting `access_token` into your session.

---

## Understanding the Authentication Flows

This application intentionally separates authentication (identity) from authorization (access) for educational purposes. Here's how each flow works:

### Flow Comparison

| Aspect | `/api/login` (Authentication) | `/api/token` (Authorization) |
|--------|-------------------------------|------------------------------|
| **Purpose** | Prove user identity | Get permission to call APIs |
| **Protocol** | OpenID Connect | OAuth 2.0 |
| **Grant Type** | Implicit (`response_type=id_token`) | Authorization Code (`response_type=code`) |
| **Token Received** | `id_token` | `access_token` |
| **Delivery Method** | `form_post` (POST body) | Backchannel (server-to-server) |
| **PKCE** | N/A (no code exchange) | Yes (`code_challenge` + `code_verifier`) |
| **Client Secret** | Not used | Used in token exchange |

### Why We Use Authorization Code + PKCE (Not Implicit) for Access Tokens

You might wonder: *"Could we just use implicit flow to get an access token too?"*

**Yes, technically we could.** Azure AD supports `response_type=token` or `response_type=id_token token` to return an access token via implicit flow, and we could even use `response_mode=form_post` to avoid putting it in the URL fragment.

**But this is discouraged.** Here's why:

1. **XSS Vulnerability**: Access tokens delivered to the browser (even via POST) end up in browser memory, making them vulnerable to cross-site scripting attacks.

2. **No Client Authentication**: With implicit flow, anyone who intercepts the authorization request can complete it. There's no client secret or PKCE to prove the legitimate client is making the token request.

3. **No Refresh Tokens**: Implicit flow cannot issue refresh tokens, meaning users must re-authenticate more frequently.

4. **Formally Deprecated**: OAuth 2.1 (the upcoming standard) formally deprecates implicit flow for access tokens. See [Why Implicit Flow is Dead](https://blog.logto.io/implicit-flow-is-dead) for a detailed explanation.

### What This Application Does Instead

**For authentication (`/api/login`):**
- Uses OIDC implicit flow to get an `id_token` only
- The `id_token` is delivered via `form_post` (not URL fragment)
- This is acceptable because the `id_token` only proves identity—it can't be used to call APIs

**For authorization (`/api/token`):**
- Uses Authorization Code flow with PKCE
- The `code_challenge` is sent to Azure AD during authorization
- The `code_verifier` is stored server-side and used during token exchange
- A `client_secret` is also used (defense in depth for server-side apps)
- The token exchange happens server-to-server—the access token is never exposed to the browser

### Best Practices (OAuth 2.1)

1. **Use Authorization Code + PKCE for all clients** - Even public clients (SPAs, mobile apps) should use auth code + PKCE, not implicit flow.

2. **Confidential clients should use PKCE + client secret** - This provides defense in depth. Even if PKCE is compromised, the attacker still needs the client secret.

3. **Keep tokens server-side when possible** - For server-rendered apps like this one, access tokens can stay on the server and never touch the browser.

4. **Separate identity from access conceptually** - An `id_token` tells you WHO the user is. An `access_token` tells you WHAT they can do. This app demonstrates that separation explicitly.

---

### Data Retrieval

* **`/api/people`**: Uses the `access_token` from your session to call the **Microsoft Graph API** (`/me/people`) and returns a list of your coworkers.

---

## 🏗 Infrastructure (Terraform)

The `infra/` directory contains Terraform scripts to automate the Azure setup. This includes:

* App Registration in Microsoft Entra ID (Azure AD).
* Required App roles
* Client IDs, Secrets, and Redirect URI configurations.

To deploy:
(check with azeezoe@appstate.edu that the infra is currently there to avoid clobbering tf state)

1. Navigate to `cd infra/envs/dev`.
2. Run `terraform init` and `terraform apply`.

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
AUTHORITY = https://login.microsoftonline.com/<appstate_azure_tenant_id>
HOST = http://localhost:7071
```

to get the client_secret and client_id, you can go to azure and find the app registration.
The client secret is only shown once. If you created the infrastructure with terraform, 
you can do a `terraform output -raw client_id`, same thing for the `secret_id`. Or ask
azeezoe@appstate.edu if the infra already exists. Tenant ID can be found in azure too (check your account settings)

2. **Install Dependencies**:
```bash
pip install -r requirements.txt

```

3. **Start the Function App**:
```bash
func start

```

The app will typically be available at `http://localhost:7071`.
