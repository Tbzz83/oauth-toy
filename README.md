# OIDC Toy Application (Python)

This project is a minimal, educational OIDC implementation built as an **Azure Function App**. Its primary purpose is to decouple the OIDC/OAuth2 handshake steps, allowing you to observe how `id_tokens` and `access_tokens` are acquired and stored independently.

---

## 🚀 Routes & Educational Flow

### Discovery & State

* **`/api/home`**: The main dashboard. Lists all available routes and their purposes.
* **`/api/session`**: Displays the data stored in **your** current active session (e.g., tokens, claims).
* **`/api/sessions`**: A "god-mode" view that lists **all** active sessions currently stored by the app. Useful for debugging local state.

### Authentication vs. Authorization

* **`/api/login`**: Intentionally requests **only an `id_token**`. This demonstrates the "Authentication" layer—proving who you are without necessarily gaining permission to call downstream APIs.
* **`/api/token`**: Initiates the **Authorization Code Flow**. It redirects to Azure AD to request permissions, processes the callback, and saves the resulting `access_token` into your session.

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
