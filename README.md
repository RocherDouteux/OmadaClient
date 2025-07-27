# ✨ OmadaClient — Python API Client for TP-Link Omada Controller ✨

Welcome to **OmadaClient**, your Python-powered key to seamless interaction with the TP-Link Omada Controller OpenAPI (v5.15+) !
This is a simple client that helps me interact with my **ER605** at home. I don't plan to extend this project too much tho.
---

## 🚀 Features

- 🔐 **Secure token-based authentication** with CSRF/session handling  
- 🎯 Retrieve **authorization & access tokens** effortlessly  
- 🏢 Fetch and manage **sites** with paging support  
- 👥 List and locate **group profiles** by name  
- 🐍 Clean, reusable, and **debug-friendly** Python design  

---

## 💾 Installation

Make sure you have Python 3.6+ and install the required dependency:

```
pip install requests dotenv
```

---

## ⚙️ Configuration & Initialization

You’ll need to supply:

| Parameter       | Description                                  |
|-----------------|----------------------------------------------|
| `base_url`      | Your Omada Controller URL (e.g. https://192.168.0.2:8043) |
| `client_id`     | OAuth2 Client ID from your Omada settings    |
| `client_secret` | OAuth2 Client Secret                          |
| `omadac_id`     | Controller ID (found in URL or settings)     |
| `username`      | Your Omada login username                     |
| `password`      | Your Omada login password                     |
| `verify_ssl`    | `False` to skip SSL verification (dev only) |
| `debug`        | `True` to enable detailed request/response logging |

---

## 🎉 Quickstart

```python
from client import OmadaClient

client = OmadaClient(
    base_url="https://192.168.0.2:8043",
    client_id="your-client-id",
    client_secret="your-client-secret",
    omadac_id="your-omadac-id",
    username="admin",
    password="your-password",
    verify_ssl=False,
    debug=True
)

client.login()
client.get_authorization_code()
client.get_access_token()

site_id = client.get_site_id("Default")
profiles = client.get_group_profiles(site_id)

print(f"Site ID for 'Default': {site_id}")
print(f"Group Profiles: {profiles}")
```

> ⚠️ **Heads up!**  
> If your Omada Controller uses self-signed certificates, use `verify_ssl=False` only during development or trusted environments. For production, always enable SSL verification to keep your communication secure.  

---

## 📂 Project Structure

```
.
├── omada_client.py        # OmadaClient implementation
├── main.py                # Script to run your client logic
├── .env                   # Environment variables
├── .gitignore             # To keep secrets & temp files out
└── README.md              # This fancy guide you’re reading now
```

---

## 📝 License

**OmadaClient** is released under the [MIT License](https://opensource.org/licenses/MIT). Use, modify, and share it freely. I won't tell Santa !

---

Built with ❤️ for everyone to enjoy.

