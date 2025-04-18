# 🌐 Cloudflare WAF Rule Manager

A Python-based tool to manage **Cloudflare WAF custom rules** using the official [cloudflare-python SDK](https://github.com/cloudflare/cloudflare-python). The tool allows or blocks requests based on the request URI path and source IP address.

---

## ⚙️ Features

- ✅ Create or update WAF custom rules
- ✅ Match wildcard URI paths (e.g., `/admin/*`)
- ✅ Allow access only to specific IPs or ranges
- ✅ Block all other requests
- ✅ Supports multiple rules via YAML config
- ✅ Dry-run mode for safe testing
- ✅ Uses API token securely via `.env` file

---

## 🛠️ Setup

### 1. Clone the repository

```
git clone https://github.com/your-user/cloudflare-waf.git
cd cloudflare-waf
```

### 2. Create a virtual environment (optional but recommended)

```
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```
pip3 install -r requirements.txt
```

### 4. Create a .env and populate the config.yaml

Create a .env file in the root of the project:

You can generate an API Token from your Cloudflare dashboard.
Make sure it includes permission for Zone > Firewall Services > Edit.


### 5. Run the script

If dry_run: true, the script will show what it would do.

Set dry_run: false to apply changes to Cloudflare.