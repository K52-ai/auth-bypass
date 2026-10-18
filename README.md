🚀 AUTH-BYPASS

⚡ Access control bypass tester for web endpoints

AUTH-BYPASS sends variations of a single request against a protected endpoint to test for authentication and authorization bypasses. It compares every response against a baseline and flags any variation that changes the HTTP status to 2xx, or produces a meaningfully different body. Six families of bypass are tested: header injection, path normalization, method override, case/encoding quirks, cookie trust, and referer/origin checks.

✨ Features

🛡️ Header injection — X-Forwarded-For, X-Real-IP, X-Original-URL, X-Rewrite-URL, and more
🔀 Path normalization — trailing slash, double slash, dot segments, semicolon tricks, null byte
🔁 HTTP method override — PUT, PATCH, DELETE, HEAD, OPTIONS, plus X-HTTP-Method-* headers
🔤 Case and encoding quirks — uppercase, percent-encoding, double-encoding, extensions
🍪 Cookie trust — admin=1, role=admin, debug=1, authenticated=true
🌐 Referer and Origin checks — same-origin, null origin
📊 Baseline comparison — status + length + MD5 hash
🎯 Classification — BYPASS / DIFFERENT / unchanged
💾 Saves findings to results.txt
🎨 Rainbow banner

📋 Requirements

🐧 Linux, macOS, or Windows
🐍 Python 3.8 or later
📦 requests

🛠️ Installation

Step 1 — Check your Python version

    python3 --version

Python 3.8 or later is required.

Step 2 — Install requests

    pip install requests

Step 3 — Clone the repository

    git clone https://github.com/K52-ai/auth-bypass.git

Step 4 — Enter the project directory

    cd auth-bypass

Step 5 — Make the script executable (optional)

    chmod +x auth_bypass.py

▶️ Usage

Step 1 — Run without arguments — banner and target prompt

    python3 auth_bypass.py

The tool prompts:

    target: https://target.com/admin
    cookie (leave empty for none): _

Step 2 — Run with a target directly

    python3 auth_bypass.py -u https://target.com/admin

Step 3 — Run with a session cookie

    python3 auth_bypass.py -u https://target.com/admin -c "session=abc123; role=user"

Step 4 — Run with extra headers

    python3 auth_bypass.py -u https://target.com/admin -H "Authorization: Bearer xyz"

Step 5 — Run with verbose output (prints unchanged variations too)

    python3 auth_bypass.py -u https://target.com/admin -v

Step 6 — Save to a custom file

    python3 auth_bypass.py -u https://target.com/admin -o myreport.txt

Step 7 — Show help

    python3 auth_bypass.py --help

📝 How It Works

Step 1 — The tool sends a baseline request to the target and records status, length, and MD5 hash of the body.

Step 2 — It builds 6 families of variations:

    header injection     — 24 variations
    path normalization   — 15 variations
    method override      — 19 variations
    case / encoding      — 9 variations
    cookie manipulation  — 11 variations
    referer / origin     — 4 variations

Step 3 — Each variation is sent with `allow_redirects=False` so redirects are visible in the status code.

Step 4 — Each response is compared to the baseline:

    status = baseline AND hash = baseline  →  unchanged
    status changed to 2xx                  →  BYPASS
    status changed otherwise               →  DIFFERENT
    same status but body changed           →  DIFFERENT

Step 5 — All BYPASS and DIFFERENT results are printed and saved.

📊 Results

🟣 BYPASS — status changed from 403/401 to 200/201/202/204
🟡 DIFFERENT — status changed (e.g. 403 → 302) or body changed
⚪ unchanged — identical response to baseline

View saved results:

    cat results.txt

🖼️ Screenshots

Add your actual screenshots to the assets/ folder, then reference them:

    ![Banner](assets/banner.png)
    ![Report](assets/report.png)

⚠️ Important Notes

🛡️ A `BYPASS` verdict means the HTTP status changed to 2xx — it does not guarantee the content is fully privileged. Verify manually in a browser or Burp.
🟡 A `DIFFERENT` verdict means the response changed but is not clearly a bypass. Common causes: redirect to /login (auth check active), error page, WAF block. Inspect manually.
🔍 Path normalization results vary by stack. `/admin/..;/admin` typically works on Tomcat/Spring; `%2e` on IIS; `//admin` on Nginx. The tool tests all of them regardless.
🌐 Cookie variations assume the backend trusts client-set flags like `admin=1`. This is rare but occurs in debug builds and misconfigured APIs.
🔐 TLS certificate verification is disabled in the HTTP client.
⚡ Requests are sequential. Total runtime is roughly 80 requests × average latency.
💾 `results.txt` is overwritten on each run.

⚖️ Responsible Use

Use AUTH-BYPASS only on systems you own or have explicit permission to test. Respect server rate limits and applicable laws.

📜 License

MIT License. See LICENSE for details.

👨‍💻 Author

K52-ai
🔗 GitHub Repository
