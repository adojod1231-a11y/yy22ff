# yy22ff

**Full-Auto Web Vulnerability Scanner.**

**سكانر ثغرات ويب متعدد الوحدات — كشف كامل تلقائي.**

[![PyPI version](https://img.shields.io/pypi/v/yy22ff)](https://pypi.org/project/yy22ff/)
[![Python](https://img.shields.io/pypi/pyversions/yy22ff)](https://pypi.org/project/yy22ff/)
[![License](https://img.shields.io/pypi/l/yy22ff)](https://pypi.org/project/yy22ff/)

---

## Overview | نظرة عامة

**English:** yy22ff is a single-shot web vulnerability scanner that chains crawling, fingerprinting, passive recon, active injection testing, file-upload exploitation, and TLS analysis into one run. It produces a timestamped, structured report (txt + JSON) that you can review offline or diff across scans.

**العربية:** yy22ff مكتبة فحص ثغرات ويب متكاملة. تشغّل عملية واحدة تبدأ بالزحف على الموقع، ثم تحديد التقنيات المستخدمة، ثم فحص سلبي، ثم اختبار حقن نشط (SQLi, XSS, LFI, RFI, SSRF, CMDi, SSTI, Redirect)، ثم استغلال رفع الملفات، وأخيراً تحليل TLS. تنتج تقرير منظم (نص + JSON) في مجلد بتاريخ ووقت كل فحص.

---

## What It Does | ماذا تفعل

### 1. Crawling & Discovery | الزحف والاكتشاف

- Recursively crawls the target domain up to a configurable depth (default 2) and URL cap (default 300).
- Extracts every link, URL parameter, and HTML form (with field names, types, and methods).
- Deduplicates URLs by fingerprinting their parameter sets.

- زحف تكراري للدومين حتى عمق محدد (2 افتراضياً) وسقف 300 URL.
- استخراج كل الروابط، والبارامترات، والنماذج (form) مع أسماء الحقول وأنواعها وطرقها.
- إزالة التكرار ببصمة البارامترات.

### 2. Passive Recon | الاستطلاع السلبي

- **Tech fingerprinting** — WordPress, Drupal, Joomla, Laravel, Django, Rails, Express, PHP, ASP.NET, Spring, Nginx, Apache, IIS, Cloudflare, Nextcloud.
- **WAF detection** — Cloudflare, AWS WAF, Sucuri, Akamai, Imperva, F5 BIG-IP, ModSecurity, FortiWeb.
- **Security headers audit** — flags missing HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
- **CORS misconfiguration** — detects wildcard origins and credential reflection.

- **بصمة التقنيات** — WordPress, Drupal, Joomla, Laravel, Django, Rails, Express, PHP, ASP.NET, Spring, Nginx, Apache, IIS, Cloudflare, Nextcloud.
- **كشف WAF** — Cloudflare, AWS WAF, Sucuri, Akamai, Imperva, F5 BIG-IP, ModSecurity, FortiWeb.
- **فحص هيدرات الأمان** — ينبه إلى HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy الناقصة.
- **كشف سوء إعداد CORS** — wildcard origins و credential reflection.

### 3. Sensitive File Discovery | اكتشاف الملفات الحساسة

- `.git/config`, `.env`, `.env.bak`, backups (`backup.zip`, `backup.sql`, `db.sql`), `phpinfo.php`, `web.config`, `composer.json`, `Dockerfile`, `.htaccess`, `robots.txt`, `sitemap.xml`, `.DS_Store`, `.svn/entries`.
- Validates matches against content signatures (`root:x:0:0:`, `DB_PASSWORD`, `APP_KEY`, `<?php`).

- ملفات مكشوفة شائعة، مع التحقق من التوقيع الداخلي للمحتوى.

### 4. Admin Panel Discovery | اكتشاف لوحات التحكم

- `/admin`, `/wp-admin/`, `/wp-login.php`, `/administrator/`, `/login`, `/phpmyadmin/`, `/manager/html`, `/adminer.php`, `/cpanel`, `/dashboard`, `/auth/login`.

### 5. Active Injection Scanning | فحص الحقن النشط

| Class | Method | Classes Covered |
|-------|--------|----------------|
| **SQLi** | Error-based + Time-based | MySQL, Oracle, PostgreSQL, SQLite, MSSQL |
| **XSS** | Reflected + Form-based | Polyglot payloads |
| **LFI** | Path traversal | `/etc/passwd`, `win.ini` |
| **RFI** | Remote inclusion | `example.com` probe |
| **SSRF** | Internal targets | `127.0.0.1`, `169.254.169.254`, `[::1]`, `localhost` |
| **CMDi** | Time-based | `; sleep 4`, `pipe sleep 4`, backticks, `$()`, `&&` |
| **SSTI** | Template eval | `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `#{7*7}`, `*{7*7}` |
| **Open Redirect** | Location header + body | `evil.test` probe |

### 6. File Upload Exploitation | استغلال رفع الملفات

- Detects `<input type="file">` forms.
- Uploads `wscan.php` with `system($_GET['c'])`.
- Probes common upload paths (`/uploads/`, `/files/`, `/media/`, `/tmp/`, `/assets/`).
- Confirms execution via `?c=id` (checks for `uid=` / `gid=`).

### 7. SSL/TLS Analysis | تحليل SSL/TLS

- Reports protocol version and cipher.
- Flags weak protocols (SSLv3, TLSv1, TLSv1.1).

### 8. Reporting | التقارير

- Live colored console output with severity tags (`+` ok, `!` vuln, `~` warn, `*` info).
- Saves to `results/<host>_<timestamp>/`:
  - `findings.txt` — all findings, one per line.
  - `raw.log` — debug log.
  - `summary.json` — structured JSON output.
  - `shell.php` — generated payload (if upload stage runs).

---

## Installation | التثبيت

    pip install yy22ff

No configuration needed. Dependencies (`requests`, `colorama`) install automatically.

---

## Quick Start | البدء السريع

### As a library | كمكتبة

    import yy22ff

    result = yy22ff.scan("https://target.com")

    print(f"Findings: {result['summary']['total']}")
    print(f"Output:   {result['output_dir']}")
    print(f"Duration: {result['duration']}s")

    for finding in result["findings"]:
        print(finding["type"], "->", finding["target"])

### From the command line | من الطرفية

    # Basic
    python -m yy22ff -u https://target.com

    # Or if installed as entry point
    yy22ff -u https://target.com

    # Advanced
    yy22ff -u target.com -d 3 -t 16 --timeout 15 --delay 0.5

    # With proxy (Burp, ZAP)
    yy22ff -u https://target.com --proxy http://127.0.0.1:8080

    # Skip file upload stage
    yy22ff -u https://target.com --no-shell

---

## API Reference | المرجع

### `yy22ff.scan(url, **options)`

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `url` | str | — | Target URL (http/https, optional scheme) |
| `depth` | int | 2 | Crawl depth |
| `threads` | int | 8 | Parallel workers |
| `timeout` | int | 10 | Request timeout (seconds) |
| `delay` | float | 0.0 | Delay between requests |
| `proxy` | str | None | HTTP/SOCKS proxy |
| `no_shell` | bool | False | Skip upload-to-shell stage |
| `verbose` | bool | True | Print findings to console |

**Returns:** `dict`

    {
        "target": "https://target.com",
        "duration": 45.2,
        "findings": [
            {"type": "sqli", "target": "...", "extra": []},
            {"type": "xss", "target": "...", "extra": []},
        ],
        "summary": {
            "total": 6,
            "by_type": {"sqli": 2, "xss": 3, "file": 1}
        },
        "output_dir": "results/target_20261031_153000"
    }

### `yy22ff.cli()`

Entry point for `pyproject.toml`'s `console_scripts`. Same as `python -m yy22ff`.

---

## CLI Arguments | أوامر الطرفية

| Flag | Purpose | Default |
|------|---------|---------|
| `-u`, `--url` | Target URL (required) | — |
| `-d`, `--depth` | Crawl depth | 2 |
| `-t`, `--threads` | Parallel workers | 8 |
| `--timeout` | Request timeout (seconds) | 10 |
| `--delay` | Delay between requests | 0.0 |
| `--proxy` | HTTP/SOCKS proxy | none |
| `--no-shell` | Skip upload to shell stage | off |

---

## Output Structure | هيكل المخرجات

    results/
    target_20261031_153000/
        findings.txt      (human-readable)
        raw.log           (debug log)
        summary.json      (structured)
        shell.php         (upload payload, if applicable)

---

## Design Notes | ملاحظات التصميم

- **Name-mangled identifiers** — every symbol is prefixed `shlhom` to reduce casual readability.
- **Modular** — each vulnerability class is a standalone function; the dispatcher runs them in parallel via `ThreadPoolExecutor`.
- **Graceful failure** — a module crash does not abort the scan; failures are logged to `raw.log`.
- **Persistent output** — every finding is written to disk immediately, so interrupted scans still produce partial reports.
- **Session reuse** — one `requests.Session` with a random user-agent for the whole scan.
- **Auto-install** — installs `requests` at runtime if missing.

---

## Feature Matrix | جدول الميزات

| Feature | Status |
|---------|--------|
| Recursive crawling | [OK] |
| Form extraction | [OK] |
| Parameter discovery | [OK] |
| Tech fingerprinting | [OK] |
| WAF detection | [OK] |
| Security headers audit | [OK] |
| CORS check | [OK] |
| Sensitive file discovery | [OK] |
| Admin panel discovery | [OK] |
| SQLi (error + time) | [OK] |
| XSS (reflected + form) | [OK] |
| LFI | [OK] |
| RFI | [OK] |
| SSRF | [OK] |
| Command Injection | [OK] |
| SSTI | [OK] |
| Open Redirect | [OK] |
| File upload to shell | [OK] |
| SSL/TLS analysis | [OK] |
| Structured JSON output | [OK] |

---

## Author | المؤلف

- **Email:** adojod1231@gmail.com
- **Telegram:** [@yy22ff](https://t.me/yy22ff)
- **PyPI:** [yy22ff](https://pypi.org/project/yy22ff/)

---

## License | الترخيص

MIT © yy22ff

---

**Built with focus. Tested on real targets.**

**صُنعت بدقة. مختبرة على أهداف حقيقية.**
