import argparse
import socket
import ssl
import requests
import json
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import urllib.robotparser
from datetime import datetime, timezone
from playwright.sync_api import sync_playwright
from fake_useragent import UserAgent
import re

# Builtwith for technology detection
try:
    import builtwith
except ImportError:
    builtwith = None

# Common ports for scanning
COMMON_PORTS = [21, 22, 25, 80, 443, 3306, 8080, 8443]

# Strict patterns for JS tech detection
STRICT_PATTERNS = {
    'React': [
        re.compile(r'/react(\.min)?\.js$', re.IGNORECASE),
        re.compile(r'\bReactDOM\b'),
        re.compile(r'\bcreateRoot\b')
    ],
    'Vue.js': [
        re.compile(r'/vue(\.min)?\.js$', re.IGNORECASE),
        re.compile(r'\bVue\.createApp\b')
    ],
    'Angular': [
        re.compile(r'/angular(\.min)?\.js$', re.IGNORECASE),
        re.compile(r'\bng\.')
    ],
    'jQuery': [
        re.compile(r'/jquery(\.min)?\.js$', re.IGNORECASE),
        re.compile(r'\$\(\s*document\b')
    ],
    'Firebase': [
        re.compile(r'/firebase(\.app)?\.js$', re.IGNORECASE),
        re.compile(r'\bfirebase\.')
    ],
    'Google Analytics': [
        re.compile(r'/gtag\.js$', re.IGNORECASE),
        re.compile(r'\bgtag\(')
    ],
    'Mixpanel': [
        re.compile(r'/mixpanel(\.min)?\.js$', re.IGNORECASE),
        re.compile(r'\bmixpanel\.init\(')
    ],
    'Segment': [
        re.compile(r'/analytics\.js$', re.IGNORECASE),
        re.compile(r'\bwindow\.analytics\.')
    ],
    'Amplitude': [
        re.compile(r'/amplitude(\.min)?\.js$', re.IGNORECASE),
        re.compile(r'\bamplitude\.getInstance\(')
    ],
}

def get_random_ua():
    return UserAgent().random

def detect_js_tech(js_url, ua, max_size=1_000_000):
    detected = []
    # URL-based
    for lib, patterns in STRICT_PATTERNS.items():
        if any(p.search(js_url) for p in patterns):
            detected.append(lib)
    # In-code if none
    if not detected:
        try:
            head = requests.head(js_url, headers={'User-Agent': ua}, timeout=5)
            size = int(head.headers.get('Content-Length', 0))
            if size <= max_size:
                resp = requests.get(js_url, headers={'User-Agent': ua}, timeout=10)
                txt = resp.text
                for lib, patterns in STRICT_PATTERNS.items():
                    if any(p.search(txt) for p in patterns[1:]):
                        detected.append(lib)
        except:
            pass
    return sorted(set(detected))

def detect_technologies_builtwith(url):
    if not builtwith:
        return []
    try:
        info = builtwith.builtwith(url)
        techs = []
        # جمع الفئات الشائعة
        for key in ('cms','web-servers','programming-languages','frameworks','javascript-libraries','analytics'):
            techs.extend(info.get(key, []))
        return list(set(techs))
    except:
        return []

def detect_waf(headers, domain):
    wafs = []
    server = headers.get('Server','').lower()
    for k in ['cloudflare','sucuri','incapsula','aws waf','f5-big-ip','shield']:
        if k in server:
            wafs.append(k)
    try:
        host = socket.gethostbyaddr(domain)[0].lower()
        for k in ['cloudflare','sucuri','incapsula','aws waf','f5-big-ip','shield']:
            if k in host:
                wafs.append(k)
    except:
        pass
    return sorted(set(wafs)) or ['None detected']

def analyze_ssl(domain):
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((domain,443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert.get('issuer',()))
                subject= dict(x[0] for x in cert.get('subject',()))
                return {
                    'issued_to': subject.get('commonName'),
                    'issued_by': issuer.get('commonName'),
                    'valid_from': cert.get('notBefore'),
                    'valid_until': cert.get('notAfter')
                }
    except Exception as e:
        return {'error': str(e)}

def analyze_robots(domain, scheme):
    rp = urllib.robotparser.RobotFileParser()
    try:
        rp.set_url(f"{scheme}://{domain}/robots.txt")
        rp.read()
        return {'robots_txt': True, 'sitemaps': rp.site_maps() or []}
    except:
        return {'robots_txt': False, 'sitemaps': []}

def port_scan(domain):
    results = {}
    for port in COMMON_PORTS:
        try:
            with socket.create_connection((domain,port), timeout=1):
                results[port] = 'Open'
        except:
            results[port] = 'Closed'
    return results

def detect_cdn(headers, ip):
    cdn=[]
    server=headers.get('Server','').lower()
    for name,sig in {'Cloudflare':'cloudflare','Akamai':'akamai','Incapsula':'incapdns'}.items():
        if sig in server: cdn.append(name)
    try:
        host=socket.gethostbyaddr(ip)[0].lower()
        for name,sig in {'Cloudflare':'cloudflare','Akamai':'akamai','Incapsula':'incapdns'}.items():
            if sig in host: cdn.append(name)
    except:
        pass
    return sorted(set(cdn)) or ['None detected']

def recon(url):
    parsed=urlparse(url)
    if not parsed.scheme:
        url='http://'+url
        parsed=urlparse(url)
    domain=parsed.netloc
    ua=get_random_ua()
    now=datetime.now(timezone.utc).isoformat()
    res={'url':url,'domain':domain,'timestamp':now,'user_agent':ua}
    try: ip=socket.gethostbyname(domain)
    except Exception as e: ip=str(e)
    res['ip']=ip
    res['ports']=port_scan(domain)
    res['ssl']= analyze_ssl(domain) if parsed.scheme=='https' else {}
    res['robots']= analyze_robots(domain, parsed.scheme)
    headers,cookies,html={}, {}, ""
    try:
        r=requests.get(url, headers={'User-Agent':ua}, timeout=10)
        headers=dict(r.headers); cookies=r.cookies.get_dict(); html=r.text
    except Exception as e:
        headers={'error':str(e)}
    res['http_headers']=headers; res['cookies']=cookies
    res['security_headers']={
        h: headers.get(h,'Not set') for h in ['Strict-Transport-Security','Content-Security-Policy','X-Frame-Options','X-Content-Type-Options','X-XSS-Protection']
    }
    res['cdn']=detect_cdn(headers, ip)
    res['waf']=detect_waf(headers, domain)
    # CMS
    cms=[]
    for name,sig in {'WordPress':'wp-content','Joomla':'index.php?option=com_','Drupal':'sites/all/'}.items():
        if sig in html: cms.append(name)
    res['cms']=cms or ['None detected']
    # Builtwith techs
    res['technologies']=detect_technologies_builtwith(url)
    js_tech={}
    with sync_playwright() as p:
        browser=p.chromium.launch(headless=True)
        page=browser.new_page(user_agent=ua)
        page.goto(url, wait_until='load', timeout=30000)
        soup=BeautifulSoup(page.content(),'html.parser')
        js_files=[(parsed.scheme+':'+s['src']) if s['src'].startswith('//')
                  else (f"{parsed.scheme}://{domain}{s['src']}") if s['src'].startswith('/')
                  else s['src']
                  for s in soup.find_all('script', src=True)]
        for js in sorted(set(js_files)):
            js_tech[js]=detect_js_tech(js, ua)
        browser.close()
    res['js_files']=js_tech
    return res

if __name__=='__main__':
    parser=argparse.ArgumentParser(description='Super Recon Tool')
    parser.add_argument('url', help='Target URL')
    args=parser.parse_args()
    report=recon(args.url)
    print(json.dumps(report, indent=2, ensure_ascii=False))
