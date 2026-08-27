# KeyGate v3 — Hardened Key Authentication System

Secure license key system with **HWID locking**, **anti-tamper signed responses**, **anti-replay**, **blacklist**, **rate limits**, **audit logs**, and Discord management bot.

Designed for tools, scripts, and executables that need reliable key auth (including Roblox executors / scripts).

---

## Features

### Core
- Create keys of any type + duration via Discord or API
- HWID binding (locks to first device that uses the key)
- Automatic expiration
- Disable keys instantly
- Reset HWID when needed
- Free key endpoint with daily IP limit

### Anti-Tamper / Anti-Bypass
- **HMAC signed responses** — client can verify the server reply was not modified
- **Timestamp anti-replay** (optional header `x-timestamp`)
- Strict input validation (key + HWID length/format)
- HWID permanently locks on first successful use
- Blacklist system (HWID / IP / Key)
- Rate limits on verify (anti-bruteforce)
- Full audit log of every action
- No secrets in frontend code
- Body size limits + Helmet

### Discord Bot
- Role-protected slash commands
- `/createkey` `/deletekey` `/resethwid` `/keyinfo` `/blacklist`

---

## Quick Setup

```bash
# 1. Copy env
cp .env.example .env

# 2. Generate strong secrets
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
# Put one in ADMIN_SECRET and another in FREE_KEY_SECRET

# 3. Fill Discord values in .env
# DISCORD_TOKEN, GUILD_ID, ROLE_ID, API_URL

# 4. Start API
cd api
npm install
node index.js

# 5. Start Bot
cd ../bot
npm install
node index.js
```

Edit `site/index.html` → set your real `API_URL` and ad links.

---

## How to use in your tool / script

### 1. Basic verify (minimum)

```js
async function checkKey(userKey, hwid) {
  const res = await fetch("https://your-api.com/api/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ code: userKey, hwid })
  });

  const data = await res.json();

  if (!data.valid) {
    // show data.reason and exit / disable features
    return false;
  }

  // optional: check data.expires_in
  return true;
}
```

### 2. Recommended (with anti-tamper)

```js
const crypto = require("crypto"); // or Web Crypto in browser

// This secret must be the SAME as ADMIN_SECRET on the server
// In production you should obfuscate it heavily or derive it
const SIGNING_SECRET = "YOUR_ADMIN_SECRET_HERE";

function verifySignature(payload) {
  const { signature, signed_at, ...rest } = payload;
  if (!signature || !signed_at) return false;

  // reject very old signatures (optional extra safety)
  if (Date.now() - signed_at > 60_000) return false;

  const expected = crypto
    .createHmac("sha256", SIGNING_SECRET)
    .update(JSON.stringify(rest))
    .digest("hex");

  return expected === signature;
}

async function checkKeySecure(userKey, hwid) {
  const res = await fetch("https://your-api.com/api/verify", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-timestamp": Date.now().toString()   // anti-replay
    },
    body: JSON.stringify({ code: userKey, hwid })
  });

  const data = await res.json();

  // 1. Check signature (anti-tamper)
  if (!verifySignature(data)) {
    console.log("Response tampered or invalid signature");
    return false;
  }

  // 2. Check validity
  if (!data.valid) {
    console.log("Key rejected:", data.reason);
    return false;
  }

  return true;
}
```

### 3. Example HWID function (Node / Electron style)

```js
const os = require("os");
const crypto = require("crypto");

function getHWID() {
  const raw = [
    os.hostname(),
    os.platform(),
    os.arch(),
    os.cpus()[0]?.model,
    Object.values(os.networkInterfaces())
      .flat()
      .find(i => i && !i.internal && i.mac !== "00:00:00:00:00:00")?.mac
  ].join("||");

  return crypto.createHash("sha256").update(raw).digest("hex");
}
```

For pure Roblox Lua executors you will need to generate a stable device fingerprint using available APIs (or pass a fingerprint from an external loader).

---

## API Reference

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/verify` | none | Main key check (used by your tool) |
| POST | `/api/free` | optional free secret + IP limit | Generate free 24h key |
| POST | `/api/create` | Admin secret | Create any key |
| POST | `/api/delete` | Admin secret | Disable key |
| POST | `/api/reset-hwid` | Admin secret | Clear HWID lock |
| POST | `/api/blacklist` | Admin secret | Ban HWID / IP / Key |
| POST | `/api/info` | Admin secret | Lookup key details |
| GET | `/health` | none | Health check |

### Verify Request
```json
{
  "code": "PREMIUM-A1B2C3-D4E5F6G7",
  "hwid": "sha256hash..."
}
```

### Verify Response (signed)
```json
{
  "valid": true,
  "type": "PREMIUM",
  "expires_at": 1735689600000,
  "expires_in": 86400,
  "signature": "hmac...",
  "signed_at": 1735600000000
}
```

---

## Discord Commands

All require the **Key Manager** role.

- `/createkey type: hours:`
- `/deletekey code:`
- `/resethwid code:`
- `/keyinfo code:`
- `/blacklist type: value: reason:`

---

## Security Recommendations

1. **Never** put `ADMIN_SECRET` in client-side code without heavy obfuscation.
2. Always use HTTPS in production.
3. Put the API behind Cloudflare or nginx with extra rate limits.
4. Rotate Discord token + any leaked tokens immediately.
5. Keep `.env` out of git (already in `.gitignore`).
6. Periodically check the `logs` table for abuse patterns.
7. For maximum protection combine with:
   - Server-side only feature flags
   - Heartbeat re-checks every X minutes
   - Integrity checks on your own binary/script

---

## Project Structure

```
KeyGate/
├── .env.example
├── .gitignore
├── README.md
├── api/
│   ├── index.js
│   └── package.json
├── bot/
│   ├── index.js
│   └── package.json
└── site/
    └── index.html
```

---

## Creating a private GitHub repo

```bash
# After you download & extract
cd KeyGate
git init
git add .
git commit -m "KeyGate v3 - hardened key system"
gh repo create KeyGate --private --source=. --remote=origin
git push -u origin main
```

Or create the repo manually on GitHub → then:

```bash
git remote add origin https://github.com/YOUR_USERNAME/KeyGate.git
git push -u origin main
```

**Do not** commit the real `.env` file.

---

Made for reliability and resistance to common key system bypasses.
