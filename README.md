# Safe-Cipher

A universal **AES-256-CBC** + **RSA-OAEP-4096** encryption library that works seamlessly across Node.js, Express, React, Vite, and Next.js — with zero platform-specific code.

[![npm version](https://img.shields.io/npm/v/safe-cipher)](https://www.npmjs.com/package/safe-cipher)
[![license](https://img.shields.io/npm/l/safe-cipher)](./LICENSE)
[![platforms](https://img.shields.io/badge/platform-node%20%7C%20browser-blue)](#platform-support)

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Platform Support](#platform-support)
- [Quick Start](#quick-start)
- [Constructor](#constructor)
- [Key Generation](#key-generation)
- [AES Symmetric Encryption](#aes-symmetric-encryption)
- [RSA Asymmetric Encryption](#rsa-asymmetric-encryption)
- [File Encryption](#file-encryption)
- [Environment Variables](#environment-variables)
- [Framework Examples](#framework-examples)
- [API Reference](#api-reference)
- [Security Notes](#security-notes)

---

## Features

- **AES-256-CBC** symmetric encryption for objects, strings, and binary files
- **RSA-OAEP-4096** asymmetric encryption with public/private key pair generation
- **Flexible key input** — combined 128-char key, explicit key+IV, or Node.js `crypto` generated keys
- **Universal** — identical API across Node.js, Express, React, Vite, and Next.js
- **Environment-aware** — `fromEnv()` auto-detects the correct env format per framework
- **Zero extra dependencies** for RSA — uses the native `crypto.subtle` Web Crypto API

---

## Installation

```bash
npm install safe-cipher
# or
yarn add safe-cipher
# or
pnpm add safe-cipher
```

---

## Platform Support

| Platform        | AES Symmetric | RSA Asymmetric | File Encryption |
| --------------- | ------------- | -------------- | --------------- |
| Node.js 19+     | ✅            | ✅             | ✅              |
| Express         | ✅            | ✅             | ✅              |
| React (Vite)    | ✅            | ✅             | ✅              |
| React (CRA)     | ✅            | ✅             | ✅              |
| Next.js server  | ✅            | ✅             | ✅              |
| Next.js client  | ✅            | ✅             | ✅              |
| Modern browsers | ✅            | ✅             | ✅              |

> RSA methods use `crypto.subtle` — available natively in all modern browsers and Node.js 19+.

---

## Quick Start

```js
import SafeCipher from "safe-cipher";

// ── AES: encrypt and decrypt an object ───────────────────────────────────
const { secretKey, iv } = SafeCipher.generateSecretKey();
const cipher = new SafeCipher(secretKey, iv);

const token = cipher.encryptData({ userId: 42, role: "admin" });
const data = cipher.decryptData(token);
console.log(data); // { userId: 42, role: "admin" }

// ── RSA: encrypt with public key, decrypt with private key ────────────────
const { publicKey, privateKey } = await SafeCipher.generateKeyPair();

const encrypted = await SafeCipher.encryptWithPublicKey({ userId: 42 }, publicKey);
const decrypted = await SafeCipher.decryptWithPrivateKey(encrypted, privateKey);
console.log(decrypted); // { userId: 42 }

// ── File: encrypt and decrypt binary data ─────────────────────────────────
import fs from "fs";
const fileBuffer = fs.readFileSync("photo.jpg");
const encFile = cipher.encryptFile(fileBuffer);
const restored = cipher.decryptFile(encFile);
fs.writeFileSync("restored.jpg", restored);
```

---

## Constructor

SafeCipher supports **two calling signatures**.

### Signature 1 — Explicit key + IV

```js
new SafeCipher(secretKey, iv);
```

| Parameter   | Type     | Description                                                         |
| ----------- | -------- | ------------------------------------------------------------------- |
| `secretKey` | `string` | 64-char hex (32 bytes) or 128-char hex (auto-truncated to 32 bytes) |
| `iv`        | `string` | 32-char hex (16 bytes)                                              |

```js
const { secretKey, iv } = SafeCipher.generateSecretKey();
const cipher = new SafeCipher(secretKey, iv);
```

### Signature 2 — Single combined key

```js
new SafeCipher(combinedKey);
```

| Parameter     | Type     | Description                                            |
| ------------- | -------- | ------------------------------------------------------ |
| `combinedKey` | `string` | 128-char hex — first 64 chars = key, chars 96–128 = IV |

```js
// Generate from terminal:
// node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
const combined = "a3f1c9...128chars";
const cipher = new SafeCipher(combined);
```

The combined key is split as:

```
position:  0        64       96      128
					 │        │        │        │
					 ▼        ▼        ▼        ▼
					 [key 32B][unused  ][IV 16B ]
						0–63    64–95    96–127
```

---

## Key Generation

### Terminal — Generate Keys Without Code

You can generate keys directly from your terminal and paste them straight into your `.env` file.

```bash
# ── Combined 128-char key (single value, recommended) ────────────────────
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
# → a3f1c9d2e8b047aa...128chars
# Paste as: SECRET_KEY=<output>

# ── Separate 32-byte AES key ──────────────────────────────────────────────
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
# → a3f1c9d2e8b047aa...64chars
# Paste as: SECRET_KEY=<output>

# ── Separate 16-byte IV ───────────────────────────────────────────────────
node -e "console.log(require('crypto').randomBytes(16).toString('hex'))"
# → b9e2f1a3c4d5e6f7...32chars
# Paste as: IV=<output>

# ── Generate both key + IV in one command ─────────────────────────────────
node -e "
const c = require('crypto');
console.log('SECRET_KEY=' + c.randomBytes(32).toString('hex'));
console.log('IV='         + c.randomBytes(16).toString('hex'));
"
# → SECRET_KEY=a3f1c9...64chars
# → IV=b9e2f1...32chars
```

Then use any of these in your `.env`:

```bash
# Option A — combined (from randomBytes(64))
SECRET_KEY=a3f1c9d2e8b047aa...128chars

# Option B — split (from randomBytes(32) + randomBytes(16))
SECRET_KEY=a3f1c9d2...64chars
IV=b9e2f1a3...32chars
```

---

### `SafeCipher.generateSecretKey()`

Generates a fresh AES-256 key + IV pair using CryptoJS.

```js
const { secretKey, iv } = SafeCipher.generateSecretKey();
// secretKey → 64-char hex string (32 bytes)
// iv        → 32-char hex string (16 bytes)

const cipher = new SafeCipher(secretKey, iv);
```

### `SafeCipher.fromNodeCryptoKey(nodeCryptoHex)`

Parses a 128-char hex key generated from Node.js's built-in `crypto` module into `{ secretKey, iv }`.

```js
import crypto from "crypto";

// Generate from code
const combined = crypto.randomBytes(64).toString("hex"); // 128-char hex

// Or generate from terminal and paste into .env:
// node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"

// Option A — split and use explicitly
const { secretKey, iv } = SafeCipher.fromNodeCryptoKey(combined);
const cipher = new SafeCipher(secretKey, iv);

// Option B — pass directly to constructor (auto-detected)
const cipher = new SafeCipher(combined);
```

### `SafeCipher.generateKeyPair()`

Generates an RSA-OAEP 4096-bit public/private key pair. Both keys are returned as Base64 strings safe to store in a database or `.env`.

```js
const { publicKey, privateKey } = await SafeCipher.generateKeyPair();

// publicKey  → share freely (DB, client config, API response)
// privateKey → keep secret (server .env, secrets manager — never send to client)
```

---

## AES Symmetric Encryption

All AES methods are **synchronous** and operate on a constructed instance.

### `cipher.encryptData(data)`

Encrypts any JSON-serializable value using AES-256-CBC. Returns a Base64 ciphertext string.

```js
const cipher = new SafeCipher(secretKey, iv);

// Object
const token = cipher.encryptData({ userId: 42, role: "admin" });

// Array
const token2 = cipher.encryptData([1, 2, 3]);

// String
const token3 = cipher.encryptData("hello world");

// Number
const token4 = cipher.encryptData(12345);
```

### `cipher.decryptData(encryptedData)`

Decrypts a ciphertext string back to the original value.

```js
const data = cipher.decryptData(token);
console.log(data); // { userId: 42, role: "admin" }
```

### Full AES round-trip examples

```js
// ── Using generateSecretKey ───────────────────────────────────────────────
const { secretKey, iv } = SafeCipher.generateSecretKey();
const cipher = new SafeCipher(secretKey, iv);

const token = cipher.encryptData({ session: "abc123", exp: Date.now() + 86400000 });
const data = cipher.decryptData(token);

// ── Using a combined Node crypto key ──────────────────────────────────────
import crypto from "crypto";
const combined = crypto.randomBytes(64).toString("hex");
const cipher2 = new SafeCipher(combined);

const token2 = cipher2.encryptData({ userId: 1 });
const data2 = cipher2.decryptData(token2);

// ── Using fromNodeCryptoKey ───────────────────────────────────────────────
const { secretKey: sk, iv: nodeIv } = SafeCipher.fromNodeCryptoKey(combined);
const cipher3 = new SafeCipher(sk, nodeIv);

const token3 = cipher3.encryptData({ role: "admin" });
const data3 = cipher3.decryptData(token3);

// ── Using fromEnv ─────────────────────────────────────────────────────────
const cipher4 = SafeCipher.fromEnv(); // reads SECRET_KEY (+ IV) from .env
const token4 = cipher4.encryptData({ userId: 99 });
const data4 = cipher4.decryptData(token4);
```

---

## RSA Asymmetric Encryption

All RSA methods are **async** and **static** — no instance needed.

### `SafeCipher.encryptWithPublicKey(data, publicKey)`

Encrypts data with the RSA public key. Anyone with the public key can encrypt — only the private key can decrypt.

```js
const { publicKey, privateKey } = await SafeCipher.generateKeyPair();

const encrypted = await SafeCipher.encryptWithPublicKey({ userId: 42, role: "admin" }, publicKey);
// → Base64 RSA ciphertext string
```

> ⚠️ RSA has a payload size limit (~446 bytes for 4096-bit keys). Use `encryptFile` for large data.

### `SafeCipher.decryptWithPrivateKey(encryptedData, privateKey)`

Decrypts a ciphertext string using the RSA private key. Only the private key holder can decrypt.

```js
const data = await SafeCipher.decryptWithPrivateKey(encrypted, privateKey);
console.log(data); // { userId: 42, role: "admin" }
```

### Full RSA round-trip examples

```js
// ── Basic encrypt / decrypt ───────────────────────────────────────────────
const { publicKey, privateKey } = await SafeCipher.generateKeyPair();

const encrypted = await SafeCipher.encryptWithPublicKey({ secret: "abc" }, publicKey);
const decrypted = await SafeCipher.decryptWithPrivateKey(encrypted, privateKey);
console.log(decrypted); // { secret: "abc" }

// ── Sender / Receiver pattern ─────────────────────────────────────────────
// Receiver generates keys and shares publicKey
const { publicKey, privateKey } = await SafeCipher.generateKeyPair();

// Sender encrypts using publicKey (no private key needed)
const payload = await SafeCipher.encryptWithPublicKey({ message: "hello", timestamp: Date.now() }, publicKey);

// Receiver decrypts using privateKey
const received = await SafeCipher.decryptWithPrivateKey(payload, privateKey);
console.log(received); // { message: "hello", timestamp: ... }

// ── Store keys for reuse ──────────────────────────────────────────────────
const keys = await SafeCipher.generateKeyPair();

// Save to .env or DB
// PUBLIC_KEY=<keys.publicKey>
// PRIVATE_KEY=<keys.privateKey>

// Later — reload from env
const reEncrypted = await SafeCipher.encryptWithPublicKey(data, process.env.PUBLIC_KEY);
const reDecrypted = await SafeCipher.decryptWithPrivateKey(reEncrypted, process.env.PRIVATE_KEY);
```

---

## File Encryption

Encrypts binary data (images, PDFs, videos, any file type) using AES-256-CBC. Accepts `Buffer`, `Uint8Array`, or `ArrayBuffer`.

### `cipher.encryptFile(fileBuffer)`

Returns a Base64 ciphertext string safe to store in a database or send over the network.

### `cipher.decryptFile(encryptedData)`

Returns a `Buffer` in Node.js or a `Uint8Array` in the browser — original bytes, byte-perfect.

### Node.js examples

```js
import fs from "fs";
import SafeCipher from "safe-cipher";

const { secretKey, iv } = SafeCipher.generateSecretKey();
const cipher = new SafeCipher(secretKey, iv);

// ── Encrypt a file ────────────────────────────────────────────────────────
const fileBuffer = fs.readFileSync("photo.jpg"); // → Buffer
const encrypted = cipher.encryptFile(fileBuffer); // → Base64 string
fs.writeFileSync("photo.enc", encrypted, "utf8");

// ── Decrypt a file ────────────────────────────────────────────────────────
const encData = fs.readFileSync("photo.enc", "utf8");
const restored = cipher.decryptFile(encData); // → Buffer
fs.writeFileSync("restored.jpg", restored);

// ── Encrypt a PDF ─────────────────────────────────────────────────────────
const pdf = fs.readFileSync("document.pdf");
const encPdf = cipher.encryptFile(pdf);
const decPdf = cipher.decryptFile(encPdf);
fs.writeFileSync("restored.pdf", decPdf);

// ── Encrypt raw Uint8Array ────────────────────────────────────────────────
const uint8 = new Uint8Array([0x89, 0x50, 0x4e, 0x47]); // PNG header bytes
const encBytes = cipher.encryptFile(uint8);
const decBytes = cipher.decryptFile(encBytes); // → Buffer
```

### Browser examples

```js
const cipher = SafeCipher.fromEnv("VITE_");

// ── Encrypt from file picker ──────────────────────────────────────────────
async function handleFileSelect(event) {
  const file = event.target.files[0];
  const arrayBuffer = await file.arrayBuffer(); // File → ArrayBuffer
  const encrypted = cipher.encryptFile(arrayBuffer); // → Base64 string

  localStorage.setItem("encryptedFile", encrypted);
  console.log("File encrypted and stored.");
}

// ── Decrypt and download ──────────────────────────────────────────────────
function handleDownload() {
  const encrypted = localStorage.getItem("encryptedFile");
  const uint8 = cipher.decryptFile(encrypted); // → Uint8Array

  const blob = new Blob([uint8]);
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "restored-file";
  a.click();
  URL.revokeObjectURL(url);
}

// ── Encrypt and send to server ────────────────────────────────────────────
async function uploadEncrypted(file) {
  const arrayBuffer = await file.arrayBuffer();
  const encrypted = cipher.encryptFile(arrayBuffer);

  await fetch("/api/upload", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name: file.name, data: encrypted }),
  });
}
```

### Express + Multer examples

```js
import express from "express";
import multer from "multer";
import SafeCipher from "safe-cipher";

const app = express();
const upload = multer({ storage: multer.memoryStorage() });
const cipher = SafeCipher.fromEnv();

app.use(express.json());

// ── Upload and encrypt ────────────────────────────────────────────────────
app.post("/upload", upload.single("file"), async (req, res) => {
  const encrypted = cipher.encryptFile(req.file.buffer); // multer → Buffer
  await db.files.create({
    name: req.file.originalname,
    mimeType: req.file.mimetype,
    size: req.file.size,
    data: encrypted, // store ciphertext
  });
  res.json({ message: "Encrypted and saved.", name: req.file.originalname });
});

// ── Download and decrypt ──────────────────────────────────────────────────
app.get("/file/:id", async (req, res) => {
  const record = await db.files.findById(req.params.id);
  if (!record) return res.status(404).json({ error: "Not found" });

  const buffer = cipher.decryptFile(record.data); // → Buffer
  res.setHeader("Content-Type", record.mimeType);
  res.setHeader("Content-Disposition", `attachment; filename="${record.name}"`);
  res.send(buffer);
});

// ── List encrypted files (metadata only) ─────────────────────────────────
app.get("/files", async (req, res) => {
  const files = await db.files.findAll({ attributes: ["id", "name", "mimeType", "size"] });
  res.json(files);
});
```

---

## Environment Variables

`SafeCipher.fromEnv(prefix?)` reads your key from environment variables and returns a ready-to-use instance.

```js
SafeCipher.fromEnv(); // Express, Node.js, Next.js server
SafeCipher.fromEnv("NEXT_PUBLIC_"); // Next.js client components
SafeCipher.fromEnv("VITE_"); // Vite / React (Vite)
SafeCipher.fromEnv("REACT_APP_"); // Create React App
SafeCipher.fromEnv("APP_"); // any custom prefix
```

### `.env` file setup

**Option A — Combined 128-char key (recommended)**

```bash
# Express / Node.js / Next.js server  →  .env or .env.local
SECRET_KEY=a3f1c9d2e8b047aa...128chars

# Vite  →  .env
VITE_SECRET_KEY=a3f1c9d2e8b047aa...128chars

# Next.js client  →  .env.local
NEXT_PUBLIC_SECRET_KEY=a3f1c9d2e8b047aa...128chars

# CRA  →  .env
REACT_APP_SECRET_KEY=a3f1c9d2e8b047aa...128chars
```

**Option B — Separate key + IV**

```bash
SECRET_KEY=a3f1c9d2...64chars
IV=b9e2f1a3...32chars
```

### Generating keys for `.env`

```bash
# ── Combined 128-char key (Option A) ─────────────────────────────────────
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"

# ── Separate key + IV in one command (Option B) ───────────────────────────
node -e "
const c = require('crypto');
console.log('SECRET_KEY=' + c.randomBytes(32).toString('hex'));
console.log('IV='         + c.randomBytes(16).toString('hex'));
"

# ── Key only ──────────────────────────────────────────────────────────────
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

# ── IV only ───────────────────────────────────────────────────────────────
node -e "console.log(require('crypto').randomBytes(16).toString('hex'))"
```

> `fromEnv()` throws a descriptive error at startup if the key is missing — fail-fast before any encryption runs.

---

## Framework Examples

### Express — Session Token Auth

```js
import "dotenv/config";
import express from "express";
import SafeCipher from "safe-cipher";

const app = express();
const cipher = SafeCipher.fromEnv(); // throws at startup if SECRET_KEY missing

app.use(express.json());

// Issue encrypted token on login
app.post("/login", async (req, res) => {
  const user = await db.findUser(req.body.email, req.body.password);
  if (!user) return res.status(401).json({ error: "Invalid credentials" });

  const token = cipher.encryptData({
    userId: user.id,
    role: user.role,
    exp: Date.now() + 86400000, // 24h expiry
  });

  res.json({ token });
});

// Verify token on protected routes
app.get("/me", (req, res) => {
  try {
    const raw = req.headers.authorization?.replace("Bearer ", "");
    const data = cipher.decryptData(raw);

    if (Date.now() > data.exp) {
      return res.status(401).json({ error: "Token expired" });
    }

    res.json({ userId: data.userId, role: data.role });
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
});

app.listen(3000);
```

### Express — RSA Ticket System

```js
// Generate once and save to .env
const { publicKey, privateKey } = await SafeCipher.generateKeyPair();

// Issue a time-limited encrypted ticket
app.post("/issue-ticket", async (req, res) => {
  const ticket = { userId: req.user.id, action: "download", exp: Date.now() + 60000 };
  const encrypted = await SafeCipher.encryptWithPublicKey(ticket, publicKey);
  res.json({ ticket: encrypted });
});

// Redeem the ticket — only server with privateKey can decrypt
app.post("/redeem-ticket", async (req, res) => {
  try {
    const ticket = await SafeCipher.decryptWithPrivateKey(req.body.ticket, privateKey);
    if (Date.now() > ticket.exp) return res.status(410).json({ error: "Ticket expired" });
    res.json({ granted: true, action: ticket.action });
  } catch {
    res.status(400).json({ error: "Invalid ticket" });
  }
});
```

### React + Vite

```jsx
// src/lib/cipher.js
import SafeCipher from "safe-cipher";
export const cipher = SafeCipher.fromEnv("VITE_");

// src/components/SecureForm.jsx
import { useState }  from "react";
import { cipher }    from "../lib/cipher";

export default function SecureForm() {
	const [status, setStatus] = useState("");

	async function handleSubmit(e) {
		e.preventDefault();
		const formData  = { name: e.target.name.value, email: e.target.email.value };
		const encrypted = cipher.encryptData(formData);

		await fetch("/api/submit", {
			method:  "POST",
			headers: { "Content-Type": "application/json" },
			body:    JSON.stringify({ payload: encrypted }),
		});

		setStatus("Submitted securely!");
	}

	return (
		<form onSubmit={handleSubmit}>
			<input name="name"  placeholder="Name"  required />
			<input name="email" placeholder="Email" required />
			<button type="submit">Submit</button>
			{status && <p>{status}</p>}
		</form>
	);
}

// src/components/FileVault.jsx
import { cipher } from "../lib/cipher";

export default function FileVault() {
	async function encrypt(e) {
		const file        = e.target.files[0];
		const arrayBuffer = await file.arrayBuffer();
		const encrypted   = cipher.encryptFile(arrayBuffer);
		localStorage.setItem("vault_file", encrypted);
		alert("File encrypted and stored.");
	}

	function decrypt() {
		const encrypted = localStorage.getItem("vault_file");
		const uint8     = cipher.decryptFile(encrypted);
		const blob      = new Blob([uint8]);
		const url       = URL.createObjectURL(blob);
		const a         = document.createElement("a");
		a.href          = url;
		a.download      = "restored";
		a.click();
		URL.revokeObjectURL(url);
	}

	return (
		<div>
			<input type="file" onChange={encrypt} />
			<button onClick={decrypt}>Download Decrypted</button>
		</div>
	);
}
```

### Next.js — Server + Client

```js
// app/api/token/route.js  (server — API route)
import SafeCipher from "safe-cipher";

const cipher = SafeCipher.fromEnv(); // SECRET_KEY from .env.local

export async function POST(req) {
  const body = await req.json();
  const encrypted = cipher.encryptData({ ...body, ts: Date.now() });
  return Response.json({ token: encrypted });
}

export async function GET(req) {
  const token = req.headers.get("x-token");
  const data = cipher.decryptData(token);
  return Response.json(data);
}
```

```jsx
// app/components/TokenDemo.jsx  (client component)
"use client";
import { useState } from "react";
import SafeCipher from "safe-cipher";

const cipher = SafeCipher.fromEnv("NEXT_PUBLIC_");

export default function TokenDemo() {
  const [token, setToken] = useState("");
  const [decoded, setDecoded] = useState(null);

  async function generate() {
    const res = await fetch("/api/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ userId: 42, role: "admin" }),
    });
    const { token } = await res.json();
    setToken(token);
  }

  function decode() {
    const data = cipher.decryptData(token);
    setDecoded(data);
  }

  return (
    <div>
      <button onClick={generate}>Generate Token</button>
      {token && <button onClick={decode}>Decode</button>}
      {decoded && <pre>{JSON.stringify(decoded, null, 2)}</pre>}
    </div>
  );
}
```

```js
// app/api/upload/route.js  (server — file upload)
import SafeCipher from "safe-cipher";

const cipher = SafeCipher.fromEnv();

export async function POST(req) {
  const formData = await req.formData();
  const file = formData.get("file");
  const buffer = Buffer.from(await file.arrayBuffer());

  const encrypted = cipher.encryptFile(buffer);
  await db.save({ name: file.name, data: encrypted });

  return Response.json({ ok: true });
}

export async function GET(req) {
  const id = new URL(req.url).searchParams.get("id");
  const record = await db.findById(id);
  const buffer = cipher.decryptFile(record.data); // → Buffer

  return new Response(buffer, {
    headers: {
      "Content-Type": "application/octet-stream",
      "Content-Disposition": `attachment; filename="${record.name}"`,
    },
  });
}
```

---

## API Reference

### Constructor

| Signature                       | Description                       |
| ------------------------------- | --------------------------------- |
| `new SafeCipher(secretKey, iv)` | Explicit 64-char key + 32-char IV |
| `new SafeCipher(combinedKey)`   | Single 128-char hex combined key  |

### Static — Key Generation & Setup

| Method                              | Returns                              | Description                                    |
| ----------------------------------- | ------------------------------------ | ---------------------------------------------- |
| `SafeCipher.generateSecretKey()`    | `{ secretKey, iv }`                  | Fresh AES-256 key + IV (64-char + 32-char hex) |
| `SafeCipher.fromNodeCryptoKey(hex)` | `{ secretKey, iv }`                  | Parse a 128-char Node.js crypto hex key        |
| `SafeCipher.generateKeyPair()`      | `Promise<{ publicKey, privateKey }>` | RSA-OAEP 4096-bit key pair as Base64 strings   |
| `SafeCipher.fromEnv(prefix?)`       | `SafeCipher`                         | Instantiate from environment variables         |

### Static — RSA Asymmetric

| Method                                      | Returns           | Description                                   |
| ------------------------------------------- | ----------------- | --------------------------------------------- |
| `SafeCipher.encryptWithPublicKey(data, pk)` | `Promise<string>` | Encrypt any JSON value with RSA public key    |
| `SafeCipher.decryptWithPrivateKey(enc, pk)` | `Promise<*>`      | Decrypt with RSA private key → original value |

### Instance — AES Symmetric

| Method                          | Input                                 | Returns                | Description                              |
| ------------------------------- | ------------------------------------- | ---------------------- | ---------------------------------------- |
| `cipher.encryptData(data)`      | Any JSON value                        | `string`               | AES-256-CBC encrypt → Base64 ciphertext  |
| `cipher.decryptData(encrypted)` | `string`                              | `*`                    | Decrypt → original JSON value            |
| `cipher.encryptFile(buffer)`    | `Buffer \| Uint8Array \| ArrayBuffer` | `string`               | AES-256-CBC encrypt binary data → Base64 |
| `cipher.decryptFile(encrypted)` | `string`                              | `Buffer \| Uint8Array` | Decrypt → original file bytes            |

---

## Security Notes

- **AES-256-CBC** with PKCS7 padding is used for all symmetric encryption
- **RSA-OAEP** with SHA-256 is used for all asymmetric encryption
- **4096-bit RSA keys** — the strongest standard size
- **`crypto.subtle`** is used for RSA — a native, audited C++ implementation, not a JavaScript re-implementation
- Never expose your **AES secret key** or **RSA private key** to the browser unless absolutely required
- For Next.js: only use `NEXT_PUBLIC_` keys for non-sensitive client-side operations
- Store all keys in `.env` files or a secrets manager (AWS Secrets Manager, HashiCorp Vault, Doppler)
- **Never commit keys to source control** — add `.env` and `.env.local` to your `.gitignore`
- RSA payload limit is ~446 bytes for a 4096-bit key — use AES `encryptFile` for larger data

---

## License

MIT © 2024
