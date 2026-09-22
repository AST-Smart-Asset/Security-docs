# AST Smart Asset Management - Security Hardening Guide

**Project:** Project 3: Smart Asset Inventory & Predictive Maintenance (AST)  
**Institution:** Badr University in Assiut (BUA DevHub Field Phase - Squad 3)

---

## 1. Cryptographic Standards & Key Management

### Password Hashing:
- **Algorithm:** `bcrypt` with work factor (salt rounds) set to **12**.
- **Enforcement:** Never store plaintext passwords; rejection of passwords shorter than 8 characters or lacking uppercase, numeric, and special characters.

### JWT Token Management:
- **Algorithm:** `HS256` (HMAC with SHA-256) using a cryptographically generated secret ($\ge 256$ bits) or `RS256` public/private key pairs.
- **Token Lifespan:** Access tokens capped at **15 minutes**. Refresh tokens stored with single-use rotation and hashed in the database.
- **Claims:** JWT payload must contain only minimal claims: `userId`, `role`, `departmentId`, `iat`, and `exp`. Never embed passwords or sensitive PII.

---

## 2. API Gateway & Network Hardening

### HTTP Headers & Express Middleware:
- **Helmet:** Enforces secure response headers:
  - `Content-Security-Policy`: Restricts scripts and framing (`frame-ancestors 'none'`).
  - `X-Content-Type-Options: nosniff`
  - `Strict-Transport-Security (HSTS)`: `max-age=31536000; includeSubDomains`
- **CORS Whitelisting:** Explicitly restrict allowed origins to registered mobile/web domains; wildcard `*` is prohibited in production.
- **Rate Limiting:**
  - Auth endpoints (`/auth/login`): 5 requests per 15 minutes per IP.
  - General API endpoints: 100 requests per minute per authenticated user.

---

## 3. Database Security & Immutable Audit Trail

### Connection Security:
- Connect to PostgreSQL using SSL/TLS (`sslmode=require` or `verify-full`).
- The application executes using a dedicated non-superuser role (`ast_app_user`) restricted to `SELECT`, `INSERT`, `UPDATE` on application tables.

### Append-Only Event Logs (AST-FR-10):
- Table `asset_events` enforces append-only semantics. Revoke `UPDATE` and `DELETE` privileges on this table from the application database user:
  ```sql
  REVOKE UPDATE, DELETE ON TABLE asset_events FROM ast_app_user;
  ```
- All mutable operations (custody transfers, status changes, work order closures) trigger automatic event insertions capturing `timestamp`, `actor_id`, `event_type`, `old_values`, and `new_values`.

---

## 4. Mobile Client Security (Flutter)

- **Token Storage:** JWT tokens must be stored using platform-native secure hardware keychains:
  - Android: `EncryptedSharedPreferences` backed by Android Keystore.
  - iOS: `Keychain Services` with `kSecAttrAccessibleAfterFirstUnlock`.
- **Network Traffic:** TLS 1.3 only; disable cleartext traffic in `AndroidManifest.xml` (`android:usesCleartextTraffic="false"`) and iOS `Info.plist`.

---

## 5. Container & Infrastructure Security

- **Non-Root Execution:** All Docker containers (`ast-backend`, `ast-ai`, `postgres`) run under dedicated non-root users (`USER node` or `USER appuser`).
- **Base Images:** Use minimal `slim` or `alpine` images to minimize CVE vulnerability surface.
- **Secret Management:** Secrets injected strictly via runtime environment variables; `.env` files are excluded from Git via `.gitignore`.
