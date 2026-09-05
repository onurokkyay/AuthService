# Auth Service

A standalone authentication and authorization service. It issues RS256 access tokens
and rotating refresh tokens, and publishes the keys other services need to verify them.

It is deliberately generic: it knows about accounts, passwords, roles and sessions, and
nothing about whatever application is using it. Dropping it into a second project should
require configuration, not code.

## What it does, and what it does not

**Owns:** registration, login, logout, refresh-token rotation, access-token signing,
key publication, and a two-value role (`USER`, `ADMIN`).

**Does not own:** business authorization, permissions, profile data, tenants, email
delivery, password reset, MFA, or social login. Deciding what a user may do inside a
domain is the consuming service's job — this service only says who they are.

There is no permission table and no RBAC engine. That is a decision, not an omission: a
permission model that is not driven by a real application's needs is guesswork, and the
role claim is enough to carry authority across the boundary.

## Stack

Java 25 · Spring Boot 4.1 · Spring Security 7.1 · PostgreSQL 16 · Flyway · Gradle

## Running it

```bash
docker compose up --build
```

Swagger UI is then at `http://localhost:8081/swagger-ui.html`.

The Compose stack runs with a **generated** key pair (`SPRING_PROFILES_ACTIVE=local`), so
every restart invalidates previously issued access tokens. That is fine for development
and unacceptable in production — see [Signing keys](#signing-keys).

## API

| Method | Path | Access | Purpose |
| --- | --- | --- | --- |
| POST | `/api/auth/register` | public | Create an account (`201`) |
| POST | `/api/auth/login` | public | Exchange credentials for a token pair |
| POST | `/api/auth/refresh` | public | Rotate a refresh token into a new pair |
| POST | `/api/auth/logout` | public | Revoke a refresh token (`204`) |
| GET | `/api/auth/me` | bearer token | The account behind the token |
| PATCH | `/api/admin/users/{id}/role` | `ADMIN` | Assign a role |
| GET | `/.well-known/jwks.json` | public | Public verification keys |

`logout` is public on purpose: it authenticates through the refresh token in the body, so
a client whose access token has already expired can still end its session.

### Errors

Every failure — including those raised by the security filter chain — uses one shape:

```json
{
  "timestamp": "2026-08-02T09:15:23.114Z",
  "code": "INVALID_CREDENTIALS",
  "message": "Invalid username or password",
  "path": "/api/auth/login"
}
```

`code` is a stable contract; clients may branch on it. Validation failures add a
`fieldErrors` array containing the field name and message — never the rejected value,
which on these endpoints would be a password.

## Using it from another service

For a Spring Boot consumer, integration is one property:

```properties
spring.security.oauth2.resourceserver.jwt.jwk-set-uri=http://auth-service:8081/.well-known/jwks.json
```

That is the whole point of signing asymmetrically. The consumer verifies tokens with the
public key and holds nothing capable of minting one; with a shared HMAC secret every
consumer would effectively be an issuer.

### Access token claims

| Claim | Value |
| --- | --- |
| `sub` | Account id (UUIDv7). **Use this as the foreign key**, never the username |
| `iss` / `aud` | As configured; verified on the way in |
| `iat` / `exp` | Issued-at and expiry (15 minutes by default) |
| `jti` | Unique per token |
| `role` | `USER` or `ADMIN` |
| `preferred_username` | Convenience for display only |

`sub` is the account id rather than the username because usernames can change; a token
outliving a rename must not point at whoever took the name next.

Role changes take effect on the next refresh. An access token issued a moment earlier
keeps the old role until it expires — the cost of stateless verification, and the reason
the access-token lifetime is short.

## Configuration

All settings are validated at startup: a missing or malformed one stops the service
rather than failing on the first request.

| Property | Env variable | Default | Meaning |
| --- | --- | --- | --- |
| `auth.jwt.issuer` | `AUTH_JWT_ISSUER` | `http://localhost:8081` | `iss` claim, verified on input |
| `auth.jwt.audience` | `AUTH_JWT_AUDIENCE` | `auth-service-clients` | `aud` claim, verified on input |
| `auth.jwt.access-token-ttl` | `AUTH_JWT_ACCESSTOKENTTL` | `15m` | Access token lifetime |
| `auth.jwt.private-key` | `AUTH_JWT_PRIVATEKEY` | – | PKCS#8 PEM resource |
| `auth.jwt.public-key` | `AUTH_JWT_PUBLICKEY` | – | X.509 PEM resource |
| `auth.refresh-token.ttl` | `AUTH_REFRESHTOKEN_TTL` | `30d` | Refresh token lifetime |
| `auth.refresh-token.cleanup-cron` | `AUTH_REFRESHTOKEN_CLEANUPCRON` | `0 15 3 * * *` | Expired-row deletion schedule |
| `auth.login.max-failed-attempts` | `AUTH_LOGIN_MAXFAILEDATTEMPTS` | `5` | Failures before lockout |
| `auth.login.lock-duration` | `AUTH_LOGIN_LOCKDURATION` | `15m` | Lockout length |
| `auth.registration.bootstrap-admin-emails` | `AUTH_REGISTRATION_BOOTSTRAPADMINEMAILS` | empty | Emails registered as `ADMIN` |
| `auth.cors.allowed-origins` | `AUTH_CORS_ALLOWEDORIGINS` | empty | Browser origins; empty denies all |

> **Environment variable names have no hyphens.** Spring maps `auth.jwt.private-key` to
> `AUTH_JWT_PRIVATEKEY` — the hyphen is removed, not replaced by an underscore.
> `AUTH_JWT_PRIVATE_KEY` is silently ignored.

### Signing keys

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out private.pem
openssl rsa -pubout -in private.pem -out public.pem
```

```properties
auth.jwt.private-key=file:/etc/auth/private.pem
auth.jwt.public-key=file:/etc/auth/public.pem
```

With no keys configured the service generates a throwaway pair — but only under the
`local` or `test` profile. Anywhere else it refuses to start, so an ephemeral key cannot
reach production by accident.

The published `kid` is the key's RFC 7638 thumbprint, so introducing a second key later
cannot collide with the first.

### The first administrator

`ADMIN` is not self-service. List an email under `auth.registration.bootstrap-admin-emails`
and the account registering with it is created as `ADMIN`; from there roles are managed
through `PATCH /api/admin/users/{id}/role`.

## Security behaviour

Worth knowing before integrating, because some of it is deliberately unhelpful to callers:

- **Failed logins are indistinguishable.** Unknown account, wrong password, disabled and
  locked all return the same `401` and the same message. Login also hashes a dummy
  password when the account does not exist, so response timing does not leak what the
  message hides.
- **Refresh tokens rotate on every use** and are stored only as a SHA-256 digest. A
  database dump does not hand out sessions.
- **Replaying a rotated token revokes every session of that account.** Either an attacker
  or the legitimate client is replaying, and there is no way to tell which, so the safe
  reading is theft. Expect users to be signed out everywhere when this triggers.
- **Multiple devices are supported.** Logging in does not disturb existing sessions.
- **Accounts lock** after the configured number of consecutive failures.
- **Nothing secret is ever logged.** Not passwords, not tokens, not token digests, not
  keys. Log lines identify accounts by UUID.
- **An inbound `X-Request-Id`** is echoed and attached to every log line for that request,
  but only if it matches a strict pattern — it reaches log output, where control
  characters would allow forged entries.

## Development

```bash
./gradlew build          # compile, Checkstyle, Spotless, tests
./gradlew spotlessApply  # fix formatting
```

The integration test starts PostgreSQL through Testcontainers, so Docker must be running.

Checkstyle warnings fail the build, and CI additionally scans the source tree for concepts
belonging to a consuming application. Keeping this service generic is enforced, not
merely intended.
