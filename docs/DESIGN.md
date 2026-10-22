# Sarcastifyer — Design and architecture

The current design of the deployed application. This is the single source for design and architecture.
For how to set up, deploy and operate the app, see the [operations runbook](RUNBOOK.md).

---

## 1. Overview and scope

Sarcastifyer is a single-purpose, **stateless** web application. A signed-in person pastes a block
of text, the app sends it to the Anthropic API with an instruction to rewrite it to be heavily
sarcastic while keeping its original intent, and **streams** the rewritten text back to the
browser. The person can also have the input and result emailed to their own address.

- **URL:** `https://sarcastifyer.example.com`, HTTPS only. (Not a real address)
- **Region:** every AWS resource is in `ca-central-1`.
- **Who can use it:** anyone with an account. The network is open to all IPs. Accounts live in
  two Amazon Cognito user pools: **users**, who sign in with an emailed one-time code, and
  **admins**, who sign in with a password and optional MFA and can manage users at `/admin`.
- **State:** none in the app. There's no database. Cognito holds all user state, and the session
  is a signed cookie.

---

## 2. Architecture

```
                        ┌───────────────────────────── ca-central-1 ─────────────────────────────┐
Browser ──HTTPS :443──▶ │ ALB (ACM cert, TLS 1.2/1.3, HSTS)  ◀── REGIONAL WAF (default allow)      │
        ──HTTP :80 ───▶ │   :80 → 301 to https://<same host>/                                     │
                        │   :443 → target group ──HTTP :8080──▶ ECS Fargate task ×1               │
                        │                                         gunicorn + Flask (app/)         │
                        │                                           ├─▶ Secrets Manager           │
                        │                                           ├─▶ Cognito (tokens, JWKS,    │
                        │                                           │     Admin* and self-service)│
                        │                                           ├─▶ SES (result email)        │
                        │                                           └─▶ Anthropic API (internet)  │
   │                    │                                                                         │
   │ sign-in redirect   │ Cognito managed login (2 prefix domains) ──email──▶ SES domain identity │
   └──────────────────▶ │   └─ redirect back to /auth/callback or /admin/auth/callback            │
                        │                                                                         │
Inbound mail ──SMTP──▶  │ SES receipt rule ─▶ S3 (7 days) ─▶ forwarder Lambda ─▶ SES ─▶ forward_to │
                        │ SES bounces/complaints, forwarder alarm ─▶ SNS sarcastifyer-alerts      │
                        └─────────────────────────────────────────────────────────────────────────┘
```

### 2.1 Request flow (transform)

```
Browser → WAF → ALB (TLS ends) → Flask
  → signed in? (session cookie; Cognito re-check every 15 min)
  → input valid? (≤ 5,000 chars) → per-user rate limit? → daily token brake?
  → transformer → Anthropic API (streaming)
  → SSE chunks stream back to the browser
  → optionally, email input + result to the signed-in user (SES)
```

### 2.2 Components

| Component | Where | Job |
|---|---|---|
| Web app | [app/](../app/), Fargate task | Pages, sign-in, sessions, guardrails, transform, `/admin`, `/account` |
| Edge | ALB + WAF ([infra/alb.tf](../infra/alb.tf), [infra/waf.tf](../infra/waf.tf)) | TLS, HTTP → HTTPS redirect, HSTS, request filtering |
| Identity | Cognito ([infra/cognito.tf](../infra/cognito.tf)) | Accounts, managed login, invitation and code email |
| Outbound email | SES ([infra/ses.tf](../infra/ses.tf)) | Domain identity used by the app, Cognito and the forwarder |
| Inbound email | SES + S3 + Lambda ([infra/inbound.tf](../infra/inbound.tf), [forwarder/](../forwarder/)) | Accept role addresses, forward to the owner |
| Alerts | SNS + CloudWatch ([infra/alerts.tf](../infra/alerts.tf)) | Bounces, complaints, forwarder errors to the owner |
| Secrets | Secrets Manager ([infra/secrets.tf](../infra/secrets.tf), [infra/cognito.tf](../infra/cognito.tf)) | API key, signing key, Cognito client secrets |

---

## 3. Hosting

### 3.1 Network

The account's network is **org-managed** and Terraform only looks it up by Name tag
([infra/vpc.tf](../infra/vpc.tf)): VPC `Primary_VPC`, with public subnets `Public_Subnet_1A` and
`Public_Subnet_1B` routed to an internet gateway. There's no NAT gateway. YOUR VPC NAMES
WILL BE DIFFERENT - change the code as required.

- The **ALB** spans both public subnets (an ALB needs two AZs).
- The **task** runs in `Public_Subnet_1A` with a public IP, used only for outbound calls (ECR,
  Secrets Manager, Cognito, SES, Anthropic).
- **Security groups:**
  - ALB: ingress 80 and 443 from `0.0.0.0/0`; egress all.
  - Task: ingress 8080 from the ALB security group only; egress all.

### 3.2 Edge: ALB, TLS and HSTS

- **Certificate:** ACM, DNS-validated, in `ca-central-1` ([infra/acm.tf](../infra/acm.tf)).
- **Listeners:**
  - 443: HTTPS, policy `ELBSecurityPolicy-TLS13-1-2-2021-06`, forwards to the target group.
  - 80: a 301 redirect to `https://<same host>:443/`. The path and query are dropped on purpose, so
    the redirect is always to the root.
- **TLS ends at the ALB.** The ALB → task hop is HTTP on 8080 inside the VPC. The app never builds
  absolute URLs from the request; it uses the configured `APP_BASE_URL`
  ([§6.6](#66-configuration)), so it doesn't need `ProxyFix`.
- **HSTS** is set by the ALB, without `includeSubDomains` or `preload`, because
  `example.com` is the org's zone and those would affect other hosts. It starts at
  `max-age=300` and is raised to a year once HTTPS has run cleanly.
- `drop_invalid_header_fields = true` (request-smuggling defence).
- **Health check:** `GET /healthz` on 8080, expecting 200. This target-group check is the only
  health check. There's no Dockerfile `HEALTHCHECK` (ECS ignores it) and no ECS container
  `healthCheck`.

### 3.3 WAF

A REGIONAL WAFv2 web ACL is associated with the ALB ([infra/waf.tf](../infra/waf.tf)). Its
**default action is allow**: the app is open to all IPs. On top of that, rules are at their
default Block actions:

1. **`rate-limit-login`:** blocks an IP that sends more than **20 requests in 5 minutes** to the
   app's sign-in routes (paths starting `/auth/` or `/admin/auth/`, any method), until its rate
   drops. The path is URL-decoded and normalized first, as gunicorn and Flask do, so variants like
   `//auth/login` and `/%61uth/login` are counted too.
2. The no-fee **AWS managed rule groups**: Amazon IP reputation, anonymous IP (VPNs, Tor, hosting
   providers), known bad inputs, the Core rule set, Linux OS and POSIX OS. Total 1,275 WCU of the
   1,500 included.

The Core rule set blocks request bodies over 8 KB, which long non-ASCII input to `/transform` can
hit before the app's 5,000-character cap does.

Password and code entry happen on Cognito's managed login, which this WAF doesn't cover.

**Allowlist (not in use).** `var.allowed_cidrs` feeds the WAF IP set `sarcastifyer-allow`, but no
rule or security group references it. It's kept so that an allowlist can be turned back on.

### 3.4 Compute: ECS Fargate, one task

- **Task definition** ([infra/ecs.tf](../infra/ecs.tf)): Fargate, `LINUX`/**`X86_64`**,
  0.25 vCPU / 0.5 GB, container port 8080, `awslogs` to `/ecs/sarcastifyer` (30-day retention).
  Images must be built with `--platform linux/amd64`; an arm64 image starts and then exits with no
  logs.
- **Container** ([Dockerfile](../Dockerfile)): `python:3.12-slim`, gunicorn with **1 worker and 8
  threads** (threads serve concurrent SSE streams), 120-second timeout.
- **Service:** `desired_count = 1`, no autoscaling, `deployment_minimum_healthy_percent = 0` and
  `deployment_maximum_percent = 100`. The old task stops before the new one starts, so **there is
  never more than one task**.
- **Why exactly one task:** the rate limiter and the daily token brake are in-memory
  ([§5.3](#53-guardrails-and-cost-controls)). They're only correct with one process. The cost is a
  brief outage on every deploy or restart, which is accepted.
- **Dormant state:** the service may be held at 0 tasks with the CLI to save cost. Terraform always
  declares 1, so that drift is intentional.

### 3.5 Images and deploys

- **ECR** repository `sarcastifyer`, scan on push, **immutable tags**. A lifecycle policy keeps the
  two newest tagged images (deployed and previous, for rollback) and expires untagged images after
  a day.
- **Tags:** each deploy pushes the commit's **short git SHA**. `image_tag`
  is required. Terraform resolves it to the image digest (`aws_ecr_image`), and the task
  definition pins `repo@sha256:…`. A new SHA means a new digest and a new task definition.
  Re-applying the deployed tag (`terraform output image_tag`) changes nothing.
- **Deploy order:** build and push, scale the service to zero, then `terraform apply -var
  image_tag=<sha>`. Scaling to zero first guarantees the old task is gone before the new one
  starts.

### 3.6 Terraform

- Root module [infra/](../infra/), AWS provider `~> 6.13`, Terraform `>= 1.11`.
- **Inputs:** [infra/variables.tf](../infra/variables.tf) has definitions only, with no defaults.
  The values are in `infra/environment.auto.tfvars`, which is gitignored and loaded automatically.
  [infra/environment.auto.tfvars.example](../infra/environment.auto.tfvars.example) is the
  committed template. `image_tag` is passed with `-var` on each apply. Values built from other
  inputs or from data sources (`app_base_url`, `cognito_from`, the inbound rule names and ARN)
  stay as locals.
- **State:** S3 bucket named in the gitignored `infra/backend.hcl` (a partial
  [infra/backend.tf](../infra/backend.tf)), encrypted, versioned, TLS-only (bucket policy) and
  `prevent_destroy`, with S3 native locking (no DynamoDB). The bucket is created once by [infra/bootstrap/](../infra/bootstrap/), which keeps its own local state.
- **DNS isn't managed here.** `example.com` should be an org-controlled Route 53 zone in another
  account. Records are requested through the org DNS approval workflow, using Terraform outputs and, for
  the ALB alias, the ALB's DNS name and hosted zone ID from the AWS CLI.
  The nine records are:
  - the domain → ALB record, an **alias A record, not a CNAME**, because it shares its name with
    the inbound MX
  - the ACM validation CNAME
  - the inbound MX
  - three SES DKIM CNAMEs
  - the MAIL FROM MX and SPF TXT
  - the DMARC TXT

  The validation, DKIM and MAIL FROM records are **permanent**: ACM renewal and SES signing depend
  on them.

---

## 4. The application

### 4.1 Units

Each unit has one job and is tested on its own.

| Module | Job |
|---|---|
| [app/\_\_init\_\_.py](../app/__init__.py) | `create_app`: wires everything, sets cookie flags and security headers, loads the identity before each request |
| [app/config.py](../app/config.py) | All tunables: model, limits, session timings, Cognito and secret names |
| [app/web.py](../app/web.py) | `/`, `/transform` (SSE), `/healthz` |
| [app/transformer.py](../app/transformer.py) | Wraps the Anthropic SDK; knows nothing about HTTP. `MissingKeyTransformer` stands in when the API key secret is absent. |
| [app/guardrails.py](../app/guardrails.py) | `RateLimiter` and `DailyTokenBrake` (in memory, thread-safe) |
| [app/mailer.py](../app/mailer.py) | Sends the plain-text result email through SES v2 |
| [app/secrets.py](../app/secrets.py) | Reads Secrets Manager once per secret and caches the value |
| [app/oidc.py](../app/oidc.py) | OIDC protocol: authorization URL, PKCE, code exchange, JWKS and token checks, logout URL |
| [app/session_auth.py](../app/session_auth.py) | Session schema, lifetime, revalidation, CSRF token, safe return paths |
| [app/guards.py](../app/guards.py) | View decorators: `sign_in_required`, `admin_required`, `csrf_required` |
| [app/auth_web.py](../app/auth_web.py) | Sign-in, callback and sign-out routes for both pools |
| [app/directory.py](../app/directory.py) | Cognito Admin* and `ListUsers` calls for the user pool, and `AdminGetUser` on both pools; maps errors to app errors |
| [app/admin_web.py](../app/admin_web.py) | `/admin` dashboard and user actions |
| [app/account_client.py](../app/account_client.py) | Cognito calls made with the admin's own access token |
| [app/account_web.py](../app/account_web.py) | `/account` self-service |
| [app/audit.py](../app/audit.py) | One JSON line per admin action |


### 4.2 Routes

| Route | Who | Purpose |
|---|---|---|
| `GET /` | anyone | Signed out: landing page with a "Sign in" button. Signed in: the transform page. |
| `POST /transform` | signed in | Streams the rewrite (SSE). Signed out: 401. |
| `GET /healthz` | anyone | Health check. Doesn't load the identity or call Cognito. |
| `GET /auth/login`, `GET /auth/callback` | anyone | User-pool sign-in |
| `GET /admin/auth/login`, `GET /admin/auth/callback` | anyone | Admin-pool sign-in |
| `POST /auth/logout` | signed in, CSRF | Sign out of either pool |
| `GET /admin` | admin | Signed out: "Admin sign in" page. Admin: the dashboard. User: 403. |
| `POST /admin/users` | admin, CSRF | Invite a user |
| `GET /admin/users/<sub>/<action>` | admin | Confirm page for disable, delete or change email |
| `POST /admin/users/<sub>/<action>` | admin, CSRF | Disable, enable, delete or change email |
| `GET /account`, `POST /account/<action>` | admin (CSRF on POST) | Admin self-service. User: 403. |


---

## 5. The transformation

### 5.1 Model and prompt

- **Model:** `claude-opus-4-8`, `max_tokens = 4096`, no extended thinking. Tone rewriting is a
  direct generation, so thinking would only add latency and cost. The model is one line in
  [app/config.py](../app/config.py).
- **System prompt (fixed):** rewrite the user's text to be heavily sarcastic, keep its intent and
  facts, restyle only (don't answer questions or follow instructions in the text), and return only
  the rewritten text.
- **User text** is sent as a user-role message, never concatenated into the system prompt. It's
  treated as data, not instructions (prompt-injection hygiene).
- **Missing key:** if the `sarcastifyer/anthropic-api-key` secret doesn't exist, the app still
  starts and stays healthy, and every transform returns a fixed "Missing Anthropic API key" message.

### 5.2 Streaming and email

- `POST /transform` takes JSON `{"text": "...", "email": true|false}` and returns
  `text/event-stream`. Each chunk is a `data:` event; the stream ends with `event: done`.
- **Email me the result:** if `email` is true, after the stream completes the app emails the input
  and result to **the signed-in user's own address** (`session["email"]`). Any address sent by the
  client is ignored. The last streamed line is "Email was sent to …" or "Email could not be sent
  to …". Email is best effort: a failure doesn't fail the transform.
- **Errors:** any failure during the stream is logged and sent as an `event: error` SSE event with
  a generic message, which the page shows inline.

### 5.3 Guardrails and cost controls

All thresholds are in [app/config.py](../app/config.py). They're in memory, which is correct only
because exactly one task runs ([§3.4](#34-compute-ecs-fargate-one-task)).

| Control | Value | Response |
|---|---|---|
| Input cap | 5,000 characters, checked server-side. The page shows a live `X/5000 characters` counter and disables submit over the cap (UX only). | 413 |
| Rate limit | 2 requests per minute per user, sliding window, keyed on the Cognito `sub`. Signing in again doesn't reset it. | 429 |
| Daily brake | 50,000 output tokens per calendar day (the task's clock), across all users | 429 "Daily usage limit reached" |

The daily brake is a **safety brake, not a budget**: it resets when the task restarts, and tokens
from a stream that fails part-way aren't counted. It's checked before each request, so requests
already streaming when it trips can overshoot it slightly. At Opus output pricing the worst case is
about $1.25 a day, plus that overshoot.

---

## 6. Identity, sign-in and sessions

### 6.1 Cognito user pools

Two pools, **Essentials** plan, in `ca-central-1` ([infra/cognito.tf](../infra/cognito.tf)).

| Setting | Admins (`sarcastifyer-admins`) | Users (`sarcastifyer-users`) |
|---|---|---|
| Who | Administrators: use the app, `/admin` and `/account` | Everyone else: use the app |
| Created by | AWS CLI only | Admins, from `/admin` |
| First sign-in factors | `PASSWORD` | `PASSWORD`, `EMAIL_OTP` (see below) |
| MFA | `OPTIONAL`: TOTP and email codes | `OFF` |
| Username | Email, case-insensitive. The internal username is a UUID equal to `sub`. | same |
| Required attributes | `email`, `given_name`, `family_name` (can't change after the pool is created) | same |
| Self-signup | Off | Off |
| Recovery | `admin_only`: no "Forgot password" link | `admin_only` |
| Password policy | 8+ characters, upper, lower, number, symbol; temporary passwords last 7 days | same (applies to no one) |
| Email | `DEVELOPER` mode through the SES domain identity, From `Sarcastifyer <hello@sarcastifyer.example.com>` | same |
| Invitation | Username, temporary password and `/admin` link | Sign-in URL and email address; no password |
| Code email | Custom MFA template naming Sarcastifyer | Cognito's default wording |
| Deletion protection | `ACTIVE` | `ACTIVE` |
| Sign-in domain | Prefix `sarcastifyer-admins.auth.ca-central-1.amazoncognito.com`, managed login v2, Cognito's default branding | Prefix `sarcastifyer-users…`, same |

**Why `PASSWORD` is in the users pool.** Cognito refuses to create a pool whose only first factor
is `EMAIL_OTP`, so the users pool lists both. User accounts are created with no password, so they
can only sign in with an emailed code. Managed login doesn't offer them a password option.

**Template workarounds:**
- The Terraform provider requires `{####}` in every invitation template. Users have no password,
  so the users pool hides it in an HTML comment (`<!-- {####} -->`). Cognito leaves it as literal
  text, so no secret is hidden there.
- Cognito rejects an empty SMS invitation template even with no SMS set up, so both pools set a
  placeholder `sms_message`. It is never sent.
- Cognito's templates are HTML only. There's no plain-text part.

**Email sending.** `DEVELOPER` mode sends through the service-linked role
`AWSServiceRoleForAmazonCognitoIdpEmailService`, so no SES sending-authorization policy is needed.
Because Cognito uses the same domain identity as the app, its bounces and complaints reach the same
alerts topic.

**App clients.** One confidential client per pool, with a client secret, authorization code flow
with PKCE, `COGNITO` as the only identity provider, and user-existence errors suppressed.

| | Admins | Users |
|---|---|---|
| Auth flows | `ALLOW_USER_SRP_AUTH`, `ALLOW_REFRESH_TOKEN_AUTH` | `ALLOW_USER_AUTH` (choice-based, for email codes), `ALLOW_REFRESH_TOKEN_AUTH` |
| Scopes | `openid email profile aws.cognito.signin.user.admin` | `openid email profile` |
| Callback | `/admin/auth/callback` | `/auth/callback` |
| Sign-out URL | `/admin` | `/` |
| Token lifetimes | ID and access 60 min; refresh 60 min (the minimum; the app never keeps it) | same |

Because user-existence errors are suppressed, an unknown email address gets no code and no error.
Nobody can use the sign-in page to find out which addresses have accounts.

**Cost:** Essentials is free up to 10,000 monthly active users per account. Email is billed at SES
rates.

### 6.2 Sign-in (OIDC, app-side)

The app runs OIDC itself against managed login ([app/oidc.py](../app/oidc.py),
[app/auth_web.py](../app/auth_web.py)). The ALB plays no part in authentication.

1. `GET /auth/login` (or `/admin/auth/login`) generates `state`, `nonce` and a PKCE verifier,
   stores them in the session, and redirects to that pool's managed login.
2. The person signs in on Cognito's page: an email code for users, a password and any MFA for
   admins.
3. Cognito redirects to that pool's callback with an authorization code.

**The callback fails closed.** On any failure, the session is cleared and the person sees a
generic "Sign-in failed, try again" page. Details are logged, never tokens or codes. The checks:

1. A sign-in for **this pool** is in progress, and `state` matches (constant-time). The pending
   sign-in is single use.
2. The code is exchanged at **that pool's** token endpoint, with the PKCE verifier and that pool's
   client secret.
3. The ID token is RS256, verified against that pool's JWKS. Keys are cached by `kid`; an unknown
   `kid` triggers a refetch.
4. Claims: `iss` is that pool's issuer, `aud` is that pool's client ID, `token_use` is `id`, `exp`
   is in the future (60-second leeway), and `nonce` matches.
5. Admin callback only: the access token is verified too (`client_id`, `token_use == "access"`), and
   its `sub` must match the ID token's.
6. The session is cleared (session-fixation defence), then filled from the verified claims. The
   session's `pool` comes from **which callback route ran**, never from a request parameter.

**Pool confusion** is prevented by design: each pool has its own route, client, issuer and JWKS, so
a user-pool token fails the admin callback's `iss` and `aud` checks.

**Return paths.** A `next` path is carried through sign-in only if it's a relative path on this app
(starts with `/`, not `//`, no backslashes, whitespace or control characters). Otherwise it falls
back to `/` or `/admin`. Only a signed-out `GET` carries its own path; a signed-out `POST` returns
to the pool's default page.

### 6.3 Session

The session is Flask's **signed (not encrypted) cookie**, signed with
`sarcastifyer/flask-signing-key` (set in [app/\_\_init\_\_.py](../app/__init__.py); contents in
[app/session_auth.py](../app/session_auth.py)).

- **Flags:** `Secure`, `HttpOnly`, `SameSite=Lax`.
- **Lifetime:** 8 hours from sign-in, enforced by the app (`SESSION_LIFETIME_SECONDS = 28800`).
- **Contents:** `sub`, `pool`, `email`, `given_name`, `family_name`, `auth_time`, `checked_at`,
  `csrf`. Admin sessions also hold their **access token** and its expiry, for `/account`. During
  sign-in only: `state`, `nonce`, the PKCE verifier and `next`.
- **Never stored:** the ID token and the refresh token. User sessions never hold an access token.
- **Size:** stays under 4 KB with a realistic admin access token (tested).
- **Never logged:** tokens, codes, passwords and client secrets.

### 6.4 Authorization

- **Signed in:** the session has a `sub` and is less than 8 hours old.
- **Admin:** signed in with `pool == "admin"`. Admins can also use `/` and `/transform`.
- A user session gets **403** on `/admin*` (apart from the sign-in routes) and `/account*`.
- Signed out, `/` shows the landing page and `/admin` the admin sign-in page. Any other page
  redirects to the right sign-in. A signed-out `POST /transform` returns 401.
- **CSRF:** a random per-session token is put in every state-changing form and checked with
  `hmac.compare_digest` on every POST to `/admin/*` and `/account/*`, and on `/auth/logout` for a
  signed-in session. `/transform` relies on JSON-only input, `SameSite=Lax` and no CORS.

### 6.5 Revalidation and sign-out

**Revalidation.** On any signed-in request where the last check is more than **15 minutes** old,
the app calls `AdminGetUser` on the session's pool:

- not found, disabled, or the account's email differs from the session's: the session is cleared
- success: `checked_at` is updated
- throttled or any other error: the session is kept and the check retried on the next request

So an admin's disable, delete or change of email takes effect in the app **within 15 minutes**.
Revalidation **fails open** for availability. During a sustained Cognito or IAM failure, the worst
case is the rest of the session's 8 hours (accepted).

A Cognito global sign-out leaves the account enabled, so revalidation can't see it. That's why
`/admin` offers **Disable** (which also revokes the user's tokens) and no separate sign-out action.

**Sign-out.** `POST /auth/logout` clears the app session, then redirects to that pool's Cognito
`/logout`, which ends the managed-login session and returns to `/` or `/admin`. If the session had
already ended, it just redirects to `/`.

### 6.6 Configuration

The task definition sets these environment variables (names and IDs only, never secret values):

- `AWS_REGION`, `EMAIL_SENDER`, `EMAIL_SENDER_NAME`, `APP_BASE_URL`
- per pool: pool ID, client ID, prefix-domain host, and the client-secret's Secrets Manager name
- `SECRET_ANTHROPIC_API_KEY`, `SECRET_FLASK_SIGNING_KEY`

Redirect, callback and sign-out URLs are built from `APP_BASE_URL`, never from the request.

---

## 7. Administration

### 7.1 `/admin` dashboard (admin pool only)

One page: an invite form and a table of the **user pool's** users ([app/admin_web.py](../app/admin_web.py)).

- **Invite:** first name, last name and email, all required. Names are trimmed, 1–100 characters,
  no control characters. The email gets a shape check (254 characters max), and Cognito does the
  final validation. The app calls `AdminCreateUser` with `email_verified=true`,
  `DesiredDeliveryMediums=["EMAIL"]` and no temporary password, and Cognito emails the invitation.
- **Table:** name, email, status (Enabled or Disabled) and created date, read from `ListUsers` on
  every page load, 60 per page. Nothing is cached.
- **Actions:**

| Action | Cognito call | Notes |
|---|---|---|
| Disable | `AdminDisableUser` | Confirm page. Blocks sign-in and revokes tokens; the app session ends within 15 minutes. |
| Enable | `AdminEnableUser` | Immediate, no confirm page (harmless and easy to undo) |
| Delete | `AdminDeleteUser` | Confirm page names the email |
| Change email | `AdminUpdateUserAttributes` (`email`, `email_verified=true`) | Confirm page. The new address becomes the sign-in name; existing sessions end within 15 minutes. |

  Errors map to plain messages: duplicate email, email already in use, user not found, throttled
  ("Try again shortly"), or invalid input. If the invitation email can't be sent, the user is still
  created and the admin sees a warning. Anything else shows a generic message.

- **Audit log:** every action, including failures, writes one JSON line to `/ecs/sarcastifyer`
  ([app/audit.py](../app/audit.py)): `event="admin_action"`, `action`, `admin_sub`, `admin_email`,
  `target_sub`, `target_email`, `previous_email` (change email only), `result` (`ok` or the error
  class) and `timestamp`. No tokens, codes or passwords.

Admins aren't listed or managed here.

### 7.2 `/account` self-service (admin sessions only)

These calls use the admin's **own access token** (scope `aws.cognito.signin.user.admin`), so they
need no IAM permissions ([app/account_web.py](../app/account_web.py),
[app/account_client.py](../app/account_client.py)).

- Shows name, email and the current MFA factors (`GetUser`).
- **TOTP:** set up (`AssociateSoftwareToken`, a QR code and the secret as text, then
  `VerifySoftwareToken` with a 6-digit code) or remove.
- **Email MFA:** on or off. **Preferred factor** when both are on.
- **Change password** (current + new).
- **Step-up:** if the stored access token is missing or within a minute of expiry (it lasts an
  hour), `/account` sends the admin back through admin sign-in with `next=/account`. Cognito may
  complete that without a prompt if its own session is still valid.

### 7.3 Admins and recovery

- **Admins** are created, disabled, enabled and deleted with the AWS CLI only (runbook). The task
  role can only read admin-pool users, for revalidation.
- **Regular Users** can't lose a password because they don't have one. A user who loses their mailbox gets
  their email changed by an admin.
- **A locked-out admin** is recovered by someone with AWS credentials: clear their MFA, set a
  temporary password and share it out of band. The admin chooses a new password at the next
  sign-in.

---

## 8. Email

### 8.1 Outbound

All outbound mail is From addresses on the **SES domain identity** `sarcastifyer.example.com`
([infra/ses.tf](../infra/ses.tf)):

- **Easy DKIM**, 2048-bit keys
- **Custom MAIL FROM** `mail.sarcastifyer.example.com`, so SPF aligns with the From domain.
  If its records go missing, SES falls back to its own MAIL FROM rather than failing.
- **DMARC** `p=quarantine`, with no reports requested
- The account has SES **production access**, so recipients don't have to be verified.

| Sender | From | To |
|---|---|---|
| App, result email (plain text) | `Sarcastifyer <hello@…>` (`EMAIL_SENDER_NAME`, `EMAIL_SENDER`) | The signed-in user only |
| Cognito: invitations, sign-in codes, MFA codes | `Sarcastifyer <hello@…>` | The account's email |
| Inbound forwarder | `<sender> via Sarcastifyer <hello@…>` | `forward_to` only |

**Bounces and complaints** for the domain identity go to the `sarcastifyer-alerts` SNS topic, with
original headers. Email feedback forwarding is **off**, so bounces don't go to `hello@` and loop
back through the forwarder. The account-level suppression list stops sends to an address after a
hard bounce or complaint.

### 8.2 Inbound

SES accepts mail only for the **`inbound_local_parts`** addresses on the domain and rejects all
others at SMTP time ([infra/inbound.tf](../infra/inbound.tf)): `hello@` (the From address),
`postmaster@` (RFC 5321) and `abuse@` and `webmaster@` (RFC 2142).

The active receipt rule (spam and virus scanning on):
1. Stores the message in S3 bucket `sarcastifyer-inbound-mail-<account>-ca-central-1` under
   `inbound/<messageId>`. The bucket blocks public access, uses SSE-S3, denies non-TLS access,
   only lets this rule write, and **expires objects after 7 days**.
2. Invokes the forwarder Lambda asynchronously ([forwarder/handler.py](../forwarder/handler.py),
   Python 3.13, arm64).

**The forwarder:**
- drops mail with a virus or spam verdict of `FAIL`, and DMARC failures whose sender policy is
  `reject`
- drops anything it has already forwarded (loop guard, `X-Sarcastifyer-Forwarded` header)
- rewrites From to "<original name> via Sarcastifyer <hello@…>", sets Reply-To to the original
  sender (an existing Reply-To is kept), and drops headers that would fail (`Sender`, `Return-Path`, the original
  `DKIM-Signature`)
- sends the raw message to `forward_to`
- logs message IDs and verdicts only, never content

Its IAM policy can only read `inbound/*` in the bucket and send From `email_sender` to
`forward_to`.

### 8.3 Alerts

SNS topic `sarcastifyer-alerts` ([infra/alerts.tf](../infra/alerts.tf)), emailed to `forward_to`
(the subscription must be confirmed once). Only SES (for this domain identity) and CloudWatch (for
alarms named `sarcastifyer-*`) can publish. It receives:
- SES bounces and complaints
- alarm `sarcastifyer-inbound-forwarder-errors`: any forwarder error in a 5-minute period. Async
  invokes retry twice, so one bad message can alarm more than once; it stays in S3 for 7 days to
  forward by hand.

---

## 9. Secrets

| Secret (Secrets Manager) | Source | In Terraform state? |
|---|---|---|
| `sarcastifyer/anthropic-api-key` | Set by hand with the CLI | No |
| `sarcastifyer/flask-signing-key` | Terraform `random_password` (48 chars) | Yes |
| `sarcastifyer/cognito-users-client` | The users app client's secret | Yes |
| `sarcastifyer/cognito-admins-client` | The admins app client's secret | Yes |

- The app reads each secret **once, at startup**, and caches it. A rotated secret takes effect
  when the task restarts.
- Nothing secret is baked into the image or passed as a plaintext environment variable.
- Secrets in Terraform state are protected by the state bucket's encryption, public access block,
  TLS-only policy and account IAM. No bucket policy limits which principals can read it (accepted
  risk).
- Rotating the signing key signs everyone out. Rotating a client secret means replacing the
  Cognito client.

---

## 10. IAM

| Role | Permissions |
|---|---|
| ECS execution role | `AmazonECSTaskExecutionRolePolicy` (ECR pull, CloudWatch Logs) |
| ECS task role, read secrets | `secretsmanager:GetSecretValue` on the four secret ARNs only |
| ECS task role, Cognito | Users pool: `AdminCreateUser`, `ListUsers`, `AdminGetUser`, `AdminDisableUser`, `AdminEnableUser`, `AdminDeleteUser`, `AdminUpdateUserAttributes`. Admins pool: `AdminGetUser` only. No wildcards. |
| ECS task role, send email | `ses:SendEmail` on the domain identity, condition `ses:FromAddress = email_sender`. Recipients aren't restricted (see [§12](#12-security-posture)). |
| Forwarder Lambda role | Write its own log group; `s3:GetObject` on `inbound/*`; `ses:SendEmail`/`SendRawEmail` From `email_sender` to `forward_to` only |
| Cognito email | AWS service-linked role `AWSServiceRoleForAmazonCognitoIdpEmailService` |


Disclaimer: although every attempt has been made to secure this sample application, there is no
guarantee offered and no warranty provided. You are responsible for your own AWS account and
application security.

