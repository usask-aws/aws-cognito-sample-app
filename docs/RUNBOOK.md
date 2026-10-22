# Sarcastifyer — Operations Runbook

Operational map for the Sarcastifyer service: first-time setup, resting states,
routine tasks, and the intentional-drift notes an operator needs before touching anything.

This is the home for all deployment steps, including
[routine deploys](#deploy-a-new-version).

> **All design details are in [DESIGN.md](DESIGN.md):** the architecture, how sign-in, sessions,
> email and the WAF work, IAM, data classification, accepted risks, and why things are the way
> they are. This runbook covers only how to set up, deploy and operate the app.

---

## First-time setup

A start-to-finish timeline, from an account with no state bucket and no app
resources to the app serving over HTTPS on its domain. Do the steps in order. Run
everything from the repository root unless a step `cd`s.

The state bucket name is account-specific, so it isn't in the repository. It's set in
the gitignored `infra/backend.hcl` and passed to every `terraform init` in `infra/`.

The one long wait is the org DNS approval (step 3). Step 2 creates everything the
DNS request needs, so it can be submitted early, and the image is built while it's
pending.

### Prerequisites
- Terraform **>= 1.11** (S3 native state locking), AWS CLI v2, Docker.
- AWS credentials for the target account. Profile names differ between
  environments, so confirm the account first with `aws sts get-caller-identity`.
- The org-provided network already exists in `ca-central-1`: a VPC tagged
  `Name=Primary_VPC` with public subnets `Public_Subnet_1A` and `Public_Subnet_1B`
  in different AZs, each routed to an internet gateway. Terraform only looks these
  up, so `plan` fails if they're missing.
- Access to the org DNS change workflow for the `example.com` zone.
- `infra/environment.auto.tfvars` with the desired values. It's gitignored, so a fresh
  clone doesn't have it. Copy the template and replace every `<placeholder>`:
  `cp infra/environment.auto.tfvars.example infra/environment.auto.tfvars`. Without it,
  `plan` and `apply` prompt for each variable.
- `infra/backend.hcl` naming the state bucket. It's gitignored too. Copy the template and set
  the bucket name: `cp infra/backend.hcl.example infra/backend.hcl`.
- If an allowlist is in place
  ([Change who can reach the app](#change-who-can-reach-the-app-allowlist)), your
  public IP is in `allowed_cidrs`. Otherwise you won't be able to reach the app to
  check it. While the app is open to all IPs, this doesn't apply.
- A clean, committed working tree. The image is tagged with the commit's short SHA.
- The Anthropic API key.
- The principal that runs the first full apply can call `iam:CreateServiceLinkedRole`.
  Cognito creates `AWSServiceRoleForAmazonCognitoIdpEmailService` to send email through SES.
- The Cognito prefix domains `sarcastifyer-users` and `sarcastifyer-admins` are free:
  `aws cognito-idp describe-user-pool-domain --region ca-central-1 --domain <name>` returns
  `{"DomainDescription": {}}`.

### 1. State backend (skip if the bucket already exists)
Bootstrap creates the S3 bucket that holds Terraform state (S3 native locking, no
DynamoDB). The bucket name is **set in `infra/backend.hcl`**, and bootstrap must
create exactly that bucket. Bucket names are global across AWS, so pick one unlikely
to be taken (for example, one that includes the account ID and region).

First check whether the bucket exists:
```bash
B=$(sed -n 's/^bucket *= *"\(.*\)"/\1/p' infra/backend.hcl)
aws s3api head-bucket --bucket "$B"
```
If it prints the bucket region, it exists: **skip to step 2**. If you get `404`
(Not Found), bootstrap it:
```bash
cd infra/bootstrap
terraform init
terraform apply -var state_bucket_name="$B"
cd ../..
```
Bootstrap keeps its own state locally in `infra/bootstrap/` (gitignored). Losing
that local state doesn't affect the bucket. The bucket has `prevent_destroy`: never destroy
bootstrap with Terraform. To apply a later bootstrap change from a
machine without that state, import the existing resources first:
```bash
cd infra/bootstrap
terraform init
B=$(sed -n 's/^bucket *= *"\(.*\)"/\1/p' ../backend.hcl)
for r in aws_s3_bucket aws_s3_bucket_versioning \
         aws_s3_bucket_server_side_encryption_configuration aws_s3_bucket_public_access_block; do
  terraform import -var state_bucket_name=$B $r.state $B
done
# Only if the TLS-only bucket policy has already been applied:
terraform import -var state_bucket_name=$B aws_s3_bucket_policy.state $B
terraform plan -var state_bucket_name=$B   # expect only the changes you made
cd ../..
```

### 2. Foundation apply: ECR repo, API-key secret, certificate, ALB and SES domain
A full apply can't run yet, for two reasons:
- **The ECR repo would be empty**, so the service would start on an image that
  doesn't exist.
- **The certificate isn't issued.** The apply would wait for it (up to the
  provider's 75-minute timeout) and then fail.

Create only these resources first:
```bash
cd infra
terraform init -backend-config=backend.hcl
# image_tag is required but unused here: -target skips the image lookup.
terraform apply -var image_tag=none \
  -target=aws_ecr_repository.app \
  -target=aws_secretsmanager_secret.anthropic_api_key \
  -target=aws_acm_certificate.app \
  -target=aws_lb.app \
  -target=aws_sesv2_email_identity.domain
# Set the Anthropic API key value (kept out of TF state):
aws secretsmanager put-secret-value --region ca-central-1 \
  --secret-id sarcastifyer/anthropic-api-key --secret-string "<your-anthropic-key>"
cd ..
```
Terraform warns that `-target` is for exceptional use. That's expected here.
Targeting `aws_lb.app` also creates the ALB security group. The ALB has no
listeners yet, so it serves nothing. The SES domain identity generates the DKIM
tokens the DNS request needs. It sends nothing yet.

### 3. Request the DNS records
Collect the values:
```bash
# ACM validation record (name, type, value)
aws acm describe-certificate --region ca-central-1 \
  --certificate-arn "$(aws acm list-certificates --region ca-central-1 \
    --query "CertificateSummaryList[?DomainName=='sarcastifyer.example.com'].CertificateArn | [0]" --output text)" \
  --query 'Certificate.DomainValidationOptions[0].ResourceRecord' --output table
# ALB DNS name and its canonical hosted zone ID (both needed for the alias record)
aws elbv2 describe-load-balancers --region ca-central-1 --names sarcastifyer-alb \
  --query 'LoadBalancers[0].[DNSName,CanonicalHostedZoneId]' --output text
# The three DKIM CNAMEs
cd infra && terraform output dkim_records && cd ..
```
If ACM hasn't filled in the validation record yet, wait a few seconds and run it
again.

Submit **one** change request through the org DNS workflow for the
`example.com` zone, with all of these records:

| Record | Type | Value | Purpose |
|---|---|---|---|
| The validation record's name (`_<hash>.sarcastifyer.example.com.`) | CNAME | The validation record's value (`_<hash>.<id>.acm-validations.aws.`) | ACM certificate |
| `sarcastifyer.example.com.` | **Alias A** (not CNAME) | The ALB DNS name, with the ALB's canonical hosted zone ID | App |
| `sarcastifyer.example.com.` | MX | `10 inbound-smtp.ca-central-1.amazonaws.com.` | Inbound mail |
| 3 × `<token>._domainkey.sarcastifyer.example.com.` | CNAME | `<token>.dkim.amazonses.com.` (from `dkim_records`) | SES DKIM |
| `mail.sarcastifyer.example.com.` | MX | `10 feedback-smtp.ca-central-1.amazonses.com.` | SES MAIL FROM |
| `mail.sarcastifyer.example.com.` | TXT | `"v=spf1 include:amazonses.com ~all"` | SES MAIL FROM (SPF) |
| `_dmarc.sarcastifyer.example.com.` | TXT | `"v=DMARC1; p=quarantine"` | DMARC |

Include these points in the request:
- **All the records are permanent.**
  - ACM checks the validation record every time it auto-renews the certificate.
    If it's removed, renewal fails and the certificate expires, taking HTTPS down
    with it.
  - SES keeps checking the DKIM and MAIL FROM records. If they're removed, signing
    or SPF alignment stops.
- **The domain record must be an alias A record, not a CNAME.** A CNAME can't share
  its name with the inbound MX. The ALB is in another account, so the console's
  target picker won't list it: enter the DNS name and canonical hosted zone ID by
  hand, with "Evaluate target health" set to No.
- **The domain record changes only if the ALB is ever recreated.** A new ALB has a
  new DNS name.

Carry on with step 4 while the request is pending.

### 4. Build and push the first image
```bash
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
REPO=$(cd infra && terraform output -raw ecr_repository_url)
TAG=$(git rev-parse --short HEAD)
aws ecr get-login-password --region ca-central-1 \
  | docker login --username AWS --password-stdin "$ACCOUNT.dkr.ecr.ca-central-1.amazonaws.com"
# --platform linux/amd64 is required: the task def is pinned X86_64.
# Tags are immutable: there's no "latest", and a SHA can't be pushed twice.
docker build --platform linux/amd64 -t "$REPO:$TAG" .
docker push "$REPO:$TAG"
```
Keep this shell open: step 6 uses `$TAG`.

### 5. Wait for the certificate to be issued
Once the org has published the records, ACM usually issues the certificate within
minutes. Check:
```bash
aws acm list-certificates --region ca-central-1 \
  --query "CertificateSummaryList[?DomainName=='sarcastifyer.example.com'].[CertificateArn,Status]" \
  --output table
```
**Don't go on until the status is `ISSUED`.** While it's `PENDING_VALIDATION`,
nothing is served and the certificate costs nothing.

If the status reaches `FAILED` (ACM gives up after about 72 hours without the
record), run this from `infra/`:
```bash
terraform apply -var image_tag=none -target=aws_acm_certificate.app \
  -replace=aws_acm_certificate.app
```
Then check the validation record again as in step 3. ACM derives it from the
account and domain, so it should match the record you already requested.

### 6. Full apply on that image
Run in the same shell as step 4 so `$TAG` is still set. This creates everything
else:
- the remaining secrets and IAM roles
- MAIL FROM and bounce/complaint notifications
- the Cognito user pools, their prefix domains, app clients and client-secret secrets
- inbound mail: the S3 bucket, the forwarder Lambda and the active receipt rule set
- the `sarcastifyer-alerts` SNS topic and its email subscription (SNS sends a
  confirmation email, step 7), and the forwarder-errors alarm
- the WAF
- the ALB listeners: HTTPS on 443 with HSTS, and port 80 redirecting to the root
  over HTTPS
- the ECS cluster, service and task def
- the ECR lifecycle policy (keeps the two newest tagged images)

The service starts one task on the image you just pushed.
```bash
cd infra && terraform apply -var image_tag="$TAG"
aws ecs wait services-stable --region ca-central-1 \
  --cluster sarcastifyer --services sarcastifyer
terraform output -raw app_url
cd ..
```
If the apply fails partway (for example, an org SCP denies an action), the
resources it already created stay in state. Fix the cause and re-run the same
apply.

### 7. Confirm email: SES status and SNS subscription
Once the step 3 records are published:
```bash
aws sesv2 get-email-identity --region ca-central-1 \
  --email-identity sarcastifyer.example.com \
  --query '[VerifiedForSendingStatus,DkimAttributes.Status,MailFromAttributes.MailFromDomainStatus]'
# expect: [true, "SUCCESS", "SUCCESS"]
```
SES usually finds the records within minutes; AWS allows up to 72 hours.

A confirmation email arrives after step 6:
- **SNS subscription confirmation** (from `no-reply@sns.amazonaws.com`), sent to
  `forward_to`. Until it's clicked, bounce, complaint and forwarder-error alerts
  aren't delivered.

See [Email (SES)](#email-ses) for the status checks and what to do about expired
links.

### 8. Check the app
This step needs the domain record from step 3 to be published.
```bash
D=sarcastifyer.example.com
curl -sI "http://$D/some/path?x=1" | grep -iE '^HTTP|^location'   # 301, Location: https://$D:443/
curl -s -o /dev/null -w '%{http_code}\n' "https://$D/healthz"     # 200
curl -sI "https://$D/healthz" | grep -i strict-transport           # max-age=...
echo | openssl s_client -connect "$D:443" -servername "$D" 2>/dev/null \
  | openssl x509 -noout -subject -issuer -enddate                 # CN = $D, Amazon issuer
```
Create the first admin ([Manage administrators](#manage-administrators-cli)), then sign in at
`https://sarcastifyer.example.com/admin` with the emailed temporary password and set a new
one. From `/admin`, invite yourself as a user, sign in at the root URL with the emailed code, and
run a transform. In the browser's developer tools (Application/Storage, then Cookies), the
`session` cookie should be **Secure**, **HttpOnly** and **SameSite=Lax**.

Then check email both ways:
- **Outbound.** Tick *Email me the result* and run a transform. The result should end
  "Email was sent to <your address>". In the received message's headers,
  `Authentication-Results` should show `spf=pass`, `dkim=pass` and `dmarc=pass`, with
  `Return-Path` on `mail.sarcastifyer.example.com`.
- **Inbound.** Send a message from any outside mailbox to
  `postmaster@sarcastifyer.example.com`. It should arrive at `forward_to` as
  "<sender> via Sarcastifyer", and replying should address the original sender.

### 9. After setup
The app is now live. From now on, use [Deploy a new version](#deploy-a-new-version)
for new code. If it won't be used for a while, you can
[scale it to zero](#go-dormant-scale-to-zero).

A few days after setup, if HTTPS has run cleanly,
[raise the HSTS max-age](#raise-the-hsts-max-age).

---

## Routine operations

**Every `terraform apply` needs `image_tag`.** It has no default. A deploy passes the new
SHA. For any other apply (rotating secrets, the allowlist, HSTS, and so on), reuse the
deployed tag first, from the repository root:
```bash
export TF_VAR_image_tag=$(cd infra && terraform output -raw image_tag)
```
The same tag resolves to the same digest, so the task def doesn't change and the task
keeps running, unless the apply changes the task def for another reason.

ECR keeps only the two newest tagged images ([infra/ecr.tf](../infra/ecr.tf)). If two newer images
were pushed without being deployed, the deployed tag has expired: infra-only applies then fail at
plan, and the task can't restart. Deploy a current SHA instead.

### Deploy a new version
Terraform doesn't build or push code: the service runs whatever image digest the task
def names. A deploy builds the image, pushes it to ECR under the commit's short SHA,
scales the service to zero, then applies the new tag. Terraform resolves the tag to its
digest and pins that.
**Brief downtime is expected and acceptable.** Why it works this way:
[DESIGN.md §3.4–3.5](DESIGN.md#34-compute-ecs-fargate-one-task).

This needs an existing service, so the very first deploy uses
[First-time setup](#first-time-setup). Run from the repository root:
```bash
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
REPO=$(cd infra && terraform output -raw ecr_repository_url)
TAG=$(git rev-parse --short HEAD)

# 1. Log Docker in to ECR.
aws ecr get-login-password --region ca-central-1 \
  | docker login --username AWS --password-stdin "$ACCOUNT.dkr.ecr.ca-central-1.amazonaws.com"

# 2. Build amd64 (the task def is pinned X86_64) and push under the SHA.
#    Tags are immutable. If this SHA is already in ECR, the push fails: skip
#    to step 3, the image is already there.
docker build --platform linux/amd64 -t "$REPO:$TAG" .
docker push "$REPO:$TAG"

# 3. Scale to zero and wait for the old task to drain.
aws ecs update-service --region ca-central-1 \
  --cluster sarcastifyer --service sarcastifyer --desired-count 0 >/dev/null
aws ecs wait services-stable --region ca-central-1 \
  --cluster sarcastifyer --services sarcastifyer

# 4. Register the new task def; this also sets desired_count back to 1.
cd infra && terraform apply -var image_tag="$TAG"

# 5. Wait for the new task to become healthy.
aws ecs wait services-stable --region ca-central-1 \
  --cluster sarcastifyer --services sarcastifyer
terraform output -raw app_url
cd ..
```
**If `docker build` or `docker push` fails, stop**, unless the push failed only
because the tag already exists. The apply fails at plan time if the tag has no image.

After a deploy the service is at `desired_count=1` (running). If the app should be
dormant again, [scale it back to zero](#go-dormant-scale-to-zero).

### Go dormant (scale to zero)
Optional, to save cost while the app won't be used for a while:
```bash
aws ecs update-service --region ca-central-1 \
  --cluster sarcastifyer --service sarcastifyer --desired-count 0
aws ecs wait services-stable --region ca-central-1 \
  --cluster sarcastifyer --services sarcastifyer
```
Do **not** run `terraform apply` to go dormant — apply resets `desired_count` to 1.

### Wake up (scale to one)
```bash
aws ecs update-service --region ca-central-1 \
  --cluster sarcastifyer --service sarcastifyer --desired-count 1
aws ecs wait services-stable --region ca-central-1 \
  --cluster sarcastifyer --services sarcastifyer
cd infra && terraform output -raw app_url    # then sign in
```
This launches the task def that's already registered — no rebuild needed. Use this
(not a full deploy) when the code hasn't changed.

### Change who can reach the app (allowlist)
**The app is open to all IPs**, and `allowed_cidrs`
(`infra/environment.auto.tfvars`) is unused. The WAF rules and the reasons are in
[DESIGN.md §3.3](DESIGN.md#33-waf).

To add an allowlist (two layers):
1. In [infra/waf.tf](../infra/waf.tf), set `default_action` to `block {}` and
   add an `allow` rule with an `ip_set_reference_statement` pointing at
   `aws_wafv2_ip_set.allow`.
2. In [infra/vpc.tf](../infra/vpc.tf), set both ALB ingress `cidr_blocks` to
   `var.allowed_cidrs`.
3. `terraform apply`.

Typical entries: an organization's network range, a trusted desktop's static IP
(`/32`), or a trusted desktop's dynamic-IP range (`/24`). To add an operator, add
their static public IP as a `/32`.

### Rotate secrets
- **Anthropic API key** (kept out of TF state):
  ```bash
  aws secretsmanager put-secret-value --region ca-central-1 \
    --secret-id sarcastifyer/anthropic-api-key --secret-string "<new-key>"
  ```
  The task reads the value when it starts, so **restart the task** to pick it up
  (scale to 0 then 1, or redeploy).
- **Cognito client secrets** (in Terraform state, like the signing key): replace the client, for
  example `terraform apply -replace=aws_cognito_user_pool_client.users`. Terraform re-creates its
  branding style and secret version and registers a new task def, which restarts the task with the
  new client ID and secret. Existing sessions stay valid.
- **Flask signing key**: a Terraform `random_password` (so it *is* in state). Rotate
  with `terraform apply -replace=random_password.flask_signing_key`, then restart the
  task the same way. This signs everyone out.

### Email (SES)
How outbound, inbound and alert email work is in [DESIGN.md §8](DESIGN.md#8-email). The DNS
records are in [First-time setup step 3](#3-request-the-dns-records). All of them are permanent.

**Production access.** You will want to move from Sandbox access to Production access in
the account that owns SES. That is outside the scope of this documentation.
 Check with `aws sesv2 get-account --region ca-central-1 --query ProductionAccessEnabled`.

**Domain status.** Check that DKIM and MAIL FROM are still healthy:
```bash
aws sesv2 get-email-identity --region ca-central-1 \
  --email-identity sarcastifyer.example.com \
  --query '[VerifiedForSendingStatus,DkimAttributes.Status,MailFromAttributes.MailFromDomainStatus]'
```
Anything other than `[true, "SUCCESS", "SUCCESS"]` means a DNS record has gone
missing:
- Compare with `terraform output dkim_records` and `terraform output mail_from_records`.
- Get the missing record put back through the org DNS workflow.
- While MAIL FROM is failing, SES falls back to its own MAIL FROM domain, so mail
  still sends.

**Inbound addresses.** To accept mail at another address on the domain, add it to
`inbound_local_parts` (`infra/environment.auto.tfvars`) and `terraform apply`. A
message the forwarder failed on stays in the inbound S3 bucket under `inbound/<messageId>` for
7 days.

**Suppressed addresses.** SES stops sending to an address after a hard bounce or a complaint. To
check or clear one:
```bash
aws sesv2 get-suppressed-destination --region ca-central-1 --email-address <addr>
aws sesv2 delete-suppressed-destination --region ca-central-1 --email-address <addr>
```
If alerts stop arriving, check that the subscription is confirmed. A
`PendingConfirmation` ARN means the confirmation link was never clicked:
```bash
aws sns list-subscriptions-by-topic --region ca-central-1 \
  --topic-arn "$(aws sns list-topics --region ca-central-1 \
    --query "Topics[?ends_with(TopicArn, ':sarcastifyer-alerts')].TopicArn | [0]" --output text)"
```
To get a new confirmation email, re-create the subscription:
`terraform apply -replace=aws_sns_topic_subscription.alerts_email`.

### Manage users (`/admin`)
Admins manage user accounts at `https://sarcastifyer.example.com/admin`: invite (first name,
last name, email), disable, enable, delete and change email. Each action writes one JSON line with
`"event": "admin_action"` to `/ecs/sarcastifyer`:
```bash
aws logs filter-log-events --region ca-central-1 --log-group-name /ecs/sarcastifyer \
  --filter-pattern '{ $.event = "admin_action" }' --query 'events[].message' --output text
```
- **End someone's access:** use *Disable*. Their app session ends within 15 minutes.
- **A user lost access to their mailbox:** use *Change email*. The new address becomes their
  sign-in name, and their existing sessions end within 15 minutes.
- If Cognito or IAM is failing, those 15-minute cut-offs don't happen
  ([DESIGN.md §6.5](DESIGN.md#65-revalidation-and-sign-out)).
- **Find a user by email:**
  `aws cognito-idp list-users --region ca-central-1 --user-pool-id "$(cd infra && terraform output -raw cognito_users_pool_id)" --filter 'email = "<addr>"'`.
  The `Username` is the `sub`.

### Manage administrators (CLI)
Admins are never created or removed from the UI. Each admin manages their own sign-in at `/account`:
an authenticator app (TOTP), email codes, the preferred MFA factor, and their password. Everything
else uses the CLI. Set `POOL=$(cd infra && terraform output -raw cognito_admins_pool_id)`.
- **Add an admin** (Cognito emails a temporary password, valid 7 days):
  ```bash
  aws cognito-idp admin-create-user --region ca-central-1 --user-pool-id "$POOL" \
    --username "<email>" --desired-delivery-mediums EMAIL \
    --user-attributes Name=email,Value="<email>" Name=email_verified,Value=true \
      Name=given_name,Value="<first>" Name=family_name,Value="<last>"
  ```
- **Resend the invitation:** the same command with `--message-action RESEND` (only the
  `--user-pool-id`, `--username` and `--desired-delivery-mediums` are needed).
- **Disable / enable / delete:** `admin-disable-user`, `admin-enable-user`, `admin-delete-user`
  with `--user-pool-id "$POOL" --username "<email>"`. `admin-disable-user` also revokes the admin's
  tokens.
- **Recover a locked-out admin** (lost authenticator or password): clear MFA, then set a temporary
  password and share it out of band. The admin sets a new password at the next sign-in.
  ```bash
  aws cognito-idp admin-set-user-mfa-preference --region ca-central-1 --user-pool-id "$POOL" \
    --username "<email>" \
    --software-token-mfa-settings Enabled=false,PreferredMfa=false \
    --email-mfa-settings Enabled=false,PreferredMfa=false
  aws cognito-idp admin-set-user-password --region ca-central-1 --user-pool-id "$POOL" \
    --username "<email>" --password "<temporary>"     # no --permanent
  ```

### View logs
```bash
aws logs tail /ecs/sarcastifyer --region ca-central-1 --follow
```

### Certificate renewal
ACM renews the certificate automatically before it expires, as long
as the validation CNAME is still published and the certificate is attached to the
ALB. Nothing needs doing. To check:
```bash
aws acm describe-certificate --region ca-central-1   --certificate-arn "$(aws acm list-certificates --region ca-central-1     --query "CertificateSummaryList[?DomainName=='sarcastifyer.example.com'].CertificateArn | [0]" --output text)"   --query 'Certificate.[Status,NotAfter,RenewalEligibility,RenewalSummary.RenewalStatus]' --output table
```
If renewal is stuck at `PENDING_VALIDATION`, the validation CNAME has probably been
removed. Get it put back through the org DNS workflow. The record's values are in
`terraform output acm_validation_records`.

---

## Teardown

Removes everything that `infra/` manages, including the ACM certificate and the
ALB. The state bucket and the org network (`Primary_VPC` and its subnets) are left
in place. After teardown, you can rerun [First-time setup](#first-time-setup) from
step 2.
```bash
# 1. Empty the ECR repo. Terraform can't delete a repo that still holds images.
IDS=$(aws ecr list-images --region ca-central-1 --repository-name sarcastifyer \
  --query 'imageIds[*]' --output json)
aws ecr batch-delete-image --region ca-central-1 --repository-name sarcastifyer \
  --image-ids "$IDS"

# 1b. Empty the inbound mail bucket. Terraform can't delete a bucket that holds objects.
aws s3 rm s3://sarcastifyer-inbound-mail-<account-id>-ca-central-1 --recursive

# 1c. Turn off deletion protection on both user pools. Destroying them deletes every account.
for p in cognito_admins_pool_id cognito_users_pool_id; do
  aws cognito-idp update-user-pool --region ca-central-1 \
    --user-pool-id "$(cd infra && terraform output -raw $p)" --deletion-protection INACTIVE
done

# 2. Destroy. -refresh=false: the ECR images are gone, so the image lookup would fail.
cd infra && terraform destroy -refresh=false -var image_tag=none && cd ..

# 3. Destroy only schedules the secrets for deletion (30-day recovery window), which
#    blocks re-creating the same names. Delete them now:
for s in $(aws secretsmanager list-secrets --region ca-central-1 --include-planned-deletion \
    --filters Key=name,Values=sarcastifyer/ --query 'SecretList[].Name' --output text); do
  aws secretsmanager delete-secret --region ca-central-1 \
    --secret-id "$s" --force-delete-without-recovery
done
```
`update-user-pool` resets settings it isn't given. That's harmless here, because the
pools are destroyed next.

If step 1 errors because the repo is already empty, carry on. Force-deleting the
secrets can't be undone. The Anthropic key has to be set again at the next setup.

Then deal with the app's records in the org DNS zone (the full list is in
[step 3](#3-request-the-dns-records)):
- **Not setting up again:** request removal of all of them through the org DNS
  workflow. Remove the inbound MX first, or senders will keep trying a domain that
  no longer accepts mail.
- **Setting up again:** check every record at step 3 against the new values.
  - The new ALB has a new DNS name, so the alias record needs updating.
  - The new SES domain identity generates **new DKIM tokens**, so the three DKIM
    CNAMEs need replacing (`terraform output dkim_records`).
  - The ACM validation CNAME should come out the same, since ACM derives it from the
    account and domain.
  - The MX, MAIL FROM and DMARC records don't change.
  - The SNS subscription is re-created, so its confirmation email has to be clicked again
    (step 7). Admins must be created again with the CLI, and users invited again.

---

## Intentional drift: `desired_count`

Terraform declares `desired_count = 1` ([infra/ecs.tf](../infra/ecs.tf)), and in
day to day use the service normally runs at 1. While the app won't be used for a while,
it may be held at **0** via the CLI to avoid paying for an idle Fargate task. **That
drift is expected — do not flag it in reviews.** Any `terraform apply` relaunches a
task (reset to 1); if the app should stay dormant,
[scale it back to zero](#go-dormant-scale-to-zero) afterwards.
