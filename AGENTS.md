# Instructions for AI agents

This file tells AI coding agents how to work in this repository. It holds working rules only. The
facts about the app live in the documents below. Read the ones that apply before you change
anything, and don't copy their contents into new files.

## Where things are documented

| Document | Read it for |
|---|---|
| [README.md](README.md) | What the app is, running the tests, and running the app locally in Docker |
| [docs/DESIGN.md](docs/DESIGN.md) | The single source for design and architecture: components, module map (§4.1), sign-in and sessions, email, IAM, data classification (§11), security controls and accepted risks (§12), testing (§13), design history and rejected options (§14), and open items (§15) |
| [docs/RUNBOOK.md](docs/RUNBOOK.md) | Setup, deploys, routine operations, teardown and intentional drift. It includes notes addressed to agents. |
| [docs/license-register/](docs/license-register/) | One entry per vetted third-party dependency |

## Before changing anything

- **Don't re-open settled decisions.** DESIGN.md records the current design, the accepted risks
  (§12) and the options already rejected (§14). Don't propose a rejected option or treat an
  accepted risk as a new finding, unless the user asks or the change you're making affects it.
- **Expected drift isn't a bug.** RUNBOOK.md describes drift that is deliberate, such as
  `desired_count`. Don't flag or "fix" it.
- **If a request conflicts with the documented design, ask.** Don't quietly work around it.

## Making changes

- **Done means the tests pass.** Run them as described in README.md. Add or update tests with
  every behaviour change, in the style DESIGN.md §13 describes: no network calls, and AWS and the
  Anthropic API faked or stubbed.
- **Terraform changes** must pass `terraform fmt -check` and `terraform validate` in `infra/`.
  Show the user the plan before anyone applies it.
- **Match the surrounding code**: its naming, comment density and idioms. Keep each module to the
  single job DESIGN.md §4.1 gives it.
- **Changes that touch security** (sign-in, sessions, CSRF, authorization, headers, guardrails,
  IAM, WAF, network, secrets, email) need extra care. Check them against DESIGN.md §6 and §12,
  and say plainly in your summary what changed.
- **New dependencies:** check the license and known vulnerabilities, add an entry to
  docs/license-register/ in the style of the existing entries, and update the dependency list in
  DESIGN.md §4.1.

## Keeping the docs current

- Update DESIGN.md and RUNBOOK.md in the same change as the behaviour they describe. Both describe
  the current state. Record significant design changes as a row in DESIGN.md §14.
- Don't add plan, spec or review documents to the repository. Earlier ones are in git history
  only.
- Write for a reader new to the project. Link to the existing section instead of restating it.

## Data and secrets

- Follow the data classification in DESIGN.md §11. Test fixtures and examples must be
  de-identified: made-up names and `example.com` addresses.
- Never commit secrets or environment-specific values. The deployment's real values live in
  gitignored files (`infra/environment.auto.tfvars` and `infra/backend.hcl`), and each has a
  committed `.example` template. Keep account IDs, real domains, bucket names and email addresses
  out of committed files. Use placeholders.
- Never put secret values in Terraform variables, logs, or the task definition's environment.
  DESIGN.md §9 explains where each secret lives.

## Actions that need the user's go-ahead

Anything that changes real infrastructure or reaches outside the repository: `terraform apply`
or `destroy`, deploys, scaling the service, changing Cognito users or admins, sending email, and
any AWS CLI command that writes. Follow the matching RUNBOOK.md procedure exactly, confirm with
the user before you start, and report what you did. Read-only commands such as `terraform plan`,
`describe-*`, `get-*` and log reads are fine.

Don't commit, push or open pull requests unless the user asks.
