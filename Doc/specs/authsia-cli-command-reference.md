# Authsia CLI Command Reference (Test Guide)

## Table of Contents

- [Scope &amp; Test Assumptions](#scope-test-assumptions)
- [Global Commands (Unlock, List, Scrape, Revert)](#global-commands-unlock-list-scrape-revert)
- [OTP](#otp)
- [Load Runtime Environment Variables](#load-runtime-environment-variables)
- [Exec (Scoped Secret Injection)](#exec-scoped-secret-injection)
- [Read (Secret Reference Resolution)](#read-secret-reference-resolution)
- [Passwords](#passwords)
- [Certificates](#certificates)
- [Notes &amp; JSON Credentials](#notes-json-credentials)
- [SSH Keys](#ssh-keys)
- [Inject (Template Secret Injection)](#inject-template-secret-injection)
- [Access (Automation Credentials)](#access-automation-credentials)
- [Agent Rule Setup](#agent-rule-setup)
- [Environment Profiles](#environment-profiles)
- [SSH Tooling](#ssh-tooling)
- [Status, Setup &amp; Doctor](#status-setup-doctor)
- [Audit (Enhanced)](#audit-enhanced)
- [Shell Completions](#shell-completions)

## Scope & Test Assumptions

This document lists all supported CLI commands with copy/paste-ready samples to validate each
activity end-to-end. Commands are grouped by item type and ordered so testers can run them in batch.

Assumptions:
- The Authsia app is installed in `/Applications`, has been launched once after
  install, and the CLI can connect over XPC.
- Biometric approval is available, or you will run `authsia unlock` first.
- CLI access is enabled for any existing items you plan to retrieve.
- Use a test vault or test items; add/edit/delete commands will mutate data.
- Create a local fixtures folder, for example: `mkdir -p ~/fixtures`.
- Replace sample file paths and names as needed.

Sample item names used below (adjust as needed): GitHub (OTP), Demo Password, Demo Cert, Kube Config,
Work SSH.

## Global Commands (Unlock, List, Scrape, Revert)

| Step | Activity | Test Payload | Command | Notes |
|------|---------|--------------|---------|-------|
| 1 | Start session | N/A | `authsia unlock` | Avoids repeated approval prompts until the session expires |
| 2 | List OTP items | N/A | `authsia list otp --format table` | Non-secret list |
| 3 | List passwords | N/A | `authsia list passwords` | Scraped items default to current machine |
| 4 | List passwords (all machines) | N/A | `authsia list passwords --all-machines --format table` | Table includes `Machine` for scraped rows |
| 5 | List certificates | N/A | `authsia list certs --format table` | Scraped rows include `Machine` |
| 6 | List notes | N/A | `authsia list notes --format table` | Scraped rows include `Machine` |
| 7 | List SSH keys | N/A | `authsia list ssh --format table` | Scraped rows include `Machine` |
| 8 | List favorites | N/A | `authsia list passwords --favorites` | Filters by favorite |
| 9 | Scrape defaults | N/A | `authsia scrape` | Scans env files, shell configs, and kube config; does not scan `~/.ssh` |
| 10 | Scrape custom paths | `~/.ssh`, `~/.kube/config` | `authsia scrape --path ~/.ssh ~/.kube/config` | Explicitly adds SSH/JSON sources |
| 11 | Scrape dry-run | N/A | `authsia scrape --dry-run` | Preview only |
| 12 | Scrape high confidence | N/A | `authsia scrape --confidence high` | Higher threshold |
| 13 | Scrape non-interactive | N/A | `authsia scrape --yes` | Auto-select all |
| 14 | Scrape quiet | N/A | `authsia scrape --quiet` | Reduce output |
| 15 | List modified files (current machine) | N/A | `authsia scrape --list-modified` | Shows machine, date, and status per backup |
| 16 | List modified files (all machines) | N/A | `authsia scrape --list-modified --all-machines` | Includes backups from other machines in shared vault |
| 17 | Revert one file | `~/.zshrc` (example) | `authsia scrape --revert ~/.zshrc` | Shows origin machine + hash before restoring |
| 18 | Revert from another machine's backup | `~/.zshrc`, machine name from `--list-modified --all-machines` | `authsia scrape --revert ~/.zshrc --machine james-macbook` | Restores the most recent unrestored backup for that machine |
| 19 | Revert all files | N/A | `authsia scrape --revert-all` | Restores all backups from current machine |
| 20 | Scrape with path-based credential | `export GOOGLE_APPLICATION_CREDENTIALS=~/gcp-key.json` | `authsia scrape --path ~/.zshrc --yes` | Migrates file content, not path |
| 21 | Revert path-based credential file | `~/.zshrc` | `authsia scrape --revert ~/.zshrc` | Original export line restored |

## OTP

OTP items are created in the app UI. Use an existing OTP item (for example, GitHub).

| Step | Activity | Test Payload | Command | Notes |
|------|---------|--------------|---------|-------|
| 1 | List OTP items | OTP: GitHub | `authsia list otp --format table` | Non-secret list |
| 2 | Get OTP via get | OTP: GitHub | `authsia get otp GitHub --copy` | Copies code |
| 3 | Generate OTP | OTP: GitHub | `authsia code GitHub --format table` | Human-readable output |
| 4 | Watch OTP | OTP: GitHub | `authsia code GitHub --watch` | Runs until interrupted |

## Load Runtime Environment Variables

Use `load` to resolve vault values into environment-style key/value assignments.

| Step | Activity | Test Payload | Command | Notes |
|------|---------|--------------|---------|-------|
| 0 | Enable shell integration (one-time) | shell=zsh | `eval "$(authsia init zsh)"` | Required for `--silent` to affect active shell |
| 1 | Load one password field as shell exports | name=Demo Password | `authsia load password "Demo Password"` | Emits `export KEY='value'` lines |
| 2 | Load folder scope (nested included) | folder=Team/API | `authsia load password --folder Team/API` | Loads all matching items in folder tree |
| 3 | Load global scope by type | type=password | `authsia load password --all` | Scraped items default to current machine |
| 4 | Load global scope across machines | type=password | `authsia load password --all --all-machines` | Includes scraped items from other machines |
| 5 | Load JSON payload | name=Demo Password | `authsia load password "Demo Password" --format json` | Machine-readable output with scrape machine fields when present |
| 6 | Apply to active shell session silently | name=Demo Password | `authsia load password "Demo Password" --silent` | Uses shell integration wrapper, no payload printed |
| 7 | Reject unsupported silent/json combination | name=Demo Password | `authsia load password "Demo Password" --format json --silent` | Returns validation error |

## Exec (Scoped Secret Injection)

Use `exec` to run a single command with vault secrets injected into its environment. Secrets never
appear on stdout or in the parent shell. Secret values in subprocess output are masked with
`<concealed by authsia>` by default. Prefer `exec` over `load` when running individual commands,
especially in environments with AI coding assistants or terminal observers.

When `AUTHSIA_ACCESS_CREDENTIAL` is set, `exec` uses it for the bridge request but strips it from the
child process environment before launch. Masking is stream-aware, so secrets split across pipe reads
are still concealed before reaching stdout/stderr.

| Step | Activity | Test Payload | Command | Notes |
|------|---------|--------------|---------|-------|
| 1 | Exec single password into env | name=Demo Password | `authsia exec --type password --query "Demo Password" -- env \| grep DEMO` | Secret appears only in child's env |
| 2 | Exec all passwords into child | type=password | `authsia exec --type password --all -- env` | All CLI-enabled passwords as env vars |
| 3 | Exec folder scope | folder=Team/API | `authsia exec --type password --folder Team/API -- printenv` | Folder-scoped secrets |
| 4 | Exec with all-machines | type=password | `authsia exec --type password --all --all-machines -- env` | Includes scraped items from other machines |
| 5 | Exec certificate field | name=Demo Cert, field=privateKey | `authsia exec --type cert --query "Demo Cert" --field privateKey -- env` | Specific field only |
| 6 | Exec note content | name=Kube Config | `authsia exec --type note --query "Kube Config" -- env` | Note content as env var |
| 7 | Exec from current .env file | .env with authsia:// refs in the current directory | `authsia exec -- make deploy` | Auto-loads the current `.env` and resolves all authsia:// refs before launch, including folder-scoped refs |
| 8 | Exec from explicit .env file | env file with authsia:// refs | `authsia exec --env-file config/.env -- make deploy` | Use for env files with another name or outside the current directory |
| 9 | Verify parent shell clean | N/A | `echo $DEMO_PASSWORD` | Should be empty — secrets don't leak to parent |
| 10 | Verify credential not inherited | env=AUTHSIA_ACCESS_CREDENTIAL=<uuid> | `AUTHSIA_ACCESS_CREDENTIAL=<uuid> authsia exec --type password --query "Demo Password" -- env \| grep AUTHSIA_ACCESS_CREDENTIAL` | No output — child does not receive the automation credential |
| 11 | Reject scope flags without type | query=MyKey (no --type) | `authsia exec --query MyKey -- env` | Returns error: --type required with scope flags |
| 12 | Reject SSH type | type=ssh | `authsia exec --type ssh --all -- env` | Returns error: use the built-in Authsia SSH agent instead |
| 13 | Reject missing command | type=password | `authsia exec --type password --all` | Returns error: use `--` to separate command |

## Read (Secret Reference Resolution)

Use `authsia read` to resolve a single `authsia://` URI and print the plaintext value. Useful for
shell scripts, writing key files to disk, or piping to other tools.

URI format: `authsia://type/item[/field][?folder=path]`

| Step | Activity | URI | Command | Notes |
|------|---------|-----|---------|-------|
| 1 | Read password field | authsia://password/Demo Password/password | `authsia read "authsia://password/Demo Password/password"` | Prints raw value, no newline added |
| 2 | Read username field | authsia://password/Demo Password/username | `authsia read "authsia://password/Demo Password/username"` | Any type-valid field |
| 3 | Export inline | authsia://password/Demo Password/password | ``export API_KEY=$(authsia read "authsia://password/Demo Password/password")`` | Standard shell substitution |
| 4 | Write private key to file | authsia://cert/Demo Cert/privateKey | `authsia read "authsia://cert/Demo Cert/privateKey" --out-file key.pem` | Creates file with 0600 permissions |
| 5 | Copy OTP code | authsia://otp/GitHub/code | `authsia read "authsia://otp/GitHub/code" --copy` | Copies to clipboard |
| 6 | Read with folder scope | authsia://password/Prod-DB/password?folder=Team/Infra | `authsia read "authsia://password/Prod-DB/password?folder=Team%2FInfra"` | Lookup is restricted to the folder tree; percent-encode slashes inside query param values |
| 7 | Reject non-URI input | N/A | `authsia read "Demo Password"` | Returns error: must be authsia:// URI |

## Passwords

Manual CRUD flow:

| Step | Activity | Test Payload | Command | Notes |
|------|---------|--------------|---------|-------|
| 1 | Add password | name=Demo Password, username=demo, password=s3cret, website=https://example.com, notes=test item | `echo 's3cret' \| authsia add password --name "Demo Password" --username demo --password - --website https://example.com --notes "test item"` | Creates item; password via stdin |
| 2 | List passwords | N/A | `authsia list passwords --format table` | Non-secret list |
| 3 | Get all fields | name=Demo Password | `authsia get password "Demo Password" --field all` | Requires approval |
| 4 | Get username | name=Demo Password | `authsia get password "Demo Password" --field username` | Field only |
| 5 | Get password | name=Demo Password | `authsia get password "Demo Password" --field password --copy` | Copies secret |
| 6 | Edit password | password=n3wpw, notes=rotated | `echo 'n3wpw' \| authsia edit password "Demo Password" --password - --notes "rotated"` | Updates fields; password via stdin |
| 7 | Get updated | name=Demo Password | `authsia get password "Demo Password" --field all` | Verify update |
| 8 | Delete password | name=Demo Password | `authsia delete password "Demo Password" --force` | Removes item |
| 9 | List after delete | N/A | `authsia list passwords` | Verify removal |

Scrape-based create flow:

| Step | Activity | Test Payload | Command | Notes |
|------|---------|--------------|---------|-------|
| 10 | Prepare .env for scrape | key=SCRAPED_PASSWORD, value=ScrapeS3cret123 | `printf 'SCRAPED_PASSWORD=ScrapeS3cret123\n' > ~/fixtures/authsia-scrape.env` | Creates test file |
| 11 | Scrape file | path=~/fixtures/authsia-scrape.env | `authsia scrape --path ~/fixtures/authsia-scrape.env --yes` | Creates a scraped password |
| 12 | List scraped | N/A | `authsia list passwords --format table` | Scraped should show yes and `Machine` |
| 13 | Get scraped password | name=SCRAPED_PASSWORD | `authsia get password SCRAPED_PASSWORD --field password` | Verify retrieval |
| 14 | Delete scraped password | name=SCRAPED_PASSWORD | `authsia delete password SCRAPED_PASSWORD --force` | Cleanup |
| 15 | List after delete | N/A | `authsia list passwords` | Verify removal |

## Certificates

| Step | Activity | Test Payload | Command | Notes |
|------|---------|--------------|---------|-------|
| 1 | Generate test certs | output=~/fixtures/demo-cert.pem, ~/fixtures/demo-key.pem | `openssl req -x509 -newkey rsa:2048 -keyout ~/fixtures/demo-key.pem -out ~/fixtures/demo-cert.pem -days 365 -nodes -subj "/CN=Authsia Demo"` | Creates a self-signed cert |
| 2 | Add certificate | name=Demo Cert, cert=demo-cert.pem, key=demo-key.pem | `authsia add cert --name "Demo Cert" --cert-file ~/fixtures/demo-cert.pem --key-file ~/fixtures/demo-key.pem --notes "test cert"` | Creates item |
| 3 | List certificates | N/A | `authsia list certs --format table` | Non-secret list |
| 4 | Get certificate | name=Demo Cert | `authsia get cert "Demo Cert" --field certificate` | Certificate only |
| 5 | Get private key | name=Demo Cert | `authsia get cert "Demo Cert" --field privateKey` | Private key only |
| 6 | Edit certificate | notes=updated notes | `authsia edit cert "Demo Cert" --notes "updated notes"` | Updates metadata |
| 7 | Get updated | name=Demo Cert | `authsia get cert "Demo Cert" --field all` | Verify update |
| 8 | Delete certificate | name=Demo Cert | `authsia delete cert "Demo Cert" --force` | Removes item |
| 9 | List after delete | N/A | `authsia list certs` | Verify removal |
| 10 | Prepare cert/key for scrape | cert=demo-cert.pem, key=demo-key.pem | `mkdir -p ~/fixtures/scrape-certs && cp ~/fixtures/demo-cert.pem ~/fixtures/scrape-certs/scraped.pem && cp ~/fixtures/demo-key.pem ~/fixtures/scrape-certs/scraped.key` | Matching basenames are combined |
| 11 | Scrape certificate directory | path=~/fixtures/scrape-certs | `authsia scrape --path ~/fixtures/scrape-certs --yes` | Creates scraped certificate items; duplicate basenames use relative-path names |
| 12 | List scraped certificates | N/A | `authsia list certs --format table` | Scraped should show yes and `Machine` |
| 13 | Get scraped certificate | name=scraped | `authsia get cert scraped --field certificate` | Certificate or bundle only |
| 14 | Get scraped private key | name=scraped | `authsia get cert scraped --field privateKey` | Private key only |
| 15 | Delete scraped certificate | name=scraped | `authsia delete cert scraped --force` | Cleanup |

## Notes & JSON Credentials

Notes are used for free-form secure text and JSON credentials. JSON content is preserved exactly as
provided; the CLI does not interpret or extract fields.

Manual CRUD flow:

| Step | Activity | Test Payload | Command | Notes |
|------|---------|--------------|---------|-------|
| 1 | Prepare JSON file | file=~/fixtures/kube-config.json | `printf '{\"kind\":\"Config\",\"apiVersion\":\"v1\"}\n' > ~/fixtures/kube-config.json` | Creates JSON payload |
| 2 | Add note from file | title=Kube Config, content=~/fixtures/kube-config.json | `authsia add note --title "Kube Config" --content-file ~/fixtures/kube-config.json` | JSON credential |
| 3 | List notes | N/A | `authsia list notes --format table` | Non-secret list |
| 4 | Get content | title=Kube Config | `authsia get note "Kube Config" --field content` | Raw JSON content |
| 5 | Edit title | title=Kube Config (Prod) | `authsia edit note "Kube Config" --title "Kube Config (Prod)"` | Rename |
| 6 | Edit content (inline) | content={"kind":"Config","apiVersion":"v1","env":"prod"} | `echo '{\"kind\":\"Config\",\"apiVersion\":\"v1\",\"env\":\"prod\"}' \| authsia edit note "Kube Config (Prod)" --content -` | Content via stdin |
| 7 | Get updated | title=Kube Config (Prod) | `authsia get note "Kube Config (Prod)" --field content` | Verify update |
| 8 | Delete note | title=Kube Config (Prod) | `authsia delete note "Kube Config (Prod)" --force` | Removes item |
| 9 | List after delete | N/A | `authsia list notes` | Verify removal |

Scrape-based create flow:

| Step | Activity | Test Payload | Command | Notes |
|------|---------|--------------|---------|-------|
| 10 | Prepare JSON for scrape | file=~/fixtures/scraped-kube.json | `printf '{\"clusters\":[]}\n' > ~/fixtures/scraped-kube.json` | Creates JSON payload |
| 11 | Scrape file | path=~/fixtures/scraped-kube.json | `authsia scrape --path ~/fixtures/scraped-kube.json --yes` | Creates a scraped note |
| 12 | List scraped | N/A | `authsia list notes --format table` | Scraped should show yes and `Machine` |
| 13 | Get scraped note | title=scraped_kube | `authsia get note scraped_kube --field content` | Title derives from filename |
| 14 | Delete scraped note | title=scraped_kube | `authsia delete note scraped_kube --force` | Cleanup |
| 15 | List after delete | N/A | `authsia list notes` | Verify removal |

## SSH Keys

SSH keys are first-class items with their own list/get/add/edit/delete commands. Normal Git and SSH usage
goes through Authsia's built-in SSH agent at `~/.authsia/agent.sock`; `authsia load ssh --system-agent`
is only a compatibility path for eligible keys and must include a TTL.

Manual CRUD flow:

| Step | Activity | Test Payload | Command | Notes |
|------|---------|--------------|---------|-------|
| 1 | Generate SSH keypair | output=~/fixtures/id_ed25519_authsia | `ssh-keygen -t ed25519 -f ~/fixtures/id_ed25519_authsia -N "" -C "laptop"` | Creates key files |
| 2 | Read fingerprint | pub=~/fixtures/id_ed25519_authsia.pub | `ssh-keygen -lf ~/fixtures/id_ed25519_authsia.pub` | Use the SHA256 value |
| 3 | Add SSH key | name=Work SSH, comment=laptop, fingerprint=SHA256:REPLACE_ME | `authsia add ssh --name "Work SSH" --public-key ~/fixtures/id_ed25519_authsia.pub --private-key ~/fixtures/id_ed25519_authsia --comment laptop --fingerprint SHA256:REPLACE_ME` | Replace fingerprint |
| 4 | List SSH keys | N/A | `authsia list ssh --format table` | Includes public key + fingerprint |
| 5 | Get fingerprint | name=Work SSH | `authsia get ssh "Work SSH" --field fingerprint` | Field only |
| 6 | Get public key | name=Work SSH | `authsia get ssh "Work SSH" --field publicKey` | Field only |
| 7 | Get private key | name=Work SSH | `authsia get ssh "Work SSH" --field privateKey` | Secret field |
| 8 | Edit comment | comment=laptop-2026 | `authsia edit ssh "Work SSH" --comment "laptop-2026"` | Updates metadata |
| 9 | Edit fingerprint | fingerprint=SHA256:UPDATED | `authsia edit ssh "Work SSH" --fingerprint SHA256:UPDATED` | Optional metadata update |
| 10 | Get updated | name=Work SSH | `authsia get ssh "Work SSH" --field all` | Verify update |
| 11 | Delete SSH key | name=Work SSH | `authsia delete ssh "Work SSH" --force` | Removes item |
| 12 | List after delete | N/A | `authsia list ssh` | Verify removal |
| 13 | Verify built-in agent | N/A | `SSH_AUTH_SOCK="$HOME/.authsia/agent.sock" ssh-add -L` | Lists vault SSH public keys when Authsia is running |
| 14 | Verify Git over built-in agent | repo=origin | `SSH_AUTH_SOCK="$HOME/.authsia/agent.sock" git ls-remote --heads origin` | Should prompt through Authsia when policy requires approval |

Adoption-based create flow:

| Step | Activity | Test Payload | Command | Notes |
|------|---------|--------------|---------|-------|
| 15 | Preview SSH key adoption | path=~/fixtures/id_ed25519_authsia; `.pub` optional for unencrypted keys | `authsia ssh adopt --path ~/fixtures/id_ed25519_authsia --dry-run` | Uses matching `.pub` metadata when present or derives public key metadata from the private key |
| 16 | Adopt SSH key file | path=~/fixtures/id_ed25519_authsia | `authsia ssh adopt --path ~/fixtures/id_ed25519_authsia --yes` | Creates an adopted SSH item, then writes an Authsia stub without duplicating the private key in a backup note |
| 17 | List adopted | N/A | `authsia list ssh --format table` | Adopted should show yes and `Machine` |
| 18 | Get adopted fingerprint | name=id_ed25519_authsia | `authsia get ssh id_ed25519_authsia --field fingerprint` | Name derives from filename |
| 19 | Delete adopted SSH key | name=id_ed25519_authsia | `authsia delete ssh id_ed25519_authsia --force` | Cleanup |
| 20 | List after delete | N/A | `authsia list ssh` | Verify removal |

## Inject (Template Secret Injection)

Use `authsia inject` to resolve all `authsia://` references in a template file and write the result
with secrets filled in. Output contains plaintext — do not commit.

| Step | Activity | Test Payload | Command | Notes |
|------|---------|--------------|---------|-------|
| 1 | Inject from stdin | template with authsia:// refs | `echo 'API_KEY=authsia://password/Demo Password/password' \| authsia inject` | Prints resolved template to stdout |
| 2 | Inject from file | --in-file template.yaml | `authsia inject --in-file config.template.yaml --out-file config.yaml` | Writes to file with 0600 permissions |
| 3 | Inject passthrough | template without refs | `echo 'PORT=8080' \| authsia inject` | Passes through unchanged |
| 4 | Inject multiple refs | N/A | `printf 'A=authsia://password/Demo Password/password\nB=authsia://password/Demo Password/username\n' \| authsia inject` | Resolves multiple URIs |
| 5 | Inject folder-scoped ref | authsia://password/Prod-DB/password?folder=Team/Infra | `echo 'DB=authsia://password/Prod-DB/password?folder=Team%2FInfra' \| authsia inject` | Folder scope is enforced before resolving the item |
| 6 | Inject error collection | missing refs | `echo 'X=authsia://password/Missing/password' \| authsia inject` | Shows all resolution errors |

## Access (Automation Credentials)

Manage scoped, time-limited automation credentials for non-interactive CLI usage (CI/CD pipelines,
scripts).

| Step | Activity | Test Payload | Command | Notes |
|------|---------|--------------|---------|-------|
| 1 | Create all-scope credential (exec-only) | name=ci-deploy, ttl=2h, allow=exec | `authsia access create --name ci-deploy --ttl 2h --allow exec` | Prints credential UUID and `export AUTHSIA_ACCESS_CREDENTIAL=...`; omitted `--scope` applies to all CLI-enabled non-OTP items |
| 2 | Create scoped multi-capability credential | scope=CI, allow=exec,load | `authsia access create --name ci-shell --scope CI --ttl 2h --allow exec,load` | Credential can run both `exec` and `load` inside `CI`; non-SSH credentials print only `AUTHSIA_ACCESS_CREDENTIAL` |
| 3 | Missing `--allow` rejected | no --allow flag | `authsia access create --name x --scope CI --ttl 2h` | Exit non-zero, error about required `--allow` |
| 4 | Unknown capability rejected | allow=bogus | `authsia access create --name x --scope CI --ttl 2h --allow bogus` | Exit non-zero, error lists valid capabilities |
| 5 | Empty/comma-only `--allow` rejected | allow="" or allow="," | `authsia access create --name x --scope CI --ttl 2h --allow ""` | Exit non-zero, "must include at least one capability" |
| 6 | Create SSH-only credential | allow=ssh | `authsia access create --name agent --ttl 15m --allow ssh` | Prints only `export AUTHSIA_SSH_ACCESS_CREDENTIAL=...` |
| 7 | List credentials (table) | N/A | `authsia access list --format table` | Shows ID, name, scope, status, expires, allowed commands |
| 8 | List JSON | N/A | `authsia access list --format json` | Machine-readable output includes `allowedCommands` array |
| 9 | List all (include expired) | N/A | `authsia access list --all` | Includes expired and revoked |
| 10 | Use credential — `exec` allowed | env=AUTHSIA_ACCESS_CREDENTIAL=<exec-only uuid> | `AUTHSIA_ACCESS_CREDENTIAL=<uuid> authsia exec --type password --query API_KEY -- env` | Child process receives loaded vault values, not the automation credential |
| 11 | List with exec credential | env=AUTHSIA_ACCESS_CREDENTIAL=<exec-only uuid> | `AUTHSIA_ACCESS_CREDENTIAL=<uuid> authsia list passwords --format table` | Non-secret list is scope-filtered for the credential |
| 12 | Credential not inherited | env=AUTHSIA_ACCESS_CREDENTIAL=<exec-only uuid> | `AUTHSIA_ACCESS_CREDENTIAL=<uuid> authsia exec --type password --query API_KEY -- env \| grep AUTHSIA_ACCESS_CREDENTIAL` | No output |
| 13 | `get` denied under exec-only | env=AUTHSIA_ACCESS_CREDENTIAL=<exec-only uuid> | `AUTHSIA_ACCESS_CREDENTIAL=<uuid> authsia get password API_KEY` | Error: "does not permit 'get'" |
| 14 | `load` denied under exec-only | same | `AUTHSIA_ACCESS_CREDENTIAL=<uuid> authsia load password --query API_KEY` | Error: "does not permit 'load'" |
| 15 | `read` denied under exec-only | same | `AUTHSIA_ACCESS_CREDENTIAL=<uuid> authsia read "authsia://password/API_KEY/password"` | Error: "does not permit 'read'" |
| 16 | `inject` denied under exec-only | same | `echo 'X=authsia://password/API_KEY/password' \| AUTHSIA_ACCESS_CREDENTIAL=<uuid> authsia inject` | Error: "does not permit 'inject'" |
| 17 | OTP denied | env=AUTHSIA_ACCESS_CREDENTIAL=<uuid> | `AUTHSIA_ACCESS_CREDENTIAL=<uuid> authsia get otp GitHub` | Error: OTP not allowed |
| 18 | OTP export unavailable in CLI | N/A | N/A | Export is not a CLI command; use the app UI |
| 19 | Revoke credential | id=<uuid> | `authsia access revoke <uuid>` | Credential is revoked |
| 20 | Verify revoked | env=AUTHSIA_ACCESS_CREDENTIAL=<uuid> | `AUTHSIA_ACCESS_CREDENTIAL=<uuid> authsia exec --type password --query X -- true` | Error: credential revoked |

## Agent Rule Setup

Create local project rules for coding agents. These commands do not create automation credentials or
grant secret access.

| Step | Activity | Test Payload | Command | Notes |
|------|---------|--------------|---------|-------|
| 1 | Claude Code rules | N/A | `authsia agent init --agent claude-code` | Creates `.authsia/agent-rules.md`, `CLAUDE.md`, and `.claude/settings.local.json` if absent |
| 2 | Compatible existing Claude settings | parseable `.claude/settings.local.json` with custom content and compatible or absent/`null` containers | `authsia agent init --agent claude-code` | Structurally adds every exact Authsia hook and the SSH-agent socket value, removes legacy Authsia Mach lookup values, and preserves custom content; absent and `null` containers are safe empty containers |
| 3 | Repeat Claude setup | settings produced or merged by step 1 or 2 | `authsia agent init --agent claude-code` | Idempotent: reports the settings unchanged and does not duplicate hooks or network values |
| 4 | Incompatible Claude settings | parseable JSON with an incompatible non-null hooks, sandbox, network, or value shape | `authsia agent init --agent claude-code` | Leaves the file byte-identical and prints manual merge guidance |
| 5 | Codex rules | N/A | `authsia agent init --agent codex` | Creates or updates `.authsia/agent-rules.md` and `AGENTS.md`; Codex rule prompts before outside-sandbox `authsia` commands |
| 6 | Cursor rules | N/A | `authsia agent init --agent cursor` | Creates `.cursor/rules/authsia.mdc` |
| 7 | Windsurf rules | N/A | `authsia agent init --agent windsurf` | Creates `.windsurf/rules/authsia.md` |
| 8 | Copilot rules | N/A | `authsia agent init --agent copilot` | Creates or updates `.authsia/agent-rules.md` and `AGENTS.md`; creates `.github/copilot/settings.local.json` when absent, otherwise leaves it unchanged with manual merge guidance |
| 9 | All agents | N/A | `authsia agent init --all --dry-run` | Prints planned changes without writing files |

Claude settings removal is structural whether invoked by agent removal,
uninstall, or workspace reset. A structurally generated-only settings file is
deleted. A merged file keeps custom content while removing every exact Authsia
hook, exact `~/.authsia/agent.sock` network value, and legacy `Authsia.Bridge`
and `Authsia.SSHAgent` Mach lookup values across duplicate entries and matchers. If
the shape cannot be removed safely, Authsia leaves the file unchanged and
prints manual cleanup guidance. A custom-only file is a byte-identical no-op.

## Workspace

Initialize a repo-local workspace, then run daily terminal or agent commands through managed env
files and existing `exec` behavior.

Successful workspace setup, update, status, reset, and env-binding changes also
record the local repo root in a non-secret known-roots file shared with the
macOS app. This lets CLI-created workspaces appear in the Workspace sidebar and
menu bar on refresh without storing secrets or scanning the disk.

Run the applied reset variants below with independent initialized-workspace
fixtures, because each successful reset removes the workspace configuration.

| Step | Activity | Test Payload | Command | Notes |
|------|---------|--------------|---------|-------|
| 1 | Preview workspace setup | repo with `.env` | `authsia workspace init --dry-run` | Shows repo folder, env files, and redacted detected secrets without writing |
| 1a | Preview setup JSON without vault approval | repo with `.env` | `authsia workspace init --plan-json --local-preview` | Emits sanitized local-only JSON and skips live vault conflict checks so native app preview cannot block on bridge approval |
| 2 | Non-interactive explicit env setup | file=.env | `authsia workspace init --yes --env-file .env --agent codex` | Requires explicit env file; writes `.authsia/workspace.json`; skips same-name existing item conflicts |
| 3 | Preview monorepo env discovery | repo with `apps/api/.env` | `authsia workspace init --dry-run` | Auto-discovers root env files and env files up to three directories deep while pruning generated/cache folders |
| 4 | Preview workspace update | file=.env.local | `authsia workspace update --dry-run --env-file .env.local` | Re-scans configured env files plus the explicit file and shows existing-item conflicts or missing-vault guidance |
| 4a | Preview update JSON without vault approval | file=.env.local | `authsia workspace update --plan-json --local-preview --env-file .env.local` | Emits sanitized local-only JSON and skips live vault conflict checks for non-blocking app preview |
| 5 | Apply explicit update | file=.env.local | `authsia workspace update --yes --env-file .env.local` | Applies high-confidence non-conflicting rewrites for the explicit file and preserves existing config choices |
| 6 | Run command from workspace | command=npm test | `authsia workspace run -- npm test` | Preflights exact active refs through scoped metadata, then delegates secret-bearing runs to `authsia exec` |
| 7 | Add one-off env file | file=.env.production | `authsia workspace run --env-file .env.production -- npm run deploy` | Adds the extra file and its exact workspace-scoped refs for this run only |
| 8 | Add workspace env binding | ref=API_KEY | `authsia workspace env add API_KEY 'authsia://password/API_KEY/password?folder=Workspaces%2Fapi'` | Stores a commit-safe env ref in `.authsia/workspace.json` without requiring a managed `.env` file |
| 9 | Validate env bindings | N/A | `authsia workspace env validate` | Checks exact workspace-scoped env refs without listing or returning vault values; unavailable scoped metadata is unverified, not missing |
| 10 | Run dry-run | N/A | `authsia workspace run --dry-run -- npm test` | Shows env files, env binding names, and command without launching |
| 11 | Preview reset | N/A | `authsia workspace reset --dry-run` | Shows managed env restore plus config/rule cleanup without writing |
| 12 | Reset generated-only Claude settings | structurally generated-only `.claude/settings.local.json` | `authsia workspace reset` | Requires confirmation and deletes the generated-only settings file with the other Authsia-managed workspace artifacts |
| 13 | Reset merged Claude settings | custom settings plus exact Authsia hooks/network values, including duplicates or repeated matchers | `authsia workspace reset` | Removes every exact Authsia hook/network value and preserves custom content |
| 14 | Reset unsafe or custom-only Claude settings | incompatible non-null shape, then a custom-only file | `authsia workspace reset` | Unsafe removal leaves the file unchanged with manual guidance; custom-only cleanup is byte-identical and unchanged |
| 15 | Status table | N/A | `authsia workspace status` | Shows Authsia folder, managed files, ref counts, agent rule state, and missing-vault guidance |
| 16 | Status JSON | N/A | `authsia workspace status --format json` | Machine-readable workspace status |

## Environment Profiles

Named folder-path mappings for quick scope switching.

| Step | Activity | Test Payload | Command | Notes |
|------|---------|--------------|---------|-------|
| 1 | Add profile | name=prod, folder=Production | `authsia env add --name prod --folder Production` | Creates profile |
| 2 | Add profile | name=staging, folder=Staging | `authsia env add --name staging --folder Staging` | Another profile |
| 3 | List profiles | N/A | `authsia env list --format table` | Shows name, folder, active status |
| 4 | Set active | name=prod | `authsia env use prod` | Sets prod as active |
| 5 | List JSON | N/A | `authsia env list --format json` | Machine-readable, check isActive field |

## SSH Tooling

Generate SSH keys, configure SSH config entries, set up Git SSH signing.

| Step | Activity | Test Payload | Command | Notes |
|------|---------|--------------|---------|-------|
| 1 | Generate keypair | name=test-key | `authsia ssh generate --name test-key --path ~/fixtures` | Creates ed25519 keypair with no passphrase |
| 2 | Verify permissions | N/A | `ls -la ~/fixtures/test-key` | Should be -rw------- (0600) |
| 3 | Refuse overwrite | name=test-key | `authsia ssh generate --name test-key --path ~/fixtures` | Returns error: refuses to overwrite |
| 4 | Configure SSH host | host=github.com, key=test-key | `authsia ssh config --host github.com --key test-key` | Upserts ~/.ssh/config entry |
| 5 | Configure with alias | host=github.com, alias=gh-work | `authsia ssh config --host github.com --alias gh-work --key test-key --user git` | Creates aliased entry |
| 6 | Idempotent config | same as step 4 | `authsia ssh config --host github.com --key test-key` | Updates without duplicating |
| 7 | Git signing setup | principal, public key | `authsia ssh git-signing --principal user@example.com --public-key ~/fixtures/test-key.pub --repo ~/fixtures/test-repo` | Creates .git/config + allowed_signers |
| 8 | Cleanup | N/A | `rm -f ~/fixtures/test-key ~/fixtures/test-key.pub` | Remove test keys |

## Status, Setup & Doctor

System health commands.

| Step | Activity | Test Payload | Command | Notes |
|------|---------|--------------|---------|-------|
| 1 | Status table | N/A | `authsia status` | Shows bridge, session, shell, SSH status |
| 2 | Status JSON | N/A | `authsia status --format json` | Machine-readable status |
| 3 | Setup status | N/A | `authsia setup --status` | Shows first-run readiness checklist without changing files |
| 4 | Repair shell integration | N/A | `authsia setup --repair` | Reinstalls Authsia-managed shell integration, then prints status |
| 5 | Cleanup managed setup | N/A | `authsia setup --uninstall-clean` | Removes only Authsia-managed shell integration blocks and user symlink |
| 6 | Doctor | N/A | `authsia doctor` | Lists issues with suggested fixes |
| 7 | Inspect bridge LaunchAgent | N/A | `launchctl print "gui/$(id -u)/Authsia.Bridge"` | Should show `program = /Applications/Authsia.app/Contents/Helpers/AuthsiaHeadless.app/Contents/MacOS/authsia-headless` when loaded |
| 8 | Verify installed app signature | N/A | `codesign --verify --verbose=4 /Applications/Authsia.app` | Confirms the app bundle and bundled CLI helper verify on disk |
| 9 | Recheck password metadata after app refresh | folder=Authsia | `authsia list passwords --format table --all-machines` | If empty while the app UI has rows, verify `authsia status`, relaunch Authsia once, then retry |
| 10 | Verify folder load without printing secrets | folder=Authsia | `authsia load password --folder Authsia >/dev/null` | Exit 0 confirms metadata lookup and Keychain retrieval without exposing values |

## Audit (Enhanced)

Audit event viewing and export.

| Step | Activity | Test Payload | Command | Notes |
|------|---------|--------------|---------|-------|
| 1 | List audit events | N/A | `authsia audit list --format table` | Table with timestamp, command, item, caller, optional agent attribution; newest event at bottom |
| 2 | List JSON | N/A | `authsia audit list --format json` | Structured event data in display order |
| 3 | List filtered | type=getPassword | `authsia audit list --type getPassword --limit 10` | Filtered results in display order |
| 4 | Export JSON | output=audit.json | `authsia audit export --format json --out audit.json` | JSON array export |
| 5 | Export NDJSON | output=audit.ndjson | `authsia audit export --format ndjson --out audit.ndjson` | Newline-delimited JSON |

## Shell Completions

| Step | Activity | Test Payload | Command | Notes |
|------|---------|--------------|---------|-------|
| 1 | Zsh completions | shell=zsh | `authsia completion zsh` | Outputs zsh completion script |
| 2 | Bash completions | shell=bash | `authsia completion bash` | Outputs bash completion script |
| 3 | Fish completions | shell=fish | `authsia completion fish` | Outputs fish completion script |
| 4 | Install zsh | N/A | `eval "$(authsia completion zsh)"` | Activates completions in current shell |
| 5 | Item metadata | existing vault list metadata | `authsia get password <TAB>` | Suggests CLI-enabled item names with type/folder metadata, never secret values |
