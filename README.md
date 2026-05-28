# Gitleaks Cloud - GitHub API Key Hunter & Secret Scanner

Cloud-hosted [gitleaks](https://github.com/gitleaks/gitleaks) (18.7k★) for hunting leaked API keys, wallet private keys, and credentials anywhere on GitHub - including **full git history**, **PR branches**, and **dangling commits**.

40 hand-tuned detectors (Razorpay, Stripe, AWS, OpenAI, Anthropic, EVM/Ethereum/Tron private keys, BIP39 mnemonics, Cashfree, PayU, Surepass, Decentro, Karza/Perfios, Attestr, Tartan + 25 more). Smart key+secret pairing for vendors that need both. Three search modes: known platform, keyword (auto-expanded variants), or custom regex.

Available as an [Apify Actor](https://apify.com/anshumanatrey/gitleaks-github-secret-scanner) - no install, no CLI, runs in cloud, flat JSON output. $0.01 + $0.02 per repo scanned.

## What's different vs running gitleaks locally

| | Local gitleaks CLI | This actor |
|---|---|---|
| Setup | Install Go + binary + write TOML | None - paste a JSON input |
| Scope | One repo at a time | All of GitHub (Code Search), a user/org, or a single repo |
| Pairing | None - flat findings | Pairs key_id with key_secret in same file (Razorpay, AWS, Twilio, PayU, Decentro, Cashfree, Stripe, Clerk) |
| PR refs | Default-branch only | Default + `refs/pull/*/head` automatically |
| All branches | Default-branch only | `--no-single-branch` by default |
| Dangling commits | Manual `git fsck` | Built-in opt-in scan |
| Filters | gitleaks doesn't expose `git log -S`, `--since`, `--author` | All exposed via advanced inputs |
| Parallel scanning | Sequential | 4 repos concurrently |
| Cost | Your compute time | $0.01 + $0.02/repo |

## Three search modes

| Mode | When to use | Input |
|---|---|---|
| **Platform** | Hunting keys for a known service (40 supported) | Pick from dropdown |
| **Keyword** | Service we don't have a hand-tuned rule for | Type the word - actor auto-expands variants (UPPER, snake_case, camelCase, dot-notation) |
| **Custom regex** | Power user with a specific pattern | Paste regex - applied across all of GitHub |

## Supported services (40)

| Category | Services |
|---|---|
| **India fintech / payments** | razorpay, payu, cashfree, decentro |
| **India KYC / verification** | surepass, karza/perfios, attestr, tartan |
| **Global payments** | stripe, aws |
| **AI APIs** | openai, anthropic, groq, gemini |
| **Auth / SaaS** | clerk, supabase, firebase, sendgrid, mailgun, postmark, twilio |
| **DevOps / messaging** | slack-bot, slack-webhook, discord-bot, datadog, pagerduty, github-pat |
| **Databases** | mongodb-uri, postgres-uri, redis-uri |
| **Cloud** | gcp-api-key, gcp-service-account |
| **Scraping / agents** | firecrawl, trigger-dev |
| **Crypto wallets** | evm-private-key (Ethereum/Polygon/BSC/Tron), solana-private-key, bitcoin-private-key, bip39-mnemonic |
| **Generic** | jwt-generic, rsa-private-key, custom |

## Inputs (all optional except `search_for` + `scope`)

### Core

| Field | What it does |
|---|---|
| `search_for` | `platform` / `keyword` / `regex` - determines which detector type runs |
| `platform` | Dropdown of 40 services (when `search_for=platform`) |
| `platform_custom` | Free-text service name (when `platform=custom`) |
| `additional_platforms` | Multi-select - scan multiple services in one run |
| `keyword` | One word; actor auto-generates UPPER, snake_case, camelCase variants |
| `regex_pattern` | Your own regex (power-user mode) |
| `scope` | `all_github` / `user_or_org` / `single_repo` |
| `target` | Username / org / repo URL (when scope is not `all_github`) |
| `github_pat` | Recommended - enables Code Search precision + private repos. Generate at [github.com/settings/tokens](https://github.com/settings/tokens) |
| `max_results` | Cap on unique repos scanned (1–1000, default 100) |

### Advanced - scan depth & filters (all default sensible)

| Field | Default | What it does |
|---|---|---|
| `include_pr_refs` | **on** | Fetches `refs/pull/*/head` after clone - catches PR-squashed secrets |
| `include_all_branches` | **on** | `git clone --no-single-branch` - scans every branch |
| `include_submodules` | off | `--recurse-submodules` - submodules can hide nested `.env` files |
| `include_dangling_objects` | off | `git fsck --dangling` - catches rebased-away history |
| `commit_since` / `commit_until` | - | Date-range filter on commits (not repos) |
| `commit_author` | - | Author regex (e.g. `.*@example\.com`) |
| `commit_message_grep` | - | Message regex (e.g. `wip\|temp\|hack` to find sloppy commits) |
| `commit_introduced_string` | - | Pickaxe `-S` - find only commits that *introduced* a specific string. Massive speedup. |
| `max_file_size_mb` | 100 | Skip huge binaries |
| `pushed_after` / `pushed_before` | - | Date filter on repo discovery (not commits) |
| `language` | - | GitHub language filter |
| `min_stars` / `max_stars` | - | Star count filter. The "goldmine combo": `max_stars=5 + pushed_before=2yr ago` → forgotten amateur repos with unrotated keys |
| `include_extensions` | all | Whitelist of file extensions (e.g. `.env`, `.yml`) |
| `include_test_keys` | on | Keep public-by-design test keys (`rzp_test_*`, `sk_test_*`). Uncheck to filter |

## Output (one record per finding)

```json
{
  "repo_url":      "https://github.com/owner/repo",
  "file":          "backend/.env",
  "line":          15,
  "permalink":     "https://github.com/owner/repo/blob/<sha>/backend/.env#L15",
  "secret_name":   "razorpay-key-secret",
  "secret_value":  "<the actual leaked value>",
  "paired":        "yes",
  "paired_with": {
    "name":  "razorpay-key-id",
    "value": "rzp_live_xxxxxxxxxxxxxx",
    "line":  14
  },
  "platform":      "razorpay",
  "branch_ref":    "history",
  "is_dangling":   false,
  "rule_id":       "razorpay-key-secret",
  "commit_sha":    "26983d72...",
  "is_test_key":   false,
  "author_name":   "alice",
  "author_email":  "alice@example.com",
  "commit_date":   "2025-06-12T10:23:14Z"
}
```

`branch_ref` tells you where in history the leak lives: `"history"` (any reachable ref), `"dangling"` (orphaned commit found via `git fsck`), or a PR ref. `is_dangling` is the same signal as a boolean.

## Pricing

Pay-per-event, deterministic:
- **$0.01** per actor start
- **$0.02** per repo successfully scanned

Typical 50-repo scan: $1.01.

## Engine architecture

```
                ┌─────────────────────────┐
  Input  ───►   │  1. Discover repos      │
                │     • PAT + all_github  → GitHub Code Search (precision)
                │     • no PAT            → GitHub repo search (broad)
                │     • user_or_org       → list owner's repos
                │     • single_repo       → 1 repo
                └────────────┬────────────┘
                             ▼
                ┌─────────────────────────┐
                │  2. Clone in parallel   │   (4 concurrent)
                │     --no-single-branch  │
                │     fetch PR refs       │
                └────────────┬────────────┘
                             ▼
                ┌─────────────────────────┐
                │  3. gitleaks history    │
                │     --log-opts pass-thru│
                │     (date / author /    │
                │      grep / pickaxe)    │
                └────────────┬────────────┘
                             ▼
                ┌─────────────────────────┐
                │  4. Pair id + secret    │
                │     (paired services)   │
                └────────────┬────────────┘
                             ▼
                       Dataset records
```

Code Search (when a PAT is provided) is the *precision repo selector*, not the finder - it returns unique repos that actually contain the pattern, then we clone+scan their full history. Cloning is the cost-driving step (gates the per-repo charge). Code Search calls are free preprocessing.

## Ethical use

This tool is for **authorized security testing only** - auditing repos you own, organizations you work for, or bug bounty programs that explicitly permit source code review.

Findings should be reported through responsible disclosure channels (the leaking developer's email, the vendor's security@ address, or a bug-bounty program). Using leaked credentials without owner authorization is illegal in most jurisdictions.

This actor only fetches public GitHub content (the same content any logged-in GitHub user could see). Private repos are scanned only if your PAT explicitly grants access.

## Detection internals

Each service has a hand-written TOML in `rules/<service>.toml` declaring:
- Regex patterns for `id` and/or `secret` components
- Test-key patterns (intentionally-public values to label-but-skip)
- Per-rule allowlists (skip placeholder values like `XXXX`, docs/vendor dirs like `node_modules/`)
- New in v0.12: `secret_regexes` allowlists evaluate against the CAPTURED secret (not the full match) - used to reject obvious code identifiers like `clientIDController` or `payUMode`

A 40-fixture test suite runs every rule against planted-leak repos before each ship. Pairing logic is unit-tested separately. 64/64 tests must pass to ship.

## How it stacks against alternatives

- **TruffleHog** (single-repo CLI): great detector library, slow (~15s/repo), no PR-branch coverage. We're 4× faster via parallelism and 100× broader (all of GitHub, not just one repo).
- **GitGuardian** / **DataDog Code Security**: solid products at $5,000+/year enterprise pricing. We're $1 per scan.
- **gitleaks** alone: catches secrets but doesn't pair id+secret, doesn't auto-expand keyword variants, doesn't fetch PR refs by default.

## Run locally for development

```bash
# Install gitleaks 8.30.1+
brew install gitleaks   # or download release from gitleaks/gitleaks

# Install Python deps
pip install -r requirements.txt

# Run the 64-test suite
python3 tests/test_each_service.py
python3 tests/test_new_modes.py

# Run main flow with a local input
cat > storage/key_value_stores/default/INPUT.json <<EOF
{
  "search_for": "platform",
  "platform": "razorpay",
  "scope": "single_repo",
  "target": "https://github.com/some/repo",
  "max_results": 1
}
EOF
python3 -m src.main
```

Findings land in `storage/datasets/default/`.

## Other Apify actors in the OSINT/security family

- [holehe-email-osint](https://github.com/AnshumanAtrey/holehe-email-osint) - find accounts registered to an email across 100+ sites
- [phoneinfoga-phone-osint](https://github.com/AnshumanAtrey/phoneinfoga-phone-osint) - phone number OSINT
- [theharvester-osint](https://github.com/AnshumanAtrey/theharvester-osint) - emails / subdomains / hosts via public sources
- [social-analyzer](https://github.com/AnshumanAtrey/social-analyzer) - username across 300+ social platforms
- [nmap-scanner](https://github.com/AnshumanAtrey/nmap-scanner) - Nmap port scanner
- [netintel](https://github.com/AnshumanAtrey/netintel) - DNS / WHOIS / IP geo / port scan / SSL / tech stack
- [instagram-profile-intel-no-login](https://github.com/AnshumanAtrey/instagram-profile-intel-no-login) - Instagram profile intel without login
- [bug-bounty-finder](https://github.com/AnshumanAtrey/bug-bounty-finder) - search programs across HackerOne, Bugcrowd, Intigriti

## License

MIT. See [LICENSE](LICENSE).
