# LowHangingFruits Burp Grabber

A Burp Suite extension for passively detecting secrets, endpoints, URLs, files, emails, and security misconfigurations in HTTP responses. Designed for security analysts and penetration testers.

## Features

### Passive Analysis
- Automatically analyzes HTTP responses without modifying traffic
- Smart filtering: only analyzes `.js`, `.json`, `.map` files, JavaScript/JSON content types, and HTML with `<script>` tags
- O(1) duplicate detection using set-based lookups
- Pre-compiled noise filters for fast matching

### Detection Categories
- **Endpoints** — API routes, admin panels, debug tools, Elasticsearch paths, Spring Actuator, etc.
- **URLs** — Full URLs with protocol detection (HTTP, WS, FTP, SSH, LDAP, database URIs)
- **Secrets** — 70+ patterns: AWS keys, GitHub tokens, Stripe, Shopify, Vault, JWTs, private keys, database connection strings, and generic credential patterns with entropy filtering
- **Files** — Sensitive file references (.sql, .bak, .env, .pem, .ssh/, .kube/config, etc.)
- **Emails** — Email addresses
- **Configurations** — Debug mode flags, source maps, CORS misconfigurations, stack traces, cloud metadata (169.254.169.254), SQL/PHP errors, server version disclosure, internal domains

### Severity Classification
- Color-coded severity column: **High** (red), **Medium** (orange), **Low** (blue), **Info** (green)
- Editable via dropdown — click to reclassify
- Auto-classification based on content:
  - Prefixed tokens (AKIA, sk_live, ghp_, etc.) → High
  - Test/dev/sandbox keys → Medium (demoted)
  - Localhost DB connections → Low (demoted)
  - Cloud metadata → High (promoted)
- Shannon entropy filter for generic patterns (discards low-entropy matches like variable names)

### Results Tab
- Filter by category and free-text search
- Click a row to view request/response with **match highlighting** (all occurrences highlighted in orange with auto-scroll)
- Right-click context menu:
  - Send to Repeater / Intruder / Comparer
  - Copy Match Value / Copy URL / Open URL in Browser
  - Send Match/URL to Whiteboard
  - Mark as False Positive (by match or URL)
- Export filtered results to JSON or CSV (includes severity)
- High/Medium findings auto-reported as Burp Scanner issues

### Patterns Tab
- View and edit regex patterns per category (endpoints, urls, secrets, files, emails, configurations)
- Add, import from file, and save custom patterns
- **Pattern Tester**: paste a regex and sample text to validate matches before adding

### Whiteboard Tab
Investigation board for security analysts to collect and organize findings:
- **8 auto-categorized sections**: Domains, Secrets, Files, Paths, Emails, URLs, Configurations, Other
- Items are auto-classified when added (by content analysis)
- **Send to Whiteboard** from results context menu (match or URL)
- **Add Item** manually with auto-classification
- Right-click on whiteboard items: Copy, Remove, Open in Browser
- **Subdomain Enumeration**: right-click a domain/URL → "Find Subdomains (crt.sh)"
  - Queries `crt.sh` Certificate Transparency logs
  - Background thread with loading indicator
  - Selection dialog with checkboxes (already-added items shown in gray)
  - Extracts root domain automatically (e.g., `www.sub.example.com` → `example.com`)
  - Supports second-level TLDs (.co.uk, .com.es, etc.)
- **HTTP Status Checks** (configurable in Settings):
  - Background checks via HEAD requests with 3s timeout
  - HTTPS-first with HTTP fallback
  - 6s hard timeout per item (stuck connections don't block)
  - 2s throttle between requests (WAF-friendly)
  - Status shown next to each domain/URL: `[200]`, `[403]`, `[TIMEOUT]`, `[NO RESPONSE]`, or `[status checks off]`
- **Export Whiteboard** to JSON or formatted TXT
- Persistent storage across Burp sessions

### Settings Tab
- **Only analyze in-scope items**: limit analysis to target scope
- **Skip media-type responses**: ignore images, videos, fonts
- **Merge duplicates**: by match only, match + URL, or no merging
- **HTTP status checks toggle**: enable/disable background domain checking
- **Noise Filters**: manage domain, string, and path exclusion lists
- **False Positive Exclusions**: manage excluded matches and URLs

## Installation

### Prerequisites

1. **Burp Suite** (Community or Professional edition)
2. **Jython Standalone JAR** — download from [jython.org](https://www.jython.org/download)

### Setup

1. Open Burp Suite → **Extensions → Options**
2. Under **Python Environment**, select your Jython JAR
3. Go to **Extensions → Installed → Add**
4. Set **Extension type** to **Python**
5. Select `low_hanging_fruits.py`
6. Click **Next** to load the extension

The extension creates 4 tabs: **Results**, **Patterns**, **Whiteboard**, and **Settings**.

## File Structure

```
fluffy-swordfish/
├── low_hanging_fruits.py       # Main extension file (~2600 lines)
├── patterns/
│   ├── default_patterns.json   # Default regex patterns (6 categories, 200+ patterns)
│   └── noise_filters.json      # Noise filters (domains, strings, paths)
└── README.md
```

## Custom Patterns

### JSON Format
```json
{
  "secrets": [
    "(?i)my_custom_pattern.*",
    "another_pattern"
  ]
}
```

### Text Format (one per line)
```
# Comments start with #
(?i)my_custom_pattern.*
another_pattern
```

Use the **Pattern Tester** in the Patterns tab to validate your regex before saving.

## License

MIT License
