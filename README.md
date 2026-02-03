# LowHangingFruits Burp Grabber

A Burp Suite extension for passively detecting secrets, endpoints, URLs, files, and emails in HTTP responses.

## Features

- **Passive Analysis**: Automatically analyzes HTTP responses without modifying traffic
- **Smart Filtering**: Only analyzes `.js`, `.json`, `.map` files, JavaScript/JSON content types, and HTML with `<script>` tags
- **Category Detection**:
  - **Endpoints**: API routes, REST endpoints, GraphQL paths
  - **URLs**: Full URLs found in responses
  - **Secrets**: API keys, tokens, passwords, private keys, database URLs
  - **Files**: Sensitive file references (.sql, .bak, .env, .pem, etc.)
  - **Emails**: Email addresses
- **Noise Filtering**: Exclude common CDNs, placeholder values, and irrelevant paths
- **Results Table**: Filter by category, click to view request/response
- **Send to Repeater**: Right-click context menu integration
- **Export**: Save results to JSON or CSV
- **Persistent Settings**: Configuration saved between Burp sessions

## Installation

### Prerequisites

1. **Burp Suite** (Community or Professional edition)
2. **Jython Standalone JAR** - Download from [jython.org](https://www.jython.org/download)

### Setup

1. Open Burp Suite and go to **Extender → Options**
2. Under **Python Environment**, click **Select file...** and choose your Jython JAR
3. Go to **Extender → Extensions → Add**
4. Set **Extension type** to **Python**
5. Click **Select file...** and choose `low_hanging_fruits.py`
6. Click **Next** to load the extension

## Usage

### Results Tab

1. Browse websites through Burp proxy
2. Switch to the **LowHangingFruits** tab
3. View detected items in the results table
4. Use the **Filter by Category** dropdown to filter results
5. Click a row to view the request/response
6. Right-click a row to **Send to Repeater**

### Settings Tab

- **Only analyze in-scope items**: Enable to limit analysis to in-scope targets
- **Skip media-type responses**: Skip images, videos, fonts, etc.
- **Custom Patterns**: Add, import, or modify regex patterns per category
- **Noise Filters**: Add domains, strings, or paths to filter out

### Exporting Results

1. Click **Export Results**
2. Choose JSON or CSV format
3. Select save location

## File Structure

```
LowHangingFruitsBurpGrabber/
├── low_hanging_fruits.py      # Main extension file
├── patterns/
│   ├── default_patterns.json  # Default regex patterns
│   └── noise_filters.json     # Default noise filters
└── README.md
```

## Custom Patterns Format

### JSON Format
```json
{
  "secrets": [
    "(?i)my_custom_pattern.*",
    "another_pattern"
  ]
}
```

### Text Format (one pattern per line)
```
# Comments start with #
(?i)my_custom_pattern.*
another_pattern
```

## License

MIT License
