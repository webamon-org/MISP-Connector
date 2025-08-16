# MISP Connector for Webamon

This project provides scripts to connect Webamon security scanning results with MISP (Malware Information Sharing Platform).

## Features

- **Webamon Integration**: Fetches scan results from Webamon API
- **MISP Integration**: Creates and updates events in MISP with security findings
- **Retry Logic**: Configurable retry mechanism for handling API timeouts and errors
- **Environment Configuration**: Secure configuration management using .env files

## Setup

1. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Environment Configuration**:
   - Copy `.env.example` to `.env`
   - Fill in your actual API keys and URLs:
     ```bash
     cp .env.example .env
     # Edit .env with your actual values
     ```

3. **Required Environment Variables**:
   - `MISP_URL`: Your MISP server URL
   - `MISP_KEY`: Your MISP API key
   - `WEBAMON_URL`: Webamon search API URL
   - `WEBAMON_KEY`: Your Webamon API key
   - `RETRY_COUNT`: Number of retry attempts (default: 2)
   - `RETRY_DELAY`: Delay between retries in seconds (default: 1.0)
   - `VERIFY_CERT`: Whether to verify SSL certificates (default: False)
   - `QUERIES_FILE`: Path to queries configuration file (default: queries.json)
   - `LOGS_DIR`: Directory for log files (default: logs)
   - `DEBUG_MODE`: Enable debug logging (default: False)
   - `VERBOSE_DUPLICATES`: Show detailed duplicate attribute messages (default: False)
   - `SUPPRESS_PYMISP_OUTPUT`: Suppress PyMISP library error output (default: True)

## Usage

### Main MISP Connector
```bash
python webamon_misp_connector.py
```

This script:
- Reads queries from `queries.json`
- Fetches data from Webamon API with specified fields
- Creates or updates events in MISP
- Handles API timeouts and errors with retry logic

### Fields Parameter

The `fields` parameter in `queries.json` allows you to specify which data fields should be returned from the Webamon API. This helps:

- **Reduce data transfer**: Only request the fields you need
- **Improve performance**: Smaller response payloads
- **Control data**: Ensure only relevant information is processed

Example fields you can request:
- `resolved_domain`: The resolved domain name
- `resolved_ip`: The resolved IP address
- `resolved_url`: The full URL
- `report_id`: Webamon report identifier
- `page_title`: Page title from the website

## Configuration Files

- **queries.json**: Define your search queries, associated tags, and fields to return
- **.env**: Environment variables (not committed to git)
- **.env.example**: Template for environment configuration

### Logging

The connector automatically logs all output to timestamped log files:

- **Log Directory**: `logs/` (configurable via `LOGS_DIR`)
- **Log File Format**: `misp_connector_YYYYMMDD_HHMMSS.log` (UTC timestamps)
- **Complete Capture**: All stdout output is captured to log files
- **Runtime Tracking**: Each log file includes start and completion timestamps in UTC
- **Audit Trail**: Full record of all connector operations and results
- **Timezone Consistency**: All timestamps use UTC for consistency across different timezones

**Example Log File Structure:**
```
=== MISP Connector Log - Started at 2025-08-16 16:30:15 UTC ===
🔍 Running query for: Irish Colleges - Website Page Title
   📋 Requesting fields: resolved_domain, resolved_ip, resolved_url, report_id, page_title
   🌐 API Request: https://pro.webamon.com/search?lucene_query=...
   🆕 Creating new event: Webamon Import - Irish Colleges - Website Page Title (2025-08-16)
   🔍 Processing 8 items for event 13
   ℹ️  Duplicate attributes will be automatically skipped (this is normal)
   ➕ Added 2 new attributes to event 13
   ℹ️  Skipped 6 duplicate attributes (already exist in MISP)
✅ MISP Connector completed successfully!
=== MISP Connector Log - Completed at 2025-08-16 16:30:45 UTC ===
```

**Benefits:**
- **Compliance**: Complete audit trail for security operations
- **Debugging**: Historical record of all runs and errors
- **Monitoring**: Track performance and success rates over time
- **Backup**: Preserve output even if terminal is closed

### queries.json Structure

Each query in `queries.json` should have the following structure:

```json
{
  "name": "Query Name",
  "description": "Query description",
  "query": "lucene_query_string",
  "fields": ["field1", "field2", "field3"],
  "tags": ["tag1", "tag2"]
}
```

- **name**: Human-readable name for the query
- **description**: Description of what the query searches for
- **query**: Lucene query string for Webamon search
- **fields**: Array of field names to return from the Webamon API (comma-separated in URL)
- **tags**: Array of MISP tags to apply to the event

## Retry Logic

The scripts implement configurable retry logic:
- Default: 2 retry attempts
- Configurable delay between retries (default: 1 second)
- Handles API timeouts and connection errors
- Continues processing after max retries are exhausted
- Detailed logging of retry attempts and failures
- Graceful handling of duplicate attributes (no retries needed)

### Duplicate Attribute Handling

MISP automatically prevents duplicate attributes within the same event. The connector handles this gracefully:

- **Automatic Detection**: Recognizes various forms of duplicate errors (403, "already exists", etc.)
- **No Retries**: Duplicate attributes are skipped immediately (saves time and API calls)
- **Clear Messaging**: Shows how many attributes were added vs. skipped
- **Configurable Logging**: Control verbosity of duplicate messages via `VERBOSE_DUPLICATES`
- **Library Output Control**: Suppress PyMISP library error messages via `SUPPRESS_PYMISP_OUTPUT`

**Example Output:**
```
   🔍 Processing 5 items for event 123
   ℹ️  Duplicate attributes will be automatically skipped (this is normal)
   ➕ Added 2 new attributes to event 123
   ℹ️  Skipped 3 duplicate attributes (already exist in MISP)
```

### PyMISP Output Suppression

The `SUPPRESS_PYMISP_OUTPUT` setting controls whether PyMISP library error messages are displayed:

- **`SUPPRESS_PYMISP_OUTPUT=True`** (default): Suppresses raw library error messages, showing only clean, formatted output
- **`SUPPRESS_PYMISP_OUTPUT=False`**: Shows all PyMISP library output (useful for debugging)

This feature ensures that duplicate attribute errors from the MISP API are handled gracefully without showing confusing raw error messages.

## Security Notes

- API keys are stored in `.env` files (excluded from git)
- SSL certificate verification can be disabled for internal MISP instances
- All sensitive configuration is externalized to environment variables

## Project Structure

```
MISP-Connector/
├── webamon_misp_connector.py    # Main connector script
├── queries.json                 # Query configuration
├── requirements.txt             # Python dependencies
├── .env                        # Environment variables (not in git)
├── .env.example                # Environment template
├── .gitignore                  # Git ignore rules
├── logs/                       # Log files directory
│   ├── misp_connector_20250816_163015.log
│   ├── misp_connector_20250816_164530.log
│   └── ...
└── README.md                   # This documentation
```
