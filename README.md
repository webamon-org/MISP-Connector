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
   - `DEBUG_MODE`: Enable debug logging (default: False)

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

## Security Notes

- API keys are stored in `.env` files (excluded from git)
- SSL certificate verification can be disabled for internal MISP instances
- All sensitive configuration is externalized to environment variables
