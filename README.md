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
   - `VERIFY_CERT`: Whether to verify SSL certificates (default: False)
   - `QUERIES_FILE`: Path to queries configuration file (default: queries.json)

## Usage

### Main MISP Connector
```bash
python webamon_misp_connector.py
```

This script:
- Reads queries from `queries.json`
- Fetches data from Webamon API
- Creates or updates events in MISP
- Handles API timeouts and errors with retry logic

## Configuration Files

- **queries.json**: Define your search queries and associated tags
- **.env**: Environment variables (not committed to git)
- **.env.example**: Template for environment configuration

## Retry Logic

The scripts implement configurable retry logic:
- Default: 2 retry attempts
- Handles API timeouts and connection errors
- Continues processing after max retries are exhausted
- Detailed logging of retry attempts and failures

## Security Notes

- API keys are stored in `.env` files (excluded from git)
- SSL certificate verification can be disabled for internal MISP instances
- All sensitive configuration is externalized to environment variables
