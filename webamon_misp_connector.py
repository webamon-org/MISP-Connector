#!/usr/bin/env python3
from pymisp import PyMISP, MISPEvent, MISPAttribute
import requests
import datetime
import json
import os
import urllib3
import time
import sys
import io
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ===== LOGGING SETUP =====
class TeeLogger:
    """Custom logger that writes to both console and log file"""
    
    def __init__(self, log_dir="logs"):
        self.log_dir = log_dir
        self.terminal = sys.stdout
        self.log_file = None
        self.setup_log_file()
    
    def setup_log_file(self):
        """Create log file with timestamp in logs directory"""
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
        
        # Use UTC time for consistent log file naming across timezones
        timestamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        log_filename = f"misp_connector_{timestamp}.log"
        log_path = os.path.join(self.log_dir, log_filename)
        
        self.log_file = open(log_path, 'w', encoding='utf-8')
        
        # Write header to log file with UTC timestamp
        header = f"=== MISP Connector Log - Started at {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC ===\n"
        self.log_file.write(header)
        self.log_file.flush()
    
    def write(self, message):
        """Write to both terminal and log file"""
        self.terminal.write(message)
        if self.log_file:
            self.log_file.write(message)
            self.log_file.flush()
    
    def flush(self):
        """Flush both terminal and log file"""
        self.terminal.flush()
        if self.log_file:
            self.log_file.flush()
    
    def close(self):
        """Close log file and restore stdout"""
        if self.log_file:
            footer = f"\n=== MISP Connector Log - Completed at {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC ===\n"
            self.log_file.write(footer)
            self.log_file.close()
            sys.stdout = self.terminal


# ===== MISP CONFIG =====
MISP_URL = os.getenv("MISP_URL")
MISP_KEY = os.getenv("MISP_KEY")
VERIFY_CERT = os.getenv("VERIFY_CERT", "False").lower() == "true"

# ===== WEBAMON CONFIG =====
WEBAMON_URL = os.getenv("WEBAMON_URL")
WEBAMON_KEY = os.getenv("WEBAMON_KEY")

# ===== FILE PATH =====
QUERIES_FILE = os.getenv("QUERIES_FILE", "queries.json")

# ===== CONFIG =====
RETRY_COUNT = int(os.getenv("RETRY_COUNT", "2"))
RETRY_DELAY = float(os.getenv("RETRY_DELAY", "1.0"))  # Delay between retries in seconds
DEBUG_MODE = os.getenv("DEBUG_MODE", "False").lower() == "true"  # Enable debug logging
SUPPRESS_PYMISP_OUTPUT = os.getenv("SUPPRESS_PYMISP_OUTPUT", "True").lower() == "true"  # Suppress PyMISP library output
LOGS_DIR = os.getenv("LOGS_DIR", "logs")  # Directory for log files

# Initialize logging
logger = TeeLogger(LOGS_DIR)
sys.stdout = logger

# Validate required environment variables
def validate_config():
    required_vars = {
        "MISP_URL": MISP_URL,
        "MISP_KEY": MISP_KEY,
        "WEBAMON_URL": WEBAMON_URL,
        "WEBAMON_KEY": WEBAMON_KEY
    }
    
    missing_vars = [var for var, value in required_vars.items() if not value]
    
    if missing_vars:
        print(f"❌ Missing required environment variables: {', '.join(missing_vars)}")
        print("Please check your .env file or set the required environment variables.")
        exit(1)

# ===== FUNCTIONS =====
def fetch_webamon_data(query, fields=None, index="scans", size=500):
    headers = {"x-api-key": f"{WEBAMON_KEY}"}
    params = {"lucene_query": query, "size": size, "index": index}
    
    # Add fields parameter if provided
    if fields and isinstance(fields, list):
        params["fields"] = ",".join(fields)
    
    # Debug logging
    if DEBUG_MODE:
        print(f"   🌐 API Request: {WEBAMON_URL}?{'&'.join([f'{k}={v}' for k, v in params.items()])}")
    
    for attempt in range(RETRY_COUNT + 1):
        try:
            r = requests.get(
                WEBAMON_URL, 
                headers=headers, 
                params=params
            )
            r.raise_for_status()
            return r.json().get("results", [])
        except requests.exceptions.Timeout:
            if attempt < RETRY_COUNT:
                print(f"   ⏰ Timeout on attempt {attempt + 1}/{RETRY_COUNT + 1}, retrying...")
                continue
            else:
                print(f"   ❌ Final timeout after {RETRY_COUNT + 1} attempts")
                return []
        except requests.exceptions.RequestException as e:
            if attempt < RETRY_COUNT:
                print(f"   🔄 Request error on attempt {attempt + 1}/{RETRY_COUNT + 1}: {e}, retrying...")
                time.sleep(RETRY_DELAY)  # Configurable delay before retry
                continue
            else:
                print(f"   ❌ Final request error after {RETRY_COUNT + 1} attempts: {e}")
                return []
        except Exception as e:
            print(f"   ❌ Unexpected error: {e}")
            return []
    
    return []

def find_existing_event(misp, event_title):
    for attempt in range(RETRY_COUNT + 1):
        try:
            events = misp.search(controller='events', eventinfo=event_title)
            if events and isinstance(events, list) and events:
                return events[0]  # Return first matching event
            return None
        except Exception as e:
            if attempt < RETRY_COUNT:
                print(f"   🔄 MISP search error on attempt {attempt + 1}/{RETRY_COUNT + 1}: {e}, retrying...")
                time.sleep(RETRY_DELAY)  # Configurable delay before retry
                continue
            else:
                print(f"   ❌ Final MISP search error after {RETRY_COUNT + 1} attempts: {e}")
                return None
    return None

def add_attributes_to_event(misp, event, data, tags):
    # Ensure we have the event ID whether it's a dict from MISP or a MISPEvent object
    event_id = event['Event']['id'] if isinstance(event, dict) else getattr(event, 'id', None)
    if event_id is None:
        raise ValueError("Event does not have an ID. Ensure it is created in MISP first.")

    added_count = 0
    duplicate_count = 0
    
    print(f"   🔍 Processing {len(data)} items for event {event_id}")
    print(f"   ℹ️  Duplicate attributes will be automatically skipped (this is normal)")

    for item in data:
        attributes_to_add = []

        # Existing mappings
        if "resolved_domain" in item:
            attributes_to_add.append(("domain", item["resolved_domain"]))
        if "resolved_ip" in item:
            attributes_to_add.append(("ip-dst", item["resolved_ip"]))
        if "resolved_url" in item:
            attributes_to_add.append(("url", item["resolved_url"]))

        # New mappings for infostealer data
        if "domain" in item:
            attributes_to_add.append(("domain", item["domain"]))
        if "username" in item:
            attributes_to_add.append(("text", f"Username: {item['username']}"))

        # Additional mappings
        if "report_id" in item:
            report_link = f"http://search.webamon.com/search/report_id={item['report_id']}"
            attributes_to_add.append(("text", f"Webamon Report ID: {item['report_id']}"))
            attributes_to_add.append(("link", report_link))
        if "page_title" in item:
            attributes_to_add.append(("text", f"Page Title: {item['page_title']}"))
        if "ingest_date" in item:
            attributes_to_add.append(("text", f"Ingest Date: {item['ingest_date']}"))
        if "tag" in item:
            attributes_to_add.append(("text", f"Tag: {item['tag']}"))

        for attr_type, attr_value in attributes_to_add:
            attr = MISPAttribute()
            attr.type = attr_type
            attr.value = attr_value
            
            # Enhanced category logic for different attribute types
            if attr_type in ["domain", "ip-dst", "url"]:
                attr.category = "Network activity"
            elif attr_type == "text" and "Username:" in attr_value:
                attr.category = "External analysis"  # Username data from infostealers
            elif attr_type == "text" and "Tag:" in attr_value:
                attr.category = "External analysis"  # Tag data from infostealers
            elif attr_type == "text" and "Ingest Date:" in attr_value:
                attr.category = "External analysis"  # Timestamp data
            else:
                attr.category = "External analysis"
            
            attr.to_ids = True
            for tag in tags:
                attr.add_tag(tag)
            
            # Add attribute with retry logic
            for attempt in range(RETRY_COUNT + 1):
                try:
                    if SUPPRESS_PYMISP_OUTPUT:
                        # Temporarily redirect stderr to capture PyMISP library output
                        old_stderr = sys.stderr
                        captured_stderr = io.StringIO()
                        sys.stderr = captured_stderr
                        
                        try:
                            misp.add_attribute(event_id, attr)
                            added_count += 1
                            break
                        finally:
                            # Restore stderr
                            sys.stderr = old_stderr
                            stderr_output = captured_stderr.getvalue()
                            captured_stderr.close()
                            
                            # Check if the stderr output contains duplicate error messages
                            if stderr_output and any(phrase in stderr_output.lower() for phrase in [
                                "already exists", 
                                "similar attribute already exists",
                                "a similar attribute already exists for this event"
                            ]):
                                print(f"   ℹ️  Attribute already exists in MISP: {attr_type}:{attr_value}")
                                duplicate_count += 1
                                break  # Don't retry for duplicates
                    else:
                        # Normal operation without stderr redirection
                        misp.add_attribute(event_id, attr)
                        added_count += 1
                        break
                        
                except Exception as e:
                    # Handle non-duplicate errors with retry logic
                    error_str = str(e)
                    
                    if "validation" in error_str.lower() or "invalid" in error_str.lower():
                        print(f"   ⚠️  Validation error for {attr_type}:{attr_value} - {e}")
                        break  # Don't retry validation errors
                    elif attempt < RETRY_COUNT:
                        print(f"   🔄 MISP add_attribute error on attempt {attempt + 1}/{RETRY_COUNT + 1}: {e}")
                        time.sleep(RETRY_DELAY)  # Configurable delay before retry
                        continue
                    else:
                        print(f"   ❌ Final MISP add_attribute error after {RETRY_COUNT + 1} attempts: {e}")
                        break

    # Print summary with both added and duplicate counts
    if duplicate_count > 0:
        print(f"   ➕ Added {added_count} new attributes to event {event_id}")
        print(f"   ℹ️  Skipped {duplicate_count} duplicate attributes (already exist in MISP)")
        if added_count == 0:
            print(f"   💡 All attributes were already present - no new data to add")
    else:
        print(f"   ➕ Added {added_count} attributes to event {event_id}")


def create_or_update_event(misp, event_name, description, data, tags):
    today_str = datetime.date.today().isoformat()
    event_title = f"Webamon Import - {event_name} ({today_str})"

    existing_event = find_existing_event(misp, event_title)
    if existing_event:
        print(f"♻ Updating existing event: {event_title}")
        add_attributes_to_event(misp, existing_event, data, tags)
    else:
        print(f"🆕 Creating new event: {event_title}")
        event = MISPEvent()
        event.info = event_title
        event.distribution = 0
        event.threat_level_id = 2
        event.analysis = 0
        for tag in tags:
            event.add_tag(tag)
        
        # Add the event to MISP with retry logic
        created_event = None
        for attempt in range(RETRY_COUNT + 1):
            try:
                created_event = misp.add_event(event)
                break
            except Exception as e:
                if attempt < RETRY_COUNT:
                    print(f"   🔄 MISP add_event error on attempt {attempt + 1}/{RETRY_COUNT + 1}: {e}, retrying...")
                    time.sleep(RETRY_DELAY)  # Configurable delay before retry
                    continue
                else:
                    print(f"   ❌ Final MISP add_event error after {RETRY_COUNT + 1} attempts: {e}")
                    return
        
        if created_event:
            add_attributes_to_event(misp, created_event, data, tags)

# ===== MAIN =====
if __name__ == "__main__":
    try:
        validate_config()

        if not os.path.exists(QUERIES_FILE):
            print(f"❌ Queries file not found: {QUERIES_FILE}")
            exit(1)

        with open(QUERIES_FILE, "r") as f:
            queries = json.load(f)

        misp = PyMISP(MISP_URL, MISP_KEY, VERIFY_CERT)

        for q in queries:
            print(f"🔍 Running query for: {q['name']}")
            
            # Validate fields parameter
            fields = q.get("fields")
            if fields:
                if not isinstance(fields, list):
                    print(f"   ⚠️  Warning: 'fields' should be a list, got {type(fields).__name__}")
                    fields = None
                else:
                    print(f"   📋 Requesting fields: {', '.join(fields)}")
            
            # Get index and size from query configuration
            index = q.get("index", "scans")
            size = q.get("size", 500)
            print(f"   📊 Using index: {index}, size: {size}")
            
            results = fetch_webamon_data(q["query"], fields, index, size)
            if results:
                create_or_update_event(
                    misp,
                    q["name"],
                    q.get("description", ""),
                    results,
                    q.get("tags", [])
                )
            else:
                print(f"⚠ No results for {q['name']}")
        
        print("✅ MISP Connector completed successfully!")
        
    except KeyboardInterrupt:
        print("\n⚠️  MISP Connector interrupted by user")
    except Exception as e:
        print(f"❌ MISP Connector failed with error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Always close the logger and restore stdout
        logger.close()
