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
        print(f"ERROR: Missing required environment variables: {', '.join(missing_vars)}")
        print("Please check your .env file or set the required environment variables.")
        exit(1)

# ===== FUNCTIONS =====
def fetch_webamon_data(query, fields=None, index="scans", size=500):
    headers = {"x-api-key": f"{WEBAMON_KEY}"}
    all_results = []
    current_from = 0
    seen_items = set()  # Track unique items to prevent duplicates

    while True:
        params = {
            "lucene_query": query,
            "size": size,
            "index": index,
            "from": current_from
        }

        # Add fields parameter if provided
        if fields and isinstance(fields, list):
            params["fields"] = ",".join(fields)

        # Debug logging
        if DEBUG_MODE:
            print(f"   DEBUG: API Request: {WEBAMON_URL}?{'&'.join([f'{k}={v}' for k, v in params.items()])}")

        for attempt in range(RETRY_COUNT + 1):
            try:
                r = requests.get(
                    WEBAMON_URL,
                    headers=headers,
                    params=params
                )
                r.raise_for_status()
                response_data = r.json()

                # Extract results from current page
                current_results = response_data.get("results", [])

                # Check for duplicates and add only unique items
                new_items = []
                for item in current_results:
                    # Create a unique identifier for this item
                    if "report_id" in item:
                        item_id = f"{item['report_id']}_{item.get('domain', '')}_{item.get('username', '')}"
                    elif "resolved_domain" in item:
                        item_id = f"{item['resolved_domain']}_{item.get('resolved_ip', '')}_{item.get('resolved_url', '')}"
                    else:
                        # Fallback for other item types
                        item_id = str(hash(str(item)))

                    if item_id not in seen_items:
                        seen_items.add(item_id)
                        new_items.append(item)
                    elif DEBUG_MODE:
                        print(f"   WARN: Duplicate item detected and skipped: {item_id}")

                all_results.extend(new_items)

                if DEBUG_MODE:
                    print(f"   DEBUG: Page results: {len(current_results)} total, {len(new_items)} new, {len(all_results)} cumulative")

                # Check if pagination exists and if there are more pages
                pagination = response_data.get("pagination")
                if not pagination:
                    # No pagination data, return current results
                    if DEBUG_MODE:
                        print(f"   INFO: No pagination data found, returning {len(all_results)} unique results")
                    return all_results

                # Check if there are more pages
                if not pagination.get("has_more", False):
                    if DEBUG_MODE:
                        print(f"   INFO: Reached last page. Total unique results: {len(all_results)}")
                    return all_results

                # Move to next page
                current_from = pagination.get("next_from", current_from + size)
                if DEBUG_MODE:
                    print(f"   DEBUG: Fetched page with {len(current_results)} results. Moving to next page (from: {current_from})")

                # Small delay between requests to be respectful to the API
                time.sleep(0.1)

                break  # Success, move to next page

            except requests.exceptions.Timeout:
                if attempt < RETRY_COUNT:
                    print(f"   WARN: Timeout on attempt {attempt + 1}/{RETRY_COUNT + 1}, retrying...")
                    continue
                else:
                    print(f"   ERROR: Final timeout after {RETRY_COUNT + 1} attempts")
                    return all_results
            except requests.exceptions.RequestException as e:
                if attempt < RETRY_COUNT:
                    print(f"   WARN: Request error on attempt {attempt + 1}/{RETRY_COUNT + 1}: {e}, retrying...")
                    time.sleep(RETRY_DELAY)  # Configurable delay before retry
                    continue
                else:
                    print(f"   ERROR: Final request error after {RETRY_COUNT + 1} attempts: {e}")
                    return all_results
            except Exception as e:
                print(f"   ERROR: Unexpected error: {e}")
                return all_results

        # Safety check to prevent infinite loops
        if current_from >= 10000:  # Arbitrary limit to prevent infinite loops
            print(f"   WARN: Safety limit reached (10,000 results), stopping pagination")
            break

    return all_results

def find_existing_event(misp, event_title):
    for attempt in range(RETRY_COUNT + 1):
        try:
            events = misp.search(controller='events', eventinfo=event_title)
            if events and isinstance(events, list) and events:
                return events[0]  # Return first matching event
            return None
        except Exception as e:
            if attempt < RETRY_COUNT:
                print(f"   WARN: MISP search error on attempt {attempt + 1}/{RETRY_COUNT + 1}: {e}, retrying...")
                time.sleep(RETRY_DELAY)  # Configurable delay before retry
                continue
            else:
                print(f"   ERROR: Final MISP search error after {RETRY_COUNT + 1} attempts: {e}")
                return None
    return None

def add_attributes_to_event(misp, event, data, tags):
    # Ensure we have the event ID whether it's a dict from MISP or a MISPEvent object
    event_id = event['Event']['id'] if isinstance(event, dict) else getattr(event, 'id', None)
    if event_id is None:
        raise ValueError("Event does not have an ID. Ensure it is created in MISP first.")

    added_count = 0
    duplicate_count = 0
    failed_count = 0
    total_attributes_processed = 0

    print(f"   INFO: Processing {len(data)} items for event {event_id}")
    print(f"   INFO: Duplicate attributes will be automatically skipped (this is normal)")

    # Track what we're actually creating
    attribute_types_created = {}

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

        total_attributes_processed += len(attributes_to_add)

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
            attribute_added = False
            for attempt in range(RETRY_COUNT + 1):
                try:
                    if SUPPRESS_PYMISP_OUTPUT:
                        # Temporarily redirect stderr to capture PyMISP library output
                        old_stderr = sys.stderr
                        captured_stderr = io.StringIO()
                        sys.stderr = captured_stderr

                        try:
                            result = misp.add_attribute(event_id, attr)
                            if result and hasattr(result, 'id'):
                                added_count += 1
                                attribute_added = True
                                # Track attribute types for debugging
                                if attr_type not in attribute_types_created:
                                    attribute_types_created[attr_type] = 0
                                attribute_types_created[attr_type] += 1
                                break
                            else:
                                # Don't print individual warnings for duplicates - too verbose
                                failed_count += 1
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
                                duplicate_count += 1
                                break  # Don't retry for duplicates
                    else:
                        # Normal operation without stderr redirection
                        result = misp.add_attribute(event_id, attr)
                        if result and hasattr(result, 'id'):
                            added_count += 1
                            attribute_added = True
                            # Track attribute types for debugging
                            if attr_type not in attribute_types_created:
                                attribute_types_created[attr_type] = 0
                            attribute_types_created[attr_type] += 1
                            break
                        else:
                            # Don't print individual warnings for duplicates - too verbose
                            failed_count += 1
                            break

                except Exception as e:
                    # Handle non-duplicate errors with retry logic
                    error_str = str(e)

                    if "validation" in error_str.lower() or "invalid" in error_str.lower():
                        # Don't print individual validation errors - too verbose
                        failed_count += 1
                        break  # Don't retry validation errors
                    elif attempt < RETRY_COUNT:
                        print(f"   WARN: MISP add_attribute error on attempt {attempt + 1}/{RETRY_COUNT + 1}: {e}")
                        time.sleep(RETRY_DELAY)  # Configurable delay before retry
                        continue
                    else:
                        print(f"   ERROR: Final MISP add_attribute error after {RETRY_COUNT + 1} attempts: {e}")
                        failed_count += 1
                        break

            if not attribute_added and failed_count == 0:
                # This shouldn't happen, but let's track it silently
                pass

    # Print detailed summary with debugging information
    print(f"   INFO: ATTRIBUTE PROCESSING SUMMARY:")
    print(f"      • Total items processed: {len(data)}")
    print(f"      • Total attributes attempted: {total_attributes_processed}")
    print(f"      • Successfully added: {added_count}")
    print(f"      • Duplicates skipped: {duplicate_count}")
    print(f"      • Failed to add: {failed_count}")

    if attribute_types_created:
        print(f"      • Attribute types created:")
        for attr_type, count in attribute_types_created.items():
            print(f"        - {attr_type}: {count}")

    # Verify the count makes sense
    expected_total = added_count + duplicate_count + failed_count
    if expected_total != total_attributes_processed:
        print(f"   WARN: COUNT MISMATCH: Expected {expected_total}, but processed {total_attributes_processed}")

    if duplicate_count > 0:
        print(f"   SUCCESS: Added {added_count} new attributes to event {event_id}")
        print(f"   INFO: Skipped {duplicate_count} duplicate attributes (already exist in MISP)")
        if added_count == 0:
            print(f"   INFO: All attributes were already present - no new data to add")
    else:
        print(f"   SUCCESS: Added {added_count} attributes to event {event_id}")


def create_or_update_event(misp, event_name, description, data, tags):
    today_str = datetime.date.today().isoformat()
    event_title = f"Webamon Import - {event_name} ({today_str})"

    existing_event = find_existing_event(misp, event_title)
    if existing_event:
        print(f"INFO: Updating existing event: {event_title}")
        add_attributes_to_event(misp, existing_event, data, tags)
    else:
        print(f"INFO: Creating new event: {event_title}")
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
                    print(f"   WARN: MISP add_event error on attempt {attempt + 1}/{RETRY_COUNT + 1}: {e}, retrying...")
                    time.sleep(RETRY_DELAY)  # Configurable delay before retry
                    continue
                else:
                    print(f"   ERROR: Final MISP add_event error after {RETRY_COUNT + 1} attempts: {e}")
                    return

        if created_event:
            add_attributes_to_event(misp, created_event, data, tags)

# ===== MAIN =====
if __name__ == "__main__":
    try:
        validate_config()

        if not os.path.exists(QUERIES_FILE):
            print(f"ERROR: Queries file not found: {QUERIES_FILE}")
            exit(1)

        with open(QUERIES_FILE, "r") as f:
            queries = json.load(f)

        misp = PyMISP(MISP_URL, MISP_KEY, VERIFY_CERT)

        for q in queries:
            print(f"INFO: Running query for: {q['name']}")

            # Validate fields parameter
            fields = q.get("fields")
            if fields:
                if not isinstance(fields, list):
                    print(f"   WARN: 'fields' should be a list, got {type(fields).__name__}")
                    fields = None
                else:
                    print(f"   INFO: Requesting fields: {', '.join(fields)}")

            # Get index and size from query configuration
            index = q.get("index", "scans")
            size = q.get("size", 500)
            print(f"   INFO: Using index: {index}, size: {size}")

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
                print(f"WARN: No results for {q['name']}")

        print("SUCCESS: MISP Connector completed successfully!")

    except KeyboardInterrupt:
        print("\nWARN: MISP Connector interrupted by user")
    except Exception as e:
        print(f"ERROR: MISP Connector failed with error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Always close the logger and restore stdout
        logger.close()
