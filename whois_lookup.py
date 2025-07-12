"""
Streamlit application for performing bulk WHOIS and RDAP lookups on domain names.
Allows users to input domains directly, upload a CSV file, and configure
lookup parameters.
"""
import logging
import re
import socket
import threading
import time
from typing import List
from urllib.parse import urlparse
import pandas as pd
import requests
from ratelimit import limits, sleep_and_retry
import streamlit as st
import whois


# Configure logging
class ExcludeFilter(logging.Filter):
    def filter(self, record):
        return 'Trying WHOIS server' not in record.getMessage()


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
logger.addFilter(ExcludeFilter())

# Rate limiting configuration
CALLS_PER_MINUTE = 10  # Conservative rate limit
PERIOD = 60  # Time period in seconds
WHOIS_TIMEOUT = 10  # Timeout in seconds for WHOIS queries

# Domain validation regex pattern
DOMAIN_REGEX = re.compile(
    r'^(?:[a-zA-Z0-9]'  # First character
    r'(?:[a-zA-Z0-9-_]{0,61}[a-zA-Z0-9])?\.)'  # Sub domain + Last char
    r'+[a-zA-Z]{2,63}$'  # TLD
)

OUTPUT_COLUMN_ORDER = [
    'domain', 'registrar', 'nameservers', 'creation_date',
    'expiration_date', 'domain_status', 'lookup_status', 'lookup_method'
]


# Two blank lines before function definition (PEP 8)


class TimeoutError(Exception):
    """Custom timeout exception"""
    pass


def with_timeout(timeout_seconds):
    """Thread-safe timeout decorator using threading with improved timing"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            result = [None]  # Use list to store result (mutable)
            exception = [None]  # Store any exception
            completed = [False]  # Track completion
            
            def target():
                try:
                    result[0] = func(*args, **kwargs)
                    completed[0] = True
                except Exception as e:
                    exception[0] = e
                    completed[0] = True
            
            thread = threading.Thread(target=target)
            thread.daemon = True
            thread.start()
            
            # Give a bit more time buffer and check completion status
            thread.join(timeout_seconds + 1.0)  # Add 1 second buffer
            
            if thread.is_alive() or not completed[0]:
                # Thread is still running or didn't complete, timeout occurred
                return None
            
            if exception[0]:
                raise exception[0]
            
            return result[0]
        return wrapper
    return decorator


def clean_date(date_value):
    """Helper function to clean date values"""
    if isinstance(date_value, list):
        date_value = date_value[0] if date_value else None
    if date_value:
        try:
            return pd.Timestamp(date_value).isoformat()
        except Exception:
            return None
    return None


def _create_error_result(domain: str, message: str, method: str) -> dict:
    """Helper to create a consistent error result dictionary."""
    return {
        'domain': domain,
        'registrar': None,
        'creation_date': None,
        'expiration_date': None,
        'domain_status': None,
        'nameservers': None,
        'lookup_status': f'error: {message}',
        'lookup_method': method
    }


def _rdap_lookup_internal(domain: str) -> dict:
    """Internal RDAP lookup without timeout handling"""
    # First, try to get the RDAP URL for the domain
    bootstrap_url = f"https://rdap.org/domain/{domain}"
    response = requests.get(bootstrap_url, timeout=WHOIS_TIMEOUT)

    if response.status_code == 404:
        return _create_error_result(domain, 'No RDAP server found for this TLD', 'RDAP')
    elif response.status_code != 200:
        msg = f'RDAP lookup failed with status {response.status_code}'
        return _create_error_result(domain, msg, 'RDAP')
    
    data = response.json()

    # Extract relevant information
    registrar = None
    if 'entities' in data:
        for entity in data['entities']:
            if 'roles' in entity and 'registrar' in entity['roles']:
                if 'vcardArray' in entity:
                    vcard = entity['vcardArray']
                    if len(vcard) > 1 and isinstance(vcard[1], list):
                        for item in vcard[1]:
                            if (isinstance(item, list) and
                                    len(item) > 3 and item[0] == 'fn'):
                                registrar = item[3]
                                break
                if registrar:
                    break

    creation_date, expiration_date = None, None
    if 'events' in data:
        for event in data['events']:
            if event.get('eventAction') == 'registration':
                creation_date = event.get('eventDate')
            elif event.get('eventAction') == 'expiration':
                expiration_date = event.get('eventDate')
            if creation_date and expiration_date:
                break

    # Get domain status
    status = data.get('status', [])
    domain_status = ', '.join(status) if status else None

    # Get nameservers
    nameservers = []
    if 'nameservers' in data:
        for ns in data['nameservers']:
            if 'ldhName' in ns:
                nameservers.append(ns['ldhName'])
    nameservers = ', '.join(sorted(nameservers)) if nameservers else None

    return {
        'domain': domain,
        'registrar': registrar,
        'creation_date': clean_date(creation_date),
        'expiration_date': clean_date(expiration_date),
        'domain_status': domain_status,
        'nameservers': nameservers,
        'lookup_status': 'success',
        'lookup_method': 'RDAP'
    }


def safe_rdap_lookup(domain: str) -> dict:
    """
    Perform RDAP lookup for a single domain with timeout protection
    """
    try:
        # Use timeout decorator to ensure hard timeout
        timeout_func = with_timeout(WHOIS_TIMEOUT)(_rdap_lookup_internal)
        result = timeout_func(domain)
        
        if result is None:  # Timeout occurred
            logger.error(f"Hard timeout error for {domain} (RDAP)")
            return _create_error_result(domain, 'Operation timed out', 'RDAP')
        
        return result
    except requests.Timeout:
        logger.error(f"Timeout error for {domain} (RDAP)")
        return _create_error_result(domain, 'Connection timed out', 'RDAP')
    except requests.exceptions.RequestException as e:
        logger.error(f"Network error looking up {domain} via RDAP: {str(e)}")
        if "404" in str(e) or "Not Found" in str(e):
            return _create_error_result(domain, 'No RDAP server found for this TLD', 'RDAP')
        return _create_error_result(domain, f'Network error: {str(e)}', 'RDAP')
    except Exception as e:
        logger.error(f"Error looking up {domain} via RDAP: {str(e)}")
        return _create_error_result(domain, str(e), 'RDAP')




@sleep_and_retry
@limits(calls=CALLS_PER_MINUTE, period=PERIOD)
def safe_whois_lookup(domain: str) -> dict:
    """
    Perform rate-limited WHOIS lookup for a single domain with improved reliability
    """
    # Try the lookup multiple times with different timeout strategies
    for attempt in range(2):
        try:
            # Set a longer socket timeout to allow for slower WHOIS servers
            original_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(WHOIS_TIMEOUT * 2)  # Double the timeout
            
            try:
                result = whois.whois(domain)
                if result is None:
                    return _create_error_result(domain, 'No WHOIS server found for this TLD', 'WHOIS')
                
                # Check if we have a valid domain_name field
                if not hasattr(result, 'domain_name') or not result.domain_name:
                    # Check if we have any useful data in the result
                    if hasattr(result, 'text') and result.text:
                        # Check for common "not found" patterns in the raw text
                        text_lower = result.text.lower()
                        if any(pattern in text_lower for pattern in [
                            'domain not found', 'no match', 'not found', 
                            'no entries found', 'object does not exist',
                            'domain status: no object found',
                            'the queried object does not exist'
                        ]):
                            return _create_error_result(domain, 'Domain not found in WHOIS database', 'WHOIS')
                        
                        # If it's not a "not found" error, it might be unparseable data
                        return _create_error_result(domain, 'Domain data not parseable (TLD may not support detailed WHOIS)', 'WHOIS')
                    else:
                        return _create_error_result(domain, 'No domain data found', 'WHOIS')

                creation_date = clean_date(
                    result.creation_date if hasattr(result, 'creation_date') else None
                )
                expiration_date = clean_date(
                    result.expiration_date if hasattr(result, 'expiration_date') else None
                )
                registrar = result.registrar if hasattr(result, 'registrar') else None
                if isinstance(registrar, list):
                    registrar = registrar[0] if registrar else None

                domain_status = result.status if hasattr(result, 'status') else None
                if isinstance(domain_status, list):
                    domain_status = ', '.join(s.lower() for s in domain_status if s)
                elif isinstance(domain_status, str):
                    domain_status = domain_status.lower()

                nameservers = result.name_servers if hasattr(result, 'name_servers') else None
                if isinstance(nameservers, list):
                    nameservers = ', '.join(sorted(ns.lower() for ns in nameservers if ns))
                elif isinstance(nameservers, str):
                    nameservers = nameservers.lower()

                return {
                    'domain': domain,
                    'registrar': registrar,
                    'creation_date': creation_date,
                    'expiration_date': expiration_date,
                    'domain_status': domain_status,
                    'nameservers': nameservers,
                    'lookup_status': 'success',
                    'lookup_method': 'WHOIS'
                }
            finally:
                socket.setdefaulttimeout(original_timeout)
                
        except socket.timeout:
            if attempt == 0:
                logger.warning(f"First timeout for {domain}, retrying...")
                continue
            logger.error(f"Timeout error for {domain} (WHOIS) after retry")
            return _create_error_result(domain, 'Connection timed out', 'WHOIS')
        except Exception as e:
            if attempt == 0 and "timeout" in str(e).lower():
                logger.warning(f"First attempt failed for {domain} with timeout-like error, retrying...")
                continue
            logger.error(f"Error looking up {domain} via WHOIS: {str(e)}")
            # Check for common python-whois error messages
            if "No match for" in str(e):
                status_msg = 'Domain not found in WHOIS database'
            elif "No WHOIS server known for" in str(e):
                status_msg = 'No WHOIS server found for this TLD'
            elif "timeout" in str(e).lower():
                status_msg = 'Connection timed out'
            else:
                status_msg = str(e)
            return _create_error_result(domain, status_msg, 'WHOIS')
    
    # Should not reach here
    return _create_error_result(domain, 'Max retries exceeded', 'WHOIS')


def is_valid_domain(domain: str) -> tuple[bool, str]:
    """
    Validate if a string is a properly formatted domain name.
    Returns (is_valid, error_message_or_cleaned_domain)
    """
    domain = domain.strip().lower()
    if not domain:
        return False, "Empty domain name"

    # Add http:// if no scheme to help urlparse
    if '://' not in domain:
        domain_to_parse = 'http://' + domain
    else:
        domain_to_parse = domain

    try:
        # urlparse is robust and handles many edge cases.
        # .hostname extracts the domain part, lowercased, and IDNA-encoded.
        parsed = urlparse(domain_to_parse)
        domain_candidate = parsed.hostname
        if not domain_candidate:
            # Fallback for cases like "domain.com/path" without a scheme
            # where urlparse puts it in `path`.
            # `http://` prepending should minimize this.
            if parsed.path and not parsed.netloc:
                domain_candidate = parsed.path.split('/')[0]
            else:
                return False, "Invalid URL structure or could not extract domain"
    except Exception:  # Broad exception for any parsing error
        return False, "Invalid URL format"

    if not domain_candidate:
        return False, "Could not extract domain"

    # Remove www. if present
    if domain_candidate.startswith('www.'):
        domain_candidate = domain_candidate[4:]

    if not domain_candidate:  # If domain was just "www." or became empty
        return False, "Empty domain after stripping www."

    # Check total length and label length constraints
    if len(domain_candidate) > 253:
        return False, "Domain name too long (max 253 chars)"

    labels = domain_candidate.split('.')
    if any(len(label) > 63 for label in labels):
        return False, "Domain label too long (max 63 chars per label)"

    if not DOMAIN_REGEX.match(domain_candidate):
        return False, "Invalid domain name format"

    return True, domain_candidate


def initialize_session_state():
    """Initialize session state variables"""
    if "processing_active" not in st.session_state:
        st.session_state.processing_active = False
    if "valid_domains" not in st.session_state:
        st.session_state["valid_domains"] = []
    if "user_requested_cancel" not in st.session_state:
        st.session_state.user_requested_cancel = False
    if "results" not in st.session_state:
        st.session_state["results"] = []
    if "all_lookups_successful" not in st.session_state:
        st.session_state.all_lookups_successful = False
    if "domains_text" not in st.session_state:
        st.session_state.domains_text = ""
    if "process_button_clicked" not in st.session_state:
        st.session_state.process_button_clicked = False
    # Add a key for the uploader that we can change
    if "uploader_key_counter" not in st.session_state:
        st.session_state.uploader_key_counter = 0
    # uploaded_csv_file will store the actual UploadedFile object
    # if "uploaded_csv_file" not in st.session_state:
    #     st.session_state.uploaded_csv_file = None # Not strictly needed to init here


def configure_layout():
    """Configure the layout of the Streamlit app"""
    st.set_page_config(layout="wide")
    st.title("Bulk Domain Lookup Tool 🕵️‍♂️")
    st.write(
        "Enter domain names (one per line) or upload a CSV to perform "
        "WHOIS/RDAP lookups.")


def add_configuration_options():
    """Add configuration options for the lookup tool"""
    st.sidebar.header("⚙️ Configuration")
    timeout = st.sidebar.number_input(
        "Lookup Timeout (seconds)",
        min_value=1,
        max_value=60,
        value=WHOIS_TIMEOUT,  # Default from global
        help="Maximum time to wait for server response per domain."
    )
    rate_limit = st.sidebar.number_input(
        "Queries per minute (approx.)",
        min_value=1,
        max_value=120,
        value=CALLS_PER_MINUTE,  # Default from global
        help=("Approximate number of queries allowed per minute. The tool "
              "sleeps between queries to distribute load.")
    )
    lookup_type = st.sidebar.selectbox(
        "Lookup Type",
        options=["WHOIS", "RDAP"],
        index=0,  # Default to WHOIS
        help=("Choose between WHOIS (broader compatibility) or RDAP "
              "(modern, structured data).")
    )
    return timeout, rate_limit, lookup_type


def get_domains_from_input(domains_text: str, uploaded_file_obj) -> tuple[List[str], List[str]]:
    """Get domains from text input and uploaded CSV file"""
    raw_domains = []
    if domains_text:
        raw_domains.extend(
            [d.strip() for d in domains_text.split('\n') if d.strip()]
        )
    if uploaded_file_obj is not None:
        try:
            # Crucial: Reset file pointer to the beginning before reading
            uploaded_file_obj.seek(0)
            df = pd.read_csv(uploaded_file_obj)
            
            # Check if there's a 'domain' column
            if 'domain' in df.columns:
                raw_domains.extend(df['domain'].dropna().str.strip().tolist())
            # If no 'domain' column, check if there's only one column (headerless CSV)
            elif len(df.columns) == 1:
                # Assume the single column contains domains (common for headerless CSVs)
                first_column = df.columns[0]
                raw_domains.extend(df[first_column].dropna().str.strip().tolist())
            else:
                st.error("Uploaded CSV file must contain a 'domain' column or be a single-column file with domains.")
                # Reset file pointer before returning on error
                uploaded_file_obj.seek(0)
                return [], []  # Return empty lists on error
        except Exception as e:
            st.error(f"Error reading CSV file: {e}")
            logger.error(f"Error reading CSV. File object type: {type(uploaded_file_obj)}, Name: {getattr(uploaded_file_obj, 'name', 'N/A')}")
            # Reset file pointer before returning on error
            try:
                uploaded_file_obj.seek(0)
            except:
                pass  # In case seek fails, don't raise another exception
            return [], []

    valid_domains = []
    invalid_domain_entries = []  # Store original entry and error

    unique_domains_to_validate = sorted(
        list(set(d.lower() for d in raw_domains if d))
    )

    for domain_input in unique_domains_to_validate:
        is_valid, result_or_error = is_valid_domain(domain_input)
        if is_valid:
            valid_domains.append(result_or_error)
        else:
            invalid_domain_entries.append(f"{domain_input} ({result_or_error})")

    return valid_domains, invalid_domain_entries


# whois_lookup.py
def process_and_display_domains(valid_domains, lookup_type, timeout_config, rate_limit_config):
    """Process and display the domains, now with an internal cancel button."""
    _current_run_completed_fully = True

    progress_bar = st.progress(0, text="Initializing lookup...")
    status_text = st.empty()
    cancel_button_placeholder = st.empty()

    # NEW: Create an empty placeholder for the DataFrame
    live_results_table_placeholder = st.empty()

    if not st.session_state.get("user_requested_cancel", False):
        def cancel_button_callback():
            st.session_state.user_requested_cancel = True
            cancel_button_placeholder.empty()
            st.toast("Cancellation signal sent. Finishing current step or stopping...")

        cancel_button_placeholder.button("Cancel Processing",
                                         key="cancel_in_progress_button",
                                         type="secondary",
                                         on_click=cancel_button_callback,
                                         use_container_width=True)

    # results_container = st.container() # REMOVE or repurpose if needed for other static content
    total_domains = len(valid_domains)
    global WHOIS_TIMEOUT
    WHOIS_TIMEOUT = timeout_config

    # --- Main processing loop ---
    for idx, domain in enumerate(valid_domains, 1):
        if st.session_state.get("user_requested_cancel", False):
            _current_run_completed_fully = False
            status_text.warning(
                "Operation cancelled by user. Processing stopped."
            )
            cancel_button_placeholder.empty()
            break

        progress_val = idx / total_domains
        progress_text = f"Processing: {domain} ({idx}/{total_domains})"
        progress_bar.progress(progress_val, text=progress_text)

        status_msg = (f"Looking up {domain}... "
                      f"({idx}/{total_domains} completed, "
                      f"{total_domains - idx} remaining)")
        status_text.text(status_msg)

        if lookup_type == "WHOIS":
            result = safe_whois_lookup(domain)
        else:
            result = safe_rdap_lookup(domain)

        st.session_state.results.append(result)

        # Update the DataFrame in the st.empty() placeholder
        if st.session_state.results:
            df_live = pd.DataFrame(st.session_state.results)
            df_live = df_live.reindex(columns=OUTPUT_COLUMN_ORDER)
            # Reset index to start from 1 instead of 0
            df_live.index = df_live.index + 1
            # Use the placeholder to display/update the DataFrame
            live_results_table_placeholder.dataframe(df_live)

        if idx < total_domains and not st.session_state.get("user_requested_cancel", False):
            time.sleep(60 / rate_limit_config)
    # --- End of processing loop ---

    cancel_button_placeholder.empty()

    # The final DataFrame display is handled by main() after processing_active becomes False.
    # So, we don't need to explicitly display it here post-loop unless we want a different presentation.
    # The live_results_table_placeholder will hold the last state from the loop.

    if _current_run_completed_fully:
        if total_domains > 0:
            processed_count = len(st.session_state.results)
            status_text.success(
                f"Processing complete! Looked up {processed_count} domain(s)."
            )
            progress_bar.progress(1.0, text="All domains processed.")
            if st.session_state.results:
                st.session_state.all_lookups_successful = all(
                    res.get('lookup_status') == 'success'
                    for res in st.session_state.results
                ) and processed_count == total_domains
            else:
                st.session_state.all_lookups_successful = (
                    False if total_domains > 0 else True
                )
        else:
            status_text.info("No valid domains were provided to process.")
            progress_bar.empty()
            st.session_state.all_lookups_successful = True
    # If cancelled, warning is already shown inside the loop.
    # The main st.session_state.processing_active is handled by main()


def reset_session_state_callback():
    """Callback to reset relevant session state variables."""
    st.session_state.results = []
    st.session_state.valid_domains = []
    st.session_state.processing_active = False
    st.session_state.all_lookups_successful = False
    st.session_state.domains_text = ""
    st.session_state.process_button_clicked = False
    st.session_state.user_requested_cancel = False

    if "uploaded_csv_file" in st.session_state:
        del st.session_state.uploaded_csv_file

    # Increment the counter to change the file uploader's key on the next rerun
    st.session_state.uploader_key_counter += 1

    # DO NOT DO THIS: (This was the line causing the error)
    # if "csv_uploader" in st.session_state:
    # st.session_state.csv_uploader = None


def main():
    initialize_session_state()
    configure_layout()

    # Inject custom CSS for button colors
    button_css = """
    <style>
        /* === General Button Kind Styling === */

        /* Primary buttons (e.g., Process Domains) -> Green */
        button[kind="primary"] {
            background-color: #4CAF50 !important; /* Green */
            color: white !important;
            border: none !important;
        }
        button[kind="primary"]:hover {
            background-color: #45a049 !important;
            color: white !important;
        }
        button[kind="primary"]:active {
            background-color: #3e8e41 !important;
            color: white !important;
        }
        button[kind="primary"]:focus {
            box-shadow: 0 0 0 0.2rem rgba(76, 175, 80, 0.5) !important;
        }

        /* Default Secondary buttons (e.g., Cancel Processing) -> Red */
        /* This will also initially apply to Reset Session. */
        button[kind="secondary"] {
            background-color: #f44336 !important; /* Red */
            color: white !important;
            border: none !important;
        }
        button[kind="secondary"]:hover {
            background-color: #e53935 !important;
            color: white !important;
        }
        button[kind="secondary"]:active {
            background-color: #d32f2f !important;
            color: white !important;
        }
        button[kind="secondary"]:focus {
             box-shadow: 0 0 0 0.2rem rgba(244, 67, 54, 0.5) !important;
        }

        /* === Specific Button Overrides for Transparent Background & White Border === */

        /* Reset Session button -> Transparent background, WHITE border */
        /* Targets the button in the second column of the "Process/Reset" button row */
        /* This selector needs to be very specific to override the general red for secondary. */
        div[data-testid="stHorizontalBlock"] > div[data-testid="stVerticalBlock"]:nth-child(2) div[data-testid="stButton"] button[kind="secondary"] {
            background-color: transparent !important;
            color: var(--text-color) !important;
            border: 1px solid white !important;
        }
        div[data-testid="stHorizontalBlock"] > div[data-testid="stVerticalBlock"]:nth-child(2) div[data-testid="stButton"] button[kind="secondary"]:hover {
            background-color: rgba(255, 255, 255, 0.1) !important;
            color: var(--text-color) !important;
            border: 1px solid white !important;
        }
        div[data-testid="stHorizontalBlock"] > div[data-testid="stVerticalBlock"]:nth-child(2) div[data-testid="stButton"] button[kind="secondary"]:active {
            background-color: rgba(255, 255, 255, 0.2) !important;
            color: var(--text-color) !important;
            border: 1px solid white !important;
        }
        div[data-testid="stHorizontalBlock"] > div[data-testid="stVerticalBlock"]:nth-child(2) div[data-testid="stButton"] button[kind="secondary"]:focus {
            border: 1px solid white !important;
            box-shadow: 0 0 0 0.2rem rgba(255, 255, 255, 0.3) !important;
        }


        /* File Uploader "Browse files" button -> Transparent background, WHITE border */
        div[data-testid="stFileUploader"] section button {
            background-color: transparent !important;
            color: var(--text-color) !important;
            border: 1px solid white !important;
        }
        div[data-testid="stFileUploader"] section button:hover {
            background-color: rgba(255, 255, 255, 0.1) !important;
            color: var(--text-color) !important;
            border: 1px solid white !important;
        }
        div[data-testid="stFileUploader"] section button:active {
            background-color: rgba(255, 255, 255, 0.2) !important;
            color: var(--text-color) !important;
            border: 1px solid white !important;
        }
        div[data-testid="stFileUploader"] section button:focus {
            border: 1px solid white !important;
            box-shadow: 0 0 0 0.2rem rgba(255, 255, 255, 0.3) !important;
        }
    </style>
    """
    st.markdown(button_css, unsafe_allow_html=True)

    timeout, rate_limit, lookup_type = add_configuration_options()

    # input_col is where most inputs go.
    # controls_col was previously for the cancel button, but it's moved.
    # You can repurpose or remove controls_col if no longer needed, or use it for other controls.
    input_col, _ = st.columns([3, 1])  # controls_col might be unused now

    with input_col:
        st.text_area(
            "Enter domains (one per line):",
            key="domains_text",  # Linked to st.session_state.domains_text
            placeholder="google.com\nexample.net\n",
            height=200,
            help="Enter one domain name per line."
        )

        # Use a dynamic key for the file_uploader based on uploader_key_counter
        # This allows the reset button to effectively "clear" the uploader by changing its key.
        uploader_key_string = f"csv_uploader_{st.session_state.uploader_key_counter}"
        uploaded_file_widget_value = st.file_uploader(
            "Or upload a CSV file with domains:",
            type=["csv"],
            help="CSV file should have a column named 'domain'.",
            key=uploader_key_string  # Dynamic key
        )

        # Manage the actual uploaded file object in a separate session state variable
        if uploaded_file_widget_value is not None:
            # If a file is newly uploaded or present in the widget, store it.
            st.session_state.uploaded_csv_file = uploaded_file_widget_value
        else:
            # If the widget is empty (e.g., after key change or user clears it),
            # ensure our stored version is also removed.
            if "uploaded_csv_file" in st.session_state:
                del st.session_state.uploaded_csv_file

        # --- Buttons ---
        b_col1, b_col2 = st.columns(2)

        with b_col1:
            if st.button("Process Domains",
                         type="primary",
                         use_container_width=True):
                st.session_state.results = []  # Clear previous results
                st.session_state.valid_domains = []  # Clear previous valid domains
                st.session_state.all_lookups_successful = False  # Reset flag
                st.session_state.user_requested_cancel = False  # Reset cancel flag
                st.session_state.processing_active = True  # Start processing mode
                st.session_state.process_button_clicked = True  # Track that this button was clicked
                st.rerun()  # Rerun to show cancel button (if any outside) and then start processing

        with b_col2:
            if st.button("Reset Session",  # <--- REMOVE type="primary"
                         use_container_width=True,
                         on_click=reset_session_state_callback):
                st.success("Inputs and results cleared. Ready for new lookup. 👍")
                st.rerun()

    # --- Domain Processing Logic ---

    # If user requested cancel while processing was supposed to be active, ensure it's turned off.
    if st.session_state.get("user_requested_cancel", False) and \
       st.session_state.get("processing_active", False):
        st.session_state.processing_active = False
        # A warning/toast about cancellation is handled within process_and_display_domains or its callback

    # This block runs if processing_active is true.
    # process_and_display_domains will itself check user_requested_cancel internally.
    if st.session_state.get("processing_active", False):
        current_domains_text = st.session_state.domains_text
        # Use the file from session_state (which reflects the uploader's state)
        file_to_process_from_session = st.session_state.get("uploaded_csv_file", None)

        if file_to_process_from_session is not None:
            logger.debug(f"Main: Attempting to process with uploaded file: {file_to_process_from_session.name}")
        else:
            logger.debug("Main: No uploaded CSV file found in session state for processing.")

        valid_domains, invalid_domains_info = get_domains_from_input(
            current_domains_text, file_to_process_from_session
        )
        st.session_state.valid_domains = valid_domains

        if invalid_domains_info:
            warning_msg = (
                f"Found {len(invalid_domains_info)} invalid or "
                f"unsupported domain entries (will be skipped):"
            )
            st.warning(warning_msg)
            for info in invalid_domains_info:
                st.caption(f" - {info}")

        # If cancellation happened *before* process_and_display_domains is called
        # (e.g., user clicks "Process" then "Cancel" very quickly before the loop starts)
        if st.session_state.get("user_requested_cancel", False):
            st.session_state.processing_active = False  # Ensure it's off
            st.warning("Operation cancelled by user before processing started.")
            st.rerun()  # Rerun to update UI
        elif not valid_domains:
            if st.session_state.get("process_button_clicked"):  # Only show error if process was actually attempted
                st.error("No valid domains found to process!")
            st.session_state.processing_active = False
            st.session_state.process_button_clicked = False  # Reset, as no processing happened
            st.rerun()
        else:  # We have valid domains and we were not cancelled before starting this block
            info_msg = (
                f"Found {len(valid_domains)} valid domains. "
                f"Starting lookup ({lookup_type})..."
            )
            st.info(info_msg)

            # Call the processing function. It will display its own cancel button
            # and check st.session_state.user_requested_cancel.
            process_and_display_domains(
                valid_domains, lookup_type, timeout, rate_limit
            )
            # After process_and_display_domains completes (fully or by its own cancellation),
            # set processing_active to False.
            st.session_state.processing_active = False
            st.session_state.process_button_clicked = False  # Reset after processing attempt
            st.rerun()  # Rerun to update UI (e.g., remove progress bar, cancel button from view)

    # --- Display Results and Download Button ---
    # This section is shown if there are results, regardless of processing_active.
    if st.session_state.results and len(st.session_state.results) > 0:
        st.markdown("---")
        st.subheader("📊 Lookup Results")

        df_results = pd.DataFrame(st.session_state.results)
        df_results = df_results.reindex(columns=OUTPUT_COLUMN_ORDER)  # Ensures all columns, fills missing with NA
        # Reset index to start from 1 instead of 0
        df_results.index = df_results.index + 1
        st.dataframe(df_results, use_container_width=True)

        csv_data = df_results.to_csv(index=False).encode('utf-8')

        all_lookups_successful_flag = st.session_state.get('all_lookups_successful', False)
        is_full_success_scenario = (
            st.session_state.valid_domains and  # Check if there were valid domains to begin with
            len(st.session_state.results) == len(st.session_state.valid_domains) and
            all_lookups_successful_flag
        )

        if is_full_success_scenario:
            download_label = "Download Full Results as CSV"
            download_filename = "domain_lookup_results_full.csv"
        else:
            download_label = "Download Partial/Current Results as CSV"
            download_filename = "domain_lookup_results_partial.csv"

        st.download_button(
            label=f"📥 {download_label}",
            data=csv_data,
            file_name=download_filename,
            mime="text/csv",
        )
    # Handle the case where "Process Domains" was clicked, no processing is active,
    # no results, and not cancelled (e.g., no valid domains were found initially).
    elif st.session_state.get("process_button_clicked") and \
            not st.session_state.get("processing_active", False) and \
            not st.session_state.results and \
            not st.session_state.get("user_requested_cancel", False):
        # This state can be reached if no valid domains were found and processing_active was set to false.
        # The specific error for "No valid domains" is shown above.
        # This provides a general "no results" if other conditions met.
        # st.info("No results to display. Ensure valid domains were provided and processed.")
        # This specific message might be redundant given other messages.
        pass


if __name__ == "__main__":
    main()
