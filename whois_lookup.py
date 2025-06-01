import streamlit as st
import whois
from ratelimit import limits, sleep_and_retry
import pandas as pd
from typing import List
import logging
import socket
import re
from urllib.parse import urlparse
import requests
import time


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


def safe_rdap_lookup(domain: str) -> dict:
    """
    Perform RDAP lookup for a single domain
    """
    try:
        # First, try to get the RDAP URL for the domain
        bootstrap_url = f"https://rdap.org/domain/{domain}"
        response = requests.get(bootstrap_url, timeout=WHOIS_TIMEOUT) # Uses global WHOIS_TIMEOUT

        if response.status_code != 200:
            return {
                'domain': domain,
                'registrar': None,
                'creation_date': None,
                'expiration_date': None,
                'domain_status': None,
                'nameservers': None,
                'lookup_status': f'error: RDAP lookup failed with status {response.status_code}',
                'lookup_method': 'RDAP'
            }

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
                                if isinstance(item, list) and len(item) > 3 and item[0] == 'fn':
                                    registrar = item[3]
                                    break

        # Get creation date
        creation_date = None
        if 'events' in data:
            for event in data['events']:
                if event.get('eventAction') == 'registration':
                    creation_date = event.get('eventDate')
                    break

        # Get expiration date
        expiration_date = None
        if 'events' in data:
            for event in data['events']:
                if event.get('eventAction') == 'expiration':
                    expiration_date = event.get('eventDate')
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
            'creation_date': clean_date(creation_date), # Clean date
            'expiration_date': clean_date(expiration_date), # Clean date
            'domain_status': domain_status,
            'nameservers': nameservers,
            'lookup_status': 'success',
            'lookup_method': 'RDAP'
        }
    except requests.Timeout:
        logger.error(f"Timeout error for {domain}")
        return {
            'domain': domain,
            'registrar': None,
            'creation_date': None,
            'expiration_date': None,
            'domain_status': None,
            'nameservers': None,
            'lookup_status': 'error: Connection timed out',
            'lookup_method': 'RDAP'
        }
    except Exception as e:
        logger.error(f"Error looking up {domain} via RDAP: {str(e)}")
        return {
            'domain': domain,
            'registrar': None,
            'creation_date': None,
            'expiration_date': None,
            'domain_status': None,
            'nameservers': None,
            'lookup_status': f'error: {str(e)}',
            'lookup_method': 'RDAP'
        }


@sleep_and_retry
@limits(calls=CALLS_PER_MINUTE, period=PERIOD)
def safe_whois_lookup(domain: str) -> dict:
    """
    Perform rate-limited WHOIS lookup for a single domain
    """
    original_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(WHOIS_TIMEOUT) # Uses global WHOIS_TIMEOUT

    try:
        result = whois.whois(domain)
        if result is None or not result.domain_name: # Added check for empty result
            return {
                'domain': domain,
                'registrar': None,
                'creation_date': None,
                'expiration_date': None,
                'domain_status': None,
                'nameservers': None,
                'lookup_status': 'error: No data found',
                'lookup_method': 'WHOIS'
            }

        creation_date = clean_date(result.creation_date if hasattr(result, 'creation_date') else None)
        expiration_date = clean_date(result.expiration_date if hasattr(result, 'expiration_date') else None)
        registrar = result.registrar if hasattr(result, 'registrar') else None
        if isinstance(registrar, list):
            registrar = registrar[0] if registrar else None

        domain_status = result.status if hasattr(result, 'status') else None
        if isinstance(domain_status, list):
            domain_status = ', '.join(s.lower() for s in domain_status if s) # Normalize and join
        elif isinstance(domain_status, str):
            domain_status = domain_status.lower()
        else:
            domain_status = None

        nameservers = result.name_servers if hasattr(result, 'name_servers') else None
        if isinstance(nameservers, list):
            nameservers = ', '.join(sorted(ns.lower() for ns in nameservers if ns)) # Normalize and join
        elif isinstance(nameservers, str):
            nameservers = nameservers.lower()
        else:
            nameservers = None

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
    except socket.timeout:
        logger.error(f"Timeout error for {domain}")
        return {
            'domain': domain,
            'registrar': None,
            'creation_date': None,
            'expiration_date': None,
            'domain_status': None,
            'nameservers': None,
            'lookup_status': 'error: Connection timed out',
            'lookup_method': 'WHOIS'
        }
    except Exception as e:
        logger.error(f"Error looking up {domain} via WHOIS: {str(e)}")
        # Check for common python-whois error messages
        if "No match for" in str(e) or "No WHOIS server known for" in str(e):
            status = 'error: Domain not found or no WHOIS server'
        else:
            status = f'error: {str(e)}'
        return {
            'domain': domain,
            'registrar': None,
            'creation_date': None,
            'expiration_date': None,
            'domain_status': None,
            'nameservers': None,
            'lookup_status': status,
            'lookup_method': 'WHOIS'
        }
    finally:
        socket.setdefaulttimeout(original_timeout)


# process_domains remains the same
def process_domains(domains: List[str], lookup_type: str) -> pd.DataFrame:
    """
    Process a list of domains with rate limiting
    """
    results = []
    for domain in domains:
        if lookup_type == "WHOIS":
            result = safe_whois_lookup(domain)
        else:
            result = safe_rdap_lookup(domain)
        results.append(result)
    return pd.DataFrame(results)


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
        parsed = urlparse(domain_to_parse)
        # Use hostname for domains, which handles ports correctly
        domain_candidate = parsed.hostname 
        if not domain_candidate: # If URL was like "example.com/path", hostname is None, path is "example.com/path"
             # Try to extract from path if netloc was empty (e.g. just "example.com" was entered)
            if parsed.path and not parsed.netloc:
                 domain_candidate = parsed.path.split('/')[0] # Take the first part of path
            else:
                 return False, "Invalid URL structure"
    except Exception: # Broad exception for any parsing error
        return False, "Invalid URL format"

    if not domain_candidate:
         return False, "Could not extract domain"

    # Remove www. if present
    if domain_candidate.startswith('www.'):
        domain_candidate = domain_candidate[4:]

    if not domain_candidate: # If domain was just "www."
        return False, "Empty domain after stripping www."

    # More robust domain regex:
    # Allows for IDNs by not strictly limiting to a-z.
    # Length of labels: 1-63. Total length: up to 253.
    # TLD: at least 2 chars, all alphabetic.
    pattern = re.compile(
        r'^(?:[a-zA-Z0-9]'  # First character of the domain
        r'(?:[a-zA-Z0-9-_]{0,61}[a-zA-Z0-9])?\.)'  # Sub domain + Last char of the domain
        r'+[a-zA-Z]{2,63}$'  # Top Level Domain
    )

    if len(domain_candidate) > 253:
        return False, "Domain name too long (max 253 chars)"
    
    labels = domain_candidate.split('.')
    if any(len(label) > 63 for label in labels):
        return False, "Domain label too long (max 63 chars per label)"
    if not pattern.match(domain_candidate):
        return False, "Invalid domain name format"
        
    return True, domain_candidate


def initialize_session_state():
    """Initialize session state variables"""
    if "processing" not in st.session_state:
        st.session_state["processing"] = False
    if "valid_domains" not in st.session_state:
        st.session_state["valid_domains"] = []
    if "results" not in st.session_state:
        st.session_state["results"] = []
    if "all_lookups_successful" not in st.session_state:
        st.session_state.all_lookups_successful = False
    # MODIFIED: Initialize domains_text for the text_area
    if "domains_text" not in st.session_state:
        st.session_state.domains_text = ""


def configure_layout():
    """Configure the layout of the Streamlit app"""
    st.set_page_config(layout="wide")
    st.title("Bulk Domain Lookup Tool 🕵️‍♂️") # Added emoji
    st.write("Enter domain names (one per line) or upload a CSV to perform WHOIS/RDAP lookups.")


def add_configuration_options():
    """Add configuration options for the lookup tool"""
    st.sidebar.header("⚙️ Configuration") # Moved to sidebar
    timeout = st.sidebar.number_input( # Moved to sidebar
        "Lookup Timeout (seconds)",
        min_value=1,
        max_value=60, # Increased max
        value=WHOIS_TIMEOUT, # Default from global
        help="Maximum time to wait for server response per domain."
    )
    rate_limit = st.sidebar.number_input( # Moved to sidebar
        "Queries per minute (approx.)",
        min_value=1,
        max_value=120, # Increased max
        value=CALLS_PER_MINUTE, # Default from global
        help="Approximate number of queries allowed per minute. The tool sleeps between queries to distribute load."
    )
    lookup_type = st.sidebar.selectbox( # Moved to sidebar
        "Lookup Type",
        options=["WHOIS", "RDAP"],
        index=0, # Default to WHOIS
        help="Choose between WHOIS (broader compatibility) or RDAP (modern, structured data)."
    )
    return timeout, rate_limit, lookup_type


def get_domains_from_input(domains_text, uploaded_file):
    """Get domains from text input and uploaded CSV file"""
    raw_domains = []
    if domains_text:
        raw_domains.extend([d.strip() for d in domains_text.split('\n') if d.strip()])

    if uploaded_file is not None:
        try:
            df = pd.read_csv(uploaded_file)
            if 'domain' in df.columns:
                raw_domains.extend(df['domain'].dropna().str.strip().tolist())
            else:
                st.error("Uploaded CSV file must contain a 'domain' column.")
                return [], [] # Return empty lists on error
        except Exception as e:
            st.error(f"Error reading CSV file: {e}")
            return [], []


    valid_domains = []
    invalid_domain_entries = [] # Store original entry and error
    
    unique_domains_to_validate = sorted(list(set(d.lower() for d in raw_domains if d))) # Process unique lowercase domains

    for domain_input in unique_domains_to_validate:
        is_valid, result_or_error = is_valid_domain(domain_input)
        if is_valid:
            valid_domains.append(result_or_error) # result_or_error is the cleaned domain
        else:
            invalid_domain_entries.append(f"{domain_input} ({result_or_error})") # Add domain and error message

    return valid_domains, invalid_domain_entries


def process_and_display_domains(valid_domains, lookup_type, timeout_config, rate_limit_config):
    """Process and display the domains"""
    # Ensure previous results for a *new* processing job are cleared from session state for this part
    # st.session_state.results = [] # This is now handled by main logic before calling this.
    st.session_state.processing = True
    st.session_state.all_lookups_successful = False # Assume not all successful until proven

    progress_bar = st.progress(0, text="Initializing lookup...")
    status_text = st.empty()
    # This container is for the live-updated table during processing
    results_container = st.container() # Changed to st.container for more flexible content

    total_domains = len(valid_domains)

    global WHOIS_TIMEOUT # Declare global to modify it
    WHOIS_TIMEOUT = timeout_config

    # MODIFIED: Cancel button logic
    # The button's existence will trigger a rerun. We check its state after the rerun.
    # We don't need a separate st.session_state key for the button itself if we handle it this way.
    
    # --- Main processing loop ---
    for idx, domain in enumerate(valid_domains, 1):
        # Check for cancellation at the start of each iteration
        # This 'cancel_processing' key could be set by a button outside this function if preferred
        if st.session_state.get("cancel_processing", False):
            st.session_state.processing = False # Ensure flag is set
            status_text.warning("Operation cancelled by user. Partial results are available.")
            st.session_state.all_lookups_successful = False
            st.session_state.cancel_processing = False # Reset cancel flag
            break  # Exit the loop

        progress_val = idx / total_domains
        progress_bar.progress(progress_val, text=f"Processing: {domain} ({idx}/{total_domains})")
        status_text.text(f"Looking up {domain}... ({idx}/{total_domains} completed, {total_domains - idx} remaining)")

        if lookup_type == "WHOIS":
            result = safe_whois_lookup(domain)
        else:
            result = safe_rdap_lookup(domain)
        
        # Append result to the main results list in session_state
        st.session_state.results.append(result)

        # Update the live DataFrame display
        if st.session_state.results:
            df_live = pd.DataFrame(st.session_state.results)
            column_order = ['domain', 'registrar', 'nameservers', 'creation_date', 'expiration_date', 'domain_status', 'lookup_status', 'lookup_method']
            for col in column_order: # Ensure all columns exist
                if col not in df_live.columns:
                    df_live[col] = pd.NA
            df_live = df_live.reindex(columns=column_order)
            results_container.dataframe(df_live) # Update the container

        # Rate limiting sleep (manual)
        if idx < total_domains: # No sleep after the last domain
             time.sleep(60 / rate_limit_config)
    # --- End of processing loop ---

    # Post-processing status
    if st.session_state.processing: # If not cancelled
        if total_domains > 0:
            status_text.success(f"Processing complete! Looked up {len(st.session_state.results)} domain(s).")
            progress_bar.progress(1.0, text="All domains processed.")
            # Check if all were successful
            if st.session_state.results:
                 st.session_state.all_lookups_successful = all(
                    res.get('lookup_status') == 'success' for res in st.session_state.results
                ) and len(st.session_state.results) == total_domains
            else: # No results but processing finished (e.g. valid_domains was empty but we proceeded)
                st.session_state.all_lookups_successful = False if total_domains > 0 else True
        else: # No domains were passed to process
            status_text.info("No valid domains were provided to process.")
            progress_bar.empty() # Clear progress bar
            st.session_state.all_lookups_successful = True # Or false, debatable for "no domains"
    
    # If loop broke due to cancellation, message already shown.
    # If it completed, processing flag remains true until here.
    st.session_state.processing = False # Mark processing as finished

def main():
    initialize_session_state()
    configure_layout()

    # Configuration options in the sidebar
    timeout, rate_limit, lookup_type = add_configuration_options()

    # Main layout columns for input
    input_col, controls_col = st.columns([3, 1])

    with input_col:
        # MODIFIED: Use st.session_state.domains_text for the text_area value
        st.session_state.domains_text = st.text_area(
            "Enter domains (one per line):",
            value=st.session_state.domains_text, # Controlled component
            placeholder="google.com\nexample.net\n",
            height=200,
            key="domains_input_area", # Using a different key to avoid conflict if 'domains_text' is used elsewhere.
                                     # Let's stick to "domains_text" as it's already in session_state init.
                                     # Value will be st.session_state.domains_text
            help="Enter one domain name per line."
        )
        uploaded_file = st.file_uploader(
            "Or upload a CSV file with domains:",
            type=["csv"],
            help="CSV file should have a column named 'domain'."
        )

    # Buttons in the controls column or below inputs
    # This state key will be set to True when the "Process Domains" button is clicked.
    # It's reset after processing or if "Reset" is clicked.
    if "process_button_clicked" not in st.session_state:
        st.session_state.process_button_clicked = False

    # --- Buttons ---
    # Use columns for Process and Reset buttons next to each other
    b_col1, b_col2 = st.columns(2)
    
    if b_col1.button("Process Domains", type="primary", use_container_width=True):
        st.session_state.process_button_clicked = True
        st.session_state.results = [] # Clear previous results before starting new processing
        st.session_state.all_lookups_successful = False # Reset flag

    if b_col2.button("Reset Session", use_container_width=True):
        st.session_state.results = []
        st.session_state.valid_domains = []
        st.session_state.processing = False
        st.session_state.all_lookups_successful = False
        st.session_state.domains_text = ""  # MODIFIED: Clear text area content
        st.session_state.process_button_clicked = False # Reset processing trigger
        if "cancel_processing" in st.session_state: # Reset cancel flag if it exists
            st.session_state.cancel_processing = False
        st.success("Inputs and results cleared. Ready for new lookup. 👍")
        st.rerun() # Rerun to reflect the cleared text area

    # --- Domain Processing Logic ---
    if st.session_state.process_button_clicked and not st.session_state.processing:
        # Get current text from session state as st.text_area now updates it directly
        current_domains_text = st.session_state.domains_text 
        valid_domains, invalid_domains_info = get_domains_from_input(current_domains_text, uploaded_file)
        st.session_state.valid_domains = valid_domains # Store for reference

        if invalid_domains_info:
            st.warning(f"Found {len(invalid_domains_info)} invalid or unsupported domain entries (will be skipped):")
            for info in invalid_domains_info:
                st.caption(f" - {info}")
        
        if not valid_domains:
            st.error("No valid domains found to process!")
            st.session_state.process_button_clicked = False # Reset button state
        else:
            st.info(f"Found {len(valid_domains)} valid domains. Starting lookup ({lookup_type})...")
            
            # Add a cancel button that sets a flag in session_state
            # This button is visible *before* processing_domains starts its loop
            if st.button("Cancel Current Processing Run", key="main_cancel_button"):
                st.session_state.cancel_processing = True # Signal to the processing function
                st.session_state.process_button_clicked = False # Stop trying to process
                st.warning("Cancellation initiated. Processing will stop shortly.")
                st.rerun() # Rerun to stop further execution of process_and_display_domains
            
            if not st.session_state.get("cancel_processing", False):
                 process_and_display_domains(valid_domains, lookup_type, timeout, rate_limit)
            
            st.session_state.process_button_clicked = False # Reset after processing attempt

    # --- Display Results and Download Button ---
    # MODIFIED: This block now always displays the DataFrame if results exist
    # and handles the download button, regardless of cancellation.
    if st.session_state.results and len(st.session_state.results) > 0:
        st.markdown("---") # Separator
        st.subheader("📊 Lookup Results")
        
        df_results = pd.DataFrame(st.session_state.results)
        column_order = ['domain', 'registrar', 'nameservers', 'creation_date', 'expiration_date', 'domain_status', 'lookup_status', 'lookup_method']
        
        for col in column_order: # Ensure all columns exist, fill with NA if not
            if col not in df_results.columns:
                df_results[col] = pd.NA
        df_results = df_results.reindex(columns=column_order)
        
        st.dataframe(df_results, use_container_width=True) # Display the DataFrame

        csv_data = df_results.to_csv(index=False).encode('utf-8')

        # Determine download button label based on whether all lookups were successful
        # or if processing was potentially partial.
        is_complete_and_successful = st.session_state.get('all_lookups_successful', False)
        
        # Further check: if we have valid_domains list and results count matches, and all successful
        if st.session_state.valid_domains and len(st.session_state.results) == len(st.session_state.valid_domains) and is_complete_and_successful:
            download_label = "Download Full Results as CSV"
            download_filename = "domain_lookup_results_full.csv"
        else: # Partial results or some failures
            download_label = "Download Partial/Current Results as CSV"
            download_filename = "domain_lookup_results_partial.csv"

        st.download_button(
            label=f"📥 {download_label}",
            data=csv_data,
            file_name=download_filename,
            mime="text/csv",
        )
    elif st.session_state.get("process_button_clicked") and not st.session_state.processing and not st.session_state.results:
        # This state means processing was attempted but yielded no results (e.g., only invalid domains)
        st.info("No results to display. Ensure valid domains were provided and processed.")


if __name__ == "__main__":
    main()
