import streamlit as st
import whois
from ratelimit import limits, sleep_and_retry
import pandas as pd
from typing import List
import logging
import socket
import re
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
        except:
            return None
    return None

@sleep_and_retry
@limits(calls=CALLS_PER_MINUTE, period=PERIOD)
def safe_whois_lookup(domain: str) -> dict:
    """
    Perform rate-limited WHOIS lookup for a single domain
    """
    # Set socket timeout
    original_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(WHOIS_TIMEOUT)
    
    try:
        result = whois.whois(domain)
        if result is None:
            return {
                'domain': domain,
                'registrar': None,
                'creation_date': None,
                'expiration_date': None,
                'domain_status': None,
                'lookup_status': 'error: No data found'
            }
        
        # Clean dates before adding to dictionary
        creation_date = clean_date(result.creation_date if hasattr(result, 'creation_date') else None)
        expiration_date = clean_date(result.expiration_date if hasattr(result, 'expiration_date') else None)
        
        # Get registrar information
        registrar = result.registrar if hasattr(result, 'registrar') else None
        if isinstance(registrar, list):
            registrar = registrar[0] if registrar else None
            
        # Get domain status
        domain_status = result.status if hasattr(result, 'status') else None
        if isinstance(domain_status, list):
            domain_status = ', '.join(domain_status)
        elif isinstance(domain_status, str):
            domain_status = domain_status
        else:
            domain_status = None
            
        return {
            'domain': domain,
            'registrar': registrar,
            'creation_date': creation_date,
            'expiration_date': expiration_date,
            'domain_status': domain_status,
            'lookup_status': 'success'
        }
    except socket.timeout:
        logger.error(f"Timeout error for {domain}")
        return {
            'domain': domain,
            'registrar': None,
            'creation_date': None,
            'expiration_date': None,
            'domain_status': None,
            'lookup_status': 'error: Connection timed out'
        }
    except Exception as e:
        logger.error(f"Error looking up {domain}: {str(e)}")
        return {
            'domain': domain,
            'registrar': None,
            'creation_date': None,
            'expiration_date': None,
            'domain_status': None,
            'lookup_status': f'error: {str(e)}'
        }
    finally:
        # Restore original timeout
        socket.setdefaulttimeout(original_timeout)

def process_domains(domains: List[str]) -> pd.DataFrame:
    """
    Process a list of domains with rate limiting
    """
    results = []
    for domain in domains:
        result = safe_whois_lookup(domain)
        results.append(result)
    return pd.DataFrame(results)

def is_valid_domain(domain: str) -> tuple[bool, str]:
    """
    Validate if a string is a properly formatted domain name.
    Returns (is_valid, error_message)
    """
    # Remove any whitespace and convert to lowercase
    domain = domain.strip().lower()
    
    # Remove any protocol and path if present
    try:
        parsed = urlparse(domain)
        if parsed.netloc:
            domain = parsed.netloc
        elif parsed.path:
            domain = parsed.path
    except:
        return False, "Invalid URL format"
    
    # Remove www. if present
    if domain.startswith('www.'):
        domain = domain[4:]
    
    # Domain name regex pattern
    pattern = r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$'
    
    if not domain:
        return False, "Empty domain name"
    
    if len(domain) > 253:
        return False, "Domain name too long"
    
    if not re.match(pattern, domain):
        return False, "Invalid domain name format"
    
    return True, domain

def main():
    global WHOIS_TIMEOUT
    
    # Make the layout wider
    st.set_page_config(layout="wide")
    
    st.title("Bulk WHOIS Lookup Tool")
    st.write("Enter domain names (one per line) to perform WHOIS lookups")

    # Initialize session state variables
    if "processing" not in st.session_state:
        st.session_state["processing"] = False
    
    if "valid_domains" not in st.session_state:
        st.session_state["valid_domains"] = []

    # Add timeout configuration in the UI
    col1, col2 = st.columns(2)
    with col1:
        timeout = st.number_input(
            "WHOIS Timeout (seconds)",
            min_value=1,
            max_value=30,
            value=WHOIS_TIMEOUT,
            help="Maximum time to wait for WHOIS server response"
        )
    with col2:
        rate_limit = st.number_input(
            "Queries per minute",
            min_value=1,
            max_value=60,
            value=CALLS_PER_MINUTE,
            help="Number of WHOIS queries allowed per minute"
        )

    domains_text = st.text_area(
        "Domain Names",
        placeholder="example.com\nexample.org\nexample.net",
        height=200
    )

    # Create columns for the buttons
    col1, col2 = st.columns(2)
    
    # Place buttons in separate columns
    start_button = col1.button("Perform Lookups")
    cancel_button = col2.button("Cancel")

    if start_button:
        if not domains_text.strip():
            st.warning("Please enter at least one domain name.")
            return
            
        # Validate domains before starting
        raw_domains = [d.strip() for d in domains_text.split('\n') if d.strip()]
        valid_domains = []
        invalid_domains = []
        
        for domain in raw_domains:
            is_valid, result = is_valid_domain(domain)
            if is_valid:
                valid_domains.append(result)
            else:
                invalid_domains.append((domain, result))
        
        # Show validation results
        if invalid_domains:
            st.error("The following entries are not valid domain names:")
            for domain, error in invalid_domains:
                st.write(f"- {domain}: {error}")
            
            if not valid_domains:
                return
            
            st.warning(f"Proceeding with {len(valid_domains)} valid domain(s)")
        
        st.session_state.processing = True
        st.session_state.valid_domains = valid_domains

    if cancel_button:
        st.session_state.processing = False
        st.session_state.valid_domains = []
        st.warning("Operation cancelled by user.")
        return

    if st.session_state.processing and st.session_state.valid_domains:
        progress_bar = st.progress(0)
        status_text = st.empty()
        results_container = st.empty()
        
        total_domains = len(st.session_state.valid_domains)
        results = []
        
        # Update timeout
        WHOIS_TIMEOUT = timeout
        
        for idx, domain in enumerate(st.session_state.valid_domains, 1):
            # Check if cancel was pressed
            if not st.session_state.processing:
                status_text.text("Operation cancelled!")
                break
                
            remaining = total_domains - idx
            status_text.text(f"Processing {domain}... ({idx}/{total_domains} completed, {remaining} remaining)")
            result = safe_whois_lookup(domain)
            results.append(result)
            
            progress = idx / total_domains
            progress_bar.progress(progress)
            
            # Create DataFrame
            df = pd.DataFrame(results)
            
            # Convert to datetime after ensuring all values are proper strings
            if 'creation_date' in df.columns:
                df['creation_date'] = pd.to_datetime(df['creation_date'], errors='coerce', utc=True)
            if 'expiration_date' in df.columns:
                df['expiration_date'] = pd.to_datetime(df['expiration_date'], errors='coerce', utc=True)
            
            # Reorder columns for better display
            column_order = ['domain', 'registrar', 'creation_date', 'expiration_date', 'domain_status', 'lookup_status']
            df = df.reindex(columns=column_order)
            
            # Display the DataFrame with custom styling
            results_container.dataframe(
                df,
                use_container_width=True,
                hide_index=True
            )
        
        if st.session_state.processing:
            status_text.text(f"Complete! Processed {total_domains} domains.")
            
            # Add download button for results
            if results:
                csv = df.to_csv(index=False)
                st.download_button(
                    label="Download Results as CSV",
                    data=csv,
                    file_name="whois_results.csv",
                    mime="text/csv"
                )
        
        # Reset processing state
        st.session_state.processing = False
        st.session_state.valid_domains = []
        
    elif start_button and not domains_text.strip():
        st.warning("Please enter at least one domain name.")

if __name__ == "__main__":
    main()
