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


def safe_rdap_lookup(domain: str) -> dict:
    """
    Perform RDAP lookup for a single domain
    """
    try:
        # First, try to get the RDAP URL for the domain
        bootstrap_url = f"https://rdap.org/domain/{domain}"
        response = requests.get(bootstrap_url, timeout=WHOIS_TIMEOUT)

        if response.status_code != 200:
            return {
                'domain': domain,
                'registrar': None,
                'creation_date': None,
                'expiration_date': None,
                'domain_status': None,
                'nameservers': None,
                'lookup_status': f'error: RDAP lookup failed with status {response.status_code}',
                'lookup_method': 'RDAP'  # Add this line
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
            'creation_date': creation_date,
            'expiration_date': expiration_date,
            'domain_status': domain_status,
            'nameservers': nameservers,
            'lookup_status': 'success',
            'lookup_method': 'RDAP'  # Add this line
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
            'lookup_method': 'RDAP'  # Add this line
        }
    except Exception as e:
        logger.error(f"Error looking up {domain}: {str(e)}")
        return {
            'domain': domain,
            'registrar': None,
            'creation_date': None,
            'expiration_date': None,
            'domain_status': None,
            'nameservers': None,
            'lookup_status': f'error: {str(e)}',
            'lookup_method': 'RDAP'  # Add this line
        }



@sleep_and_retry
@limits(calls=CALLS_PER_MINUTE, period=PERIOD)
def safe_whois_lookup(domain: str) -> dict:
    """
    Perform rate-limited WHOIS lookup for a single domain
    """
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
                'nameservers': None,
                'lookup_status': 'error: No data found',
                'lookup_method': 'WHOIS'  # Add this line
            }

        # Clean dates
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
            
        # Get nameservers
        nameservers = result.name_servers if hasattr(result, 'name_servers') else None
        if isinstance(nameservers, list):
            nameservers = ', '.join(sorted(nameservers))
        elif isinstance(nameservers, str):
            nameservers = nameservers
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
            'lookup_method': 'WHOIS'  # Add this line
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
            'nameservers': None,
            'lookup_status': f'error: {str(e)}'
        }
    finally:
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
    
    st.title("Bulk Domain Lookup Tool")
    st.write("Enter domain names (one per line) to perform lookups")

    # Initialize session state variables
    if "processing" not in st.session_state:
        st.session_state["processing"] = False
    
    if "valid_domains" not in st.session_state:
        st.session_state["valid_domains"] = []

    # Add configuration options
    col1, col2, col3 = st.columns(3)
    with col1:
        timeout = st.number_input(
            "Lookup Timeout (seconds)",
            min_value=1,
            max_value=30,
            value=WHOIS_TIMEOUT,
            help="Maximum time to wait for server response"
        )
    with col2:
        rate_limit = st.number_input(
            "Queries per minute",
            min_value=1,
            max_value=60,
            value=CALLS_PER_MINUTE,
            help="Number of queries allowed per minute"
        )
    with col3:
        lookup_type = st.selectbox(
            "Lookup Type",
            options=["WHOIS", "RDAP"],
            help="Choose between WHOIS or RDAP lookup"
        )

    # Text area for domain input
    domains_text = st.text_area(
        "Enter domains (one per line)",
        placeholder="google.com\namazon.com\nmicrosoft.com\napple.com\nfacebook.com",
        height=200,
        help="Enter one domain name per line"
    )

    # Process domains when submitted
    if st.button("Process Domains"):
        # Reset the processing state
        st.session_state.processing = True
        
        # Parse and validate domains
        domains = [d.strip().lower() for d in domains_text.split('\n') if d.strip()]
        valid_domains = []
        invalid_domains = []
        
        for domain in domains:
            if is_valid_domain(domain):
                valid_domains.append(domain)
            else:
                invalid_domains.append(domain)
        
        # Store valid domains in session state
        st.session_state.valid_domains = valid_domains
        
        # Show validation results
        if invalid_domains:
            st.error(f"Found {len(invalid_domains)} invalid domains: {', '.join(invalid_domains)}")
        
        if not valid_domains:
            st.error("No valid domains found to process!")
            st.session_state.processing = False
            return
        
        st.info(f"Found {len(valid_domains)} valid domains to process")

    # Cancel button
    if st.session_state.processing:
        if st.button("Cancel"):
            st.session_state.processing = False
            st.warning("Cancelling operation...")

    # Process domains if we're in processing state and have valid domains
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
            
            # Use the selected lookup method
            if lookup_type == "WHOIS":
                result = safe_whois_lookup(domain)
            else:
                result = safe_rdap_lookup(domain)
                
            results.append(result)
            
            # Update progress
            progress = idx / total_domains
            progress_bar.progress(progress)
            
            # Create DataFrame and display results so far
            df = pd.DataFrame(results)
            
            # Reorder columns for better display
            column_order = ['domain', 'registrar', 'nameservers', 'creation_date', 'expiration_date', 'domain_status', 'lookup_status', 'lookup_method']
            df = df.reindex(columns=column_order)
            
            # Display results
            results_container.dataframe(df)
            
            # Rate limiting
            time.sleep(60/rate_limit)
        
        # Final status update
        if st.session_state.processing:
            status_text.text("Processing complete!")
        
        # Reset processing state
        st.session_state.processing = False
        
        # Add download button for CSV
        if results:
            csv = df.to_csv(index=False)
            st.download_button(
                label="Download results as CSV",
                data=csv,
                file_name="domain_lookup_results.csv",
                mime="text/csv"
            )

if __name__ == "__main__":
    main()

