# WHOIS Lookup Tool

A Streamlit-based web application for performing bulk domain WHOIS and RDAP lookups. This tool allows users to input multiple domain names and retrieve comprehensive registration information including registrar details, creation/expiration dates, nameservers, and domain status.

## Features

- **Bulk Domain Processing**: Handle multiple domains at once via text input or CSV upload
- **Multiple Lookup Methods**: Support for both WHOIS and RDAP protocols
- **Rate Limiting**: Built-in rate limiting (configurable 1-60 queries/minute) to avoid overwhelming servers
- **Input Validation**: Automatic domain name validation with URL parsing and normalization
- **Real-time Progress**: Live progress tracking and results display
- **Export Functionality**: CSV download for lookup results
- **Configurable Settings**: Adjustable timeout and rate limiting parameters

## Installation

Install the required dependencies:

```bash
pip install streamlit python-whois ratelimit pandas
```

## Usage

Start the Streamlit application:

```bash
streamlit run whois_lookup.py
```

The application will be available at `http://localhost:8501`

## Configuration

The application includes several configurable parameters:

- **Lookup Timeout**: 1-30 seconds (default: 10 seconds)
- **Rate Limiting**: 1-60 queries per minute (default: 10 queries/minute)
- **Lookup Method**: Choose between WHOIS or RDAP protocols

## Input Methods

1. **Text Area**: Enter domain names separated by new lines
2. **CSV Upload**: Upload a CSV file with domain names

## Output

The application provides:

- Real-time results table with domain information
- Success/failure status for each lookup
- CSV export functionality (available when lookups are successful)
- Progress tracking during bulk operations

## Technical Details

- Built with Streamlit for the web interface
- Uses `python-whois` library for WHOIS queries
- Implements RDAP protocol for alternative lookups
- Session state management for tracking processing status
- Rate limiting to comply with server policies