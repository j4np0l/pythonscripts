#!/usr/bin/env python3

import argparse
import socket
import requests
import concurrent.futures
import sys
from urllib.parse import urlparse, urljoin

# Try importing dns.resolver, guide user if missing
try:
    import dns.resolver
    import dns.exception
except ImportError:
    print("[-] Error: 'dnspython' library not found.")
    print("[-] Please install it using: pip install dnspython")
    sys.exit(1)

# Suppress InsecureRequestWarning for self-signed certs
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# --- Configuration ---
# Common subdomains to check (can be expanded significantly)
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "admin", "panel", "test", "dev", "staging", "api", "app", "blog", "shop",
    "support", "docs", "portal", "vpn", "m", "owa", "intranet", "internal",
    "secure", "static", "cdn", "status", "beta", "prod", "uat", "demo",
    "v1", "v2", "v3", "graphql", "ws", "chat", "files", "images", "assets"
]

# Common web ports
WEB_PORTS = [80, 443]

# Common API paths to check
API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3", "/v1", "/v2", "/v3",
    "/rest", "/graphql", "/swagger.json", "/openapi.json", "/swagger/v1/swagger.json",
    "/api/swagger.json", "/api/openapi.json", "/.well-known/openid-configuration"
]

# User-Agent for requests
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
}

# Timeout for requests (seconds)
TIMEOUT = 5

# Max workers for threading
MAX_WORKERS = 20
# ---------------------

def resolve_subdomain(domain, subdomain_to_check):
    """
    Attempts to resolve a subdomain using DNS.
    Returns the subdomain if resolution is successful, None otherwise.
    """
    target = f"{subdomain_to_check}.{domain}"
    try:
        # Use system default resolver
        resolver = dns.resolver.Resolver()
        resolver.resolve(target, 'A') # Check for A record
        # print(f"[+] Resolved: {target}") # Debugging
        return target
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout, dns.resolver.NoNameservers):
        # Expected errors if subdomain doesn't exist or DNS fails
        pass
    except Exception as e:
        # Catch other potential DNS errors
        print(f"[-] DNS Error resolving {target}: {e}", file=sys.stderr)
    return None

def find_subdomains(domain):
    """
    Finds subdomains using a predefined list and DNS resolution concurrently.
    """
    print(f"[*] Starting subdomain enumeration for: {domain}")
    found_subdomains = set()
    # Add the base domain itself
    found_subdomains.add(domain)

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # Create futures for each subdomain check
        future_to_subdomain = {executor.submit(resolve_subdomain, domain, sub): sub for sub in COMMON_SUBDOMAINS}

        for future in concurrent.futures.as_completed(future_to_subdomain):
            result = future.result()
            if result:
                found_subdomains.add(result)
                print(f"[+] Found Subdomain: {result}")

    print(f"[*] Found {len(found_subdomains) -1} potential subdomains (plus base domain).") # -1 because base domain was added initially
    return list(found_subdomains)

def check_web_server(target):
    """
    Checks if a web server is running on standard HTTP/HTTPS ports for a given target (domain or subdomain).
    Returns a list of base URLs (e.g., http://target, https://target) if a server responds.
    """
    web_app_urls = []
    for port in WEB_PORTS:
        scheme = "https" if port == 443 else "http"
        url = f"{scheme}://{target}:{port}" if port not in [80, 443] else f"{scheme}://{target}"

        try:
            # Use HEAD request to be lighter, fallback to GET if needed
            response = requests.head(url, headers=HEADERS, timeout=TIMEOUT, verify=False, allow_redirects=True)
            # Consider any 2xx, 3xx, or 401/403 as indicators of a web server
            if response.status_code < 500:
                 # Sometimes HEAD is disallowed, try GET
                 if response.status_code in [405, 404] and scheme == "http": # Only retry GET on HTTP for speed
                     try:
                         response_get = requests.get(url, headers=HEADERS, timeout=TIMEOUT, verify=False, allow_redirects=True, stream=True)
                         if response_get.status_code < 500:
                             print(f"[+] Found Web App: {url} (Status: {response_get.status_code})")
                             web_app_urls.append(url)
                         response_get.close() # Close stream
                     except requests.exceptions.RequestException:
                         pass # Ignore GET error if HEAD already failed differently
                 else:
                    print(f"[+] Found Web App: {url} (Status: {response.status_code})")
                    web_app_urls.append(url)

        except requests.exceptions.Timeout:
            # print(f"[-] Timeout connecting to {url}") # Verbose
            pass
        except requests.exceptions.ConnectionError:
            # print(f"[-] Connection error for {url}") # Verbose
            pass
        except requests.exceptions.RequestException as e:
            print(f"[-] Error checking {url}: {e}", file=sys.stderr)

    return web_app_urls

def find_api_endpoints(base_url):
    """
    Checks for common API endpoints on a given base web application URL.
    """
    found_apis = []
    print(f"[*] Checking for API endpoints on: {base_url}")
    for path in API_PATHS:
        api_url = urljoin(base_url, path) # Handles relative paths correctly
        try:
            response = requests.get(api_url, headers=HEADERS, timeout=TIMEOUT, verify=False, allow_redirects=False) # Don't follow redirects for APIs usually
            # Look for successful responses or specific API indicators
            # 401/403 often mean the endpoint exists but requires auth
            if response.status_code in [200, 201, 204, 401, 403]:
                 # Check content type for json (common for APIs)
                content_type = response.headers.get('Content-Type', '').lower()
                if 'json' in content_type or response.status_code in [401, 403]: # Assume 401/403 are API related
                    print(f"[+] Potential API Endpoint: {api_url} (Status: {response.status_code}, Content-Type: {content_type})")
                    found_apis.append(api_url)
                # Add more specific checks here if needed (e.g., looking for 'swagger', 'openapi' in content)

        except requests.exceptions.Timeout:
            pass # Ignore timeouts
        except requests.exceptions.ConnectionError:
            pass # Ignore connection errors
        except requests.exceptions.RequestException as e:
            print(f"[-] Error checking API path {api_url}: {e}", file=sys.stderr)
    return found_apis

def main():
    parser = argparse.ArgumentParser(description="Discover subdomains, web applications, and API endpoints for a given domain.")
    parser.add_argument("domain", help="The target domain (e.g., example.com)")
    parser.add_argument("-w", "--wordlist", help="Path to a custom subdomain wordlist file (one subdomain per line). Overrides internal list.", default=None)
    parser.add_argument("-t", "--threads", help="Number of threads for subdomain enumeration.", type=int, default=MAX_WORKERS)
    parser.add_argument("--timeout", help="Request timeout in seconds.", type=int, default=TIMEOUT)


    args = parser.parse_args()
    domain = args.domain
    global MAX_WORKERS, TIMEOUT, COMMON_SUBDOMAINS

    MAX_WORKERS = args.threads
    TIMEOUT = args.timeout

    # Override common subdomains if a wordlist is provided
    if args.wordlist:
        try:
            with open(args.wordlist, 'r') as f:
                COMMON_SUBDOMAINS = [line.strip() for line in f if line.strip()]
            print(f"[*] Using custom wordlist: {args.wordlist} ({len(COMMON_SUBDOMAINS)} entries)")
        except FileNotFoundError:
            print(f"[-] Error: Wordlist file not found: {args.wordlist}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"[-] Error reading wordlist file {args.wordlist}: {e}", file=sys.stderr)
            sys.exit(1)


    # --- Stage 1: Find Subdomains ---
    subdomains = find_subdomains(domain)
    if not subdomains:
        print("[-] No subdomains found (including base domain). Exiting.")
        sys.exit(0)

    all_web_apps = []
    all_api_endpoints = []

    # --- Stage 2: Find Web Apps ---
    print("\n[*] Starting web application discovery...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_webcheck = {executor.submit(check_web_server, sub): sub for sub in subdomains}
        for future in concurrent.futures.as_completed(future_to_webcheck):
            web_apps = future.result()
            if web_apps:
                all_web_apps.extend(web_apps)

    if not all_web_apps:
        print("[-] No running web applications found on standard ports.")
    else:
        print(f"\n[*] Found {len(all_web_apps)} potential web application URLs.")

    # --- Stage 3: Find API Endpoints ---
    print("\n[*] Starting API endpoint discovery...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_apicheck = {executor.submit(find_api_endpoints, base_url): base_url for base_url in all_web_apps}
        for future in concurrent.futures.as_completed(future_to_apicheck):
            apis = future.result()
            if apis:
                all_api_endpoints.extend(apis)

    # --- Final Summary ---
    print("\n" + "="*40)
    print("          Scan Summary")
    print("="*40)
    print(f"Target Domain: {domain}")

    print("\n--- Found Subdomains ---")
    if len(subdomains) > 1 or domain in subdomains : # Check if more than just base domain or if base domain itself resolved
        # Sort alphabetically for clarity, keeping base domain separate if needed
        sorted_subs = sorted([s for s in subdomains if s != domain])
        print(f"- {domain} (Base Domain)")
        for sub in sorted_subs:
            print(f"- {sub}")
    else:
        print("None (excluding base domain).")


    print("\n--- Found Web Applications (HTTP/HTTPS) ---")
    if all_web_apps:
        for app_url in sorted(list(set(all_web_apps))): # Use set to remove potential duplicates
            print(f"- {app_url}")
    else:
        print("None.")

    print("\n--- Found Potential API Endpoints ---")
    if all_api_endpoints:
        for api_url in sorted(list(set(all_api_endpoints))): # Use set to remove potential duplicates
            print(f"- {api_url}")
    else:
        print("None.")

    print("\n" + "="*40)
    print("[*] Scan Finished.")


if __name__ == "__main__":
    # Ensure dnspython is available before running main
    if 'dns.resolver' in sys.modules:
        main()
    else:
        # Error message already printed during import attempt
        sys.exit(1)
