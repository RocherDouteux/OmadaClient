import logging
import socket

logger = logging.getLogger(__name__)

def resolve_fqdns_to_ipv4(fqdns):
    results = {}

    for fqdn in fqdns:
        try:
            addr_info = socket.getaddrinfo(fqdn, None, socket.AF_INET)  # Only IPv4
            ips = list({result[4][0] for result in addr_info})
            results[fqdn] = ips
        except socket.gaierror as e:
            logger.error(f"Failed to resolve FQDN '{fqdn}': {e}")
            results[fqdn] = []

    logger.info(f"FQDNs resolved to IPs: {results}")
    return results