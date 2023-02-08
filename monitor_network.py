import os
import requests
import socket
import ipaddress
import re
import datetime
import subprocess

from typing import List, Tuple

# Env vars
SENDGRID_API_KEY = os.environ['SENDGRID_API_KEY']
NOTIFICATION_EMAIL_SOURCE = os.environ.get(
    'NOTIFICATION_EMAIL_SOURCE', "asn-monitor@automation-mail.ewpratten.com")
NOTIFICATION_EMAIL_DEST = os.environ['NOTIFICATION_EMAIL_DEST']
TARGET_ROUTE_SET = os.environ['TARGET_ROUTE_SET']
WHOIS_SERVER = os.environ.get('WHOIS_SERVER', "rr.arin.net")
CLOUDFLARE_TOKEN = os.environ['CLOUDFLARE_TOKEN']
ASN = os.environ['ASN']


def send_email(source_address: str, dest_address: str, subject: str,
               body: str):
    """Uses the SendGrid API to send an email.

    Args:
        source_address (str): Address to send from
        dest_address (str): Address to send to
        subject (str): Email subject
        body (str): Email body

    Raises:
        Exception: API error
    """

    print(f"Sending email from {source_address} to {dest_address}")
    response = requests.post(
        "https://api.sendgrid.com/v3/mail/send",
        headers={"Authorization": f"Bearer {SENDGRID_API_KEY}"},
        json={
            "personalizations": [{
                "to": [{
                    "email": dest_address
                }]
            }],
            "from": {
                "email": source_address
            },
            "subject": subject,
            "content": [{
                "type": "text/plain",
                "value": body
            }]
        })

    if int(response.status_code / 100) != 2:
        raise Exception(
            f"Sendgrid API returned status code {response.status_code} with message {response.text}"
        )


def get_monitored_prefixes(
) -> List[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Get a list of prefixes to monitor.

    Returns:
        List[IPv4Network | IPv6Network]: List of IP prefixes
    """

    # Make a whois request to get the list of prefixes
    print(f"Querying {WHOIS_SERVER} for {TARGET_ROUTE_SET}")
    whois_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    whois_socket.connect((WHOIS_SERVER, 43))
    whois_socket.sendall(f"{TARGET_ROUTE_SET}\n".encode())

    whois_response = whois_socket.recv(4096).decode()
    whois_socket.close()

    # Parse the response
    prefixes: List[str] = []
    for line in whois_response.splitlines():
        if line.startswith("members:"):
            prefixes.extend(line.split(":", 1)[1].strip().split(" "))
        elif line.startswith("mp-members:"):
            prefixes.extend(line.split(":", 1)[1].strip().split(" "))

    # Convert the prefixes to objects
    return [ipaddress.ip_network(prefix) for prefix in prefixes]


def get_zone_for_prefix(
        prefix: ipaddress.IPv4Network | ipaddress.IPv6Network) -> str:
    """Converts a prefix to the zone name used in Cloudflare.

    Args:
        prefix (ipaddress.IPv4Network | ipaddress.IPv6Network): Prefix to convert

    Returns:
        str: Cloudflare zone name
    """

    # Explode the prefix
    exploded = re.split(r"\.|:", prefix.network_address.exploded)

    # Strip off the appropriate number of octets based on the prefix length
    octets_to_strip = 0
    if prefix.version == 4:
        octets_to_strip = (32 - prefix.prefixlen) // 8
    elif prefix.version == 6:
        x = []
        for chunk in exploded:
            x.extend(list(chunk))
        exploded = x
        octets_to_strip = (128 - prefix.prefixlen) // 4

    # Reverse the octets and convert to a .arpa domain
    exploded.reverse()
    exploded = exploded[octets_to_strip:]
    return ".".join(
        exploded) + ".in-addr.arpa" if prefix.version == 4 else ".".join(
            exploded) + ".ip6.arpa"


def list_ptrs_for_zone(zone_name: str) -> List[Tuple[str, str]]:
    """Fetches a list of all PTR records for a CloudFlare zone.

    Args:
        zone_name (str): Name of the zone to query

    Raises:
        Exception: API error
    Returns:
        List[Tuple[str, str]]: Ptr records (domain, content)
    """

    # Convert the zone name to a zone ID
    print(f"Querying Cloudflare API for zone ID for zone {zone_name}")
    response = requests.get("https://api.cloudflare.com/client/v4/zones",
                            headers={
                                "Authorization": f"Bearer {CLOUDFLARE_TOKEN}",
                                "Content-Type": "application/json"
                            })

    # Check the response
    if int(response.status_code / 100) != 2:
        raise Exception(
            f"Cloudflare API returned status code {response.status_code} with message {response.text}"
        )

    # Parse the response and get the zone ID
    data = response.json()
    zone_id = None
    for zone in data["result"]:
        if zone["name"] == zone_name:
            zone_id = zone["id"]
            break

    if zone_id is None:
        raise Exception(f"Could not find zone ID for zone {zone_name}")

    # Make a request to the Cloudflare API
    print(f"Querying Cloudflare API for PTR records in zone {zone_id}")
    response = requests.get(
        f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?type=PTR",
        headers={
            "Authorization": f"Bearer {CLOUDFLARE_TOKEN}",
            "Content-Type": "application/json"
        })

    # Check the response
    if int(response.status_code / 100) != 2:
        raise Exception(
            f"Cloudflare API returned status code {response.status_code} with message {response.text}"
        )

    # Parse the response
    data = response.json()
    records: List[Tuple[str, str]] = []
    for record in data["result"]:
        records.append((record["name"], record["content"]))

    return records


def arpa_domain_to_ip(
        domain: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """COnverts an .arpa domain to an IP address.

    Args:
        domain (str): FQDN of the .arpa domain

    Returns:
        ipaddress.IPv4Address | ipaddress.IPv6Address: IP address
    """

    if "in-addr" in domain:
        # IPv4
        exploded = domain.split(".")
        exploded.reverse()
        return ipaddress.IPv4Address(".".join(exploded[2:]))
    elif "ip6" in domain:
        # IPv6
        exploded = domain.split(".")
        exploded.reverse()
        exploded = exploded[2:]
        exploded = [
            "".join(exploded[i:i + 4]) for i in range(0, len(exploded), 4)
        ]
        return ipaddress.IPv6Address(":".join(exploded))


def main():

    # Get a list of prefixes to work with
    prefixes = get_monitored_prefixes()

    # Get a list of PTR records pointing to hosts in the monitored prefixes
    ptrs: List[Tuple[str, str]] = []
    for prefix in prefixes:
        zone_name = get_zone_for_prefix(prefix)
        ptrs.extend(list_ptrs_for_zone(zone_name))
    print(f"Found {len(ptrs)} PTR records")

    # Convert that list to a list of IPs that we know are in use
    used_ips: List[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for ptr in ptrs:
        used_ips.append(arpa_domain_to_ip(ptr[0]))

    # Split the addresses into IPv4 and IPv6
    used_v4 = [ip for ip in used_ips if isinstance(ip, ipaddress.IPv4Address)]
    used_v6 = [ip for ip in used_ips if isinstance(ip, ipaddress.IPv6Address)]

    # Run nmap scans for all used hosts
    print("Running IPv4 nmap scan")
    nmap_v4 = subprocess.run(["nmap"] + [str(addr) for addr in used_v4],
                             capture_output=True)
    print("Running IPv6 nmap scan")
    nmap_v6 = subprocess.run(["nmap", "-6"] + [str(addr) for addr in used_v6],
                             capture_output=True)
    nmap_v4_output = "\n".join([
        f"> {line}" for line in nmap_v4.stdout.decode("utf-8").splitlines()
    ])
    nmap_v6_output = "\n".join([
        f"> {line}" for line in nmap_v6.stdout.decode("utf-8").splitlines()
    ])

    # Track all hosts that have a PTR record but no A or AAAA record
    hosts_without_dns: List[str] = []
    for arpa, hostname in ptrs:

        # Use NSLookup to check if the hostname has an A or AAAA record
        nslookup = subprocess.run(["nslookup", hostname], capture_output=True)

        if "can't find" in nslookup.stdout.decode("utf-8").lower():
            hosts_without_dns.append(
                f" - {arpa_domain_to_ip(arpa)} {hostname}")
    hosts_without_dns = "\n".join(hosts_without_dns)
    
    # Construct the email body
    date_time = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    date = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    rs_prefix_list = "\n".join([f" - {prefix}" for prefix in prefixes])
    email_body = f"""
This is an automated email from the ASN monitoring system.
This report was generated at {date_time}

Prefixes to monitor have been obtained from: {TARGET_ROUTE_SET}
Current route-set members are: 
{rs_prefix_list}

IPv4 NETWORK SCAN RESULTS:
{nmap_v4_output}

IPv6 NETWORK SCAN RESULTS:
{nmap_v6_output}

HOSTS WITH PTR BUT NO A OR AAAA RECORDS:
{hosts_without_dns}

"""[1:]

    # Send the email
    print("Sending email")
    send_email(NOTIFICATION_EMAIL_SOURCE, NOTIFICATION_EMAIL_DEST,
               f"ASN Monitoring Report for AS{ASN} on {date}", email_body)


if __name__ == "__main__":
    main()