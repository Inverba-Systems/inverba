"""
SSRF-safe address validation for the notary.

The notary fetches attacker-supplied URLs from Inverba infrastructure, so an SSRF
here is critical. The ONLY correct defense is to resolve the hostname to a real
IP and validate the *resolved address* -- never to blacklist URL string formats,
because there are always more encodings (decimal, octal, hex, short-form, IPv6,
IPv4-mapped IPv6, mixed). `http://2852039166/` and `http://169.254.169.254/`
resolve to the same address; only checking the resolved address catches both.

Residual DNS-rebinding window (documented honestly, not hidden): this validates
the address the resolver returns, then the HTTP client resolves again when it
connects. A hostname that returns a public address here and a private one on the
connect (TTL=0 rebinding) is not fully closed at this layer. `validated_ips()`
exposes the checked addresses so a caller that can pin the connection to them
(connect-by-IP) may do so; where the client cannot pin, this window remains and
is the reason the notary also runs behind network-layer egress controls in a
real deployment. What IS closed here: every string-encoding of a private/metadata
address, and per-hop redirect targets (see notary._safe_fetch).
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

# Cloud metadata endpoints (also covered by link-local, listed for clarity).
_METADATA = {
    ipaddress.ip_address("169.254.169.254"),   # AWS/GCP/Azure IMDS
    ipaddress.ip_address("fd00:ec2::254"),       # AWS IMDS over IPv6
}


class SSRFError(Exception):
    """Raised when a URL resolves to a disallowed (internal) address."""


def is_disallowed_ip(ip) -> bool:
    """True if `ip` is private/loopback/link-local/reserved/multicast/unspecified
    or a known cloud-metadata address. IPv4-mapped IPv6 is unwrapped first."""
    if isinstance(ip, str):
        ip = ipaddress.ip_address(ip)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_reserved or ip.is_multicast or ip.is_unspecified
            or ip in _METADATA)


def default_resolver(host: str) -> list[str]:
    """Resolve a hostname to all its IP addresses via the OS resolver.

    getaddrinfo also normalizes non-canonical literals (decimal/octal/hex/short
    IPv4), so those encodings are validated as their real address."""
    infos = socket.getaddrinfo(host, None)
    return [info[4][0] for info in infos]


def validate_public_url(url: str, resolver=default_resolver) -> list[str]:
    """Resolve `url`'s host and confirm EVERY resolved address is public.

    Returns the validated IP strings (so a caller may pin to them). Raises
    SSRFError if the host is missing, unresolvable, or any resolved address is
    disallowed."""
    host = urlparse(url).hostname
    if not host:
        raise SSRFError("URL has no host")
    try:
        ips = resolver(host)
    except (socket.gaierror, OSError) as e:
        raise SSRFError(f"cannot resolve host {host!r}: {e}")
    if not ips:
        raise SSRFError(f"host {host!r} did not resolve to any address")
    for ip in ips:
        try:
            if is_disallowed_ip(ip):
                raise SSRFError(
                    f"host {host!r} resolves to disallowed address {ip} "
                    "(private/loopback/link-local/reserved/metadata)")
        except ValueError:
            raise SSRFError(f"host {host!r} resolved to an unparseable address {ip!r}")
    return list(ips)
