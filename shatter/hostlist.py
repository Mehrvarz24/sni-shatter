"""sni-shatter — hostlist support.

A hostlist decides which connections the desync strategies apply to. Two
files are supported (both simple text, one entry per line, `#` comments):

  * include list ("hostlist"): only hosts on it get desync treatment;
    everything else passes through untouched.
  * exclude list ("hostlist_exclude"): hosts on it never get desync
    treatment; everything else does.

Entries may be:
  - plain domains:      youtube.com
  - wildcard subdomain: *.youtube.com   (also matches youtube.com itself)
  - IP addresses:       142.250.185.78
  - CIDR ranges:        142.250.0.0/15
"""
import ipaddress


def _match_entry(entry: str, host: str) -> bool:
    entry = entry.strip().lower().lstrip(".")
    host = (host or "").strip().lower().rstrip(".")
    if not entry or not host:
        return False
    # CIDR / IP
    if "/" in entry:
        try:
            return ipaddress.ip_address(host) in ipaddress.ip_network(entry)
        except ValueError:
            return False
    try:
        ipaddress.ip_address(entry)
        return entry == host
    except ValueError:
        pass
    # domain
    if entry.startswith("*."):
        base = entry[2:]
        return host == base or host.endswith("." + base)
    return host == entry or host.endswith("." + entry)


def load_hostlist(path) -> list:
    if not path:
        return []
    try:
        with open(path, encoding="utf-8") as f:
            return [ln.split("#", 1)[0].strip().lower()
                    for ln in f if ln.strip() and not ln.lstrip().startswith("#")]
    except OSError:
        return []


def host_allowed(host, cfg) -> bool:
    """True when `host` should receive desync treatment."""
    if not host:
        return True
    inc = cfg.get("_hostlist_inc")
    exc = cfg.get("_hostlist_exc")
    if inc is not None:
        for e in inc:
            if _match_entry(e, host):
                break
        else:
            return False
    if exc is not None:
        for e in exc:
            if _match_entry(e, host):
                return False
    return True


class HostList:
    """Compiled hostlist bound to a config; cached so files are read once."""

    def __init__(self, cfg):
        self.cfg = cfg

    def allowed(self, host) -> bool:
        if "_hostlist_inc" not in self.cfg and self.cfg.get("hostlist"):
            self.cfg["_hostlist_inc"] = load_hostlist(self.cfg["hostlist"])
        if "_hostlist_exc" not in self.cfg and self.cfg.get("hostlist_exclude"):
            self.cfg["_hostlist_exc"] = load_hostlist(self.cfg["hostlist_exclude"])
        return host_allowed(host, self.cfg)
