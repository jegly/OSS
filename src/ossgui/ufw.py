"""Firewall state and rules — BUILD_PLAN §4.6.

Everything goes through the ``ufw`` CLI; ``user.rules`` is never edited directly.
Rules are built from validated fields into an argv list, so nothing the user
types is ever interpolated into a shell.

What can be read without root:
  /etc/ufw/ufw.conf     ENABLED, LOGLEVEL
  /etc/default/ufw      DEFAULT_{INPUT,OUTPUT,FORWARD}_POLICY, IPV6
The rule list itself lives in root-only files, so it takes one privileged read.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path

ACTIONS = ("allow", "deny", "reject", "limit")
DIRECTIONS = ("in", "out")
PROTOCOLS = ("any", "tcp", "udp")
POLICIES = ("allow", "deny", "reject")
LOG_LEVELS = ("off", "low", "medium", "high", "full")

UFW_BIN = "/usr/sbin/ufw"

_PORT = re.compile(r"^\d{1,5}(:\d{1,5})?$")
_COMMENT = re.compile(r"^[A-Za-z0-9 ._:/()-]{0,64}$")
#: An application profile name as ufw prints it ("CUPS", "OpenSSH", "Samba").
_APP_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._+-]{0,63}$")
_CONF_LINE = re.compile(r"^\s*([A-Z_0-9]+)\s*=\s*\"?([^\"#]*)\"?")


class UfwError(ValueError):
    """A rule or policy we refuse to build a command from."""


# --------------------------------------------------------------------------- #
#  Model
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Rule:
    """One firewall rule, in the subset of ufw's grammar we support."""

    action: str = "deny"
    direction: str = "in"
    port: str = ""
    proto: str = "any"
    from_addr: str = "any"
    to_addr: str = "any"
    comment: str = ""
    #: True when ufw reported this rule as (v6) — the IPv6 half of a pair.
    v6: bool = False
    #: The application profile this rule was written against ("CUPS", "OpenSSH"),
    #: for rules `ufw status` reports by profile name instead of by port. Set
    #: only by parse_status; a rule this app builds itself never has one.
    app: str = ""

    @property
    def managed(self) -> bool:
        """Whether this app can build a ufw command for this rule.

        An application-profile rule names a profile from /etc/ufw/applications.d
        rather than a port and an address, and the port set behind that name is
        the profile's to change. This app neither builds nor deletes those: it
        shows them so the rule list is the truth, and leaves them alone.
        """
        return not self.app

    def validate(self) -> None:
        """Reject anything we would not be able to build a safe command from."""
        if self.action not in ACTIONS:
            raise UfwError(f"unknown action {self.action!r}")
        if self.direction not in DIRECTIONS:
            raise UfwError(f"unknown direction {self.direction!r}")
        if self.app:
            # An app-profile rule carries a name where a port and address would
            # be, so the port/address rules below do not apply to it. It is
            # still pattern-checked, because it reaches the UI as a label.
            if not _APP_NAME.match(self.app):
                raise UfwError(f"not an application profile name: {self.app!r}")
            return
        if self.proto not in PROTOCOLS:
            raise UfwError(f"unknown protocol {self.proto!r}")
        if self.port and not _PORT.match(self.port):
            raise UfwError(f"not a port or port range: {self.port!r}")
        if self.port:
            for part in self.port.split(":"):
                if not 0 < int(part) < 65536:
                    raise UfwError(f"port out of range: {part}")
            if ":" in self.port and self.proto == "any":
                # ufw requires an explicit protocol for a range.
                raise UfwError("a port range needs tcp or udp, not 'any'")
        for address in (self.from_addr, self.to_addr):
            _validate_address(address)
        if not _COMMENT.match(self.comment):
            raise UfwError("comment has characters that are not allowed")
        if not self.port and self.from_addr == "any" and self.to_addr == "any":
            raise UfwError("a rule needs at least a port or an address")

    def to_argv(self, delete: bool = False) -> list[str]:
        """The exact ufw invocation for this rule."""
        self.validate()
        if self.app:
            # Never guessed. `ufw allow CUPS` expands to whatever the profile
            # declares today, so re-issuing it is not the same operation as the
            # one that created the rule, and a wrong delete here would roll the
            # whole transaction back over a rule the user never touched.
            raise UfwError(
                f"{self.app} is an application-profile rule; this app does not "
                f"build ufw commands for those"
            )
        argv = [UFW_BIN]
        if delete:
            argv.append("delete")
        argv.append(self.action)
        argv.append(self.direction)

        simple = self.from_addr == "any" and self.to_addr == "any"
        if simple:
            argv.append(f"{self.port}/{self.proto}" if self.proto != "any" else self.port)
        else:
            argv += ["from", self.from_addr]
            argv += ["to", self.to_addr]
            if self.port:
                argv += ["port", self.port]
            if self.proto != "any":
                argv += ["proto", self.proto]
        if self.comment and not delete:
            argv += ["comment", self.comment]
        return argv

    @property
    def summary(self) -> str:
        if self.app:
            return f"{self.action} {self.direction} {self.app}"
        where = ""
        if self.from_addr != "any":
            where += f" from {self.from_addr}"
        if self.to_addr != "any":
            where += f" to {self.to_addr}"
        port = f"{self.port}/{self.proto}" if self.proto != "any" else self.port
        return f"{self.action} {self.direction} {port}{where}".strip()

    def key(self) -> tuple:
        """Identity for diffing, ignoring the comment."""
        return (
            self.action,
            self.direction,
            self.port,
            self.proto,
            self.from_addr,
            self.to_addr,
            self.v6,
            self.app,
        )


def _validate_address(address: str) -> None:
    if address == "any":
        return
    try:
        ipaddress.ip_network(address, strict=False)
    except ValueError as exc:
        raise UfwError(f"not an address or subnet: {address!r}") from exc


@dataclass
class State:
    """The whole firewall configuration."""

    enabled: bool = False
    logging: str = "low"
    ipv6: bool = True
    default_incoming: str = "deny"
    default_outgoing: str = "allow"
    default_routed: str = "deny"
    rules: list[Rule] = field(default_factory=list)
    #: False until a privileged read has actually loaded the rule list.
    rules_loaded: bool = False

    def copy(self) -> "State":
        return State(
            enabled=self.enabled,
            logging=self.logging,
            ipv6=self.ipv6,
            default_incoming=self.default_incoming,
            default_outgoing=self.default_outgoing,
            default_routed=self.default_routed,
            rules=list(self.rules),
            rules_loaded=self.rules_loaded,
        )

    def redundant_rules(self) -> list[Rule]:
        """Rules that only restate the default policy (§4.6 rule hygiene).

        With a default-deny-incoming policy, an explicit inbound deny for one
        port changes nothing. They are kept — they hold their position above any
        later allow — but folded away so the list stays readable.
        """
        out = []
        for rule in self.rules:
            policy = (
                self.default_incoming if rule.direction == "in" else self.default_outgoing
            )
            if rule.action in ("deny", "reject") and policy in ("deny", "reject"):
                out.append(rule)
        return out

    def missing_recommended(self) -> list[tuple[Rule, str]]:
        """Outbound allowances whose absence breaks something quietly (§4.6)."""
        if self.default_outgoing == "allow":
            return []

        suggestions = [
            (
                Rule("allow", "out", "53", "udp", comment="DNS"),
                "Plain DNS. Without it nothing resolves a name, which presents as "
                "every application being broken rather than as a firewall problem.",
            ),
            (
                Rule("allow", "out", "53", "tcp", comment="DNS over TCP"),
                "DNS falls back to TCP for large answers and for zone transfers. "
                "Allowing only UDP works until an answer does not fit in a datagram.",
            ),
            (
                Rule("allow", "out", "123", "udp", comment="NTP time sync"),
                "Without this systemd-timesyncd cannot reach a time server and the "
                "clock drifts — silently, because nothing reports it. A wrong clock "
                "then breaks TLS certificate validation.",
            ),
            (
                Rule("allow", "out", "853", "tcp", comment="DNS over TLS"),
                "Required the moment DNS over TLS is enabled. Without it name "
                "resolution stops dead.",
            ),
            (
                Rule("allow", "out", "67:68", "udp", comment="DHCP renewal"),
                "Some strict setups need this for DHCP lease renewal. Losing the "
                "lease takes the whole network interface with it.",
            ),
            (
                Rule("allow", "out", "443", "tcp", comment="HTTPS"),
                "Package updates, the software centre and almost everything else "
                "outbound. Denying it is defensible on a server and rarely on a "
                "desktop.",
            ),
            (
                Rule("allow", "out", "80", "tcp", comment="HTTP"),
                "Debian and Ubuntu mirrors still serve over plain HTTP, and OCSP "
                "and CRL certificate-revocation checks use it. Without it apt may "
                "hang rather than fail.",
            ),
        ]
        have = {(r.port, r.proto, r.direction) for r in self.rules if r.action == "allow"}
        return [
            (rule, why)
            for rule, why in suggestions
            if (rule.port, rule.proto, rule.direction) not in have
        ]


# --------------------------------------------------------------------------- #
#  Reading
# --------------------------------------------------------------------------- #


def _read_conf(path: str) -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return out
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        match = _CONF_LINE.match(line)
        if match:
            out[match.group(1)] = match.group(2).strip()
    return out


#: /etc/default/ufw stores the iptables target, not the word ufw's CLI takes.
#: Reading these as if they were "deny"/"allow" silently reports the wrong
#: policy — and this machine has DROP outgoing, which would have read as "allow".
_TARGET_TO_POLICY = {"drop": "deny", "accept": "allow", "reject": "reject"}


def read_unprivileged() -> State:
    """Everything readable without root: policies, logging, enabled, IPv6."""
    conf = _read_conf("/etc/ufw/ufw.conf")
    defaults = _read_conf("/etc/default/ufw")

    def policy(name: str, fallback: str) -> str:
        raw = defaults.get(name, "").strip().strip('"').lower()
        if raw in _TARGET_TO_POLICY:
            return _TARGET_TO_POLICY[raw]
        return raw if raw in POLICIES else fallback

    level = conf.get("LOGLEVEL", "low").lower()
    return State(
        enabled=conf.get("ENABLED", "no").lower() == "yes",
        logging=level if level in LOG_LEVELS else "low",
        ipv6=defaults.get("IPV6", "yes").lower() == "yes",
        default_incoming=policy("DEFAULT_INPUT_POLICY", "deny"),
        default_outgoing=policy("DEFAULT_OUTPUT_POLICY", "allow"),
        default_routed=policy("DEFAULT_FORWARD_POLICY", "deny"),
    )


#: `22/tcp   ALLOW IN   Anywhere   # comment`, as printed by `ufw status`.
_STATUS_ROW = re.compile(
    r"^(?P<to>\S+(?:\s\(v6\))?)\s+"
    r"(?P<action>ALLOW|DENY|REJECT|LIMIT)\s+(?P<direction>IN|OUT|FWD)\s+"
    r"(?P<from>.+?)\s*(?:#\s*(?P<comment>.*))?$"
)


def parse_status(output: str) -> list[Rule]:
    """Parse `ufw status` output into rules. Runs on the privileged read."""
    rules: list[Rule] = []
    for line in output.splitlines():
        line = line.rstrip()
        if not line or line.startswith(("Status:", "To", "--", "Default:", "New profiles:")):
            continue
        match = _STATUS_ROW.match(line.strip())
        if match is None:
            continue

        direction = match.group("direction").lower()
        if direction == "fwd":
            continue  # routed rules are policy-level here, not per-rule

        to_field = match.group("to")
        v6 = "(v6)" in to_field
        to_field = to_field.replace("(v6)", "").strip()

        port, proto, to_addr, app = "", "any", "any", ""
        if "/" in to_field:
            port, _, proto = to_field.partition("/")
            if proto not in PROTOCOLS:
                proto = "any"
        elif to_field.lower() in ("anywhere", "anywhere (v6)"):
            to_addr = "any"
        elif to_field.isdigit() or ":" in to_field and to_field.replace(":", "").isdigit():
            port = to_field
        else:
            # Neither a port nor an address, so it is an application profile
            # name — `ufw allow CUPS` prints as `CUPS  ALLOW IN  Anywhere`.
            # Recorded as one, not stuffed into to_addr: a Rule with a profile
            # name in an address field fails its own validate(), which made the
            # privileged read of the rule list fail outright on any machine with
            # one ("not an address or subnet: 'CUPS'") and, once past that,
            # raised out of the middle of an apply with the files already
            # written and no rollback.
            to_addr = to_field
            try:
                _validate_address(to_field)
            except UfwError:
                to_addr, app = "any", to_field

        from_field = match.group("from").strip()
        from_addr = "any" if from_field.lower().startswith("anywhere") else from_field
        if from_addr != "any":
            try:
                _validate_address(from_addr)
            except UfwError:
                from_addr = "any"  # a named application profile, not an address

        rules.append(
            Rule(
                action=match.group("action").lower(),
                direction=direction,
                port=port,
                proto=proto,
                from_addr=from_addr,
                to_addr=to_addr,
                comment=(match.group("comment") or "").strip()[:64],
                v6=v6,
                app=app,
            )
        )
    return rules


# --------------------------------------------------------------------------- #
#  Planning
# --------------------------------------------------------------------------- #


def plan_commands(current: State, wanted: State) -> list[tuple[list[str], str]]:
    """``(argv, why)`` pairs turning *current* into *wanted*.

    Incremental, never `ufw reset`: a reset would drop rules this app has not
    been told about and disable the firewall mid-transaction.
    """
    commands: list[tuple[list[str], str]] = []

    for name, attribute, flag in (
        ("incoming", "default_incoming", "incoming"),
        ("outgoing", "default_outgoing", "outgoing"),
        ("routed", "default_routed", "routed"),
    ):
        new = getattr(wanted, attribute)
        if new == getattr(current, attribute):
            continue
        if new not in POLICIES:
            raise UfwError(f"unknown default policy {new!r}")
        commands.append(
            ([UFW_BIN, "default", new, flag], f"default {new} {name}")
        )

    if wanted.logging != current.logging:
        if wanted.logging not in LOG_LEVELS:
            raise UfwError(f"unknown logging level {wanted.logging!r}")
        commands.append(([UFW_BIN, "logging", wanted.logging], "logging level"))

    if current.rules_loaded:
        current_keys = {rule.key(): rule for rule in current.rules}
        wanted_keys = {rule.key(): rule for rule in wanted.rules}

        # `not rule.managed` skips application-profile rules on both sides: they
        # are shown for completeness but never built into a command, so a
        # machine with `ufw allow CUPS` can still have its policy and other
        # rules changed instead of the whole apply failing on that one row.
        for key, rule in current_keys.items():
            if key not in wanted_keys and not rule.v6 and rule.managed:
                commands.append((rule.to_argv(delete=True), f"remove: {rule.summary}"))
        for key, rule in wanted_keys.items():
            if key not in current_keys and not rule.v6 and rule.managed:
                commands.append((rule.to_argv(), f"add: {rule.summary}"))

    # Enabling last, so the policy and rules are already in place when it comes up.
    if wanted.enabled != current.enabled:
        if wanted.enabled:
            commands.append(([UFW_BIN, "--force", "enable"], "enable the firewall"))
        else:
            commands.append(([UFW_BIN, "disable"], "disable the firewall"))

    return commands


def to_payload(state: State) -> dict:
    """Serialise for the helper. Only validated primitives cross the boundary."""
    return {
        "enabled": state.enabled,
        "logging": state.logging,
        "ipv6": state.ipv6,
        "default_incoming": state.default_incoming,
        "default_outgoing": state.default_outgoing,
        "default_routed": state.default_routed,
        "rules_loaded": state.rules_loaded,
        "rules": [
            {
                "action": r.action,
                "direction": r.direction,
                "port": r.port,
                "proto": r.proto,
                "from_addr": r.from_addr,
                "to_addr": r.to_addr,
                "comment": r.comment,
                "v6": r.v6,
                "app": r.app,
            }
            for r in state.rules
        ],
    }


def from_payload(data: dict) -> State:
    """Rebuild a State from a payload, validating every rule on the way in."""
    if not isinstance(data, dict):
        raise UfwError("ufw payload is not an object")

    def pick(name: str, allowed: tuple[str, ...], fallback: str) -> str:
        value = data.get(name, fallback)
        if not isinstance(value, str) or value not in allowed:
            raise UfwError(f"bad value for {name}: {value!r}")
        return value

    rules = []
    for raw in data.get("rules", ()):
        if not isinstance(raw, dict):
            raise UfwError("a rule is not an object")
        rule = Rule(
            action=str(raw.get("action", "deny")),
            direction=str(raw.get("direction", "in")),
            port=str(raw.get("port", "")),
            proto=str(raw.get("proto", "any")),
            from_addr=str(raw.get("from_addr", "any")),
            to_addr=str(raw.get("to_addr", "any")),
            comment=str(raw.get("comment", "")),
            v6=bool(raw.get("v6", False)),
            app=str(raw.get("app", "")),
        )
        rule.validate()
        rules.append(rule)

    return State(
        enabled=bool(data.get("enabled", False)),
        logging=pick("logging", LOG_LEVELS, "low"),
        ipv6=bool(data.get("ipv6", True)),
        default_incoming=pick("default_incoming", POLICIES, "deny"),
        default_outgoing=pick("default_outgoing", POLICIES, "allow"),
        default_routed=pick("default_routed", POLICIES, "deny"),
        rules=rules,
        rules_loaded=bool(data.get("rules_loaded", False)),
    )


#: One-click default-policy sets. ``(label, subtitle, policies, caveat)``.
#: Policies map directly onto the three State attributes.
POSTURES: list[tuple[str, str, dict[str, str], str]] = [
    (
        "Desktop",
        "Nothing reaches you unless you asked for it; anything may go out.",
        {"default_incoming": "deny", "default_outgoing": "allow", "default_routed": "deny"},
        "",
    ),
    (
        "Visible refusal",
        "Same as Desktop, but refused connections get an answer instead of a "
        "silent drop.",
        {"default_incoming": "reject", "default_outgoing": "allow", "default_routed": "deny"},
        "Reject tells a scanner the host is there. It is friendlier on a trusted "
        "LAN and louder on a hostile network.",
    ),
    (
        "Locked down",
        "Deny in both directions. Only traffic you have written a rule for moves "
        "at all.",
        {"default_incoming": "deny", "default_outgoing": "deny", "default_routed": "deny"},
        "This breaks DNS, NTP and updates the moment it is applied unless the "
        "outbound allowances below are in place first. Add those, then switch.",
    ),
]

#: Ports worth offering as one-click blocks, grouped so the button grid reads as
#: categories rather than as one wall of numbers. Everything here is a service
#: that either should not be exposed at all, or is routinely exposed by accident.
PORT_GROUPS: list[tuple[str, list[tuple[str, str, str]]]] = [
    (
        "Remote access",
        [
            ("22", "tcp", "SSH"),
            ("23", "tcp", "Telnet"),
            ("3389", "tcp", "RDP remote desktop"),
            ("5900:5910", "tcp", "VNC"),
            ("512:514", "tcp", "rsh / rlogin / rexec"),
            ("5555", "tcp", "Android ADB"),
        ],
    ),
    (
        "File sharing",
        [
            ("445", "tcp", "SMB file sharing"),
            ("139", "tcp", "NetBIOS session"),
            ("137:138", "udp", "NetBIOS name/datagram"),
            ("111", "tcp", "RPC portmapper"),
            ("2049", "tcp", "NFS"),
            ("21", "tcp", "FTP"),
            ("69", "udp", "TFTP"),
            ("873", "tcp", "rsync daemon"),
            ("548", "tcp", "AFP / Netatalk"),
        ],
    ),
    (
        "Discovery & printing",
        [
            ("631", "tcp", "CUPS printing"),
            ("5353", "udp", "mDNS / Bonjour"),
            ("1900", "udp", "SSDP / UPnP discovery"),
            ("5355", "udp", "LLMNR"),
            ("3702", "udp", "WS-Discovery"),
            ("1901", "udp", "UPnP events"),
        ],
    ),
    (
        "Databases & caches",
        [
            ("3306", "tcp", "MySQL"),
            ("5432", "tcp", "PostgreSQL"),
            ("6379", "tcp", "Redis"),
            ("27017", "tcp", "MongoDB"),
            ("11211", "tcp", "memcached"),
            ("9200:9300", "tcp", "Elasticsearch"),
            ("1433", "tcp", "MS SQL Server"),
            ("5984", "tcp", "CouchDB"),
        ],
    ),
    (
        "Management & legacy",
        [
            ("623", "udp", "IPMI / BMC"),
            ("161:162", "udp", "SNMP"),
            ("25", "tcp", "SMTP"),
            ("143", "tcp", "IMAP (cleartext)"),
            ("110", "tcp", "POP3 (cleartext)"),
            ("389", "tcp", "LDAP (cleartext)"),
            ("6000:6063", "tcp", "X11 forwarding"),
            ("2375", "tcp", "Docker API (unencrypted)"),
        ],
    ),
    (
        "Web & proxies",
        [
            ("80", "tcp", "HTTP"),
            ("443", "tcp", "HTTPS"),
            ("8080", "tcp", "HTTP alternate"),
            ("8443", "tcp", "HTTPS alternate"),
            ("3128", "tcp", "Squid proxy"),
            ("8000", "tcp", "Dev server"),
        ],
    ),
]

#: Flat view, kept because presets and tests index it by port.
COMMON_PORTS = [entry for _group, entries in PORT_GROUPS for entry in entries]
