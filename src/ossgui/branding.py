"""The header stamped on every file the app generates.

Kept in one place so the sysctl drop-in, the systemd drop-in, the USBGuard
policy and the GRUB script all carry the same mark — someone finding one of
these files months later should be able to tell what wrote it and how to undo it
without going looking.

Every target we write uses ``#`` for comments, including apt.conf, which is
documented as taking ``//`` but accepts ``#`` as well (verified against
apt-config on 26.04).
"""

from __future__ import annotations

NAME = "OSS"
TAGLINE = "Operating System Settings"

#: figlet 'standard'. Wide enough to be obvious, short enough not to bury the
#: two lines underneath that actually tell you what to do.
ART = r"""  ___  ____ ____
 / _ \/ ___/ ___|
| | | \___ \___ \
| |_| |___) |__) |
 \___/|____/____/"""

COMMENT = "#"

#: How the app recognises a file as its own. Needed for the targets we edit in
#: place — /etc/login.defs exists whether or not we have touched it, so the only
#: way to tell our edit from the distribution's original is a mark we left.
#:
#: It is a distinct constant rather than a phrase lifted out of the banner text,
#: because the two must not drift apart: when the banner was changed to the ASCII
#: art the old "Managed by OSS" line disappeared, and the recogniser silently
#: stopped matching anything at all.
MARKER = f"{NAME} — {TAGLINE}"


def _comment(text: str) -> str:
    """Prefix each line, leaving blank lines as a bare comment character."""
    out = []
    for line in text.splitlines():
        out.append(f"{COMMENT} {line}".rstrip() if line else COMMENT)
    return "\n".join(out) + "\n"


def header(footer: str) -> str:
    """The art, the marker, and one line saying how to undo this file."""
    return _comment(f"{ART}\n\n{MARKER}\n\nDo not edit by hand.\n{footer}")


#: For a drop-in we own outright: deleting it is the undo.
DROPIN = header("Delete this file to revert this section to stock.")

#: For a pre-existing system file we edit in place — deleting it reverts nothing.
IN_PLACE = header(
    "The original was saved alongside this file as .bak — restore it to revert."
)

#: For files whose section needs a command to unload as well as a deletion.
def with_footer(footer: str) -> str:
    return header(footer)
