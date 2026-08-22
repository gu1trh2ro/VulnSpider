"""Conservative classification for passive navigation candidates."""

from __future__ import annotations

from urllib.parse import unquote, urlsplit


_AUTHENTICATION_TERMINATION_TOKENS = frozenset(
    {
        "logoff",
        "logout",
        "signout",
    }
)
_PAGE_EXTENSIONS = (
    ".aspx",
    ".html",
    ".jspx",
    ".php",
    ".asp",
    ".cgi",
    ".htm",
    ".jsp",
)


def authentication_state_change_token(url: str) -> str | None:
    """Return a clear authentication-termination token in a URL path.

    Matching is segment based rather than substring based so documentation paths
    such as ``/docs/logout-behavior`` remain navigable. Query and fragment values
    are deliberately ignored.
    """

    if type(url) is not str or not url:
        return None
    try:
        path = urlsplit(url).path
    except ValueError:
        return None
    for raw_segment in path.split("/"):
        segment = unquote(raw_segment, errors="replace").casefold()
        if ";" in segment:
            segment = segment.split(";", 1)[0]
        for extension in _PAGE_EXTENSIONS:
            if segment.endswith(extension):
                segment = segment[: -len(extension)]
                break
        if segment in _AUTHENTICATION_TERMINATION_TOKENS:
            return segment
    return None
