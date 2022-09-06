"""Find secrets within data"""

import re
from typing import Match
from urllib.parse import urlparse


from secretscanner.types import SecretFormat


# https://gist.github.com/gruber/249502
JG_URL_REGEX = r"(?i)\b((?:[a-z][\w-]+:(?:/{1,3}|[a-z0-9%])|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"


def find_re_secret(data: str, regex: str) -> list[Match[str]]:
    """Look for text matching a regular expression"""
    regex = f"({regex})"  # parse into a match group
    return list(re.finditer(regex, data, flags=re.IGNORECASE))


def find_url_secret(data: str, scheme: str | None = None) -> list[Match[str]]:
    """Look for a URL with a password matching the scheme if specified"""
    matches = list(re.finditer(JG_URL_REGEX, data, flags=re.IGNORECASE))
    found: list[Match[str]] = []
    if matches:
        for match in matches:
            if scheme is None:
                found.append(match)
            else:
                url_str = match.group(0)
                url = urlparse(url_str)
                if url.scheme == scheme and url.password is not None:
                    found.append(match)

    return found


def find_secrets(data: str, secret_format: SecretFormat) -> list[Match[str]]:
    """Find all secrets within the data"""
    if secret_format["type"] == "url":
        matches = find_url_secret(data, scheme=secret_format["format"])
    else:
        matches = find_re_secret(data, secret_format["format"])

    matches = list(matches)
    return matches
