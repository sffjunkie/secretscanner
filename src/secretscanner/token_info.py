"""Token parsing information"""
from secretscanner.types import (
    TokenIssuerParseInfo,
    IssuerTokenFormats,
)

token_format: IssuerTokenFormats = {
    "github": r"[A-Za-z0-9_]{36,251}",
    "digitalocean": r"[A-Za-z0-9_]{64,}",
    "adafruit": r"[A-Za-z0-9]{32}",
    "discord": r"[A-Za-z0-9]{32}",
    "linode": r"[A-Za-z0-9]{64}",
}

token_issuer_parse_info: TokenIssuerParseInfo = {
    # https://github.blog/changelog/2021-03-31-authentication-token-format-updates-are-generally-available/
    "github": {
        "pat": {
            "type": "re",
            "format": f"ghp_{token_format['github']}",
        },
        "oauth": {
            "type": "re",
            "format": f"gho_{token_format['github']}",
        },
        "user-to-server": {
            "type": "re",
            "format": f"ghu_{token_format['github']}",
        },
        "server-to-server": {
            "type": "re",
            "format": f"ghs_{token_format['github']}",
        },
        "refresh": {
            "type": "re",
            "format": f"ghr_{token_format['github']}",
        },
    },
    "pypi": {
        "pat": {"type": "re", "format": "pypi-[A-Za-z0-9_]{16,}"},
    },
    # https://docs.digitalocean.com/reference/api/create-personal-access-token/
    "digitalocean": {
        "pat": {
            "type": "re",
            "format": f"dop_v1_{token_format['digitalocean']}",
        },
        "oauth": {
            "type": "re",
            "format": f"doo_v1_{token_format['digitalocean']}",
        },
        "refresh": {
            "type": "re",
            "format": f"dor_v1_{token_format['digitalocean']}",
        },
    },
    "postgresql": {
        "url": {"type": "url", "format": "postgres"},
    },
    "adafruit": {
        # https://io.adafruit.com/api/docs/#authentication
        "header": {"type": "re", "format": f"X-AIO-Key: {token_format['adafruit']}"},
        "url": {
            "type": "re",
            "format": f"x-aio-key={token_format['adafruit']}",
        },
        "env": {
            "type": "re",
            "format": fr"ADAFRUIT_IO_KEY\s*\=\s*{token_format['adafruit']}",
        },
    },
    "discord": {
        "url": {
            "type": "re",
            "format": f"client_id={token_format['discord']}",
        },
        "bot": {
            "type": "re",
            "format": f"Authorization: Bot {token_format['discord']}",
        },
    },
    "linode": {
        "env": {
            "type": "re",
            "format": fr"LINODE_API_TOKEN\s*=\s*{token_format['linode']}",
        },
        "yaml": {
            "type": "re",
            "format": fr"LINODE_API_TOKEN\s*:\s*\"?{token_format['linode']}\"?",
        },
        "bearer": {
            "type": "re",
            "format": f"Authorization: Bearer {token_format['linode']}",
        },
    },
}
