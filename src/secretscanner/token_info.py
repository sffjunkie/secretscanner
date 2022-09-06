from secretscanner.types import (
    TokenIssuerParseInfo,
    TokenParseInfo,
)

token_format: TokenParseInfo = {
    "github": "[A-Za-z0-9_]{36,251}",
    "digitalocean": "[A-Za-z0-9_]{64,}",
    "adafruit": "[A-Za-z0-9]{32}",
    "discord": "[A-Za-z0-9]{32}",
    "linode": "[A-Za-z0-9]{64}",
}
token_issuer_parse_info: TokenIssuerParseInfo = {
    # https://github.blog/changelog/2021-03-31-authentication-token-format-updates-are-generally-available/
    "github": {
        "pat": f"re(ghp_{token_format['github']})",
        "oauth": f"re(gho_{token_format['github']})",
        "user-to-server": f"re(ghu_{token_format['github']})",
        "server-to-server": f"re(ghs_{token_format['github']})",
        "refresh": f"re(ghr_{token_format['github']})",
    },
    "pypi": {"pat": "re(pypi-[A-Za-z0-9_]{16,})"},
    # https://docs.digitalocean.com/reference/api/create-personal-access-token/
    "digitalocean": {
        "pat": f"re(dop_v1_{token_format['digitalocean']})",
        "oauth": f"re(doo_v1_{token_format['digitalocean']})",
        "refresh": f"re(dor_v1_{token_format['digitalocean']})",
    },
    "postgresql": {"url": "url(postgres)"},
    "adafruit": {
        # https://io.adafruit.com/api/docs/#authentication
        "header": f"re(X-AIO-Key: {token_format['adafruit']})",
        "url": f"re(x-aio-key={token_format['adafruit']})",
        "env": fr"re(ADAFRUIT_IO_KEY\s*\=\s*{token_format['adafruit']})",
    },
    "discord": {
        "url": f"re(client_id={token_format['discord']})",
        "bot": f"re(Authorization: Bot {token_format['discord']})",
    },
    "linode": {
        "env": fr"re(LINODE_API_TOKEN\s*=\s*{token_format['linode']})",
        "yaml": fr"re(LINODE_API_TOKEN\s*:\s*\"?{token_format['linode']}\"?)",
        "bearer": f"re(Authorization: Bearer {token_format['linode']})",
    },
}
