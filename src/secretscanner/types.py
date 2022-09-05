from typing import TypedDict

TokenFormat = str
TokenType = str
TokenParseInfo = dict[TokenType, TokenFormat]
TokenIssuer = str
TokenIssuerParseInfo = dict[TokenIssuer, TokenParseInfo]


class TokenInfo(TypedDict):
    file: str
    issuer: TokenIssuer
    token: str
    type: TokenType
    ignored: bool


TokenResults = list[TokenInfo]
