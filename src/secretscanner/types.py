from typing import TypedDict

TokenIssuer = str
IssuerTokenFormats = dict[TokenIssuer, str]


class TokenFormat(TypedDict):
    type: str
    format: str


# TokenFormat = str
TokenType = str
TokenParseInfo = dict[TokenType, TokenFormat]
TokenIssuerParseInfo = dict[TokenIssuer, TokenParseInfo]


class Token(TypedDict):
    file: str
    issuer: TokenIssuer
    token: str
    type: TokenType
    ignored: bool


TokenResults = list[Token]
