# Eve Online ESI MCP Server

## Overview

This project implements a local MCP (Model Context Protocol) server for accessing the EVE Online ESI (EVE Swagger Interface) API. It uses the FastMCP library to create a proxy server based on the ESI OpenAPI specification, with built-in support for OAuth authentication via EVE Online's SSO. The server handles multiple characters, stores authentication tokens securely in a SQLite database, and automatically refreshes expired tokens. It's designed for developers and EVE Online enthusiasts who need programmatic access to ESI endpoints in a secure, multi-character setup.

Key technologies:
- Python 3.8+
- FastMCP for MCP server creation
- httpx for asynchronous HTTP requests
- SQLite for local token storage
- OAuth2 PKCE flow for secure authentication

## Features

- **Multi-Character Support**: Authenticate and manage multiple EVE Online characters, with tokens stored per character.
- **Automatic Token Refresh**: Tokens are refreshed on-demand when expired, using stored refresh tokens.
- **Dynamic Authorization**: Automatically adds Bearer tokens to ESI requests based on the character ID in the API path.
- **SSO Integration**: Easy character addition via browser-based OAuth flow.
- **OpenAPI-Driven**: Generated from the official ESI OpenAPI spec, ensuring compatibility with future API changes.
- **Logging**: Detailed debug logging to a file for troubleshooting.
- **Local Storage**: Tokens and character data stored in `~/.esi-mcp/characters.db`.

## Installation

1. **Prerequisites**:
   - Python 3.8 or higher.
   - Install required dependencies:
     ```
     pip install fastmcp httpx sqlite3 asyncio secrets base64 hashlib re logging pathlib urllib3
     ```
     Note: Some dependencies like `fastmcp` may require specific installation instructions; check the [FastMCP documentation](https://fastmcp.cloud/docs) for details.

2. **Clone the Repository**:
   ```
   git clone https://github.com/unclemusclez/EveOnlineMCP.git
   cd EveOnlineMCP
   ```

3. **Run the Script**:
   ```
   python esi.py
   ```
   This starts the MCP server in stdio transport mode. For other transports (e.g., HTTP), modify `mcp.run(transport="stdio")` accordingly.

## Usage

### Adding a Character
The server includes a tool `add_character` to authenticate new characters:
- Call the tool via the MCP interface (e.g., from a client).
- It opens a browser for EVE Online SSO login.
- After authentication, the character's details and tokens are saved to the database.

Example (pseudocode for client-side call):
```python
result = await mcp_client.add_character()
print(result)  # "Authenticated character: CharacterName (ID: 123456789)"
```
### Removing a Character
The server includes a tool `delete_character` to remove a character from the database:
- Call the tool via the MCP interface (e.g., from a client).
- It removes the character's details and tokens from the database.
- If the character is set as default, this setting is cleared.

Example (pseudocode for client-side call):
```python
result = await mcp_client.remove_character(character_id=123456789)
print(result)  # "Removed character: CharacterName (ID: 123456789)"
```

### Making ESI Requests
- The server proxies ESI endpoints, e.g., `/characters/{character_id}/wallet/`.
- Authentication is handled automatically based on the `character_id` in the path.
- Use a FastMCP client to interact with the server.

Example client usage:
```python
from fastmcp import Client

async with Client("stdio") as client:  # Or HTTP transport
    balance = await client.GetCharactersCharacterIdWallet(character_id=123456789)
    print(balance)
```

### Database Management
- Characters and tokens are stored in `~/.esi-mcp/characters.db`.
- Tables:
  - `characters`: Stores character_id, name, scopes, access_token, refresh_token, token_expiry.
  - `settings`: Stores defaults like `default_character_id`.

You can query the DB manually with SQLite tools for inspection.

### Logging
- Logs are written to `~/.esi-mcp/esi-mcp.log`.
- Set logging level in code if needed (default: DEBUG).

## Configuration

- **OAuth Constants**:
  - `CLIENT_ID` and `CLIENT_SECRET`: Replace with your EVE Online developer app credentials.
  - `SCOPES`: List of ESI scopes; customize as needed.
  - `CALLBACK_URL`: Local callback for SSO (default: http://localhost:8000/auth/callback).

- **Compatibility Date**: Set to "2025-08-26" for future-proofing; update as per ESI changes.

- **Database Path**: Customizable via `DB_PATH`.

## Troubleshooting

- **Token Errors**: Check logs for refresh failures; ensure CLIENT_ID is valid.
- **SSO Issues**: Verify browser opens and callback port (8000) is free.
- **Unauthorized (401)**: Ensure character is added and has required scopes (e.g., `esi-wallet.read_character_wallet.v1`).
- **No Tokens Found**: Run `add_character` tool first.

## Contributing

Contributions are welcome! Please fork the repo and submit pull requests for bug fixes or features. Ensure code follows PEP8 and includes tests where possible.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE.md) for details.

---

For more details on EVE Online ESI, visit the [official documentation](https://developers.eveonline.com/api-explorer). For FastMCP, refer to [FastMCP Docs](https://fastmcp.cloud/docs).