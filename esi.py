import os
import json
import logging
import asyncio
import secrets
import base64
import hashlib
import httpx
import sqlite3
import re


from fastmcp import FastMCP
from fastmcp.server.auth import OAuthProxy
from fastmcp.server.auth.providers.jwt import JWTVerifier
from fastmcp.client.auth.oauth import OAuth, OAuthToken
from fastmcp.client.oauth_callback import create_oauth_callback_server
from fastmcp.server import Context

from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlencode
from .config import *

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Create a FileHandler
file_handler = logging.FileHandler(ESI_MCP_LOG_PATH)
file_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

logger.debug(f"HOME_DIR: {HOME_DIR}")
logger.debug(f"ESI_MCP_DIR: {ESI_MCP_DIR}")
logger.debug(f"ESI_MCP_DIR exists: {ESI_MCP_DIR.exists()}")

# Initialize SQL database
def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS characters (
                character_id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                scopes TEXT,
                access_token TEXT,
                refresh_token TEXT,
                token_expiry TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)
        conn.commit()

init_db()

# SQL helper functions
def save_character(character_id, name, scopes, access_token=None, refresh_token=None, token_expiry=None):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            INSERT OR REPLACE INTO characters 
            (character_id, name, scopes, access_token, refresh_token, token_expiry)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (character_id, name, scopes, access_token, refresh_token, token_expiry))
        conn.commit()

def get_characters():
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute("SELECT * FROM characters")
        columns = [desc[0] for desc in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]

def delete_character(character_id):
    with sqlite3.connect(DB_PATH) as conn:
        # Check if this is the default character
        default_char_id = get_default_character_id()
        is_default = character_id == default_char_id
        
        # Delete the character
        conn.execute("DELETE FROM characters WHERE character_id = ?", (character_id,))
        
        # If it was the default character, clear the default
        if is_default:
            conn.execute("DELETE FROM settings WHERE key = 'default_character_id'")
        
        conn.commit()
def get_default_character_id():
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute("SELECT value FROM settings WHERE key = 'default_character_id'")
        row = cursor.fetchone()
        return int(row[0]) if row else None

def set_default_character_id(character_id):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            INSERT OR REPLACE INTO settings (key, value) VALUES ('default_character_id', ?)
        """, (str(character_id),))
        conn.commit()


# Helper functions
def generate_pkce_pair():
    code_verifier = base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8').rstrip('=')
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode('utf-8')).digest()
    ).decode('utf-8').rstrip('=')
    return code_verifier, code_challenge

def generate_state():
    return base64.urlsafe_b64encode(os.urandom(16)).decode('utf-8').rstrip('=')

async def get_character_id_from_token(access_token):
    async with httpx.AsyncClient() as client:
        response = await client.get(
            "https://login.eveonline.com/oauth/verify",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        if response.status_code == 200:
            data = response.json()
            return data.get('CharacterID')
        return None

async def create_oauth_client():
    return httpx.AsyncClient(base_url="https://esi.evetech.net")

# Global dict for OAuth instances per character
character_oauths = {}

# Configure token verification for EVE Online
token_verifier = JWTVerifier(
    jwks_uri="https://login.eveonline.com/oauth/jwks",
    issuer="https://login.eveonline.com",
    audience="EVE Online",
    required_scopes=SCOPES
)

# Create the OAuth proxy
oauth = OAuthProxy(
    upstream_authorization_endpoint="https://login.eveonline.com/v2/oauth/authorize",
    upstream_token_endpoint="https://login.eveonline.com/v2/oauth/token",
    upstream_client_id=CLIENT_ID,
    upstream_client_secret=CLIENT_SECRET,
    token_verifier=token_verifier,
    allowed_client_redirect_uris=[
        "http://localhost:*",
        "http://127.0.0.1:*"
    ],
    base_url="http://localhost:8000",
    redirect_path="/auth/callback",
)

# Headers for the backend client (no static Authorization; added per-request)
headers = {
    "Accept-Language": "en",
    "X-Compatibility-Date": "2025-08-26",
    "X-Tenant": "tranquility",
    "Content-Type": "application/json",
    "Accept": "application/json",
    "User-Agent": "ESI MCP Client",
}

# Create an HTTP client for ESI API
client = httpx.AsyncClient(
    base_url="https://esi.evetech.net",
    headers=headers,
)

# Define request hook to add authorization dynamically
async def add_auth_header(request):
    path = request.url.path
    match = re.match(r'/characters/(\d+)/', path)
    if match:
        character_id = int(match.group(1))
        # Get tokens from SQL
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.execute("""
                SELECT access_token, refresh_token, token_expiry 
                FROM characters WHERE character_id = ?
            """, (character_id,))
            row = cursor.fetchone()
        if not row:
            logger.error(f"No tokens for character {character_id}")
            return
        access_token, refresh_token, expiry_str = row
        if not access_token:
            logger.error(f"No access token for character {character_id}")
            return
        # Check expiry
        try:
            if expiry_str is None:
                raise ValueError("No expiration time")
            expiry = datetime.fromisoformat(expiry_str)
            if expiry < datetime.utcnow():
                # Refresh token
                async with httpx.AsyncClient() as temp_client:
                    token_params = {
                        "grant_type": "refresh_token",
                        "refresh_token": refresh_token,
                        "client_id": CLIENT_ID,
                    }
                    response = await temp_client.post("https://login.eveonline.com/v2/oauth/token", data=token_params)
                    if response.status_code != 200:
                        logger.error(f"Failed to refresh token for character {character_id}: {response.text}")
                        return
                    token_data = response.json()
                    access_token = token_data["access_token"]
                    refresh_token = token_data.get("refresh_token", refresh_token)  # May rotate
                    expires_in = token_data["expires_in"]
                    expiry = datetime.utcnow() + timedelta(seconds=expires_in)
                    expiry_str = expiry.isoformat()
                    # Save back to SQL
                    with sqlite3.connect(DB_PATH) as conn:
                        conn.execute("""
                            UPDATE characters 
                            SET access_token = ?, refresh_token = ?, token_expiry = ? 
                            WHERE character_id = ?
                        """, (access_token, refresh_token, expiry_str, character_id))
                        conn.commit()
                logger.info(f"Refreshed token for character {character_id}")
            logger.debug(f"Adding auth for character {character_id}: {access_token[:10]}...")
            request.headers['Authorization'] = f'Bearer {access_token}'
        except Exception as e:
            logger.error(f"Error handling token for character {character_id}: {str(e)}")
            return

client.event_hooks['request'] = [add_auth_header]

# Load OpenAPI spec
openapi_spec_url = "https://esi.evetech.net/meta/openapi.json?compatibility_date=2025-08-26"
openapi_spec = httpx.get(openapi_spec_url).json()

# Create the MCP server
mcp = FastMCP.from_openapi(
    auth=oauth,
    openapi_spec=openapi_spec,
    client=client,
    name="ESI MCP Server"
)

@mcp.tool
async def add_character(ctx: Context) -> str:
    """Add a new character by authenticating with EVE Online SSO."""
    logger.debug("Starting authentication")

    try:
        # Fetch OAuth server metadata
        async with httpx.AsyncClient() as temp_client:
            response = await temp_client.get(METADATA_URL)
            response.raise_for_status()
            oauth_metadata = response.json()
            auth_endpoint = oauth_metadata["authorization_endpoint"]
            token_endpoint = oauth_metadata["token_endpoint"]
            logger.debug(f"Fetched auth_endpoint: {auth_endpoint}, token_endpoint: {token_endpoint}")

        # Generate PKCE pair and state
        code_verifier, code_challenge = generate_pkce_pair()
        state = generate_state()

        # Build authorization URL
        auth_params = {
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": CALLBACK_URL,
            "scope": " ".join(SCOPES),
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256"
        }
        auth_url = f"{auth_endpoint}?{urlencode(auth_params)}"
        logger.debug(f"Opening browser for authorization: {auth_url}")

        oauth_instance = OAuth(
            mcp_url=METADATA_URL,
            scopes=SCOPES,
            client_name="ESI MCP Client",
            callback_port=CALLBACK_PORT,
            additional_client_metadata={"client_id": CLIENT_ID}
        )
        await oauth_instance.redirect_handler(authorization_url=auth_url)

        # Start OAuth callback server
        response_future = asyncio.Future()
        server = create_oauth_callback_server(
            port=CALLBACK_PORT,
            callback_path=CALLBACK_PATH,
            server_url=METADATA_URL,
            response_future=response_future
        )
        
        server_task = asyncio.create_task(server.serve())
            
        try:
            callback_response = await asyncio.wait_for(response_future, timeout=300.0)
            code, received_state = callback_response
            if not code:
                logger.error("Failed to obtain authorization code")
                return "Failed to obtain authorization code"
            if received_state != state:
                logger.error("State mismatch: CSRF protection failed")
                return "State mismatch: CSRF protection failed"
            logger.debug(f"Received authorization code: {code}, state: {received_state}")
        except asyncio.TimeoutError:
            logger.error("Timeout waiting for OAuth callback")
            return "Timeout waiting for OAuth callback"
        finally:
            server_task.cancel()
            try:
                await server_task
            except asyncio.CancelledError:
                pass

        # Exchange code for token
        token_params = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": CLIENT_ID,
            "code_verifier": code_verifier
        }

        async with httpx.AsyncClient() as temp_client:
            response = await temp_client.post(token_endpoint, data=token_params)
            response.raise_for_status()
            token_data = response.json()
            access_token = token_data.get("access_token")
            refresh_token = token_data.get("refresh_token")
            expires_in = token_data.get("expires_in")
            if not access_token:
                logger.error("Failed to obtain access token")
                return "Failed to obtain access token"
            logger.debug(f"Successfully obtained access token: {access_token[:10]}...")

        # Extract character_id and name
        character_id = await get_character_id_from_token(access_token)
        if not character_id:
            logger.error("Failed to extract character_id")
            return "Failed to extract character_id"

        async with await create_oauth_client() as temp_client:
            headers = {
                "Authorization": f"Bearer {access_token}",
                "X-Compatibility-Date": COMPATIBILITY_DATE
            }
            logger.debug(f"Using headers: {headers}")
            response = await temp_client.get(f"/latest/characters/{character_id}/", headers=headers)
            response.raise_for_status()
            character_name = response.json().get("name", "Unknown")
            logger.info(f"Fetched character name: {character_name}")

        # Save token and details to database
        token_expiry = (datetime.utcnow() + timedelta(seconds=expires_in)).isoformat()
        save_character(
            character_id=int(character_id),
            name=character_name,
            scopes=" ".join(SCOPES),
            access_token=access_token,
            refresh_token=refresh_token,
            token_expiry=token_expiry
        )
        logger.info(f"Saved character {character_id} ({character_name}) to database")

        # Verify character was saved
        characters = get_characters()
        if any(c["character_id"] == int(character_id) for c in characters):
            logger.info(f"Verified: Character {character_id} found in database")
        else:
            logger.error(f"Failed to verify: Character {character_id} not found in database")

        # Set as default if no default exists
        if not get_default_character_id():
            set_default_character_id(int(character_id))
            logger.info(f"Set default character to ID {character_id}")

        return f"Authenticated character: {character_name} (ID: {character_id})"
    except Exception as e:
        logger.error(f"Authentication failed: {e}", exc_info=True)
        return f"Authentication failed: {str(e)}"

if __name__ == "__main__":
    mcp.run(transport="stdio")