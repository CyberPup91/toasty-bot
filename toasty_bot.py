import os
import re
import json
import time
import shlex
import sqlite3
import asyncio
import aiohttp
import yaml

from pathlib import Path
from collections import deque
from datetime import datetime, timezone
from dotenv import load_dotenv, set_key

# ============================================================
# 1. ENVIRONMENT & AUTH
# ============================================================

ENV_PATH = ".env"
REDEEMS_CONFIG_PATH = os.getenv("REDEEMS_CONFIG_PATH") or "redeems.yaml"
load_dotenv(ENV_PATH)

CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")

# Bot account tokens (for IRC, chat & whispers)
BOT_TOKEN = os.getenv("BOT_TOKEN")
REFRESH_TOKEN = os.getenv("REFRESH_TOKEN")

# Broadcaster account tokens (for Channel Point EventSub & reward management)
BROADCASTER_CLIENT_ID = (os.getenv("BROADCASTER_CLIENT_ID") or "").strip() or None
BROADCASTER_TOKEN = os.getenv("BROADCASTER_TOKEN")
BROADCASTER_REFRESH_TOKEN = os.getenv("BROADCASTER_REFRESH_TOKEN")

# In-memory auth tracking
TOKEN_EXPIRES_AT = 0
BROADCASTER_TOKEN_EXPIRES_AT = 0

TARGET_CHANNEL = (
    os.getenv("TARGET_CHANNEL") or "toastyyvt"
).lower().strip("# ")

BOT_NICK = (
    os.getenv("BOT_USERNAME") or "CyberThePup"
).lower().strip("# ")

DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")

# Usernames allowed to manage Channel Point rewards & whisper commands (case-insensitive)
_env_redeem_users = [
    u.strip().lower().lstrip("@")
    for u in (os.getenv("REDEEMS_ALLOWED_USERS") or "").split(",")
    if u.strip()
]
REDEEMS_ALLOWED_USERS = _env_redeem_users or [
    "cyberthepup",
    "toastyyvt",
]

# Staged reward actions awaiting "$reward confirm" (keyed by lowercase username)
PENDING_REWARD_ACTIONS: dict[str, dict] = {}
REWARD_CONFIRM_TTL = 45

# Global Twitch User IDs (populated dynamically at launch)
BROADCASTER_USER_ID = None
BOT_USER_ID = None


# ============================================================
# 2. OAUTH TOKEN MANAGEMENT & ID RESOLUTION
# ============================================================

APP_ACCESS_TOKEN = None
APP_TOKEN_EXPIRES_AT = 0
TTG_REFRESH_URL = "https://twitchtokengenerator.com/api/v2/tokens/refresh"


def update_env_file(key: str, value: str, env_path: str = ENV_PATH):
    """Persists updated keys back to .env on disk and process memory."""
    try:
        set_key(env_path, key, value, quote_mode="never")
        os.environ[key] = value
        print(f"[ENV SUCCESS] Persisted {key} to disk.")
    except Exception as e:
        print(f"[ENV ERROR] Failed to update {key} in {env_path}: {e}")


def get_broadcaster_client_id() -> str:
    """Returns the Client ID that owns BROADCASTER_TOKEN, falling back to CLIENT_ID."""
    return (
        BROADCASTER_CLIENT_ID
        or (os.getenv("BROADCASTER_CLIENT_ID") or "").strip()
        or CLIENT_ID
    )


async def get_app_access_token(force_refresh: bool = False):
    """Returns a cached App Access Token, refreshing only if missing or within 5 minutes of expiry."""
    global APP_ACCESS_TOKEN, APP_TOKEN_EXPIRES_AT

    if not force_refresh and APP_ACCESS_TOKEN and time.time() < (APP_TOKEN_EXPIRES_AT - 300):
        return APP_ACCESS_TOKEN

    url = "https://id.twitch.tv/oauth2/token"
    payload = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "client_credentials",
    }

    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=payload) as resp:
            if resp.status == 200:
                data = await resp.json()
                APP_ACCESS_TOKEN = data["access_token"]
                expires_in = data.get("expires_in", 3600)
                APP_TOKEN_EXPIRES_AT = time.time() + expires_in
                print(
                    f"[AUTH] Cached new App Access Token (valid for ~{expires_in // 86400} days)."
                )
                return APP_ACCESS_TOKEN
            else:
                body = await resp.text()
                print(f"[AUTH ERROR] App Access Token failed ({resp.status}): {body}")
                return None


async def refresh_oauth_token():
    """Requests a new bot access token from Twitch, sets expiration, and updates .env."""
    global BOT_TOKEN, REFRESH_TOKEN, TOKEN_EXPIRES_AT

    url = "https://id.twitch.tv/oauth2/token"
    payload = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "refresh_token",
        "refresh_token": REFRESH_TOKEN,
    }

    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=payload) as resp:
            if resp.status == 200:
                data = await resp.json()

                BOT_TOKEN = data["access_token"]
                REFRESH_TOKEN = data.get("refresh_token", REFRESH_TOKEN)

                expires_in = data.get("expires_in", 14400)
                TOKEN_EXPIRES_AT = time.time() + expires_in

                update_env_file("BOT_TOKEN", BOT_TOKEN)
                update_env_file("REFRESH_TOKEN", REFRESH_TOKEN)

                print(
                    f"[AUTH] Successfully refreshed BOT_TOKEN! Valid for {expires_in // 60} minutes."
                )
                return BOT_TOKEN

            body = await resp.text()
            print(
                f"[AUTH ERROR] Bot token refresh failed ({resp.status}): {body}"
            )
            return None


async def validate_or_refresh_token():
    """Validates current bot token with Twitch and updates TOKEN_EXPIRES_AT; refreshes if invalid."""
    global BOT_TOKEN, TOKEN_EXPIRES_AT

    if not BOT_TOKEN:
        print("[AUTH] No BOT_TOKEN found. Attempting refresh...")
        return await refresh_oauth_token()

    clean_token = BOT_TOKEN.replace("oauth:", "").strip()
    headers = {"Authorization": f"OAuth {clean_token}"}

    async with aiohttp.ClientSession() as session:
        async with session.get(
            "https://id.twitch.tv/oauth2/validate", headers=headers
        ) as resp:
            if resp.status == 200:
                data = await resp.json()
                expires_in = data.get("expires_in", 14400)
                if expires_in < 180:
                    print(f"[AUTH] BOT_TOKEN expires in {expires_in}s; refreshing now...")
                    return await refresh_oauth_token()

                TOKEN_EXPIRES_AT = time.time() + expires_in
                print(
                    f"[AUTH] Current BOT_TOKEN is valid for {expires_in // 60} more minutes."
                )
                return BOT_TOKEN

            print("[AUTH] BOT_TOKEN expired or invalid. Refreshing token...")
            return await refresh_oauth_token()


async def get_valid_token() -> str:
    """Returns a valid bot OAuth token. Refreshes proactively 3 minutes before expiration."""
    global BOT_TOKEN, TOKEN_EXPIRES_AT

    if not BOT_TOKEN or time.time() >= (TOKEN_EXPIRES_AT - 180):
        print("[AUTH] Bot token missing or expiring within 3 minutes. Validating/Refreshing...")
        return await validate_or_refresh_token()

    return BOT_TOKEN


async def refresh_broadcaster_token():
    """Refreshes BROADCASTER_TOKEN via TwitchTokenGenerator v2 API (no client_secret required)."""
    global BROADCASTER_TOKEN, BROADCASTER_REFRESH_TOKEN, BROADCASTER_TOKEN_EXPIRES_AT

    if not BROADCASTER_REFRESH_TOKEN:
        print("[AUTH WARNING] No BROADCASTER_REFRESH_TOKEN configured; redemption tracking disabled.")
        return None

    headers = {
        "Accept": "application/json, text/plain",
        "Content-Type": "application/json",
    }
    payload = {
        "refresh_token": BROADCASTER_REFRESH_TOKEN.strip(),
    }

    async with aiohttp.ClientSession() as session:
        async with session.post(TTG_REFRESH_URL, headers=headers, json=payload) as resp:
            body = await resp.text()
            if resp.status == 200:
                try:
                    data = json.loads(body)
                except Exception as e:
                    print(f"[AUTH ERROR] Failed to parse TTG refresh response: {e} | body={body}")
                    return None

                payload_data = data.get("data") if isinstance(data.get("data"), dict) else data
                new_access = (
                    payload_data.get("access_token")
                    or payload_data.get("token")
                )
                if not new_access:
                    print(f"[AUTH ERROR] TTG refresh 200 but no access token found: {body}")
                    return None

                BROADCASTER_TOKEN = new_access
                new_refresh = payload_data.get("refresh_token")
                if new_refresh:
                    BROADCASTER_REFRESH_TOKEN = new_refresh

                expires_in = int(payload_data.get("expires_in") or 14400)
                BROADCASTER_TOKEN_EXPIRES_AT = time.time() + expires_in

                update_env_file("BROADCASTER_TOKEN", BROADCASTER_TOKEN)
                if new_refresh:
                    update_env_file("BROADCASTER_REFRESH_TOKEN", BROADCASTER_REFRESH_TOKEN)

                print(
                    f"[AUTH] Successfully refreshed BROADCASTER_TOKEN via TTG! "
                    f"Valid for ~{expires_in // 60} minutes."
                )
                return BROADCASTER_TOKEN

            print(f"[AUTH ERROR] TTG broadcaster token refresh failed ({resp.status}): {body}")
            return None


async def validate_or_refresh_broadcaster_token():
    """Validates broadcaster token with Twitch; refreshes if invalid and captures its Client ID."""
    global BROADCASTER_TOKEN, BROADCASTER_TOKEN_EXPIRES_AT, BROADCASTER_CLIENT_ID

    if not BROADCASTER_TOKEN:
        refreshed = await refresh_broadcaster_token()
        if not refreshed:
            return None

    clean_token = BROADCASTER_TOKEN.replace("oauth:", "").strip()
    headers = {"Authorization": f"OAuth {clean_token}"}

    async with aiohttp.ClientSession() as session:
        async with session.get(
            "https://id.twitch.tv/oauth2/validate", headers=headers
        ) as resp:
            if resp.status == 200:
                data = await resp.json()
                expires_in = data.get("expires_in", 14400)
                detected_client_id = (data.get("client_id") or "").strip()

                if detected_client_id and detected_client_id != BROADCASTER_CLIENT_ID:
                    BROADCASTER_CLIENT_ID = detected_client_id
                    update_env_file("BROADCASTER_CLIENT_ID", BROADCASTER_CLIENT_ID)
                    print(f"[AUTH] Detected BROADCASTER_CLIENT_ID: {BROADCASTER_CLIENT_ID}")

                if expires_in < 180:
                    print(f"[AUTH] BROADCASTER_TOKEN expires in {expires_in}s; refreshing now...")
                    refreshed = await refresh_broadcaster_token()
                    if refreshed and not BROADCASTER_CLIENT_ID:
                        return await validate_or_refresh_broadcaster_token()
                    return refreshed

                BROADCASTER_TOKEN_EXPIRES_AT = time.time() + expires_in
                print(
                    f"[AUTH] Current BROADCASTER_TOKEN is valid for {expires_in // 60} more minutes."
                )
                return BROADCASTER_TOKEN

            print("[AUTH] BROADCASTER_TOKEN expired or invalid. Refreshing token...")
            refreshed = await refresh_broadcaster_token()
            if refreshed and not BROADCASTER_CLIENT_ID:
                return await validate_or_refresh_broadcaster_token()
            return refreshed


async def get_valid_broadcaster_token() -> str | None:
    """Returns a valid broadcaster OAuth token (without 'oauth:' prefix), refreshing within 3 minutes of expiry."""
    global BROADCASTER_TOKEN, BROADCASTER_TOKEN_EXPIRES_AT

    if not BROADCASTER_TOKEN or time.time() >= (BROADCASTER_TOKEN_EXPIRES_AT - 180):
        print("[AUTH] Broadcaster token missing or expiring within 3 minutes. Validating/Refreshing...")
        await validate_or_refresh_broadcaster_token()

    if not BROADCASTER_TOKEN:
        return None

    return BROADCASTER_TOKEN.replace("oauth:", "").strip()


async def fetch_user_ids_by_login(logins):
    """
    Fetches numeric Twitch User IDs for a list of usernames.
    Returns a dictionary mapping username (lowercase) -> user_id.
    """
    if not logins:
        return {}

    token = await get_valid_token()
    clean_token = token.replace("oauth:", "")

    params = [("login", login.lower()) for login in logins]
    url = "https://api.twitch.tv/helix/users"

    headers = {
        "Client-ID": CLIENT_ID,
        "Authorization": f"Bearer {clean_token}",
    }

    async with aiohttp.ClientSession() as session:
        async with session.get(
            url, headers=headers, params=params
        ) as resp:
            if resp.status == 200:
                data = await resp.json()
                return {
                    user["login"].lower(): user["id"]
                    for user in data.get("data", [])
                }
            else:
                body = await resp.text()
                print(f"[ID RESOLVER ERROR] {resp.status}: {body}")
                return {}


async def init_global_twitch_ids():
    """Resolves and sets global BROADCASTER_USER_ID and BOT_USER_ID from logins."""
    global BROADCASTER_USER_ID, BOT_USER_ID

    print(
        f"[INIT] Resolving Twitch IDs for '{TARGET_CHANNEL}' and '{BOT_NICK}'..."
    )

    id_map = await fetch_user_ids_by_login([TARGET_CHANNEL, BOT_NICK])

    BROADCASTER_USER_ID = id_map.get(TARGET_CHANNEL)
    BOT_USER_ID = id_map.get(BOT_NICK)

    if not BROADCASTER_USER_ID or not BOT_USER_ID:
        raise RuntimeError(
            f"[FATAL] Failed to resolve Twitch IDs! "
            f"Broadcaster: {BROADCASTER_USER_ID}, Bot: {BOT_USER_ID}"
        )

    print("[INIT] Twitch IDs Resolved successfully!")
    print(f"       -> Broadcaster ({TARGET_CHANNEL}): {BROADCASTER_USER_ID}")
    print(f"       -> Bot ({BOT_NICK}): {BOT_USER_ID}")


# ============================================================
# 2B. MODULAR YAML REDEMPTION CONFIG
# ============================================================

class RedeemConfig:
    def __init__(self, path: str = REDEEMS_CONFIG_PATH):
        self.path = Path(path)
        self.triggers: list[tuple[re.Pattern, str]] = []
        self.rewards: dict[str, dict] = {}
        self.processed_ids: deque[str] = deque(maxlen=500)
        self.reload()

    def reload(self) -> tuple[int, int]:
        if not self.path.exists():
            print(f"[REDEEMS] Config file '{self.path}' not found; skipping load.")
            self.triggers = []
            self.rewards = {}
            return 0, 0

        raw = yaml.safe_load(self.path.read_text(encoding="utf-8")) or {}

        self.triggers = [
            (re.compile(item["pattern"], re.IGNORECASE), item["label"])
            for item in raw.get("triggers", [])
            if item.get("pattern") and item.get("label")
        ]

        self.rewards = {
            item["match_title"].strip().lower(): item
            for item in raw.get("rewards", [])
            if item.get("match_title")
        }

        print(
            f"[REDEEMS] Loaded {len(self.rewards)} reward rule(s) "
            f"and {len(self.triggers)} trigger pattern(s) from {self.path}."
        )
        return len(self.rewards), len(self.triggers)

    @staticmethod
    def _resolve_timer_settings(
        reward: dict, is_sub: bool, tier: str | None
    ) -> tuple[str, str]:
        """Resolves (command_prefix, duration_value) based on subscriber status/tier."""
        prefix = str(reward.get("command_prefix", "!time")).strip()
        if is_sub and reward.get("sub_command_prefix"):
            prefix = str(reward["sub_command_prefix"]).strip()
        elif not is_sub and reward.get("non_sub_command_prefix"):
            prefix = str(reward["non_sub_command_prefix"]).strip()

        duration = None
        if is_sub:
            tier_durations = reward.get("tier_durations") or {}
            normalized_tiers = {str(k): v for k, v in tier_durations.items()}
            if tier and str(tier) in normalized_tiers:
                duration = normalized_tiers[str(tier)]
            elif "sub_duration_minutes" in reward:
                duration = reward["sub_duration_minutes"]
        else:
            if "non_sub_duration_minutes" in reward:
                duration = reward["non_sub_duration_minutes"]

        if duration is None:
            duration = reward.get("duration_minutes", 3)

        return prefix, str(duration).strip()

    async def build_command(
        self,
        redemption_id: str,
        reward_title: str,
        event_topic: str,      # "add" or "update"
        status: str,           # "unfulfilled", "fulfilled", "canceled"
        user_id: str = "",
        user_name: str = "",
        user_input: str = "",
        broadcaster_id: str | None = None,
    ) -> str | None:
        # Ignore canceled/refunded redemptions
        if status == "canceled":
            return None

        # Deduplicate processed redemptions
        if redemption_id and redemption_id in self.processed_ids:
            return None

        reward = self.rewards.get(reward_title.strip().lower())
        if not reward:
            return None

        expected_stage = reward.get("trigger_on", "fulfilled").strip().lower()

        if expected_stage == "fulfilled":
            # Matches queued rewards on .update (status == "fulfilled")
            # AND skip-queue rewards on .add (status == "fulfilled")
            if status != "fulfilled":
                return None
        elif expected_stage == "add":
            if event_topic != "add":
                return None
        else:
            return None

        action_type = reward.get("type", "timer").strip().lower()
        result_cmd = None

        if action_type == "command":
            template = reward.get("command", "").strip()
            if template:
                result_cmd = template.format(
                    user=user_name.strip(),
                    input=(user_input or "").strip(),
                ).strip()

        elif action_type == "timer":
            needs_sub_check = any(
                key in reward
                for key in (
                    "sub_duration_minutes",
                    "non_sub_duration_minutes",
                    "tier_durations",
                    "sub_command_prefix",
                    "non_sub_command_prefix",
                )
            )

            is_sub = False
            tier = None
            if needs_sub_check and broadcaster_id and user_id:
                async with aiohttp.ClientSession() as session:
                    is_sub, tier = await get_subscriber_status(
                        session=session,
                        client_id=get_broadcaster_client_id(),
                        broadcaster_id=str(broadcaster_id),
                        user_id=str(user_id),
                    )
                print(
                    f"[REDEEM SUB CHECK] user={user_name} ({user_id}) -> "
                    f"is_sub={is_sub}, tier={tier}"
                )

            label = reward.get("fallback_label", reward_title)
            for pattern, matched_label in self.triggers:
                match = pattern.search(user_input or "")
                if match:
                    if "{word}" in matched_label:
                        captured_word = (match.groupdict().get("word") or "").strip(" :-\"'.,!?")
                        if captured_word:
                            label = matched_label.format(word=captured_word)
                        else:
                            label = matched_label.replace(": {word}", "").replace("{word}", "").strip()
                    else:
                        label = matched_label
                    break

            label = (
                str(label)
                .replace("{user}", user_name.strip())
                .replace("{input}", (user_input or "").strip())
                .strip()
            )

            prefix, duration = self._resolve_timer_settings(
                reward, is_sub=is_sub, tier=tier
            )
            result_cmd = f"{prefix} {duration} {label}".strip()

        if result_cmd and redemption_id:
            self.processed_ids.append(redemption_id)

        return result_cmd


redeem_config = RedeemConfig()


# ============================================================
# 3. DATABASE
# ============================================================

conn = sqlite3.connect(
    "bot_data.db",
    check_same_thread=False
)

cursor = conn.cursor()

cursor.execute('''
    CREATE TABLE IF NOT EXISTS raids (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        raider_name TEXT NOT NULL,
        viewers INTEGER DEFAULT 0,
        timestamp INTEGER NOT NULL,
        stream_id TEXT
    )
''')

cursor.execute('''
    CREATE TABLE IF NOT EXISTS raids_out (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_name TEXT NOT NULL,
        viewers INTEGER DEFAULT 0,
        timestamp INTEGER NOT NULL,
        stream_id TEXT
    )
''')

cursor.execute("""
    CREATE TABLE IF NOT EXISTS custom_commands (
        name TEXT PRIMARY KEY,
        response TEXT NOT NULL
    )
""")

cursor.execute("""
    CREATE TABLE IF NOT EXISTS stream_state (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        stream_id TEXT,
        started_at INTEGER
    )
""")

cursor.execute("""
    CREATE TABLE IF NOT EXISTS auto_shoutout_friends (
        username TEXT PRIMARY KEY,
        added_by TEXT NOT NULL,
        added_at INTEGER NOT NULL
    )
""")

cursor.execute("""
    CREATE TABLE IF NOT EXISTS auto_shoutout_history (
        stream_id TEXT NOT NULL,
        username TEXT NOT NULL,
        triggered_at INTEGER NOT NULL,
        PRIMARY KEY (stream_id, username)
    )
""")

conn.commit()


# ============================================================
# 4. STREAM, RAID & AUTO-SHOUTOUT DATABASE HELPERS
# ============================================================

def get_current_stream_id():
    cursor.execute("SELECT stream_id FROM stream_state WHERE id = 1")
    row = cursor.fetchone()
    return row[0] if row else None


def set_current_stream(stream_id):
    cursor.execute("""
        INSERT INTO stream_state (id, stream_id, started_at)
        VALUES (1, ?, ?)
        ON CONFLICT(id)
        DO UPDATE SET
            stream_id = excluded.stream_id,
            started_at = excluded.started_at
    """, (stream_id, int(time.time())))
    conn.commit()


def clear_stream_raids():
    cursor.execute("DELETE FROM raids")
    conn.commit()
    print("[RAIDS] Cleared previous stream's raid history.")


def is_stream_currently_tracked(stream_id):
    return get_current_stream_id() == stream_id


def start_new_stream(stream_id):
    old_stream_id = get_current_stream_id()
    if old_stream_id == stream_id:
        return False

    if old_stream_id is not None:
        print(f"[STREAM] New stream detected: {old_stream_id} -> {stream_id}")
    else:
        print(f"[STREAM] Starting raid tracking for stream {stream_id}")

    # clear_stream_raids()
    # Testing this being disabled, supposedly the $ending and $raiders doesn't pull from the same thing????? findme
    set_current_stream(stream_id)
    return True


def record_raid(stream_id, raider_name, viewers):
    cursor.execute("""
        INSERT INTO raids (stream_id, raider_name, viewers, timestamp)
        VALUES (?, ?, ?, ?)
    """, (stream_id, raider_name, viewers, int(time.time())))
    conn.commit()


def record_raid_out(stream_id, target_name, viewers):
    cursor.execute("""
        INSERT INTO raids_out (stream_id, target_name, viewers, timestamp)
        VALUES (?, ?, ?, ?)
    """, (stream_id, target_name, viewers, int(time.time())))
    conn.commit()


def get_last_raid_out(target_name: str) -> tuple[int, int] | None:
    """Returns (timestamp, viewers) of the most recent outgoing raid to target_name, or None."""
    cursor.execute("""
        SELECT timestamp, viewers
        FROM raids_out
        WHERE LOWER(target_name) = ?
        ORDER BY timestamp DESC
        LIMIT 1
    """, (target_name.strip().lstrip("@").lower(),))
    return cursor.fetchone()


def get_formatted_raiders():
    stream_id = get_current_stream_id()
    if not stream_id:
        return None

    cursor.execute("""
        SELECT raider_name, viewers
        FROM raids
        WHERE stream_id = ?
        ORDER BY timestamp ASC
    """, (stream_id,))

    rows = cursor.fetchall()
    if not rows:
        return None

    formatted = [
        f"{raider} ({viewers} viewers) - https://twitch.tv/{raider.lower()}"
        for raider, viewers in rows
    ]
    return " | ".join(formatted)


async def send_discord_raiders_webhook():
    if not DISCORD_WEBHOOK_URL:
        print("[DISCORD] DISCORD_WEBHOOK_URL not set in .env, skipping.")
        return

    stream_id = get_current_stream_id()
    if not stream_id:
        return

    cursor.execute("""
        SELECT raider_name, viewers
        FROM raids
        WHERE stream_id = ?
        ORDER BY timestamp ASC
    """, (stream_id,))

    rows = cursor.fetchall()
    if not rows:
        print("[DISCORD] No raiders recorded tonight, skipping webhook.")
        return

    raider_lines = [
        f"<https://twitch.tv/{raider.lower()}>"
        for raider, viewers in rows
    ]
    content = "**Tonight's Raiders:**\n" + "\n".join(raider_lines)
    payload = {"content": content, "flags": 4}

    async with aiohttp.ClientSession() as session:
        async with session.post(DISCORD_WEBHOOK_URL, json=payload) as resp:
            if resp.status in [200, 204]:
                print("[DISCORD SUCCESS] Posted raiders to Discord!")
            else:
                body = await resp.text()
                print(f"[DISCORD ERROR] ({resp.status}): {body}")


# ------------------------------------------------------------
# Google Form / Sheet Logging Helper
# ------------------------------------------------------------

GOOGLE_FORM_ID = (os.getenv("GOOGLE_FORM_ID") or "").strip()
FORM_ENTRY_RAIDER_NAME = (os.getenv("FORM_ENTRY_RAIDER_NAME") or "").strip()
FORM_ENTRY_VIEWERS = (os.getenv("FORM_ENTRY_VIEWERS") or "").strip()
FORM_ENTRY_TWITCH_URL = (os.getenv("FORM_ENTRY_TWITCH_URL") or "").strip()
FORM_ENTRY_NOTES = (os.getenv("FORM_ENTRY_NOTES") or "").strip()

GOOGLE_FORM_ID_OUT = (os.getenv("GOOGLE_FORM_ID_OUT") or "").strip()
FORM_ENTRY_OUT_TARGET = (os.getenv("FORM_ENTRY_OUT_TARGET") or "").strip()
FORM_ENTRY_OUT_VIEWERS = (os.getenv("FORM_ENTRY_OUT_VIEWERS") or "").strip()
FORM_ENTRY_OUT_URL = (os.getenv("FORM_ENTRY_OUT_URL") or "").strip()
FORM_ENTRY_OUT_NOTES = (os.getenv("FORM_ENTRY_OUT_NOTES") or "").strip()


async def log_raid_to_google_sheet(raider_name: str, viewers: int, notes: str = ""):
    if not GOOGLE_FORM_ID or not FORM_ENTRY_RAIDER_NAME:
        return

    url = f"https://docs.google.com/forms/d/e/{GOOGLE_FORM_ID}/formResponse"
    payload = {
        FORM_ENTRY_RAIDER_NAME: raider_name,
        FORM_ENTRY_VIEWERS: str(viewers),
        FORM_ENTRY_TWITCH_URL: f"https://twitch.tv/{raider_name.lower()}",
        FORM_ENTRY_NOTES: notes,
        "fvv": "1",
        "pageHistory": "0",
    }
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        "Referer": f"https://docs.google.com/forms/d/e/{GOOGLE_FORM_ID}/viewform",
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=payload, headers=headers) as resp:
                body = await resp.text()
                if resp.status in (200, 302, 303) and ("Your response has been recorded" in body or "freebird" in body):
                    print(f"[GOOGLE SHEET SUCCESS] Logged raid from @{raider_name} ({viewers} viewers)")
                else:
                    print(f"[GOOGLE SHEET ERROR] Incoming raid log submission rejected (HTTP {resp.status}).")
    except Exception as e:
        print(f"[GOOGLE SHEET EXCEPTION] {e}")


async def log_outgoing_raid_to_google_sheet(target_name: str, viewers: int, notes: str = ""):
    if not GOOGLE_FORM_ID_OUT or not FORM_ENTRY_OUT_TARGET:
        return

    url = f"https://docs.google.com/forms/d/e/{GOOGLE_FORM_ID_OUT}/formResponse"
    payload = {
        FORM_ENTRY_OUT_TARGET: target_name,
        FORM_ENTRY_OUT_VIEWERS: str(viewers),
        FORM_ENTRY_OUT_URL: f"https://twitch.tv/{target_name.lower()}",
        FORM_ENTRY_OUT_NOTES: notes,
        "fvv": "1",
        "pageHistory": "0",
    }
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        "Referer": f"https://docs.google.com/forms/d/e/{GOOGLE_FORM_ID_OUT}/viewform",
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=payload, headers=headers) as resp:
                body = await resp.text()
                if resp.status in (200, 302, 303) and ("Your response has been recorded" in body or "freebird" in body):
                    print(f"[GOOGLE SHEET SUCCESS] Logged outgoing raid to @{target_name} ({viewers} viewers)")
                else:
                    print(f"[GOOGLE SHEET ERROR] Outgoing raid log submission rejected (HTTP {resp.status}).")
    except Exception as e:
        print(f"[GOOGLE SHEET EXCEPTION] Outgoing raid log error: {e}")


# ------------------------------------------------------------
# Auto-Shoutout Friends Helpers
# ------------------------------------------------------------

def add_auto_so_friend(username, added_by):
    cursor.execute("""
        INSERT INTO auto_shoutout_friends (username, added_by, added_at)
        VALUES (?, ?, ?)
        ON CONFLICT(username) DO NOTHING
    """, (username.lower(), added_by.lower(), int(time.time())))
    conn.commit()


def remove_auto_so_friend(username):
    cursor.execute("DELETE FROM auto_shoutout_friends WHERE username = ?", (username.lower(),))
    conn.commit()


def get_auto_so_friends():
    cursor.execute("SELECT username FROM auto_shoutout_friends ORDER BY username ASC")
    return [row[0] for row in cursor.fetchall()]


def is_auto_so_friend(username):
    cursor.execute("SELECT 1 FROM auto_shoutout_friends WHERE username = ?", (username.lower(),))
    return cursor.fetchone() is not None


def has_been_auto_shouted_out(stream_id, username):
    cursor.execute("""
        SELECT 1 FROM auto_shoutout_history
        WHERE stream_id = ? AND username = ?
    """, (stream_id, username.lower()))
    return cursor.fetchone() is not None


def record_auto_shoutout(stream_id, username):
    cursor.execute("""
        INSERT INTO auto_shoutout_history (stream_id, username, triggered_at)
        VALUES (?, ?, ?)
        ON CONFLICT(stream_id, username) DO NOTHING
    """, (stream_id, username.lower(), int(time.time())))
    conn.commit()


# ============================================================
# 5. TWITCH HELIX API HELPERS
# ============================================================

async def get_stream_info(username):
    token = await get_valid_token()
    clean_token = token.replace("oauth:", "")

    headers = {
        "Client-ID": CLIENT_ID,
        "Authorization": f"Bearer {clean_token}"
    }

    async with aiohttp.ClientSession() as session:
        async with session.get(
            "https://api.twitch.tv/helix/users",
            params={"login": username},
            headers=headers
        ) as resp:
            if resp.status != 200:
                return None, "Variety", ""

            user_data = await resp.json()
            if not user_data.get("data"):
                return None, "Variety", ""

            user_id = user_data["data"][0]["id"]
            bio = user_data["data"][0]["description"]

        async with session.get(
            "https://api.twitch.tv/helix/channels",
            params={"broadcaster_id": user_id},
            headers=headers
        ) as resp:
            game_name = "Variety"
            if resp.status == 200:
                chan_data = await resp.json()
                if chan_data.get("data"):
                    game_name = chan_data["data"][0].get("game_name") or "Variety"

        return user_id, game_name, bio


async def get_current_stream(username):
    token = await get_valid_token()
    clean_token = token.replace("oauth:", "")

    headers = {
        "Client-ID": CLIENT_ID,
        "Authorization": f"Bearer {clean_token}"
    }

    async with aiohttp.ClientSession() as session:
        async with session.get(
            "https://api.twitch.tv/helix/streams",
            params={"user_login": username},
            headers=headers
        ) as resp:
            if resp.status == 401:
                new_token = await refresh_oauth_token()
                if new_token:
                    headers["Authorization"] = f"Bearer {new_token.replace('oauth:', '')}"
                    async with session.get(
                        "https://api.twitch.tv/helix/streams",
                        params={"user_login": username},
                        headers=headers
                    ) as retry_resp:
                        if retry_resp.status == 200:
                            data = await retry_resp.json()
                            return data["data"][0] if data.get("data") else None
                return None

            if resp.status != 200:
                return None

            data = await resp.json()
            return data["data"][0] if data.get("data") else None


async def send_announcement(broadcaster_id, moderator_id, message_text, color="orange"):
    token = await get_valid_token()
    clean_token = token.replace("oauth:", "")

    url = (
        "https://api.twitch.tv/helix/chat/announcements"
        f"?broadcaster_id={broadcaster_id}"
        f"&moderator_id={moderator_id}"
    )

    headers = {
        "Client-ID": CLIENT_ID,
        "Authorization": f"Bearer {clean_token}",
        "Content-Type": "application/json"
    }

    payload = {"message": message_text, "color": color}

    async with aiohttp.ClientSession() as session, session.post(
        url, headers=headers, json=payload
    ) as resp:
        if resp.status == 204:
            print("[API SUCCESS] Announcement banner sent!")
            return True

        err_body = await resp.text()
        print(f"[API ERROR] Announcement failed ({resp.status}): {err_body}")
        return False


async def send_native_shoutout(to_broadcaster_id: str) -> bool:
    """
    Triggers Twitch's native /shoutout card via Helix API using the bot's moderator token.
    Requires `moderator:manage:shoutouts` on BOT_TOKEN and channel to be live.
    """
    if not BROADCASTER_USER_ID or not BOT_USER_ID or not to_broadcaster_id:
        return False

    token = await get_valid_token()
    clean_token = token.replace("oauth:", "")

    url = "https://api.twitch.tv/helix/chat/shoutouts"
    params = {
        "from_broadcaster_id": str(BROADCASTER_USER_ID),
        "to_broadcaster_id": str(to_broadcaster_id),
        "moderator_id": str(BOT_USER_ID),
    }
    headers = {
        "Client-ID": CLIENT_ID,
        "Authorization": f"Bearer {clean_token}",
    }

    async with aiohttp.ClientSession() as session:
        async with session.post(url, params=params, headers=headers) as resp:
            if resp.status == 204:
                print(f"[SHOUTOUT SUCCESS] Native Twitch shoutout sent for user ID {to_broadcaster_id}!")
                return True
            elif resp.status == 400:
                body = await resp.text()
                print(f"[SHOUTOUT SKIPPED] Channel offline or invalid target (400): {body}")
                return False
            elif resp.status == 429:
                print("[SHOUTOUT COOLDOWN] Twitch shoutout rate limit / cooldown active (429).")
                return False
            else:
                body = await resp.text()
                print(f"[SHOUTOUT ERROR] ({resp.status}): {body}")
                return False


async def send_whisper(to_user_id: str, message_text: str) -> bool:
    """Sends a Twitch whisper from BOT_USER_ID via Helix API (requires user:manage:whispers)."""
    if not BOT_USER_ID or not to_user_id or str(to_user_id) == str(BOT_USER_ID):
        return False

    token = await get_valid_token()
    clean_token = token.replace("oauth:", "").strip()

    url = "https://api.twitch.tv/helix/whispers"
    params = {
        "from_user_id": str(BOT_USER_ID),
        "to_user_id": str(to_user_id),
    }
    headers = {
        "Client-ID": CLIENT_ID,
        "Authorization": f"Bearer {clean_token}",
        "Content-Type": "application/json",
    }
    payload = {"message": message_text[:500]}

    async with aiohttp.ClientSession() as session:
        async with session.post(url, params=params, headers=headers, json=payload) as resp:
            if resp.status == 204:
                print(f"[WHISPER SUCCESS] Sent reply to user ID {to_user_id}")
                return True
            body = await resp.text()
            print(f"[WHISPER ERROR] ({resp.status}): {body}")
            return False


RERUN_TAG_TOKENS = {
    "rerun",
    "reruns",
    "replay",
    "replays",
    "prerecorded",
    "vodcast",
    "vodcasts",
    "rebroadcast",
    "rebroadcasts",
    "restream",
    "restreams",
    "encore",
}

RERUN_TITLE_RE = re.compile(
    r"\b(?:reruns?|replays?|pre[-\s]?recorded|vodcasts?|re[-\s]?broadcasts?|re[-\s]?streams?|encore)\b",
    re.IGNORECASE,
)


def detect_rerun_reasons(stream: dict) -> list[str]:
    """Checks stream type, tags, and title for rerun/replay/pre-recorded indicators."""
    reasons: list[str] = []

    stream_type = (stream.get("type") or "live").lower()
    if stream_type != "live":
        reasons.append(f"type: {stream_type}")

    for tag in stream.get("tags") or []:
        normalized = re.sub(r"[\s_-]+", "", str(tag).lower())
        if normalized in RERUN_TAG_TOKENS:
            reasons.append(f"tag: {tag}")

    title = stream.get("title") or ""
    title_match = RERUN_TITLE_RE.search(title)
    if title_match:
        reasons.append(f"title: '{title_match.group(0)}'")

    return reasons


def format_stream_uptime(started_at: str | None) -> str:
    """Formats a Helix stream started_at ISO timestamp as uptime (e.g. '2h 15m' or '42m')."""
    if not started_at:
        return "unknown uptime"
    try:
        start_dt = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
        total_mins = max(0, int((datetime.now(timezone.utc) - start_dt).total_seconds() // 60))
        hours, mins = divmod(total_mins, 60)
        if hours > 0:
            return f"{hours}h {mins}m"
        return f"{mins}m"
    except Exception:
        return "unknown uptime"


async def get_channel_chat_modes(
    broadcaster_id: str, session: aiohttp.ClientSession | None = None
) -> list[str]:
    """Fetches followers-only and subscribers-only status via GET /helix/chat/settings."""
    if not broadcaster_id:
        return []

    token = await get_valid_token()
    clean_token = token.replace("oauth:", "").strip()
    headers = {
        "Client-ID": CLIENT_ID,
        "Authorization": f"Bearer {clean_token}",
    }
    url = "https://api.twitch.tv/helix/chat/settings"
    params = {"broadcaster_id": str(broadcaster_id)}

    async def _fetch(sess: aiohttp.ClientSession) -> list[str]:
        async with sess.get(url, headers=headers, params=params) as resp:
            if resp.status != 200:
                return []
            items = (await resp.json()).get("data", [])
            if not items:
                return []
            settings = items[0]
            modes: list[str] = []
            if settings.get("subscriber_mode"):
                modes.append("subs-only")
            if settings.get("follower_mode"):
                dur = settings.get("follower_mode_duration")
                if dur and int(dur) > 0:
                    modes.append(f"followers-only ({int(dur)}m)")
                else:
                    modes.append("followers-only")
            return modes

    if session is not None:
        return await _fetch(session)

    async with aiohttp.ClientSession() as new_session:
        return await _fetch(new_session)


def format_relative_ago(ts: int | None) -> str:
    """Formats a Unix timestamp as a relative age string (e.g. '21d ago' or 'never')."""
    if ts is None:
        return "never"

    elapsed = max(0, int(time.time()) - int(ts))
    if elapsed < 3600:
        return "under 1h ago"
    if elapsed < 86400:
        return f"{elapsed // 3600}h ago"
    if elapsed < 60 * 86400:
        return f"{elapsed // 86400}d ago"
    return f"{elapsed // (30 * 86400)}mo ago"


def format_last_raided_out(login: str) -> str:
    """Returns a relative timestamp for the last outgoing raid (e.g. '21d ago' or 'never')."""
    record = get_last_raid_out(login)
    return format_relative_ago(record[0] if record else None)


async def get_live_raiders_summary(extra_logins: list[str] | None = None) -> list[str]:
    """
    Checks ALL historical raiders (plus any extra usernames) against GET /helix/streams
    and GET /helix/chat/settings.
    """
    cursor.execute(
        """
        SELECT LOWER(raider_name)
        FROM raids
        GROUP BY LOWER(raider_name)
        ORDER BY MAX(timestamp) DESC
        """
    )
    raiders: list[str] = [row[0] for row in cursor.fetchall()]

    for name in extra_logins or []:
        clean = name.strip().lstrip("@").lower()
        if clean and clean not in raiders:
            raiders.append(clean)

    if not raiders:
        return ["No raiders recorded in the database yet."]

    token = await get_valid_token()
    clean_token = token.replace("oauth:", "").strip()
    headers = {
        "Client-ID": CLIENT_ID,
        "Authorization": f"Bearer {clean_token}",
    }

    live_data: list[dict] = []
    chat_modes_list: list[list[str]] = []
    async with aiohttp.ClientSession() as session:
        for i in range(0, len(raiders), 100):
            batch = raiders[i : i + 100]
            params = [("user_login", r) for r in batch]
            async with session.get(
                "https://api.twitch.tv/helix/streams", headers=headers, params=params
            ) as resp:
                if resp.status != 200:
                    body = await resp.text()
                    print(f"[LIVE RAIDERS ERROR] ({resp.status}): {body}")
                    return [f"Failed to check live status (HTTP {resp.status})."]
                live_data.extend((await resp.json()).get("data", []))

        if not live_data:
            return [f"Checked {len(raiders)} past raider(s) — none are currently live."]

        chat_modes_list = await asyncio.gather(
            *(get_channel_chat_modes(s.get("user_id", ""), session) for s in live_data)
        )

    cursor.execute(
        """
        SELECT LOWER(target_name), MAX(timestamp)
        FROM raids_out
        GROUP BY LOWER(target_name)
        """
    )
    last_raided_map: dict[str, int] = {
        row[0]: int(row[1])
        for row in cursor.fetchall()
        if row[0] and row[1] is not None
    }

    enriched = []
    for s, modes in zip(live_data, chat_modes_list):
        login = s["user_login"].lower()
        reasons = detect_rerun_reasons(s)
        last_ts = last_raided_map.get(login)
        enriched.append((bool(reasons), last_ts, s, modes))

    enriched.sort(
        key=lambda item: (
            item[0],
            0 if item[1] is None else 1,
            0 if item[1] is None else item[1],
            -int(item[2].get("viewer_count", 0)),
        )
    )

    header = f"Live raiders ({len(enriched)}/{len(raiders)}): "
    entries: list[str] = []
    for is_rerun, last_ts, s, modes in enriched:
        rerun_badge = " [RERUN]" if is_rerun else ""
        game = s.get("game_name") or "No Category"
        uptime = format_stream_uptime(s.get("started_at"))
        ago = format_relative_ago(last_ts)
        raided_label = f"raided {ago}" if ago != "never" else "never raided"
        mode_suffix = f", {', '.join(modes)}" if modes else ""
        entries.append(
            f"{s['user_name']}{rerun_badge} ({game}, {s['viewer_count']} viewers, up {uptime}, {raided_label}{mode_suffix}) twitch.tv/{s['user_login']}"
        )

    messages: list[str] = []
    current = header
    for entry in entries:
        sep = "" if current == header else " | "
        if len(current) + len(sep) + len(entry) <= 490:
            current += sep + entry
        else:
            if current.strip():
                messages.append(current)
            current = entry[:490]

    if current.strip():
        messages.append(current)

    return messages


async def check_raid_target_status(raw_target: str) -> str:
    """Checks if a target channel is live, flags reruns, compares category, and shows uptime, chat modes, and last raid out."""
    target_login = raw_target.strip().lstrip("@").lower()
    if not target_login:
        return "Usage: check <username>"

    last_raided = format_last_raided_out(target_login)

    target_stream = await get_current_stream(target_login)
    if not target_stream:
        user_id, last_game, _ = await get_stream_info(target_login)
        if not user_id:
            return f"Channel '{target_login}' was not found on Twitch."
        return (
            f"{target_login} is currently OFFLINE (last category: {last_game}) — "
            f"Last raided: {last_raided}."
        )

    target_name = target_stream.get("user_name") or target_login
    target_game = (target_stream.get("game_name") or "No Category").strip()
    viewers = target_stream.get("viewer_count", 0)
    uptime = format_stream_uptime(target_stream.get("started_at"))

    modes = await get_channel_chat_modes(target_stream.get("user_id", ""))
    chat_str = ", ".join(modes) if modes else "open"

    rerun_reasons = detect_rerun_reasons(target_stream)
    rerun_note = (
        f" [WARNING: RERUN DETECTED ({', '.join(rerun_reasons)})]"
        if rerun_reasons
        else ""
    )

    host_stream = await get_current_stream(TARGET_CHANNEL)
    if host_stream:
        host_game = (host_stream.get("game_name") or "No Category").strip()
        if target_game.lower() == host_game.lower():
            cat_status = f"SAME category ({target_game})"
        else:
            cat_status = f"DIFFERENT category (theirs: {target_game} | ours: {host_game})"
    else:
        cat_status = f"Category: {target_game}"

    return (
        f"{target_name} is LIVE ({viewers} viewers, up {uptime}){rerun_note} — "
        f"{cat_status} — Chat: {chat_str} — Last raided: {last_raided} — twitch.tv/{target_login}"
    )


async def get_subscriber_status(
    session: aiohttp.ClientSession,
    client_id: str | None = None,
    broadcaster_id: str | None = None,
    user_id: str | None = None,
) -> tuple[bool, str | None]:
    """Checks whether user_id is subscribed to broadcaster_id.

    Returns (is_sub, tier) where tier is '1000', '2000', '3000', or None.
    """
    if not broadcaster_id or not user_id:
        return False, None

    # Broadcasters don't always show up in /subscriptions/user for their own channel
    if str(user_id) == str(broadcaster_id):
        return True, "3000"

    token = await get_valid_broadcaster_token()
    if not token:
        print("[SUB CHECK] No valid broadcaster token available; defaulting to non-sub.")
        return False, None

    req_client_id = get_broadcaster_client_id() or client_id or CLIENT_ID

    url = "https://api.twitch.tv/helix/subscriptions"
    headers = {
        "Client-ID": req_client_id,
        "Authorization": f"Bearer {token}",
    }
    params = {
        "broadcaster_id": str(broadcaster_id),
        "user_id": str(user_id),
    }

    async with session.get(url, headers=headers, params=params) as resp:
        if resp.status == 200:
            data = await resp.json()
            entries = data.get("data", [])
            if entries:
                return True, str(entries[0].get("tier") or "1000")
            return False, None

        if resp.status == 404:
            return False, None

        body = await resp.text()
        print(f"[SUB CHECK ERROR] ({resp.status}): {body}")
        return False, None


# ------------------------------------------------------------
# Custom Channel Point Reward Management Helpers
# ------------------------------------------------------------

def _reward_headers() -> tuple[str, dict] | tuple[None, None]:
    target_id = str(BROADCASTER_USER_ID or "")
    req_client_id = get_broadcaster_client_id()
    if not target_id or not req_client_id:
        return None, None
    return target_id, {
        "Client-ID": req_client_id,
        "Content-Type": "application/json",
    }


async def find_custom_reward(title: str) -> dict | None:
    """Fetches a custom reward on the channel by case-insensitive title."""
    target_id, base_headers = _reward_headers()
    token = await get_valid_broadcaster_token()
    if not target_id or not token:
        return None

    headers = {**base_headers, "Authorization": f"Bearer {token}"}
    url = "https://api.twitch.tv/helix/channel_points/custom_rewards"

    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers, params={"broadcaster_id": target_id}) as resp:
            if resp.status != 200:
                body = await resp.text()
                print(f"[REWARD LOOKUP ERROR] ({resp.status}): {body}")
                return None
            rewards = (await resp.json()).get("data", [])

    return next(
        (r for r in rewards if (r.get("title") or "").strip().lower() == title.strip().lower()),
        None,
    )


async def create_custom_reward(payload: dict) -> tuple[bool, str]:
    """Creates a new custom reward owned by BROADCASTER_CLIENT_ID."""
    target_id, base_headers = _reward_headers()
    token = await get_valid_broadcaster_token()
    if not target_id or not token:
        return False, "Missing broadcaster ID or token."

    create_body = dict(payload)
    initial_paused = create_body.pop("is_paused", None)

    headers = {**base_headers, "Authorization": f"Bearer {token}"}
    url = "https://api.twitch.tv/helix/channel_points/custom_rewards"

    async with aiohttp.ClientSession() as session:
        async with session.post(url, headers=headers, params={"broadcaster_id": target_id}, json=create_body) as resp:
            body = await resp.text()
            if resp.status != 200:
                return False, f"Twitch rejected create ({resp.status}): {body}"
            created = json.loads(body).get("data", [{}])[0]

    if initial_paused is True and created.get("id"):
        await update_custom_reward(created["id"], created.get("title", ""), {"is_paused": True})

    return True, f"Created '{created.get('title')}' (cost: {created.get('cost')})."


async def clone_custom_reward(title: str, suffix: str = " (Bot)") -> tuple[bool, str]:
    """Clones an existing custom reward with a suffix so the bot owns its Client ID."""
    source = await find_custom_reward(title)
    if not source:
        return False, f"No reward found matching '{title}'."

    cloned_title = f"{source['title']}{suffix}"[:45]
    payload = {
        "title": cloned_title,
        "cost": source["cost"],
        "prompt": source.get("prompt") or "",
        "is_enabled": bool(source.get("is_enabled", True)),
        "background_color": source.get("background_color") or "#9147FF",
        "is_user_input_required": bool(source.get("is_user_input_required", False)),
        "should_redemptions_skip_request_queue": bool(
            source.get("should_redemptions_skip_request_queue", False)
        ),
    }

    global_cd = source.get("global_cooldown_setting") or {}
    if global_cd.get("is_enabled"):
        payload["is_global_cooldown_enabled"] = True
        payload["global_cooldown_seconds"] = global_cd.get("global_cooldown_seconds", 0)

    max_stream = source.get("max_per_stream_setting") or {}
    if max_stream.get("is_enabled"):
        payload["is_max_per_stream_enabled"] = True
        payload["max_per_stream"] = max_stream.get("max_per_stream", 0)

    max_user = source.get("max_per_user_per_stream_setting") or {}
    if max_user.get("is_enabled"):
        payload["is_max_per_user_per_stream_enabled"] = True
        payload["max_per_user_per_stream"] = max_user.get("max_per_user_per_stream", 0)

    return await create_custom_reward(payload)


async def update_custom_reward(reward_id: str, reward_title: str, updates: dict) -> tuple[bool, str]:
    """Updates an existing bot-owned custom reward via PATCH."""
    target_id, base_headers = _reward_headers()
    token = await get_valid_broadcaster_token()
    if not target_id or not token:
        return False, "Missing broadcaster ID or token."

    headers = {**base_headers, "Authorization": f"Bearer {token}"}
    url = "https://api.twitch.tv/helix/channel_points/custom_rewards"
    params = {"broadcaster_id": target_id, "id": reward_id}

    async with aiohttp.ClientSession() as session:
        async with session.patch(url, headers=headers, params=params, json=updates) as resp:
            body = await resp.text()
            if resp.status == 200:
                updated = json.loads(body).get("data", [{}])[0]
                return True, f"Updated '{updated.get('title', reward_title)}'."
            if resp.status == 403:
                return False, f"Cannot edit '{reward_title}'—it wasn't created by this bot's Client ID (clone it first)."
            return False, f"Twitch rejected edit ({resp.status}): {body}"


async def delete_custom_reward(reward_id: str, reward_title: str) -> tuple[bool, str]:
    """Deletes a bot-owned custom reward via DELETE."""
    target_id, base_headers = _reward_headers()
    token = await get_valid_broadcaster_token()
    if not target_id or not token:
        return False, "Missing broadcaster ID or token."

    headers = {**base_headers, "Authorization": f"Bearer {token}"}
    url = "https://api.twitch.tv/helix/channel_points/custom_rewards"
    params = {"broadcaster_id": target_id, "id": reward_id}

    async with aiohttp.ClientSession() as session:
        async with session.delete(url, headers=headers, params=params) as resp:
            if resp.status == 204:
                return True, f"Deleted reward '{reward_title}'."
            body = await resp.text()
            if resp.status == 403:
                return False, f"Cannot delete '{reward_title}'—it wasn't created by this bot's Client ID."
            return False, f"Twitch rejected delete ({resp.status}): {body}"


STARTUP_PAUSE_REWARD = (os.getenv("STARTUP_PAUSE_REWARD") or "").strip()


async def pause_startup_reward():
    """Pauses the configured bot-owned reward when a new stream starts."""
    if not STARTUP_PAUSE_REWARD:
        return

    reward = await find_custom_reward(STARTUP_PAUSE_REWARD)
    if not reward:
        print(f"[REWARDS WARNING] Startup reward '{STARTUP_PAUSE_REWARD}' not found.")
        return

    ok, msg = await update_custom_reward(
        reward["id"], reward["title"], {"is_paused": True}
    )
    prefix = "[REWARDS SUCCESS]" if ok else "[REWARDS ERROR]"
    print(f"{prefix} {msg}")


async def list_manageable_rewards() -> list[dict] | None:
    """Fetches all custom rewards owned by BROADCASTER_CLIENT_ID."""
    target_id, base_headers = _reward_headers()
    token = await get_valid_broadcaster_token()
    if not target_id or not token:
        return None

    headers = {**base_headers, "Authorization": f"Bearer {token}"}
    url = "https://api.twitch.tv/helix/channel_points/custom_rewards"
    params = {"broadcaster_id": target_id, "only_manageable_rewards": "true"}

    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers, params=params) as resp:
            if resp.status != 200:
                body = await resp.text()
                print(f"[REWARD LIST ERROR] ({resp.status}): {body}")
                return None
            return (await resp.json()).get("data", [])


async def reset_reward_stream_limit(reward_id: str, reward_title: str, max_per_stream: int) -> tuple[bool, str]:
    """Toggles max_per_stream off and back on to reset Twitch's current-stream redemption counter."""
    ok, msg = await update_custom_reward(
        reward_id, reward_title, {"is_max_per_stream_enabled": False}
    )
    if not ok:
        return False, msg

    ok, msg = await update_custom_reward(
        reward_id,
        reward_title,
        {
            "is_max_per_stream_enabled": True,
            "max_per_stream": max(1, int(max_per_stream)),
        },
    )
    if not ok:
        return False, f"Disabled stream limit on '{reward_title}', but failed to re-enable: {msg}"

    return True, f"Reset per-stream redemption count for '{reward_title}' (limit: {max_per_stream})."


def parse_reward_kv_args(tokens: list[str]) -> dict:
    """Parses key=value options covering all Twitch Helix custom reward parameters."""
    updates: dict = {}
    true_vals = {"true", "1", "yes", "on"}
    false_vals = {"false", "0", "no", "off", "none"}
    bool_map = {**{k: True for k in true_vals}, **{k: False for k in false_vals}}

    for tok in tokens:
        if "=" not in tok:
            continue
        k, v = tok.split("=", 1)
        k = k.strip().lower()
        v = v.strip()
        v_low = v.lower()

        if k == "title":
            if not v:
                raise ValueError("Title cannot be empty.")
            updates["title"] = v[:45]

        elif k == "cost":
            updates["cost"] = max(1, int(v))

        elif k == "prompt":
            updates["prompt"] = v[:200]

        elif k in ("input", "user_input", "is_user_input_required"):
            if v_low not in bool_map:
                raise ValueError(f"Invalid boolean for {k}: {v}")
            updates["is_user_input_required"] = bool_map[v_low]

        elif k in ("skipqueue", "skip_queue", "should_redemptions_skip_request_queue"):
            if v_low not in bool_map:
                raise ValueError(f"Invalid boolean for {k}: {v}")
            updates["should_redemptions_skip_request_queue"] = bool_map[v_low]

        elif k in ("enabled", "is_enabled"):
            if v_low not in bool_map:
                raise ValueError(f"Invalid boolean for {k}: {v}")
            updates["is_enabled"] = bool_map[v_low]

        elif k in ("paused", "is_paused"):
            if v_low not in bool_map:
                raise ValueError(f"Invalid boolean for {k}: {v}")
            updates["is_paused"] = bool_map[v_low]

        elif k in ("color", "background_color"):
            hex_val = v if v.startswith("#") else f"#{v}"
            if not re.fullmatch(r"#[0-9A-Fa-f]{6}", hex_val):
                raise ValueError("Color must be a 6-digit hex code (e.g. #9147FF).")
            updates["background_color"] = hex_val.upper()

        elif k in ("cooldown", "global_cooldown", "global_cooldown_seconds"):
            if v_low in false_vals:
                updates["is_global_cooldown_enabled"] = False
            else:
                secs = int(v)
                if secs <= 0:
                    updates["is_global_cooldown_enabled"] = False
                else:
                    updates["is_global_cooldown_enabled"] = True
                    updates["global_cooldown_seconds"] = secs

        elif k in ("cooldown_enabled", "is_global_cooldown_enabled"):
            if v_low not in bool_map:
                raise ValueError(f"Invalid boolean for {k}: {v}")
            updates["is_global_cooldown_enabled"] = bool_map[v_low]

        elif k in ("max_stream", "max_per_stream", "stream_limit"):
            if v_low in false_vals:
                updates["is_max_per_stream_enabled"] = False
            else:
                limit = int(v)
                if limit <= 0:
                    updates["is_max_per_stream_enabled"] = False
                else:
                    updates["is_max_per_stream_enabled"] = True
                    updates["max_per_stream"] = limit

        elif k in ("max_stream_enabled", "is_max_per_stream_enabled"):
            if v_low not in bool_map:
                raise ValueError(f"Invalid boolean for {k}: {v}")
            updates["is_max_per_stream_enabled"] = bool_map[v_low]

        elif k in ("max_user", "max_per_user", "max_per_user_per_stream", "user_limit"):
            if v_low in false_vals:
                updates["is_max_per_user_per_stream_enabled"] = False
            else:
                limit = int(v)
                if limit <= 0:
                    updates["is_max_per_user_per_stream_enabled"] = False
                else:
                    updates["is_max_per_user_per_stream_enabled"] = True
                    updates["max_per_user_per_stream"] = limit

        elif k in ("max_user_enabled", "is_max_per_user_per_stream_enabled"):
            if v_low not in bool_map:
                raise ValueError(f"Invalid boolean for {k}: {v}")
            updates["is_max_per_user_per_stream_enabled"] = bool_map[v_low]

    return updates


# ============================================================
# 6. IRC CHAT & CHAT API HELPERS
# ============================================================

async def send_chat(writer, message):
    """Sends a message to the configured Twitch channel over IRC."""
    payload = f"PRIVMSG #{TARGET_CHANNEL} :{message}\r\n"
    writer.write(payload.encode("utf-8"))
    await writer.drain()


async def send_chat_as_bot(message_text, writer=None, reply_fn=None):
    """
    Sends a message via Helix Chat API using an App Access Token (Bot Badge).
    If reply_fn is provided (e.g. from a whisper), routes the reply there instead.
    Falls back to IRC send_chat() if writer is provided and API call fails.
    """
    if reply_fn is not None:
        await reply_fn(message_text)
        return True

    if not BROADCASTER_USER_ID or not BOT_USER_ID:
        print("[CHAT ERROR] Global Twitch IDs are not initialized!")
        return False

    token = await get_app_access_token()
    if not token:
        if writer:
            await send_chat(writer, message_text)
        return False

    url = "https://api.twitch.tv/helix/chat/messages"
    headers = {
        "Client-ID": CLIENT_ID,
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    payload = {
        "broadcaster_id": str(BROADCASTER_USER_ID),
        "sender_id": str(BOT_USER_ID),
        "message": message_text
    }

    async with aiohttp.ClientSession() as session:
        async with session.post(url, headers=headers, json=payload) as resp:
            if resp.status == 200:
                print(f"[CHAT API (BOT BADGE)] Sent: {message_text}")
                return True
            else:
                body = await resp.text()
                print(f"[CHAT ERROR] {resp.status}: {body}")
                if writer:
                    print("[CHAT FALLBACK] Sending via IRC...")
                    await send_chat(writer, message_text)
                return False


async def send_raiders_message(writer=None, notify_if_empty: bool = True, reply_fn=None):
    raiders_list = get_formatted_raiders()
    if not raiders_list:
        if notify_if_empty:
            await send_chat_as_bot(
                "No raids recorded this stream yet!", writer=writer, reply_fn=reply_fn
            )
        return

    full_msg = f"Huge thanks to tonight's raiders! Check out their channels: {raiders_list}"
    if reply_fn is not None and len(full_msg) > 490:
        for idx in range(0, len(full_msg), 490):
            if idx > 0:
                await asyncio.sleep(0.4)
            await reply_fn(full_msg[idx : idx + 490])
        return

    await send_chat_as_bot(full_msg, writer=writer, reply_fn=reply_fn)


# ============================================================
# 7. COMMAND HANDLER
# ============================================================

TIMER_USAGE_COOLDOWN = 4
_last_timer_usage_sent = 0.0


def is_privileged_user(sender: str, tags: dict) -> bool:
    raw_badges = tags.get("badges", "")
    badge_names = {
        entry.split("/", 1)[0]
        for entry in raw_badges.split(",")
        if entry
    }
    is_mod = (
        tags.get("mod") == "1"
        or bool(badge_names & {"broadcaster", "moderator", "lead_moderator"})
    )
    is_owner = sender.lower() in [BOT_NICK, TARGET_CHANNEL]
    return is_mod or is_owner


def is_allowed_to_manage_redeems(sender: str) -> bool:
    return sender.lower().lstrip("@") in {
        u.lower().lstrip("@") for u in REDEEMS_ALLOWED_USERS
    }


async def handle_command_logic(writer, sender, message_text, tags, reply_fn=None):
    global _last_timer_usage_sent

    content = message_text.strip()

    if not content.startswith("$"):
        return

    parts = content[1:].split(" ")
    cmd_trigger = parts[0].lower()
    args = parts[1:]

    # Allow $redeem as an alias for $reward
    if cmd_trigger == "redeem":
        cmd_trigger = "reward"
        content = "$reward" + content[len("$redeem"):]

    # --------------------------------------------------------
    # $reloadredeems (Hot-reload redeems.yaml)
    # --------------------------------------------------------
    if cmd_trigger == "reloadredeems":
        if not is_privileged_user(sender, tags):
            return

        try:
            reward_count, trigger_count = redeem_config.reload()
            await send_chat_as_bot(
                f"Reloaded configuration ({reward_count} rewards, {trigger_count} triggers).",
                writer=writer,
                reply_fn=reply_fn,
            )
        except Exception as e:
            await send_chat_as_bot(
                f"Failed to reload configuration: {e}",
                writer=writer,
                reply_fn=reply_fn,
            )

    # --------------------------------------------------------
    # $reward / $redeem <list|info|create|clone|edit|reset|delete|confirm|cancel>
    # --------------------------------------------------------
    elif cmd_trigger == "reward":
        if not is_allowed_to_manage_redeems(sender):
            return

        sender_key = sender.lower().lstrip("@")
        raw_arg_str = content[len("$reward"):].strip()

        if not raw_arg_str:
            await send_chat_as_bot(
                'Usage: $reward <list|info|create|clone|edit|reset|delete|confirm|cancel> | Example: $reward edit "guide the raid!" paused=false max_stream=2',
                writer=writer,
                reply_fn=reply_fn,
            )
            return

        try:
            tokens = shlex.split(raw_arg_str)
        except ValueError as e:
            await send_chat_as_bot(
                f"Invalid quotes in command: {e}", writer=writer, reply_fn=reply_fn
            )
            return

        sub = tokens[0].lower()
        rest = tokens[1:]

        # --- List bot-owned rewards ---
        if sub == "list":
            owned = await list_manageable_rewards()
            if owned is None:
                await send_chat_as_bot(
                    "Failed to fetch bot-owned rewards from Twitch.",
                    writer=writer,
                    reply_fn=reply_fn,
                )
                return
            if not owned:
                await send_chat_as_bot(
                    "No rewards are currently owned by this bot's Client ID.",
                    writer=writer,
                    reply_fn=reply_fn,
                )
                return

            entries = []
            for r in owned:
                state = "paused" if r.get("is_paused") else ("enabled" if r.get("is_enabled") else "disabled")
                entries.append(f"{r['title'].strip()} ({r['cost']} pts, {state})")
            await send_chat_as_bot(
                f"Bot-owned rewards: {' | '.join(entries)}"[:480],
                writer=writer,
                reply_fn=reply_fn,
            )
            return

        # --- Inspect a specific reward's settings ---
        if sub == "info":
            if not rest:
                await send_chat_as_bot(
                    'Usage: $reward info "Reward Title"', writer=writer, reply_fn=reply_fn
                )
                return

            title = rest[0].strip()
            r = await find_custom_reward(title)
            if not r:
                await send_chat_as_bot(
                    f"No reward found matching '{title}'.", writer=writer, reply_fn=reply_fn
                )
                return

            s_lim = r.get("max_per_stream_setting") or {}
            u_lim = r.get("max_per_user_per_stream_setting") or {}
            cd = r.get("global_cooldown_setting") or {}

            stream_str = str(s_lim["max_per_stream"]) if s_lim.get("is_enabled") else "off"
            user_str = str(u_lim["max_per_user_per_stream"]) if u_lim.get("is_enabled") else "off"
            cd_str = f"{cd['global_cooldown_seconds']}s" if cd.get("is_enabled") else "off"

            summary = (
                f"'{r['title'].strip()}': cost={r['cost']}, enabled={r.get('is_enabled')}, "
                f"paused={r.get('is_paused')}, in_stock={r.get('is_in_stock')}, "
                f"input={r.get('is_user_input_required')}, skipqueue={r.get('should_redemptions_skip_request_queue')}, "
                f"max_stream={stream_str}, max_user={user_str}, cooldown={cd_str}, color={r.get('background_color')}"
            )
            await send_chat_as_bot(summary[:480], writer=writer, reply_fn=reply_fn)
            return

        # --- Confirm staged action ---
        if sub == "confirm":
            pending = PENDING_REWARD_ACTIONS.pop(sender_key, None)
            if not pending:
                await send_chat_as_bot(
                    "No pending reward action to confirm.", writer=writer, reply_fn=reply_fn
                )
                return

            if time.time() - pending["created_at"] > REWARD_CONFIRM_TTL:
                await send_chat_as_bot(
                    f"That reward confirmation expired ({REWARD_CONFIRM_TTL}s limit). Run the command again.",
                    writer=writer,
                    reply_fn=reply_fn,
                )
                return

            action = pending["action"]
            if action == "create":
                _, msg = await create_custom_reward(pending["payload"])
            elif action == "clone":
                _, msg = await clone_custom_reward(pending["title"], suffix=pending["suffix"])
            elif action == "edit":
                _, msg = await update_custom_reward(pending["reward_id"], pending["title"], pending["updates"])
            elif action == "reset":
                _, msg = await reset_reward_stream_limit(
                    pending["reward_id"], pending["title"], pending["max_per_stream"]
                )
            elif action == "delete":
                _, msg = await delete_custom_reward(pending["reward_id"], pending["title"])
            else:
                msg = "Unknown staged action."

            await send_chat_as_bot(msg, writer=writer, reply_fn=reply_fn)
            return

        # --- Cancel staged action ---
        if sub == "cancel":
            if PENDING_REWARD_ACTIONS.pop(sender_key, None):
                await send_chat_as_bot(
                    "Cancelled pending reward change.", writer=writer, reply_fn=reply_fn
                )
            else:
                await send_chat_as_bot(
                    "No pending reward action to cancel.", writer=writer, reply_fn=reply_fn
                )
            return

        # --- Stage: CREATE ---
        if sub == "create":
            if len(rest) < 2:
                await send_chat_as_bot(
                    'Usage: $reward create "Title" cost=500 [prompt="..."] [input=true] [skipqueue=false] [paused=false] [color=#9147FF] [cooldown=60] [max_stream=1] [max_user=1]',
                    writer=writer,
                    reply_fn=reply_fn,
                )
                return

            title = rest[0].strip()[:45]
            try:
                opts = parse_reward_kv_args(rest[1:])
            except ValueError as e:
                await send_chat_as_bot(f"Invalid option: {e}", writer=writer, reply_fn=reply_fn)
                return

            if "cost" not in opts:
                await send_chat_as_bot(
                    "You must specify cost=<number> when creating a reward.",
                    writer=writer,
                    reply_fn=reply_fn,
                )
                return

            payload = {"title": title, **opts}
            PENDING_REWARD_ACTIONS[sender_key] = {
                "action": "create",
                "payload": payload,
                "created_at": time.time(),
            }
            await send_chat_as_bot(
                f"Stage CREATE '{title}' (cost={payload['cost']})? Type '$reward confirm' within {REWARD_CONFIRM_TTL}s or '$reward cancel'.",
                writer=writer,
                reply_fn=reply_fn,
            )

        # --- Stage: CLONE ---
        elif sub == "clone":
            if not rest:
                await send_chat_as_bot(
                    'Usage: $reward clone "Existing Reward Title"', writer=writer, reply_fn=reply_fn
                )
                return

            title = rest[0].strip()
            existing = await find_custom_reward(title)
            if not existing:
                await send_chat_as_bot(
                    f"No existing reward found matching '{title}'.",
                    writer=writer,
                    reply_fn=reply_fn,
                )
                return

            cloned_name = f"{existing['title']} (Bot)"[:45]
            PENDING_REWARD_ACTIONS[sender_key] = {
                "action": "clone",
                "title": existing["title"],
                "suffix": " (Bot)",
                "created_at": time.time(),
            }
            await send_chat_as_bot(
                f"Stage CLONE '{existing['title']}' -> '{cloned_name}' (cost={existing['cost']})? Type '$reward confirm' within {REWARD_CONFIRM_TTL}s or '$reward cancel'.",
                writer=writer,
                reply_fn=reply_fn,
            )

        # --- Stage: EDIT ---
        elif sub == "edit":
            if len(rest) < 2:
                await send_chat_as_bot(
                    'Usage: $reward edit "Title" [title="New"] [cost=500] [prompt="..."] [enabled=true] [paused=false] [input=true] [skipqueue=false] [color=#9147FF] [cooldown=60] [max_stream=1] [max_user=1]',
                    writer=writer,
                    reply_fn=reply_fn,
                )
                return

            title = rest[0].strip()
            existing = await find_custom_reward(title)
            if not existing:
                await send_chat_as_bot(
                    f"No reward found matching '{title}'.", writer=writer, reply_fn=reply_fn
                )
                return

            try:
                updates = parse_reward_kv_args(rest[1:])
            except ValueError as e:
                await send_chat_as_bot(f"Invalid option: {e}", writer=writer, reply_fn=reply_fn)
                return

            if not updates:
                await send_chat_as_bot(
                    "No valid fields provided (title=, cost=, prompt=, enabled=, paused=, input=, skipqueue=, color=, cooldown=, max_stream=, max_user=).",
                    writer=writer,
                    reply_fn=reply_fn,
                )
                return

            PENDING_REWARD_ACTIONS[sender_key] = {
                "action": "edit",
                "reward_id": existing["id"],
                "title": existing["title"],
                "updates": updates,
                "created_at": time.time(),
            }
            summary = ", ".join(f"{k}={v}" for k, v in updates.items())
            await send_chat_as_bot(
                f"Stage EDIT '{existing['title']}' ({summary})? Type '$reward confirm' within {REWARD_CONFIRM_TTL}s or '$reward cancel'.",
                writer=writer,
                reply_fn=reply_fn,
            )

        # --- Stage: RESET per-stream redemption count ---
        elif sub == "reset":
            if not rest:
                await send_chat_as_bot(
                    'Usage: $reward reset "Reward Title"', writer=writer, reply_fn=reply_fn
                )
                return

            title = rest[0].strip()
            existing = await find_custom_reward(title)
            if not existing:
                await send_chat_as_bot(
                    f"No reward found matching '{title}'.", writer=writer, reply_fn=reply_fn
                )
                return

            stream_setting = existing.get("max_per_stream_setting") or {}
            if not stream_setting.get("is_enabled"):
                await send_chat_as_bot(
                    f"'{existing['title'].strip()}' does not have a per-stream limit enabled.",
                    writer=writer,
                    reply_fn=reply_fn,
                )
                return

            max_val = stream_setting.get("max_per_stream", 1)
            PENDING_REWARD_ACTIONS[sender_key] = {
                "action": "reset",
                "reward_id": existing["id"],
                "title": existing["title"],
                "max_per_stream": max_val,
                "created_at": time.time(),
            }
            await send_chat_as_bot(
                f"Stage RESET stream limit on '{existing['title'].strip()}' (re-opening {max_val} slot(s))? Type '$reward confirm' within {REWARD_CONFIRM_TTL}s or '$reward cancel'.",
                writer=writer,
                reply_fn=reply_fn,
            )

        # --- Stage: DELETE ---
        elif sub == "delete":
            if not rest:
                await send_chat_as_bot(
                    'Usage: $reward delete "Reward Title"', writer=writer, reply_fn=reply_fn
                )
                return

            title = rest[0].strip()
            existing = await find_custom_reward(title)
            if not existing:
                await send_chat_as_bot(
                    f"No reward found matching '{title}'.", writer=writer, reply_fn=reply_fn
                )
                return

            PENDING_REWARD_ACTIONS[sender_key] = {
                "action": "delete",
                "reward_id": existing["id"],
                "title": existing["title"],
                "created_at": time.time(),
            }
            await send_chat_as_bot(
                f"Stage DELETE '{existing['title']}' (cost={existing['cost']})? This cannot be undone! Type '$reward confirm' within {REWARD_CONFIRM_TTL}s or '$reward cancel'.",
                writer=writer,
                reply_fn=reply_fn,
            )

        else:
            await send_chat_as_bot(
                "Unknown subcommand. Use: $reward <list|info|create|clone|edit|reset|delete|confirm|cancel>",
                writer=writer,
                reply_fn=reply_fn,
            )

    # --------------------------------------------------------
    # $raiders / $raids
    # --------------------------------------------------------
    elif cmd_trigger in ["raiders", "raids"]:
        await send_raiders_message(writer, reply_fn=reply_fn)

    # --------------------------------------------------------
    # $time / $t / $timer / $tp (Bare usage hint only; overlay handles active args)
    # --------------------------------------------------------
    elif cmd_trigger in ["time", "t", "timer", "tp"]:
        if not is_privileged_user(sender, tags):
            return

        clean_args = [a for a in args if a]
        if not clean_args:
            now = time.time()
            if now - _last_timer_usage_sent >= TIMER_USAGE_COOLDOWN:
                _last_timer_usage_sent = now
                await send_chat_as_bot(
                    "Timer usage: $t <time> [label] | $tp <time> [label] | $tl <label> | $t pause/resume/stop/+2m",
                    writer=writer,
                    reply_fn=reply_fn,
                )

    # --------------------------------------------------------
    # $ending / $wrapup
    # --------------------------------------------------------
    elif cmd_trigger in ["ending", "wrapup", "raidout"]:
        if not is_privileged_user(sender, tags):
            return

        await send_chat_as_bot("!raid", writer=writer)
        await asyncio.sleep(3)
        await send_chat_as_bot("!subraid", writer=writer)
        await asyncio.sleep(3)

        await send_raiders_message(writer, notify_if_empty=False)
        await send_discord_raiders_webhook()

    # --------------------------------------------------------
    # $so (Chat Banner) & $sso (Super-Shoutout: Banner + Native /shoutout)
    # --------------------------------------------------------
    elif cmd_trigger in ["so", "sso"]:
        if not is_privileged_user(sender, tags):
            return

        if not args:
            await send_chat_as_bot(f"Usage: ${cmd_trigger} <username>", writer=writer)
            return

        target_user = args[0].lower().lstrip("@")
        target_id, game_name, bio = await get_stream_info(target_user)
        clean_bio = f" Bio: {bio[:135]}..." if bio else ""

        so_msg = (
            f"Check out {target_user}, last seen playing {game_name} 🍞 "
            f"Go follow: https://twitch.tv/{target_user} 🍞 {clean_bio}"
        )

        # 1. Chat announcement banner (with chat fallback)
        success = False
        if BROADCASTER_USER_ID and BOT_USER_ID:
            success = await send_announcement(
                BROADCASTER_USER_ID, BOT_USER_ID, so_msg, color="orange"
            )

        if not success:
            await send_chat_as_bot(f"/me ⭐ {so_msg}", writer=writer)

        # 2. Native Twitch /shoutout card (only for $sso)
        if cmd_trigger == "sso" and target_id:
            await send_native_shoutout(target_id)

    # --------------------------------------------------------
    # $autoso
    # --------------------------------------------------------
    elif cmd_trigger == "autoso":
        if not is_privileged_user(sender, tags):
            return

        if not args:
            await send_chat_as_bot(
                "Usage: $autoso <add|del|list> [@username]", writer=writer, reply_fn=reply_fn
            )
            return

        subaction = args[0].lower()

        if subaction == "list":
            friends = get_auto_so_friends()
            if not friends:
                await send_chat_as_bot(
                    "No friends configured for auto-shoutouts yet!",
                    writer=writer,
                    reply_fn=reply_fn,
                )
            else:
                await send_chat_as_bot(
                    f"Auto-shoutout friends: {', '.join(friends)}",
                    writer=writer,
                    reply_fn=reply_fn,
                )

        elif subaction in ["add", "append"]:
            if len(args) < 2:
                await send_chat_as_bot(
                    "Usage: $autoso add @username", writer=writer, reply_fn=reply_fn
                )
                return
            target = args[1].lower().lstrip("@")
            add_auto_so_friend(target, sender)
            await send_chat_as_bot(
                f"Added {target} to the auto-shoutout friends list!",
                writer=writer,
                reply_fn=reply_fn,
            )

        elif subaction in ["del", "delete", "remove"]:
            if len(args) < 2:
                await send_chat_as_bot(
                    "Usage: $autoso del @username", writer=writer, reply_fn=reply_fn
                )
                return
            target = args[1].lower().lstrip("@")
            remove_auto_so_friend(target)
            await send_chat_as_bot(
                f"Removed {target} from the auto-shoutout friends list!",
                writer=writer,
                reply_fn=reply_fn,
            )

    # --------------------------------------------------------
    # $cmd
    # --------------------------------------------------------
    elif cmd_trigger == "cmd":
        if not is_privileged_user(sender, tags):
            return

        if not args:
            await send_chat_as_bot(
                "Usage: $cmd <add|edit|delete|list> <$cmdname> [response]",
                writer=writer,
                reply_fn=reply_fn,
            )
            return

        subaction = args[0].lower()

        if subaction == "list":
            cursor.execute("SELECT name FROM custom_commands")
            cmds = [row[0] for row in cursor.fetchall()]
            if not cmds:
                await send_chat_as_bot(
                    "No custom commands set up yet!", writer=writer, reply_fn=reply_fn
                )
            else:
                await send_chat_as_bot(
                    f"Custom commands: {', '.join(cmds)}", writer=writer, reply_fn=reply_fn
                )

        elif subaction in ["add", "edit"]:
            if len(args) < 3:
                await send_chat_as_bot(
                    "Usage: $cmd add $cmdname Response text here",
                    writer=writer,
                    reply_fn=reply_fn,
                )
                return

            cmd_name = args[1].lower().lstrip("$").lstrip("!")
            response_text = " ".join(args[2:])

            cursor.execute(
                """
                INSERT INTO custom_commands (name, response)
                VALUES (?, ?)
                ON CONFLICT(name)
                DO UPDATE SET response = excluded.response
                """,
                (cmd_name, response_text),
            )
            conn.commit()
            await send_chat_as_bot(
                f"Command ${cmd_name} updated successfully!",
                writer=writer,
                reply_fn=reply_fn,
            )

        elif subaction in ["delete", "del", "remove"]:
            if len(args) < 2:
                await send_chat_as_bot(
                    "Usage: $cmd delete $cmdname", writer=writer, reply_fn=reply_fn
                )
                return

            cmd_name = args[1].lower().lstrip("$").lstrip("!")
            cursor.execute("DELETE FROM custom_commands WHERE name = ?", (cmd_name,))
            conn.commit()
            await send_chat_as_bot(
                f"Command ${cmd_name} deleted!", writer=writer, reply_fn=reply_fn
            )

    # --------------------------------------------------------
    # DYNAMIC CUSTOM COMMAND
    # --------------------------------------------------------
    else:
        cursor.execute("SELECT response FROM custom_commands WHERE name = ?", (cmd_trigger,))
        row = cursor.fetchone()
        if row:
            await send_chat_as_bot(row[0], writer=writer, reply_fn=reply_fn)


# ============================================================
# 8. IRC TAG PARSER
# ============================================================

def parse_tags(tag_str):
    tags = {}
    if tag_str.startswith("@"):
        for part in tag_str[1:].split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                tags[k] = v
    return tags


# ============================================================
# 9. EVENTSUB RAID & REDEMPTION HANDLERS
# ============================================================

async def handle_raid_in(event, stream_id):
    raider = event.get(
        "from_broadcaster_user_name",
        event.get("from_broadcaster_user_login", "Unknown"),
    )
    viewers = int(event.get("viewers", 0))
    raider_login = event.get("from_broadcaster_user_login", raider)

    print(f"[RAID IN] {raider} raided #{TARGET_CHANNEL} with {viewers} viewers!")
    record_raid(stream_id, raider_login, viewers)

    raider_id, game_name, bio = await get_stream_info(raider_login)
    clean_bio = f" Bio: {bio[:120]}..." if bio else ""

    so_msg = (
        f"Check out {raider_login}, last seen playing {game_name} 🍞 "
        f"Go follow: https://twitch.tv/{raider_login} 🍞 {clean_bio}"
    )

    await asyncio.sleep(15)

    success = False
    if BROADCASTER_USER_ID and BOT_USER_ID:
        success = await send_announcement(
            BROADCASTER_USER_ID, BOT_USER_ID, so_msg, color="orange"
        )

    if not success:
        await send_chat_as_bot(f"/me ⭐ {so_msg}")

    if raider_id:
        await send_native_shoutout(raider_id)

    await log_raid_to_google_sheet(raider_login, viewers)


async def handle_raid_out(writer, event):
    target_name = event.get(
        "to_broadcaster_user_name",
        event.get("to_broadcaster_user_login", "Unknown"),
    )
    target_login = event.get("to_broadcaster_user_login", target_name)
    viewers = int(event.get("viewers", 0))
    print(f"[RAID OUT] #{TARGET_CHANNEL} raided {target_name} with {viewers} viewers!")
    record_raid_out(get_current_stream_id(), target_login, viewers)
    await log_outgoing_raid_to_google_sheet(target_name, viewers)


async def handle_redemption_event(writer, event_topic: str, event: dict):
    """Processes Channel Point redemption .add and .update events via redeems.yaml."""
    redemption_id = event.get("id", "")
    status = (event.get("status") or "").lower()
    user_id = str(event.get("user_id") or "")
    user_name = event.get("user_name") or event.get("user_login") or ""
    user_input = event.get("user_input") or ""
    reward = event.get("reward") or {}
    reward_title = reward.get("title") or ""

    print(
        f"[REDEEM {event_topic.upper()}] '{reward_title}' by {user_name} ({user_id}) "
        f"(status={status}, input={user_input!r})"
    )

    cmd = await redeem_config.build_command(
        redemption_id=redemption_id,
        reward_title=reward_title,
        event_topic=event_topic,
        status=status,
        user_id=user_id,
        user_name=user_name,
        user_input=user_input,
        broadcaster_id=BROADCASTER_USER_ID,
    )

    if cmd:
        print(f"[REDEEM TRIGGER] Executing chat command: {cmd}")
        await send_chat_as_bot(cmd, writer=writer)


# ============================================================
# 10. BACKGROUND TASKS & EVENTSUB WEBSOCKETS
# ============================================================

async def stream_monitor_loop():
    print("[STREAM MONITOR] Started monitoring live status...")
    while True:
        try:
            current_stream = await get_current_stream(TARGET_CHANNEL)
            if current_stream:
                live_stream_id = current_stream["id"]
                if not is_stream_currently_tracked(live_stream_id):
                    if start_new_stream(live_stream_id):
                        await pause_startup_reward()
        except Exception as e:
            print(f"[STREAM MONITOR ERROR] {type(e).__name__}: {e}")

        await asyncio.sleep(60)


async def eventsub_listener(writer, broadcaster_id):
    """
    Maintains the broadcaster Twitch EventSub WebSocket.
    Handles:
- channel.raid (using BROADCASTER_TOKEN / BOT_TOKEN)
- channel.channel_points_custom_reward_redemption.add & .update (using BROADCASTER_TOKEN)
    """
    base_eventsub_url = "wss://eventsub.wss.twitch.tv/ws?keepalive_timeout_seconds=30"
    eventsub_url = base_eventsub_url
    reconnecting = False

    while True:
        try:
            bot_token = await validate_or_refresh_token()
            broadcaster_token = await validate_or_refresh_broadcaster_token()

            if not bot_token:
                print("[EVENTSUB ERROR] Unable to acquire valid BOT_TOKEN. Retrying in 10s...")
                await asyncio.sleep(10)
                continue

            clean_bot_token = bot_token.replace("oauth:", "").strip()
            clean_broadcaster_token = (
                broadcaster_token.replace("oauth:", "").strip()
                if broadcaster_token
                else None
            )
            broadcaster_client_id = get_broadcaster_client_id()

            async with aiohttp.ClientSession() as session:
                print(
                    f"[EVENTSUB] Connecting to "
                    f"{'Twitch reconnect URL' if reconnecting else 'EventSub'}..."
                )

                async with session.ws_connect(eventsub_url, heartbeat=30) as ws:
                    welcome = await ws.receive_json()
                    metadata = welcome.get("metadata", {})

                    if metadata.get("message_type") != "session_welcome":
                        print("[EVENTSUB ERROR] Did not receive session_welcome.")
                        eventsub_url = base_eventsub_url
                        reconnecting = False
                        await asyncio.sleep(5)
                        continue

                    session_id = welcome["payload"]["session"]["id"]
                    print(f"[EVENTSUB] Connected. Session ID: {session_id}")

                    if reconnecting:
                        print("[EVENTSUB] Reconnected; existing subscriptions transferred.")
                    else:
                        if clean_broadcaster_token:
                            eventsub_auth_token = clean_broadcaster_token
                            eventsub_client_id = broadcaster_client_id
                        else:
                            eventsub_auth_token = clean_bot_token
                            eventsub_client_id = CLIENT_ID

                        subscriptions = [
                            (
                                eventsub_auth_token,
                                eventsub_client_id,
                                {
                                    "type": "channel.raid",
                                    "version": "1",
                                    "condition": {"to_broadcaster_user_id": broadcaster_id},
                                },
                            ),
                            (
                                eventsub_auth_token,
                                eventsub_client_id,
                                {
                                    "type": "channel.raid",
                                    "version": "1",
                                    "condition": {"from_broadcaster_user_id": broadcaster_id},
                                },
                            ),
                        ]

                        if clean_broadcaster_token:
                            subscriptions.extend([
                                (
                                    clean_broadcaster_token,
                                    broadcaster_client_id,
                                    {
                                        "type": "channel.channel_points_custom_reward_redemption.add",
                                        "version": "1",
                                        "condition": {"broadcaster_user_id": broadcaster_id},
                                    },
                                ),
                                (
                                    clean_broadcaster_token,
                                    broadcaster_client_id,
                                    {
                                        "type": "channel.channel_points_custom_reward_redemption.update",
                                        "version": "1",
                                        "condition": {"broadcaster_user_id": broadcaster_id},
                                    },
                                ),
                            ])
                        else:
                            print(
                                "[EVENTSUB WARNING] No BROADCASTER_TOKEN available; "
                                "Channel Point redemption subscriptions skipped."
                            )

                        for auth_token, req_client_id, subscription in subscriptions:
                            headers = {
                                "Client-ID": req_client_id,
                                "Authorization": f"Bearer {auth_token}",
                                "Content-Type": "application/json",
                            }
                            payload = {
                                **subscription,
                                "transport": {
                                    "method": "websocket",
                                    "session_id": session_id,
                                },
                            }

                            async with session.post(
                                "https://api.twitch.tv/helix/eventsub/subscriptions",
                                headers=headers,
                                json=payload,
                            ) as resp:
                                if resp.status == 202:
                                    print(
                                        f"[EVENTSUB] Subscribed to {subscription['type']} "
                                        f"({subscription['condition']})"
                                    )
                                else:
                                    body = await resp.text()
                                    print(
                                        f"[EVENTSUB ERROR] Subscription failed "
                                        f"({resp.status}) for {subscription['type']}: {body}"
                                    )

                    reconnecting = False
                    eventsub_url = base_eventsub_url

                    async for msg in ws:
                        if msg.type == aiohttp.WSMsgType.TEXT:
                            try:
                                data = msg.json()
                            except Exception as e:
                                print(f"[EVENTSUB ERROR] Invalid JSON: {e}")
                                continue

                            metadata = data.get("metadata", {})
                            message_type = metadata.get("message_type")

                            if message_type == "session_keepalive":
                                continue

                            elif message_type == "session_reconnect":
                                reconnect_url = (
                                    data.get("payload", {})
                                    .get("session", {})
                                    .get("reconnect_url")
                                )
                                if reconnect_url:
                                    eventsub_url = reconnect_url
                                    reconnecting = True
                                else:
                                    eventsub_url = base_eventsub_url
                                    reconnecting = False
                                break

                            elif message_type == "notification":
                                payload = data.get("payload", {})
                                subscription = payload.get("subscription", {})
                                event = payload.get("event", {})
                                event_type = subscription.get("type")

                                if event_type == "channel.raid":
                                    if event.get("to_broadcaster_user_id") == broadcaster_id:
                                        current_stream_id = get_current_stream_id()
                                        if current_stream_id:
                                            await handle_raid_in(event, current_stream_id)
                                        else:
                                            print("[RAID IN] Ignoring raid (channel offline).")

                                    elif event.get("from_broadcaster_user_id") == broadcaster_id:
                                        await handle_raid_out(writer, event)

                                elif event_type == "channel.channel_points_custom_reward_redemption.add":
                                    await handle_redemption_event(writer, "add", event)

                                elif event_type == "channel.channel_points_custom_reward_redemption.update":
                                    await handle_redemption_event(writer, "update", event)

                            elif message_type == "revocation":
                                subscription = data.get("payload", {}).get("subscription", {})
                                print(
                                    f"[EVENTSUB WARNING] Subscription revoked: "
                                    f"{subscription.get('type')} status={subscription.get('status')}"
                                )
                                eventsub_url = base_eventsub_url
                                reconnecting = False
                                break

                        elif msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                            print(
                                f"[EVENTSUB] WebSocket closed. Code: {ws.close_code}, "
                                f"Exception: {ws.exception()}"
                            )
                            eventsub_url = base_eventsub_url
                            reconnecting = False
                            break

        except asyncio.CancelledError:
            print("[EVENTSUB] Listener stopped.")
            return

        except Exception as e:
            print(f"[EVENTSUB ERROR] {type(e).__name__}: {e}")
            eventsub_url = base_eventsub_url
            reconnecting = False

        print("[EVENTSUB] Reconnecting in 5 seconds...")
        await asyncio.sleep(5)


async def bot_whisper_eventsub_listener():
    """
    Maintains a dedicated EventSub WebSocket authenticated as BOT_USER_ID
    to receive user.whisper.message events (Twitch requires separate sockets per user).
    """
    base_eventsub_url = "wss://eventsub.wss.twitch.tv/ws?keepalive_timeout_seconds=30"
    eventsub_url = base_eventsub_url
    reconnecting = False

    while True:
        try:
            bot_token = await validate_or_refresh_token()
            if not bot_token or not BOT_USER_ID:
                print("[WHISPER WS ERROR] Missing BOT_TOKEN or BOT_USER_ID. Retrying in 10s...")
                await asyncio.sleep(10)
                continue

            clean_bot_token = bot_token.replace("oauth:", "").strip()

            async with aiohttp.ClientSession() as session:
                print(
                    f"[WHISPER WS] Connecting to "
                    f"{'Twitch reconnect URL' if reconnecting else 'EventSub'}..."
                )

                async with session.ws_connect(eventsub_url, heartbeat=30) as ws:
                    welcome = await ws.receive_json()
                    metadata = welcome.get("metadata", {})

                    if metadata.get("message_type") != "session_welcome":
                        print("[WHISPER WS ERROR] Did not receive session_welcome.")
                        eventsub_url = base_eventsub_url
                        reconnecting = False
                        await asyncio.sleep(5)
                        continue

                    session_id = welcome["payload"]["session"]["id"]
                    print(f"[WHISPER WS] Connected. Session ID: {session_id}")

                    if reconnecting:
                        print("[WHISPER WS] Reconnected; whisper subscription transferred.")
                    else:
                        headers = {
                            "Client-ID": CLIENT_ID,
                            "Authorization": f"Bearer {clean_bot_token}",
                            "Content-Type": "application/json",
                        }
                        payload = {
                            "type": "user.whisper.message",
                            "version": "1",
                            "condition": {"user_id": str(BOT_USER_ID)},
                            "transport": {
                                "method": "websocket",
                                "session_id": session_id,
                            },
                        }

                        async with session.post(
                            "https://api.twitch.tv/helix/eventsub/subscriptions",
                            headers=headers,
                            json=payload,
                        ) as resp:
                            if resp.status == 202:
                                print(
                                    f"[WHISPER WS] Subscribed to user.whisper.message "
                                    f"({{'user_id': '{BOT_USER_ID}'}})"
                                )
                            else:
                                body = await resp.text()
                                print(
                                    f"[WHISPER WS ERROR] Subscription failed "
                                    f"({resp.status}): {body}"
                                )

                    reconnecting = False
                    eventsub_url = base_eventsub_url

                    async for msg in ws:
                        if msg.type == aiohttp.WSMsgType.TEXT:
                            try:
                                data = msg.json()
                            except Exception as e:
                                print(f"[WHISPER WS ERROR] Invalid JSON: {e}")
                                continue

                            metadata = data.get("metadata", {})
                            message_type = metadata.get("message_type")

                            if message_type == "session_keepalive":
                                continue

                            elif message_type == "session_reconnect":
                                reconnect_url = (
                                    data.get("payload", {})
                                    .get("session", {})
                                    .get("reconnect_url")
                                )
                                if reconnect_url:
                                    eventsub_url = reconnect_url
                                    reconnecting = True
                                else:
                                    eventsub_url = base_eventsub_url
                                    reconnecting = False
                                break

                            elif message_type == "notification":
                                payload = data.get("payload", {})
                                event_type = payload.get("subscription", {}).get("type")
                                event = payload.get("event", {})

                                if event_type == "user.whisper.message":
                                    from_id = str(event.get("from_user_id") or "")
                                    from_login = (event.get("from_user_login") or "").lower()
                                    text = ((event.get("whisper") or {}).get("text") or "").strip()

                                    if from_id != str(BOT_USER_ID) and is_allowed_to_manage_redeems(from_login):
                                        parts = text.split()
                                        cmd = parts[0].lower() if parts else ""

                                        if cmd in ("$raiders", "$raidtargets", "raiders", "raidtargets"):
                                            replies = await get_live_raiders_summary(parts[1:])
                                            for idx, msg_chunk in enumerate(replies):
                                                if idx > 0:
                                                    await asyncio.sleep(0.4)
                                                await send_whisper(from_id, msg_chunk)

                                        elif cmd in ("$check", "check", "$raidcheck", "raidcheck"):
                                            target = parts[1] if len(parts) > 1 else ""
                                            reply = await check_raid_target_status(target)
                                            await send_whisper(from_id, reply)

                                        elif cmd in ("$help", "help", "$commands", "commands"):
                                            help_msg = (
                                                "Whisper commands: "
                                                "raidtargets [extra_users] | "
                                                "check <user> | "
                                                "$reward / $redeem <list|info|create|clone|edit|reset|delete|confirm|cancel> | "
                                                "$cmd <add|edit|delete|list> | "
                                                "$autoso <add|del|list> | "
                                                "$reloadredeems"
                                            )
                                            await send_whisper(from_id, help_msg)

                                        elif text.startswith("$"):
                                            allowed_whisper_cmds = {
                                                "reward",
                                                "redeem",
                                                "cmd",
                                                "reloadredeems",
                                                "autoso",
                                                "raiders",
                                                "raids",
                                            }
                                            bare = cmd.lstrip("$")
                                            if bare in allowed_whisper_cmds:
                                                async def _whisper_reply(msg: str):
                                                    await send_whisper(from_id, msg)

                                                await handle_command_logic(
                                                    writer=None,
                                                    sender=from_login,
                                                    message_text=text,
                                                    tags={"mod": "1"},
                                                    reply_fn=_whisper_reply,
                                                )

                            elif message_type == "revocation":
                                sub = data.get("payload", {}).get("subscription", {})
                                print(
                                    f"[WHISPER WS WARNING] Subscription revoked: "
                                    f"{sub.get('type')} status={sub.get('status')}"
                                )
                                eventsub_url = base_eventsub_url
                                reconnecting = False
                                break

                        elif msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                            print(
                                f"[WHISPER WS] WebSocket closed. Code: {ws.close_code}, "
                                f"Exception: {ws.exception()}"
                            )
                            eventsub_url = base_eventsub_url
                            reconnecting = False
                            break

        except asyncio.CancelledError:
            print("[WHISPER WS] Listener stopped.")
            return

        except Exception as e:
            print(f"[WHISPER WS ERROR] {type(e).__name__}: {e}")
            eventsub_url = base_eventsub_url
            reconnecting = False

        print("[WHISPER WS] Reconnecting in 5 seconds...")
        await asyncio.sleep(5)


# ============================================================
# 11. MAIN
# ============================================================

async def main():
    token = await validate_or_refresh_token()
    if not token:
        print("[CRITICAL] Could not acquire a valid BOT_TOKEN.")
        return

    clean_token = token.replace("oauth:", "")
    await init_global_twitch_ids()

    current_stream = await get_current_stream(TARGET_CHANNEL)
    if current_stream:
        current_stream_id = current_stream["id"]
        if start_new_stream(current_stream_id):
            await pause_startup_reward()
        print(f"[STREAM] Currently live. Stream ID: {current_stream_id}")
    else:
        print("[STREAM] Channel is currently offline.")

    print(f"[IRC] Connecting to Twitch IRC for #{TARGET_CHANNEL}...")
    reader, writer = await asyncio.open_connection("irc.chat.twitch.tv", 6667)

    writer.write(
        b"CAP REQ :twitch.tv/tags "
        b"twitch.tv/commands "
        b"twitch.tv/membership\r\n"
    )
    writer.write(f"PASS oauth:{clean_token}\r\n".encode())
    writer.write(f"NICK {BOT_NICK}\r\n".encode())
    writer.write(f"JOIN #{TARGET_CHANNEL}\r\n".encode())
    await writer.drain()

    eventsub_task = asyncio.create_task(
        eventsub_listener(writer, BROADCASTER_USER_ID)
    )
    whisper_task = asyncio.create_task(
        bot_whisper_eventsub_listener()
    )
    monitor_task = asyncio.create_task(stream_monitor_loop())

    print("--------------------------------------------------")
    print(f"Bot ({BOT_NICK}) is LIVE on #{TARGET_CHANNEL}!")
    print("--------------------------------------------------")

    try:
        while True:
            data = await reader.readline()
            if not data:
                break

            line = data.decode("utf-8", errors="ignore").strip()

            if line.startswith("PING"):
                writer.write(b"PONG :tmi.twitch.tv\r\n")
                await writer.drain()
                continue

            if "PRIVMSG" in line:
                parts = line.split(" ", 4)
                tags = parse_tags(parts[0]) if line.startswith("@") else {}

                sender = "Unknown"
                if tags.get("display-name"):
                    sender = tags["display-name"]
                elif "!" in line:
                    sender = line.split("!")[0].lstrip("@").split(":")[-1]

                message_text = line.split(f"PRIVMSG #{TARGET_CHANNEL} :", 1)[-1]

                # Auto-Shoutout Friends Check
                active_stream_id = get_current_stream_id()
                if active_stream_id and is_auto_so_friend(sender):
                    if not has_been_auto_shouted_out(active_stream_id, sender):
                        record_auto_shoutout(active_stream_id, sender)
                        print(f"[AUTO-SO] Triggered automatic shoutout for friend: {sender}")

                        _, game_name, bio = await get_stream_info(sender)
                        clean_bio = f" Bio: {bio[:160]}..." if bio else ""

                        so_msg = (
                            f"Check out {sender}, last seen playing {game_name} 🍞 "
                            f"Go follow: https://twitch.tv/{sender} 🍞 {clean_bio}"
                        )

                        success = False
                        if BROADCASTER_USER_ID and BOT_USER_ID:
                            success = await send_announcement(
                                BROADCASTER_USER_ID, BOT_USER_ID, so_msg, color="orange"
                            )

                        if not success:
                            await send_chat_as_bot(f"/me ⭐ {so_msg}", writer=writer)

                await handle_command_logic(writer, sender, message_text, tags)

    finally:
        print("[BOT] Shutting down...")
        eventsub_task.cancel()
        whisper_task.cancel()
        monitor_task.cancel()

        try:
            await asyncio.gather(
                eventsub_task, whisper_task, monitor_task, return_exceptions=True
            )
        except Exception:
            pass

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


# ============================================================
# 12. ENTRY POINT
# ============================================================

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[BOT STOPPED] Exiting safely.")