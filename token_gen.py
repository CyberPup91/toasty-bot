#!/usr/bin/env python3
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


def load_client_id() -> str:
    """Reads CLIENT_ID from environment or local .env file, prompting if missing."""
    cid = (os.getenv("CLIENT_ID") or "").strip()
    if not cid and Path(".env").exists():
        for raw_line in Path(".env").read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if line.startswith("CLIENT_ID="):
                cid = line.split("=", 1)[1].strip().strip("\"'")
                break
    if not cid:
        cid = input("Enter Twitch CLIENT_ID: ").strip()
    return cid


def read_scopes() -> str:
    """Reads pasted scopes separated by spaces, commas, newlines, or bullet points."""
    print("Paste your scopes (space, comma, or newline separated).")
    print("Press Enter on an empty line when finished:\n")

    lines = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if not line.strip():
            if lines:
                break
            continue
        lines.append(line)

    raw = "\n".join(lines)
    # Strip markdown bullets (-, *, •), quotes, and split on whitespace/commas
    cleaned = re.sub(r"(?m)^\s*[-*•]\s*", "", raw)
    tokens = [
        t.strip("\"',;")
        for t in re.split(r"[\s,]+", cleaned)
        if t.strip("\"',;")
    ]

    # Deduplicate while preserving order
    unique_scopes = list(dict.fromkeys(tokens))
    return " ".join(unique_scopes)


def post_form(url: str, data: dict) -> tuple[int, dict]:
    encoded = urllib.parse.urlencode(data).encode("utf-8")
    req = urllib.request.Request(url, data=encoded, method="POST")
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore")
        try:
            return e.code, json.loads(body)
        except json.JSONDecodeError:
            return e.code, {"message": body}


def main():
    client_id = load_client_id()
    if not client_id:
        print("Error: CLIENT_ID is required.")
        return

    scopes = read_scopes()
    if not scopes:
        print("Error: No scopes provided.")
        return

    print(f"\nRequesting device code for scopes:\n  {scopes}\n")

    status, device = post_form(
        "https://id.twitch.tv/oauth2/device",
        {"client_id": client_id, "scopes": scopes},
    )
    if status != 200:
        print(f"Device authorization failed ({status}): {device}")
        return

    print("1. Open this URL (logged into the Twitch account you want to authorize):")
    print(f"   {device['verification_uri']}")
    print(f"2. Enter code: {device['user_code']}\n")
    print("Waiting for authorization...")

    interval = int(device.get("interval", 5))
    deadline = time.time() + int(device.get("expires_in", 1800))

    while time.time() < deadline:
        time.sleep(interval)
        status, token_data = post_form(
            "https://id.twitch.tv/oauth2/token",
            {
                "client_id": client_id,
                "scopes": scopes,
                "device_code": device["device_code"],
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            },
        )
        if status == 200:
            granted = " ".join(token_data.get("scope", []))
            print("\nAuthorization successful!")
            print(f"Granted scopes: {granted}\n")
            print(f"BOT_TOKEN={token_data['access_token']}")
            print(f"REFRESH_TOKEN={token_data['refresh_token']}")
            return

        msg = token_data.get("message", "")
        if msg == "authorization_pending":
            continue
        if msg == "slow_down":
            interval += 2
            continue

        print(f"\nAuthorization failed ({status}): {token_data}")
        return

    print("\nTimed out waiting for authorization.")


if __name__ == "__main__":
    main()
