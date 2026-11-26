#!/usr/bin/env python3
import csv
import re
import sqlite3
import sys
import time
from datetime import datetime
from pathlib import Path

USERNAME_HEADERS = (
    "raider_name",
    "raider name",
    "raider",
    "target_name",
    "target name",
    "target",
    "raided",
    "username",
    "user",
    "channel",
    "login",
    "name",
)
URL_HEADERS = ("twitch_url", "twitch url", "url", "link", "channel url")
VIEWER_HEADERS = ("viewers", "viewer count", "viewer_count", "count")
TIMESTAMP_HEADERS = ("timestamp", "date", "time", "created_at")


def clean_username(raw: str) -> str:
    val = (raw or "").strip()
    url_match = re.search(
        r"(?:https?://)?(?:www\.)?twitch\.tv/([A-Za-z0-9_]+)", val, re.IGNORECASE
    )
    if url_match:
        return url_match.group(1).lower()
    val = val.lstrip("@").strip().lower()
    return val if re.fullmatch(r"[a-z0-9_]{1,30}", val) else ""


def parse_timestamp(raw: str, fallback: int) -> int:
    val = (raw or "").strip()
    if not val:
        return fallback
    if val.isdigit():
        return int(val)
    for fmt in (
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %H:%M",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d",
        "%m/%d/%Y",
    ):
        try:
            return int(datetime.strptime(val, fmt).timestamp())
        except ValueError:
            continue
    return fallback


def parse_viewers(raw: str) -> int:
    digits = re.sub(r"[^\d]", "", raw or "")
    return int(digits) if digits else 0


def find_column(header_map: dict[str, str], candidates: tuple[str, ...]) -> str | None:
    for key in candidates:
        if key in header_map:
            return header_map[key]
    return None


def main():
    args = [a for a in sys.argv[1:] if a != "--out"]
    is_outgoing = "--out" in sys.argv[1:]

    if not args:
        print("Usage: python3 import_raiders.py <export.csv> [path/to/bot_data.db] [--out]")
        sys.exit(1)

    csv_path = Path(args[0])
    db_path = Path(args[1]) if len(args) > 1 else Path("bot_data.db")

    if not csv_path.exists():
        print(f"Error: CSV file not found: {csv_path}")
        sys.exit(1)

    table = "raids_out" if is_outgoing else "raids"
    name_col_db = "target_name" if is_outgoing else "raider_name"

    with csv_path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            print("Error: CSV file has no headers.")
            sys.exit(1)

        header_map = {h.strip().lower(): h for h in reader.fieldnames if h}
        user_col = find_column(header_map, USERNAME_HEADERS)
        url_col = find_column(header_map, URL_HEADERS)
        viewer_col = find_column(header_map, VIEWER_HEADERS)
        ts_col = find_column(header_map, TIMESTAMP_HEADERS)

        if not user_col and not url_col:
            print("Could not auto-detect a username column.")
            print("Available columns:", ", ".join(reader.fieldnames))
            chosen = input("Enter the exact column name containing usernames: ").strip()
            if chosen not in reader.fieldnames:
                print("Invalid column name.")
                sys.exit(1)
            user_col = chosen

        rows = list(reader)

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute(
        f"""
        CREATE TABLE IF NOT EXISTS {table} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            {name_col_db} TEXT NOT NULL,
            viewers INTEGER DEFAULT 0,
            timestamp INTEGER NOT NULL,
            stream_id TEXT
        )
        """
    )

    # Track already-imported (username, viewers, timestamp) tuples to prevent double-imports
    cur.execute(
        f"SELECT LOWER({name_col_db}), viewers, timestamp FROM {table} WHERE stream_id = 'imported'"
    )
    existing_imported = {(r[0], r[1], r[2]) for r in cur.fetchall() if r[0]}

    now = int(time.time())
    imported = 0
    skipped_dup = 0
    skipped_invalid = 0

    for idx, row in enumerate(rows):
        username = clean_username(row.get(user_col, "")) if user_col else ""
        if not username and url_col:
            username = clean_username(row.get(url_col, ""))

        if not username:
            skipped_invalid += 1
            continue

        viewers = parse_viewers(row.get(viewer_col, "")) if viewer_col else 0
        # Offset fallback by row index if CSV has no timestamp column so row order is preserved
        ts = parse_timestamp(row.get(ts_col, ""), now + idx) if ts_col else (now + idx)

        key = (username, viewers, ts)
        if key in existing_imported:
            skipped_dup += 1
            continue

        cur.execute(
            f"""
            INSERT INTO {table} ({name_col_db}, viewers, timestamp, stream_id)
            VALUES (?, ?, ?, 'imported')
            """,
            (username, viewers, ts),
        )
        existing_imported.add(key)
        imported += 1

    conn.commit()
    conn.close()

    print(
        f"Done! Imported {imported} row(s) into {db_path} ({table}) "
        f"(skipped {skipped_dup} duplicate imported rows, {skipped_invalid} blank/invalid rows)."
    )


if __name__ == "__main__":
    main()