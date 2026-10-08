#!/usr/bin/env python3
"""Bulk-export Canvas courses as IMSCC files."""

import argparse
import csv
import json
import os
import re
import sys
import tempfile
import threading
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse

WORKERS = 3
MAX_COURSES = 500
MAX_EXPORT_WAIT = 30 * 60
POLL_INTERVAL = 5
HTTP_TIMEOUT = (10, 60)
RETRY_STATUSES = {429, 500, 502, 503, 504}
stop_requested = threading.Event()


class ExportError(Exception):
    pass


def requests_module():
    try:
        import requests
    except ImportError as exc:
        raise ExportError("The requests dependency is missing; install it with: python -m pip install requests") from exc
    return requests


class TokenManager:
    def __init__(self, credentials_path, credentials):
        self.path = credentials_path
        self.credentials = credentials
        self.lock = threading.Lock()
        self.access_token = None
        self.refresh_token = credentials["refresh_token"]

    def refresh(self, rejected_token=None):
        with self.lock:
            if rejected_token is not None and self.access_token != rejected_token:
                return self.access_token

            response = request_with_retries(
                "POST",
                self.credentials["canvas_url"] + "/login/oauth2/token",
                data={
                    "grant_type": "refresh_token",
                    "client_id": self.credentials["client_id"],
                    "client_secret": self.credentials["client_secret"],
                    "refresh_token": self.refresh_token,
                },
                allow_redirects=False,
            )
            require_success(response)
            try:
                payload = response.json()
                access_token = payload["access_token"]
            except (ValueError, KeyError, TypeError):
                raise ExportError("OAuth response did not contain an access token")
            if not isinstance(access_token, str) or not access_token:
                raise ExportError("OAuth response did not contain an access token")

            new_refresh_token = payload.get("refresh_token")
            if isinstance(new_refresh_token, str) and new_refresh_token and new_refresh_token != self.refresh_token:
                self._save_refresh_token(new_refresh_token)
                self.refresh_token = new_refresh_token
            self.access_token = access_token
            return access_token

    def _save_refresh_token(self, refresh_token):
        updated = dict(self.credentials)
        updated["refresh_token"] = refresh_token
        temp_path = None
        try:
            fd, temp_path = tempfile.mkstemp(prefix=".credentials.", suffix=".tmp", dir=self.path.parent)
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as temp_file:
                json.dump(updated, temp_file, indent=2)
                temp_file.write("\n")
                temp_file.flush()
                os.fsync(temp_file.fileno())
            os.replace(temp_path, self.path)
            self.credentials = updated
        except OSError as exc:
            if temp_path:
                try:
                    os.unlink(temp_path)
                except OSError:
                    pass
            raise ExportError(f"Could not securely update credentials file: {exc}") from exc


def retry_delay(response, attempt):
    value = response.headers.get("Retry-After") if response is not None else None
    if value:
        try:
            return max(0.0, min(60.0, float(value)))
        except ValueError:
            try:
                retry_at = parsedate_to_datetime(value)
                if retry_at.tzinfo is None:
                    retry_at = retry_at.replace(tzinfo=timezone.utc)
                return max(0.0, min(60.0, (retry_at - datetime.now(timezone.utc)).total_seconds()))
            except (TypeError, ValueError, OverflowError):
                pass
    return min(30.0, 2 ** (attempt - 1))


def request_with_retries(method, url, **kwargs):
    requests = requests_module()
    for attempt in range(1, 6):
        if stop_requested.is_set():
            raise ExportError("Interrupted")
        try:
            response = requests.request(method, url, timeout=HTTP_TIMEOUT, **kwargs)
        except requests.RequestException as exc:
            if attempt == 5:
                raise ExportError(f"Network error: {type(exc).__name__}") from exc
            time.sleep(min(30.0, 2 ** (attempt - 1)))
            continue
        if response.status_code in RETRY_STATUSES and attempt < 5:
            delay = retry_delay(response, attempt)
            response.close()
            time.sleep(delay)
            continue
        return response
    raise ExportError("Request failed after 5 attempts")


def require_success(response):
    if 200 <= response.status_code < 300:
        return
    if response.status_code >= 400:
        raise ExportError(f"HTTP {response.status_code}")
    raise ExportError(f"Unexpected HTTP redirect/status {response.status_code}")


def canvas_api_request(token_manager, method, url, **kwargs):
    for auth_attempt in range(2):
        token = token_manager.refresh() if token_manager.access_token is None else token_manager.access_token
        headers = dict(kwargs.pop("headers", {}))
        headers["Authorization"] = f"Bearer {token}"
        response = request_with_retries(
            method, url, headers=headers, allow_redirects=False, **kwargs
        )
        if response.status_code == 401 and auth_attempt == 0:
            response.close()
            token_manager.refresh(rejected_token=token)
            continue
        require_success(response)
        return response
    raise ExportError("HTTP 401 after token refresh")


def load_credentials(path):
    try:
        with path.open(encoding="utf-8") as file:
            credentials = json.load(file)
    except (OSError, json.JSONDecodeError) as exc:
        raise ExportError(f"Cannot read credentials file {path}: {exc}") from exc
    required = ("canvas_url", "client_id", "client_secret", "refresh_token")
    if not isinstance(credentials, dict) or any(not isinstance(credentials.get(key), str) or not credentials[key] for key in required):
        raise ExportError("Credentials file must contain nonempty canvas_url, client_id, client_secret, and refresh_token values")
    parsed = urlparse(credentials["canvas_url"])
    if parsed.scheme != "https" or not parsed.netloc or parsed.query or parsed.fragment:
        raise ExportError("canvas_url must be an HTTPS URL without a query or fragment")
    credentials["canvas_url"] = credentials["canvas_url"].rstrip("/")
    return credentials


def load_course_ids(path):
    ids = []
    seen = set()
    try:
        with path.open(encoding="utf-8-sig", newline="") as file:
            reader = csv.reader(file)
            header = next(reader, None)
            if not header or not header or header[0].strip() != "course_id":
                raise ExportError("CSV must have a course_id header")
            for row in reader:
                if not row or all(not cell.strip() for cell in row):
                    continue
                value = row[0].strip()
                if not value:
                    continue
                if not re.fullmatch(r"[0-9]+", value) or int(value) <= 0:
                    raise ExportError(f"Invalid course ID on CSV row {reader.line_num}: {value!r}")
                if value not in seen:
                    seen.add(value)
                    ids.append(value)
                    if len(ids) > MAX_COURSES:
                        raise ExportError(f"CSV exceeds the maximum of {MAX_COURSES} unique course IDs")
    except OSError as exc:
        raise ExportError(f"Cannot read CSV file {path}: {exc}") from exc
    if not ids:
        raise ExportError("CSV contains no course IDs")
    return ids


def safe_download_url(value):
    if not isinstance(value, str):
        raise ExportError("Export response did not include a download URL")
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise ExportError("Canvas returned an invalid or non-HTTPS download URL")
    return value


def download_export(url, destination):
    requests = requests_module()
    url = safe_download_url(url)
    part_path = destination.with_name(destination.name + ".part")
    try:
        for attempt in range(1, 6):
            if stop_requested.is_set():
                raise ExportError("Interrupted")
            response = request_with_retries(
                "GET", url, stream=True, allow_redirects=False
            )
            if response.is_redirect:
                location = response.headers.get("Location")
                response.close()
                if not location or attempt == 5:
                    raise ExportError("Download redirect limit exceeded")
                url = safe_download_url(urljoin(url, location))
                continue
            require_success(response)
            try:
                with part_path.open("wb") as output:
                    for chunk in response.iter_content(chunk_size=1024 * 1024):
                        if stop_requested.is_set():
                            raise ExportError("Interrupted")
                        if chunk:
                            output.write(chunk)
            finally:
                response.close()
            if not part_path.exists() or part_path.stat().st_size == 0:
                raise ExportError("Downloaded file is empty")
            if not zipfile.is_zipfile(part_path):
                raise ExportError("Downloaded file is not a readable ZIP archive")
            os.replace(part_path, destination)
            return
    except requests.RequestException as exc:
        raise ExportError(f"Download failed: {type(exc).__name__}") from exc
    finally:
        try:
            part_path.unlink()
        except FileNotFoundError:
            pass


def process_course(course_id, token_manager, output_dir):
    destination = output_dir / f"{course_id}.imscc"
    if destination.exists() and destination.stat().st_size > 0:
        return "Skipped"

    base = token_manager.credentials["canvas_url"]
    response = canvas_api_request(
        token_manager,
        "POST",
        f"{base}/api/v1/courses/{course_id}/content_exports",
        data={"export_type": "common_cartridge"},
    )
    try:
        export_id = response.json()["id"]
    except (ValueError, KeyError, TypeError):
        raise ExportError("Canvas response did not include an export ID")
    response.close()

    status_url = f"{base}/api/v1/courses/{course_id}/content_exports/{export_id}"
    deadline = time.monotonic() + MAX_EXPORT_WAIT
    while True:
        if stop_requested.is_set():
            raise ExportError("Interrupted")
        if time.monotonic() >= deadline:
            raise ExportError("Export timed out after 30 minutes")
        response = canvas_api_request(token_manager, "GET", status_url)
        try:
            status = response.json()
        except ValueError:
            response.close()
            raise ExportError("Canvas returned invalid export status")
        response.close()
        state = status.get("workflow_state")
        if state in {"exported", "completed", "complete", "success", "succeeded"}:
            attachment = status.get("attachment") or {}
            download_export(attachment.get("url"), destination)
            return "Downloaded"
        if state in {"failed", "errored", "error"}:
            raise ExportError("Canvas export failed")
        if state not in {"queued", "running", "created", "waiting", "exporting"}:
            raise ExportError(f"Unexpected export state: {state!r}")
        time.sleep(min(POLL_INTERVAL, max(0, deadline - time.monotonic())))


def main():
    parser = argparse.ArgumentParser(description="Bulk-export Canvas courses as IMSCC files")
    parser.add_argument("--csv", default="courses.csv", help="CSV file containing course_id values")
    parser.add_argument("--credentials", default="credentials.json", help="Canvas OAuth credentials JSON file")
    parser.add_argument("--output", default="exports", help="Directory for completed IMSCC files")
    args = parser.parse_args()

    try:
        credentials_path = Path(args.credentials)
        credentials = load_credentials(credentials_path)
        course_ids = load_course_ids(Path(args.csv))
        output_dir = Path(args.output)
        output_dir.mkdir(parents=True, exist_ok=True)
    except (ExportError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print("Canvas IMSCC Bulk Export")
    print(f"Courses: {len(course_ids)}")
    print(f"Workers: {WORKERS}")
    token_manager = TokenManager(credentials_path, credentials)
    totals = {"Downloaded": 0, "Skipped": 0, "Failed": 0}
    futures = {}
    executor = ThreadPoolExecutor(max_workers=WORKERS)
    try:
        for course_id in course_ids:
            futures[executor.submit(process_course, course_id, token_manager, output_dir)] = course_id
        done = 0
        for future in as_completed(futures):
            done += 1
            course_id = futures[future]
            try:
                result = future.result()
                totals[result] += 1
                print(f"[{done}/{len(course_ids)}] {course_id} - {result}", flush=True)
            except Exception as exc:
                totals["Failed"] += 1
                detail = str(exc) or type(exc).__name__
                print(f"[{done}/{len(course_ids)}] {course_id} - Failed: {detail}", flush=True)
    except KeyboardInterrupt:
        stop_requested.set()
        for future in futures:
            future.cancel()
        print("\nInterrupted; waiting for active requests to stop.", file=sys.stderr)
        executor.shutdown(wait=True, cancel_futures=True)
        return 1
    else:
        executor.shutdown(wait=True)

    print("\nSummary:")
    print(f"Downloaded: {totals['Downloaded']}")
    print(f"Skipped: {totals['Skipped']}")
    print(f"Failed: {totals['Failed']}")
    return 1 if totals["Failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
