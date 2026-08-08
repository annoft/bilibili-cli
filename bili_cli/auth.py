"""Authentication for Bilibili.

Strategy:
1. Try loading saved credential from ~/.bilibili-cli/credential.json
2. Fallback: QR code login via bilibili-api-python + terminal display

The browser-cookie extraction implementation is retained below for future
opt-in work, but it is intentionally not called by the active authentication
flow.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Literal

import qrcode
from bilibili_api.login_v2 import QrCodeLogin, QrCodeLoginChannel, QrCodeLoginEvents
from bilibili_api.utils.network import Credential

logger = logging.getLogger(__name__)

CONFIG_DIR = Path.home() / ".bilibili-cli"
CREDENTIAL_FILE = CONFIG_DIR / "credential.json"

# Required cookies for a valid Bilibili session
REQUIRED_COOKIES = {"SESSDATA"}

# Extra cookie fields that help bypass Bilibili's 412 anti-scraping checks
EXTRA_COOKIE_FIELDS = ("buvid3", "buvid4", "dedeuserid")

# Retained for the dormant browser-refresh implementation.
CREDENTIAL_TTL_DAYS = 7
_CREDENTIAL_TTL_SECONDS = CREDENTIAL_TTL_DAYS * 86400
_BROWSER_EXTRACTION_TIMEOUT_SECONDS = 15
_BROWSER_EXTRACTION_DEADLINE_SECONDS = 60


AuthMode = Literal["optional", "read", "write"]


def get_credential(mode: AuthMode = "read") -> Credential | None:
    """Load and validate the saved credential according to ``mode``.

    - optional: only load saved credential (no network validation)
    - read: validate the saved credential; if validation is indeterminate (network),
      return it as a best-effort read credential
    - write: same as read, but require bili_jct capability
    """
    require_write = mode == "write"

    # 1. Saved credential file
    cred = _load_saved_credential()
    if cred:
        if mode == "optional":
            return cred

        validation = _validate_credential(cred, require_write=require_write)
        if validation is True:
            logger.info("Loaded valid credential from %s", CREDENTIAL_FILE)
            return cred
        if validation is None:
            if require_write:
                logger.warning("Credential validation is unavailable; refusing to use it for a write operation")
                return None
            logger.warning("Credential validation failed due to network; using saved credential as best effort")
            return cred
        if validation is False:
            if require_write and bool(cred.sessdata) and not bool(cred.bili_jct):
                logger.warning("Saved credential is read-only; keeping it for read operations")
                return None
            else:
                logger.warning("Saved credential is expired, clearing")
                clear_credential()

    return None


def _has_write_capability(credential: Credential) -> bool:
    """Return whether a credential has the fields required by write APIs."""
    return bool(getattr(credential, "sessdata", "")) and bool(getattr(credential, "bili_jct", ""))


def _select_browser_credential(
    require_write: bool = False,
) -> tuple[Credential | None, bool | None]:
    """Return the best API-valid browser credential, trying every browser.

    This helper is retained with the browser extraction implementation for
    future opt-in use. The active authentication flow deliberately does not
    call it.
    """
    candidates = _extract_browser_credentials(require_write=require_write)
    candidates.sort(key=_has_write_capability, reverse=True)

    best_effort: Credential | None = None
    for candidate in candidates:
        validation = _validate_credential(candidate, require_write=require_write)
        if validation is True:
            return candidate, True
        if validation is None and best_effort is None:
            best_effort = candidate

    if best_effort is not None:
        return best_effort, None
    return None, False


def _is_credential_stale() -> bool:
    """Check if saved credential file is older than TTL."""
    if not CREDENTIAL_FILE.exists():
        return False
    try:
        data = json.loads(CREDENTIAL_FILE.read_text())
        saved_at = data.get("saved_at", 0)
        if not saved_at:
            # Legacy file without saved_at — treat as stale to add the field
            return True
        return (time.time() - saved_at) > _CREDENTIAL_TTL_SECONDS
    except (json.JSONDecodeError, OSError):
        return False


def _validate_credential(cred: Credential, require_write: bool = False) -> bool | None:
    """Check if a credential is valid.

    Returns:
      - True: credential validated by API
      - False: credential confirmed invalid or missing required fields
      - None: validation is indeterminate due to network/runtime issues
    """
    from bilibili_api import user
    from bilibili_api.exceptions import NetworkException

    if not getattr(cred, "sessdata", ""):
        return False
    if require_write and not getattr(cred, "bili_jct", ""):
        return False

    async def _check():
        try:
            await user.get_self_info(cred)
            return True
        except NetworkException:
            return None
        except Exception:
            return False

    try:
        return asyncio.run(_check())
    except Exception:
        return None


def _load_saved_credential() -> Credential | None:
    """Load credential from saved file."""
    if not CREDENTIAL_FILE.exists():
        return None

    try:
        data = json.loads(CREDENTIAL_FILE.read_text())
        sessdata = data.get("sessdata", "")
        if not sessdata:
            return None
        return Credential(
            sessdata=sessdata,
            bili_jct=data.get("bili_jct", ""),
            ac_time_value=data.get("ac_time_value", ""),
            buvid3=data.get("buvid3", ""),
            buvid4=data.get("buvid4", ""),
            dedeuserid=data.get("dedeuserid", ""),
        )
    except (json.JSONDecodeError, KeyError) as e:
        logger.warning("Failed to load saved credential: %s", e)
        return None


def _extract_browser_credentials(require_write: bool = False) -> list[Credential]:
    """Extract Bilibili cookie candidates from local browsers.

    Runs extraction in a subprocess with timeout to avoid hanging
    when the browser is running (Chrome DB lock issue).
    """
    cookie_check = 'cookies.get("SESSDATA")'
    if require_write:
        cookie_check = 'cookies.get("SESSDATA") and cookies.get("bili_jct")'

    extract_script = f'''
import json, os, sys
from pathlib import Path
try:
    import browser_cookie3 as bc3
except ImportError:
    print(json.dumps({{"error": "not_installed"}}))
    sys.exit(0)

def thorium():
    base = Path(os.environ.get("LOCALAPPDATA", "")) / "Thorium" / "User Data"
    local_state = base / "Local State"
    if not local_state.is_file():
        return []

    profiles = [base / "Default"] + sorted(base.glob("Profile *"))
    profile_candidates = []
    for profile in profiles:
        cookies = []
        seen = set()
        for relative_path in (Path("Network") / "Cookies", Path("Cookies")):
            cookie_file = profile / relative_path
            if not cookie_file.is_file():
                continue
            try:
                cj = bc3.Chrome(
                    cookie_file=str(cookie_file),
                    domain_name=".bilibili.com",
                    key_file=str(local_state),
                ).load()
            except Exception:
                continue
            for cookie in cj:
                key = (cookie.name, cookie.domain, cookie.path)
                if key not in seen:
                    seen.add(key)
                    cookies.append(cookie)
        if cookies:
            profile_candidates.append((profile.name, cookies))
    return profile_candidates

def single(loader):
    return [("", loader(domain_name=".bilibili.com"))]

loaders = {{
    "Chrome": lambda: single(bc3.chrome),
    "Firefox": lambda: single(bc3.firefox),
    "Edge": lambda: single(bc3.edge),
    "Brave": lambda: single(bc3.brave),
    "Thorium": thorium,
}}
name = sys.argv[1]
credential_cookie_names = {{"SESSDATA", "bili_jct", "ac_time_value", "buvid3", "buvid4", "DedeUserID"}}
try:
    candidates = []
    for profile_name, cj in loaders[name]():
        cookies = {{
            c.name: c.value
            for c in cj
            if c.name in credential_cookie_names and "bilibili.com" in (c.domain or "")
        }}
        if {cookie_check}:
            label = name if not profile_name else f"{{name}}/{{profile_name}}"
            candidates.append({{"browser": label, "cookies": cookies}})
    if candidates:
        print(json.dumps({{"candidates": candidates}}))
    else:
        print(json.dumps({{"error": "no_cookies"}}))
except Exception:
    print(json.dumps({{"error": "no_cookies"}}))
'''

    browser_names = ("Chrome", "Firefox", "Edge", "Brave", "Thorium")
    credentials: list[Credential] = []
    deadline = time.monotonic() + _BROWSER_EXTRACTION_DEADLINE_SECONDS
    for browser_name in browser_names:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            logger.warning("Browser cookie extraction reached its overall time limit")
            break
        try:
            result = subprocess.run(
                [sys.executable, "-c", extract_script, browser_name],
                capture_output=True,
                text=True,
                timeout=min(_BROWSER_EXTRACTION_TIMEOUT_SECONDS, max(1, remaining)),
            )

            if result.returncode != 0:
                logger.debug("Cookie extraction subprocess failed for %s: %s", browser_name, result.stderr)
                continue

            output = result.stdout.strip()
            if not output:
                logger.debug("Cookie extraction returned empty output for %s", browser_name)
                continue

            data = json.loads(output)
            if "error" in data:
                if data["error"] == "not_installed":
                    logger.debug("browser-cookie3 not installed, skipping")
                    break
                logger.debug("No valid Bilibili cookies found in %s", browser_name)
                continue

            for item in data["candidates"]:
                cookies = item["cookies"]
                candidate_browser = item["browser"]
                if not REQUIRED_COOKIES.issubset(cookies):
                    logger.debug("Browser cookies missing required keys: %s", REQUIRED_COOKIES)
                    continue
                logger.info("Found credential candidate in %s (%d cookies)", candidate_browser, len(cookies))
                credentials.append(
                    Credential(
                        sessdata=cookies.get("SESSDATA", ""),
                        bili_jct=cookies.get("bili_jct", ""),
                        ac_time_value=cookies.get("ac_time_value", ""),
                        buvid3=cookies.get("buvid3", ""),
                        buvid4=cookies.get("buvid4", ""),
                        dedeuserid=cookies.get("DedeUserID", ""),
                    )
                )
        except subprocess.TimeoutExpired:
            logger.warning(
                "Cookie extraction timed out for %s (browser may be running). "
                "Try closing the browser or use `bili login`.",
                browser_name,
            )
        except OSError as e:
            logger.warning("Cookie extraction could not start for %s: %s", browser_name, e)
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            logger.warning("Cookie extraction parse error for %s: %s", browser_name, e)

    return credentials


def save_credential(credential: Credential):
    """Save credential to config file with timestamp for TTL tracking."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)

    data = {
        "sessdata": credential.sessdata,
        "bili_jct": credential.bili_jct,
        "ac_time_value": credential.ac_time_value or "",
        "buvid3": credential.buvid3 or "",
        "buvid4": credential.buvid4 or "",
        "dedeuserid": credential.dedeuserid or "",
        "saved_at": time.time(),
    }
    CREDENTIAL_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    CREDENTIAL_FILE.chmod(0o600)  # Owner-only read/write
    logger.info("Credential saved to %s", CREDENTIAL_FILE)


def clear_credential():
    """Remove saved credential file."""
    if CREDENTIAL_FILE.exists():
        CREDENTIAL_FILE.unlink()
        logger.info("Credential removed: %s", CREDENTIAL_FILE)


def _supports_unicode_half_blocks() -> bool:
    """Return True when stdout encoding can represent half-block glyphs."""
    encoding = getattr(sys.stdout, "encoding", None)
    if not encoding:
        return False
    try:
        "▀▄█".encode(encoding)
    except (LookupError, UnicodeEncodeError):
        return False
    return True


def _render_compact_qr(data: str) -> str | None:
    """Render a compact QR code using Unicode half-block characters.

    Uses ▀, ▄, █, and space to encode two vertical modules per character row,
    reducing the QR code height by half compared to full-block rendering.
    Each module is 1 character wide (vs 2 in qrcode-terminal), so total area
    is ~25% of the original.
    """
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_L)
    qr.add_data(data)
    qr.make(fit=True)
    matrix = qr.get_matrix()

    # Add 1-module quiet zone
    size = len(matrix)
    padded = [[False] * (size + 2)]
    for row in matrix:
        padded.append([False] + list(row) + [False])
    padded.append([False] * (size + 2))
    matrix = padded
    rows = len(matrix)

    # Check terminal width and warn if too narrow
    term_cols = shutil.get_terminal_size(fallback=(80, 24)).columns
    qr_width = len(matrix[0])
    if qr_width > term_cols:
        logger.warning(
            "Terminal width (%d) too narrow for compact QR (%d), falling back",
            term_cols,
            qr_width,
        )
        return None

    lines: list[str] = []
    # Process two rows at a time using half-block characters
    # top=black, bottom=black → █ (full block)
    # top=black, bottom=white → ▀ (upper half)
    # top=white, bottom=black → ▄ (lower half)
    # top=white, bottom=white → ' ' (space)
    for y in range(0, rows, 2):
        line = ""
        top_row = matrix[y]
        bottom_row = matrix[y + 1] if y + 1 < rows else [False] * len(top_row)
        for x in range(len(top_row)):
            top = top_row[x]
            bottom = bottom_row[x]
            if top and bottom:
                line += "█"
            elif top and not bottom:
                line += "▀"
            elif not top and bottom:
                line += "▄"
            else:
                line += " "
        lines.append(line)
    return "\n".join(lines)


def _get_qr_terminal_output(login: QrCodeLogin) -> str:
    """Choose compact QR rendering when possible, otherwise use default output."""
    default_qr = login.get_qrcode_terminal()

    qr_link = getattr(login, "_QrCodeLogin__qr_link", None)
    if not qr_link:
        logger.warning("QR link unavailable from QrCodeLogin internals, using default renderer")
        return default_qr

    if not _supports_unicode_half_blocks():
        logger.warning("stdout encoding cannot render Unicode QR blocks, using default renderer")
        return default_qr

    compact_qr = _render_compact_qr(qr_link)
    if compact_qr is None:
        return default_qr
    return compact_qr


async def qr_login() -> Credential:
    """QR code login via terminal.

    Displays a QR code in the terminal, polls until login completes,
    then saves and returns the credential.
    """
    login = QrCodeLogin(QrCodeLoginChannel.TV)
    await login.generate_qrcode()

    # Display QR code in terminal
    print("\n📱 请使用 Bilibili App 扫描以下二维码登录:\n")
    print(_get_qr_terminal_output(login))
    print("\n⭐ 扫码后请在手机上确认登录...")

    # Poll login state
    while True:
        state = await login.check_state()

        if state == QrCodeLoginEvents.DONE:
            credential = login.get_credential()
            if not _has_write_capability(credential):
                raise RuntimeError("二维码登录未获得可写凭证，请重试")
            save_credential(credential)
            print("\n✅ 登录成功！凭证已保存")
            return credential

        elif state == QrCodeLoginEvents.TIMEOUT:
            raise RuntimeError("二维码已过期，请重试")

        elif state == QrCodeLoginEvents.CONF:
            print("  📲 已扫码，请在手机上确认...")

        await asyncio.sleep(2)
