"""Tests for auth module."""

import asyncio
import json
import subprocess
import sys
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from bilibili_api.exceptions import NetworkException
from bilibili_api.utils.network import Credential

from bili_cli.auth import (
    _get_qr_terminal_output,
    _load_saved_credential,
    _render_compact_qr,
    _supports_unicode_half_blocks,
    _validate_credential,
    clear_credential,
    get_credential,
    qr_login,
    save_credential,
)


def test_load_missing_file(tmp_path):
    with patch("bili_cli.auth.CREDENTIAL_FILE", tmp_path / "nope.json"):
        assert _load_saved_credential() is None


def test_save_and_load(tmp_path):
    cred_file = tmp_path / "cred.json"
    with patch("bili_cli.auth.CREDENTIAL_FILE", cred_file), \
         patch("bili_cli.auth.CONFIG_DIR", tmp_path):
        cred = Credential(
            sessdata="test_sess", bili_jct="test_jct",
            buvid3="buvid3_val", buvid4="buvid4_val", dedeuserid="12345",
        )
        save_credential(cred)

        # File should exist with correct permissions
        assert cred_file.exists()

        # Load it back
        loaded = _load_saved_credential()
        assert loaded is not None
        assert loaded.sessdata == "test_sess"
        assert loaded.bili_jct == "test_jct"
        assert loaded.buvid3 == "buvid3_val"
        assert loaded.buvid4 == "buvid4_val"
        assert loaded.dedeuserid == "12345"


def test_save_creates_directory(tmp_path):
    new_dir = tmp_path / "new_config"
    cred_file = new_dir / "cred.json"
    with patch("bili_cli.auth.CREDENTIAL_FILE", cred_file), \
         patch("bili_cli.auth.CONFIG_DIR", new_dir):
        cred = Credential(sessdata="s", bili_jct="j")
        save_credential(cred)
        assert new_dir.exists()
        assert cred_file.exists()


def test_load_corrupt_file(tmp_path):
    cred_file = tmp_path / "bad.json"
    cred_file.write_text("not json at all")
    with patch("bili_cli.auth.CREDENTIAL_FILE", cred_file):
        assert _load_saved_credential() is None


def test_load_empty_sessdata(tmp_path):
    cred_file = tmp_path / "empty.json"
    cred_file.write_text(json.dumps({"sessdata": "", "bili_jct": "x"}))
    with patch("bili_cli.auth.CREDENTIAL_FILE", cred_file):
        assert _load_saved_credential() is None


def test_clear_credential(tmp_path):
    cred_file = tmp_path / "cred.json"
    cred_file.write_text("{}")
    with patch("bili_cli.auth.CREDENTIAL_FILE", cred_file):
        clear_credential()
        assert not cred_file.exists()


def test_clear_credential_nonexistent(tmp_path):
    with patch("bili_cli.auth.CREDENTIAL_FILE", tmp_path / "nope.json"):
        # Should not raise
        clear_credential()


def test_validate_valid_credential():
    with patch("bilibili_api.user.get_self_info", new_callable=AsyncMock, return_value={"mid": 1}):
        cred = Credential(sessdata="valid")
        assert _validate_credential(cred) is True


def test_validate_expired_credential():
    with patch("bilibili_api.user.get_self_info", new_callable=AsyncMock, side_effect=Exception("expired")):
        cred = Credential(sessdata="expired")
        assert _validate_credential(cred) is False


def test_validate_network_error_returns_none():
    with patch("bilibili_api.user.get_self_info", new_callable=AsyncMock, side_effect=NetworkException(-1, "timeout")):
        cred = Credential(sessdata="valid")
        assert _validate_credential(cred) is None


def test_validate_credential_requires_bili_jct_for_write():
    with patch("bilibili_api.user.get_self_info", new_callable=AsyncMock, return_value={"mid": 1}):
        cred = Credential(sessdata="valid", bili_jct="")
        assert _validate_credential(cred, require_write=True) is False


def test_get_credential_uses_saved_when_valid():
    saved = Credential(sessdata="saved", bili_jct="jct")
    with patch("bili_cli.auth._is_credential_stale", return_value=False), \
         patch("bili_cli.auth._load_saved_credential", return_value=saved), \
         patch("bili_cli.auth._validate_credential", return_value=True) as mock_validate, \
         patch("bili_cli.auth._extract_browser_credentials") as mock_extract:
        cred = get_credential()
        assert cred is saved
        mock_validate.assert_called_once_with(saved, require_write=False)
        mock_extract.assert_not_called()


def test_get_credential_falls_back_to_browser_and_saves():
    browser = Credential(sessdata="browser", bili_jct="jct")
    with patch("bili_cli.auth._load_saved_credential", return_value=None), \
         patch("bili_cli.auth._extract_browser_credentials", return_value=[browser]), \
         patch("bili_cli.auth._validate_credential", return_value=True), \
         patch("bili_cli.auth.save_credential") as mock_save:
        cred = get_credential()
        assert cred is browser
        mock_save.assert_called_once_with(browser)


def test_get_credential_skips_expired_browser_candidate():
    expired = Credential(sessdata="expired", bili_jct="old")
    valid = Credential(sessdata="valid", bili_jct="new")
    with patch("bili_cli.auth._load_saved_credential", return_value=None), \
         patch("bili_cli.auth._extract_browser_credentials", return_value=[expired, valid]), \
         patch("bili_cli.auth._validate_credential", side_effect=[False, True]) as mock_validate, \
         patch("bili_cli.auth.save_credential") as mock_save:
        assert get_credential() is valid
        assert mock_validate.call_count == 2
        mock_save.assert_called_once_with(valid)


def test_get_credential_prefers_write_capable_browser_candidate():
    read_only = Credential(sessdata="read-only", bili_jct="")
    write_capable = Credential(sessdata="write-capable", bili_jct="jct")
    with patch("bili_cli.auth._load_saved_credential", return_value=None), \
         patch("bili_cli.auth._extract_browser_credentials", return_value=[read_only, write_capable]), \
         patch("bili_cli.auth._validate_credential", return_value=True) as mock_validate, \
         patch("bili_cli.auth.save_credential") as mock_save:
        assert get_credential() is write_capable
        mock_validate.assert_called_once_with(write_capable, require_write=False)
        mock_save.assert_called_once_with(write_capable)


def test_get_credential_keeps_saved_on_validation_network_error():
    saved = Credential(sessdata="saved", bili_jct="jct")
    with patch("bili_cli.auth._is_credential_stale", return_value=False), \
         patch("bili_cli.auth._load_saved_credential", return_value=saved), \
         patch("bili_cli.auth._validate_credential", return_value=None), \
         patch("bili_cli.auth.clear_credential") as mock_clear, \
         patch("bili_cli.auth._extract_browser_credentials") as mock_extract:
        cred = get_credential()
        assert cred is saved
        mock_clear.assert_not_called()
        mock_extract.assert_not_called()


def test_get_credential_clears_expired_saved_and_returns_none_when_browser_invalid():
    saved = Credential(sessdata="saved", bili_jct="jct")
    browser = Credential(sessdata="browser", bili_jct="jct")
    with patch("bili_cli.auth._is_credential_stale", return_value=False), \
         patch("bili_cli.auth._load_saved_credential", return_value=saved), \
         patch("bili_cli.auth._extract_browser_credentials", return_value=[browser]), \
         patch("bili_cli.auth._validate_credential", side_effect=[False, False]), \
         patch("bili_cli.auth.clear_credential") as mock_clear, \
         patch("bili_cli.auth.save_credential") as mock_save:
        cred = get_credential()
        assert cred is None
        mock_clear.assert_called_once()
        mock_save.assert_not_called()


def test_get_credential_optional_uses_saved_without_validation():
    saved = Credential(sessdata="saved", bili_jct="jct")
    with patch("bili_cli.auth._is_credential_stale", return_value=True), \
         patch("bili_cli.auth._load_saved_credential", return_value=saved), \
         patch("bili_cli.auth._validate_credential") as mock_validate, \
         patch("bili_cli.auth._extract_browser_credentials") as mock_extract:
        cred = get_credential(mode="optional")
        assert cred is saved
        mock_validate.assert_not_called()
        mock_extract.assert_not_called()


def test_get_credential_write_rejects_missing_bili_jct():
    saved = Credential(sessdata="saved", bili_jct="")
    with patch("bili_cli.auth._is_credential_stale", return_value=False), \
         patch("bili_cli.auth._load_saved_credential", return_value=saved), \
         patch("bili_cli.auth._extract_browser_credentials", return_value=[]) as mock_extract, \
         patch("bili_cli.auth._validate_credential", return_value=False), \
         patch("bili_cli.auth.clear_credential") as mock_clear:
        cred = get_credential(mode="write")
        assert cred is None
        mock_extract.assert_called_once_with(require_write=True)
        mock_clear.assert_not_called()


def test_get_credential_write_rejects_indeterminate_validation():
    saved = Credential(sessdata="saved", bili_jct="jct")
    with patch("bili_cli.auth._is_credential_stale", return_value=False), \
         patch("bili_cli.auth._load_saved_credential", return_value=saved), \
         patch("bili_cli.auth._validate_credential", return_value=None), \
         patch("bili_cli.auth._extract_browser_credentials") as mock_extract:
        assert get_credential(mode="write") is None
        mock_extract.assert_not_called()


def test_stale_read_refresh_does_not_clobber_write_capable_saved_credential():
    saved = Credential(sessdata="saved", bili_jct="jct")
    browser = Credential(sessdata="browser", bili_jct="")
    with patch("bili_cli.auth._is_credential_stale", return_value=True), \
         patch("bili_cli.auth._load_saved_credential", return_value=saved), \
         patch("bili_cli.auth._extract_browser_credentials", return_value=[browser]), \
         patch("bili_cli.auth._validate_credential", return_value=True), \
         patch("bili_cli.auth.save_credential") as mock_save:
        assert get_credential(mode="read") is saved
        mock_save.assert_called_once_with(saved)


def test_qr_login_rejects_credential_without_write_capability():
    class DummyLogin:
        async def generate_qrcode(self):
            return None

        async def check_state(self):
            from bilibili_api.login_v2 import QrCodeLoginEvents

            return QrCodeLoginEvents.DONE

        def get_credential(self):
            return Credential(sessdata="session", bili_jct="")

    with patch("bili_cli.auth.QrCodeLogin", return_value=DummyLogin()), \
         patch("bili_cli.auth.save_credential") as mock_save, \
         patch("bili_cli.auth._get_qr_terminal_output", return_value="QR"):
        with pytest.raises(RuntimeError, match="未获得可写凭证"):
            asyncio.run(qr_login())
        mock_save.assert_not_called()


def test_qr_login_saves_write_capable_credential():
    credential = Credential(sessdata="session", bili_jct="jct")

    class DummyLogin:
        async def generate_qrcode(self):
            return None

        async def check_state(self):
            from bilibili_api.login_v2 import QrCodeLoginEvents

            return QrCodeLoginEvents.DONE

        def get_credential(self):
            return credential

    with patch("bili_cli.auth.QrCodeLogin", return_value=DummyLogin()), \
         patch("bili_cli.auth.save_credential") as mock_save, \
         patch("bili_cli.auth._get_qr_terminal_output", return_value="QR"):
        assert asyncio.run(qr_login()) is credential
        mock_save.assert_called_once_with(credential)


def test_extract_browser_credentials_timeout_returns_empty(browser_credential_extractor):
    with patch("bili_cli.auth.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="x", timeout=1)):
        assert browser_credential_extractor() == []


def test_extract_browser_credentials_bad_json_returns_empty(browser_credential_extractor):
    fake = SimpleNamespace(returncode=0, stdout="not-json", stderr="")
    with patch("bili_cli.auth.subprocess.run", return_value=fake):
        assert browser_credential_extractor() == []


def test_extract_browser_credentials_empty_output_returns_empty(browser_credential_extractor):
    fake = SimpleNamespace(returncode=0, stdout="   ", stderr="")
    with patch("bili_cli.auth.subprocess.run", return_value=fake):
        assert browser_credential_extractor() == []


def test_extract_browser_credentials_keeps_candidate_when_later_browser_times_out(browser_credential_extractor):
    candidate = SimpleNamespace(
        returncode=0,
        stdout=json.dumps({"candidates": [{"browser": "Chrome", "cookies": {"SESSDATA": "session", "bili_jct": "jct"}}]}),
        stderr="",
    )
    no_cookies = SimpleNamespace(returncode=0, stdout=json.dumps({"error": "no_cookies"}), stderr="")
    timeout = subprocess.TimeoutExpired(cmd="x", timeout=15)
    with patch("bili_cli.auth.subprocess.run", side_effect=[candidate, timeout, no_cookies, no_cookies, no_cookies]):
        credentials = browser_credential_extractor()

    assert len(credentials) == 1
    assert credentials[0].sessdata == "session"
    assert credentials[0].bili_jct == "jct"


def test_extract_browser_credentials_write_requires_bili_jct(browser_credential_extractor):
    fake = SimpleNamespace(
        returncode=0,
        stdout=json.dumps({"candidates": [{"browser": "Chrome", "cookies": {"SESSDATA": "session", "bili_jct": "jct"}}]}),
        stderr="",
    )
    no_cookies = SimpleNamespace(returncode=0, stdout=json.dumps({"error": "no_cookies"}), stderr="")
    with patch("bili_cli.auth.subprocess.run", side_effect=[fake, no_cookies, no_cookies, no_cookies, no_cookies]) as mock_run:
        credentials = browser_credential_extractor(require_write=True)

    assert len(credentials) == 1
    script = mock_run.call_args.args[0][2]
    assert 'if cookies.get("SESSDATA") and cookies.get("bili_jct"):' in script
    assert '"Thorium": thorium' in script
    assert 'Path("Network") / "Cookies"' in script
    compile(script, "<browser-cookie-extractor>", "exec")
    assert [call.args[0][3] for call in mock_run.call_args_list] == ["Chrome", "Firefox", "Edge", "Brave", "Thorium"]


def test_extract_browser_credentials_keeps_thorium_profiles_separate(browser_credential_extractor, tmp_path, monkeypatch):
    base = tmp_path / "Thorium" / "User Data"
    base.mkdir(parents=True)
    (base / "Local State").write_text("{}")
    for profile in ("Default", "Profile 1"):
        cookie_file = base / profile / "Network" / "Cookies"
        cookie_file.parent.mkdir(parents=True)
        cookie_file.touch()
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))

    class FakeChrome:
        def __init__(self, cookie_file, domain_name, key_file):
            self.cookie_file = cookie_file

        def load(self):
            profile = Path(self.cookie_file).parent.parent.name
            sessdata = "default-session" if profile == "Default" else "profile-session"
            cookies = [SimpleNamespace(name="SESSDATA", value=sessdata, domain=".bilibili.com", path="/")]
            if profile == "Profile 1":
                cookies.append(SimpleNamespace(name="bili_jct", value="profile-jct", domain=".bilibili.com", path="/"))
            return cookies

    fake_browser_cookie3 = SimpleNamespace(
        Chrome=FakeChrome,
        chrome=lambda **kwargs: [],
        firefox=lambda **kwargs: [],
        edge=lambda **kwargs: [],
        brave=lambda **kwargs: [],
    )
    no_cookies = SimpleNamespace(returncode=0, stdout=json.dumps({"error": "no_cookies"}), stderr="")

    def run(command, **kwargs):
        if command[3] != "Thorium":
            return no_cookies
        output = StringIO()
        with patch.dict(sys.modules, {"browser_cookie3": fake_browser_cookie3}), patch.object(sys, "argv", ["-c", "Thorium"]):
            with redirect_stdout(output):
                exec(command[2], {"__name__": "__main__"})
        return SimpleNamespace(returncode=0, stdout=output.getvalue(), stderr="")

    with patch("bili_cli.auth.subprocess.run", side_effect=run):
        credentials = browser_credential_extractor()

    assert [(credential.sessdata, bool(credential.bili_jct)) for credential in credentials] == [
        ("default-session", False),
        ("profile-session", True),
    ]


def test_render_compact_qr_returns_multiline_text():
    with patch("bili_cli.auth.shutil.get_terminal_size", return_value=SimpleNamespace(columns=200, lines=24)):
        rendered = _render_compact_qr("https://example.com")
    assert rendered is not None
    assert "\n" in rendered
    assert any(ch in rendered for ch in "▀▄█")


def test_render_compact_qr_returns_none_when_terminal_too_narrow():
    with patch("bili_cli.auth.shutil.get_terminal_size", return_value=SimpleNamespace(columns=1, lines=24)):
        assert _render_compact_qr("https://example.com") is None


def test_supports_unicode_half_blocks_with_utf8():
    with patch("bili_cli.auth.sys.stdout", SimpleNamespace(encoding="utf-8")):
        assert _supports_unicode_half_blocks() is True


def test_supports_unicode_half_blocks_with_non_unicode_encoding():
    with patch("bili_cli.auth.sys.stdout", SimpleNamespace(encoding="cp1252")):
        assert _supports_unicode_half_blocks() is False


def test_get_qr_terminal_output_falls_back_when_private_qr_link_missing():
    class DummyLogin:
        def get_qrcode_terminal(self):
            return "DEFAULT_QR"

    assert _get_qr_terminal_output(DummyLogin()) == "DEFAULT_QR"


def test_get_qr_terminal_output_falls_back_when_unicode_not_supported():
    class DummyLogin:
        _QrCodeLogin__qr_link = "https://example.com"

        def get_qrcode_terminal(self):
            return "DEFAULT_QR"

    with patch("bili_cli.auth._supports_unicode_half_blocks", return_value=False):
        assert _get_qr_terminal_output(DummyLogin()) == "DEFAULT_QR"


def test_get_qr_terminal_output_falls_back_when_compact_render_returns_none():
    class DummyLogin:
        _QrCodeLogin__qr_link = "https://example.com"

        def get_qrcode_terminal(self):
            return "DEFAULT_QR"

    with patch("bili_cli.auth._supports_unicode_half_blocks", return_value=True), \
         patch("bili_cli.auth._render_compact_qr", return_value=None):
        assert _get_qr_terminal_output(DummyLogin()) == "DEFAULT_QR"


def test_get_qr_terminal_output_prefers_compact_rendering_when_available():
    class DummyLogin:
        _QrCodeLogin__qr_link = "https://example.com"

        def get_qrcode_terminal(self):
            return "DEFAULT_QR"

    with patch("bili_cli.auth._supports_unicode_half_blocks", return_value=True), \
         patch("bili_cli.auth._render_compact_qr", return_value="COMPACT_QR"):
        assert _get_qr_terminal_output(DummyLogin()) == "COMPACT_QR"
