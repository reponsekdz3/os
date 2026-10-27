"""Ed25519 approvals bind an active scope manifest to an organization-trusted key."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from osforge.security.scope import load_scope

APPROVAL_VERSION = 1
DOMAIN_SEPARATOR = b"OSFORGE-AUTHORIZED-SCOPE-V1\n"



_SIGNER_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")


def default_trust_store_dir() -> Path:
    """Return the administrator-managed system-level approval trust store."""
    if os.name == "nt":
        return Path(r"C:\ProgramData") / "OSForge" / "trusted-approvers"
    return Path("/etc/osforge/trusted-approvers")


def validate_signer_id(signer_id: str) -> str:
    value = signer_id.strip()
    if not _SIGNER_ID.fullmatch(value):
        raise ValueError("Signer ID must be 1–100 letters, digits, dots, underscores, or hyphens, and start with a letter or digit.")
    return value



def _assert_system_trust_store(directory: Path) -> None:
    """On POSIX, require root-owned, non-group/world-writable trust-store ancestors."""
    if os.name == "nt":
        # Windows deployment relies on the administrator-managed ACLs on ProgramData.
        return
    for candidate in (directory, directory.parent, directory.parent.parent):
        try:
            stat = candidate.stat()
        except OSError as exc:
            raise PermissionError("Cannot verify system approval trust-store permissions: " + str(exc)) from exc
        if stat.st_uid != 0 or stat.st_mode & 0o022:
            raise PermissionError(
                "Approval trust store is not safely administrator-owned: " + str(candidate) +
                ". Each trust-store directory must be root-owned and not group/world-writable."
            )


def trust_public_key(
    public_key_path: str | Path,
    *,
    signer_id: str,
    trust_store_dir: str | Path | None = None,
) -> Path:
    """Install a public key into the configured trust store without overwriting entries."""
    identity = validate_signer_id(signer_id)
    source = Path(public_key_path).expanduser().resolve()
    try:
        loaded = serialization.load_pem_public_key(source.read_bytes())
    except (OSError, ValueError, TypeError) as exc:
        raise ValueError(f"Could not load public key: {exc}") from exc
    if not isinstance(loaded, Ed25519PublicKey):
        raise ValueError("Only Ed25519 public keys can be trusted for scope approvals.")
    destination_dir = Path(trust_store_dir).expanduser().resolve() if trust_store_dir else default_trust_store_dir()
    destination = destination_dir / (identity + ".pem")
    destination_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
    if trust_store_dir is None:
        _assert_system_trust_store(destination_dir)
    try:
        with destination.open("xb") as handle:
            handle.write(source.read_bytes())
        if os.name != "nt":
            destination.chmod(0o644)
    except FileExistsError as exc:
        raise ValueError("Trusted signer " + repr(identity) + " already exists; refusing to overwrite its key.") from exc
    except OSError as exc:
        destination.unlink(missing_ok=True)
        raise ValueError(
            "Could not install trusted key to " + str(destination) + ". The system trust store must be writable "
            "by an administrator; OS Forge never auto-elevates."
        ) from exc
    return destination


def trusted_public_key_path(
    signer_id: str,
    trust_store_dir: str | Path | None = None,
) -> Path:
    identity = validate_signer_id(signer_id)
    directory = Path(trust_store_dir).expanduser().resolve() if trust_store_dir else default_trust_store_dir()
    if trust_store_dir is None and directory.exists():
        _assert_system_trust_store(directory)
    path = directory / (identity + ".pem")
    if not path.is_file():
        raise ValueError(
            "No trusted public key is installed for signer " + repr(identity) + " in " + str(directory) + ". "
            "Ask an administrator to install the approver public key into the system trust store."
        )
    return path


def approval_signer_id(approval_path: str | Path) -> str:
    """Read the untrusted signer label only to select a key; the signature is verified afterwards."""
    path = Path(approval_path).expanduser().resolve()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"Cannot read approval file {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"Approval file is not valid JSON (line {exc.lineno}).") from exc
    if not isinstance(data, dict):
        raise ValueError("Approval document root must be an object.")
    return validate_signer_id(str(data.get("signer_id", "")))


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _parse_time(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be an ISO-8601 timestamp with timezone.")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field} is not valid ISO-8601.") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field} must include a timezone.")
    return parsed.astimezone(timezone.utc)


def _canonical_scope_bytes(scope_path: str | Path) -> bytes:
    path = Path(scope_path).expanduser().resolve()
    # Validate structure and expiry before calculating the signed digest.
    load_scope(path, require_active=True)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot canonicalize scope file: {exc}") from exc
    return json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _approval_message(payload: dict[str, Any]) -> bytes:
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return DOMAIN_SEPARATOR + canonical


def generate_keypair(
    private_key_path: str | Path,
    public_key_path: str | Path,
    *,
    passphrase: str,
) -> tuple[Path, Path]:
    """Generate an Ed25519 organization key pair; never overwrite either path."""
    private_path = Path(private_key_path).expanduser().resolve()
    public_path = Path(public_key_path).expanduser().resolve()
    if private_path == public_path:
        raise ValueError("Private and public key paths must be different.")
    if private_path.exists() or public_path.exists():
        raise ValueError("Refusing to overwrite an existing key file.")
    if len(passphrase) < 12:
        raise ValueError("Key passphrase must contain at least 12 characters.")
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode("utf-8")),
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_tmp = private_path.with_suffix(private_path.suffix + ".tmp")
    public_tmp = public_path.with_suffix(public_path.suffix + ".tmp")
    try:
        private_tmp.write_bytes(private_bytes)
        public_tmp.write_bytes(public_bytes)
        if os.name != "nt":
            private_tmp.chmod(0o600)
            public_tmp.chmod(0o644)
        # Re-check immediately before publication to avoid knowingly replacing a file.
        if private_path.exists() or public_path.exists():
            raise ValueError("A key file appeared during generation; refusing to overwrite it.")
        private_tmp.replace(private_path)
        public_tmp.replace(public_path)
        if os.name != "nt":
            private_path.chmod(0o600)
            public_path.chmod(0o644)
    except Exception:
        private_tmp.unlink(missing_ok=True)
        public_tmp.unlink(missing_ok=True)
        # Do not remove final files automatically; a partial publication needs explicit review.
        raise
    return private_path, public_path


def sign_scope(
    scope_path: str | Path,
    private_key_path: str | Path,
    *,
    signer_id: str,
    passphrase: str,
    output_path: str | Path,
    expires_at: str | None = None,
) -> dict[str, Any]:
    """Sign the exact JSON scope digest using an encrypted Ed25519 private key."""
    identity = validate_signer_id(signer_id)
    scope_bytes = _canonical_scope_bytes(scope_path)
    scope = load_scope(scope_path, require_active=True)
    expiry = _parse_time(expires_at, "approval expires_at") if expires_at else scope.expires_at
    now = _utcnow()
    if expiry <= now:
        raise ValueError("Approval expiry must be in the future.")
    if expiry > scope.expires_at:
        raise ValueError("Approval expiry may not extend beyond the scope's expiry.")
    if expiry - now > timedelta(days=366):
        raise ValueError("Approvals may not last longer than 366 days.")
    private_path = Path(private_key_path).expanduser().resolve()
    try:
        loaded = serialization.load_pem_private_key(
            private_path.read_bytes(), password=passphrase.encode("utf-8")
        )
    except (OSError, ValueError, TypeError) as exc:
        raise ValueError(f"Could not load encrypted private key: {exc}") from exc
    if not isinstance(loaded, Ed25519PrivateKey):
        raise ValueError("The signing key must be Ed25519.")
    payload: dict[str, Any] = {
        "approval_version": APPROVAL_VERSION,
        "signer_id": identity,
        "signed_at": now.isoformat(),
        "expires_at": expiry.isoformat(),
        "scope_sha256": hashlib.sha256(scope_bytes).hexdigest(),
        "authorization_reference": scope.authorization_reference,
    }
    payload["signature"] = base64.b64encode(loaded.sign(_approval_message(payload))).decode("ascii")
    output = Path(output_path).expanduser().resolve()
    if output.exists():
        raise ValueError(f"Refusing to overwrite existing approval file: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    try:
        temporary.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        if output.exists():
            raise ValueError(f"Approval file appeared during signing: {output}")
        temporary.replace(output)
    finally:
        temporary.unlink(missing_ok=True)
    return {"approval_path": str(output), "signer_id": identity, "expires_at": expiry.isoformat(),
            "scope_sha256": payload["scope_sha256"]}


def verify_scope_approval(
    scope_path: str | Path,
    approval_path: str | Path,
    public_key_path: str | Path,
) -> dict[str, Any]:
    """Verify scope integrity and a trusted public-key signature immediately before use."""
    scope = load_scope(scope_path, require_active=True)
    approval_file = Path(approval_path).expanduser().resolve()
    public_file = Path(public_key_path).expanduser().resolve()
    try:
        approval = json.loads(approval_file.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"Cannot read approval file {approval_file}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"Approval file is not valid JSON (line {exc.lineno}).") from exc
    if not isinstance(approval, dict) or type(approval.get("approval_version")) is not int or approval.get("approval_version") != APPROVAL_VERSION:
        raise ValueError(f"Approval document must use approval_version={APPROVAL_VERSION}.")
    signature_text = approval.get("signature")
    if not isinstance(signature_text, str) or len(signature_text) > 256:
        raise ValueError("Approval signature is missing or malformed.")
    signature = base64.b64decode(signature_text, validate=True)
    payload = {key: value for key, value in approval.items() if key != "signature"}
    scope_bytes = _canonical_scope_bytes(scope_path)
    actual_digest = hashlib.sha256(scope_bytes).hexdigest()
    expected_digest = approval.get("scope_sha256")
    if not isinstance(expected_digest, str) or actual_digest != expected_digest:
        raise ValueError("Scope content does not match the signed approval; obtain a new approval.")
    if approval.get("authorization_reference") != scope.authorization_reference:
        raise ValueError("Approval authorization reference does not match the scope manifest.")
    signer_id = validate_signer_id(str(approval.get("signer_id", "")))
    signed_at = _parse_time(approval.get("signed_at"), "signed_at")
    expiry = _parse_time(approval.get("expires_at"), "approval expires_at")
    now = _utcnow()
    if signed_at > now + timedelta(minutes=5):
        raise ValueError("Approval signing time is in the future; check the signer system clock.")
    if expiry <= now:
        raise ValueError("Signed approval has expired; obtain a renewed approval.")
    if expiry > scope.expires_at:
        raise ValueError("Signed approval extends beyond the authorized scope's expiry.")
    if expiry <= signed_at:
        raise ValueError("Approval expiry must be later than its signing time.")
    try:
        public_key_obj = serialization.load_pem_public_key(public_file.read_bytes())
    except (OSError, ValueError, TypeError) as exc:
        raise ValueError(f"Could not load trusted public key: {exc}") from exc
    if not isinstance(public_key_obj, Ed25519PublicKey):
        raise ValueError("The trusted approval key must be Ed25519.")
    try:
        public_key_obj.verify(signature, _approval_message(payload))
    except InvalidSignature as exc:
        raise ValueError("Approval signature is invalid for the configured trusted public key.") from exc
    return {
        "verified": True,
        "signer_id": signer_id,
        "signed_at": signed_at.isoformat(),
        "expires_at": expiry.isoformat(),
        "scope_sha256": actual_digest,
        "authorization_reference": scope.authorization_reference,
        "scope_path": str(Path(scope_path).expanduser().resolve()),
        "approval_path": str(approval_file),
        "public_key_path": str(public_file),
    }
