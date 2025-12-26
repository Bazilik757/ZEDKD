import base64
import hashlib
import hmac
import json
import os
import secrets
from typing import Optional

from .paths import DECRYPTED_DIR, ENCRYPTED_DIR
from .utils import (
    calc_doc_hash_bytes,
    log_event,
    now_iso,
    safe_load_data,
    safe_save_data,
)

__all__ = [
    "generate_keys",
    "load_keys",
    "sign_document",
    "verify_signature",
    "xor_cipher",
    "encrypt_file",
    "decrypt_file",
]


def generate_keys(username: str) -> str:
    existing = safe_load_data(f"keys:{username}", None)
    if existing and existing.get("private_key") and existing.get("public_key"):
        log_event(username, "generate_keys", "skip", extra={"reason": "already_exists"})
        raise ValueError("Ключи уже созданы для этого пользователя")

    private_key = secrets.token_bytes(32)
    public_key = hashlib.sha256(private_key).hexdigest()
    key_data = {
        "username": username,
        "private_key": private_key.hex(),
        "public_key": public_key,
    }
    key_id = f"keys:{username}"
    safe_save_data(key_id, key_data)
    log_event(username, "generate_keys", "ok", extra={"key_id": key_id})
    return key_id


def load_keys(username: str):
    key_id = f"keys:{username}"
    data = safe_load_data(key_id, {})
    if not data:
        raise FileNotFoundError(f"Ключи пользователя {username} не найдены")
    return data


def sign_document(username: str, file_path: str, doc_id: Optional[str] = None) -> str:
    keys = load_keys(username)
    if not keys or "private_key" not in keys:
        raise ValueError("Ключи пользователя не найдены/некорректны")

    with open(file_path, "rb") as f:
        data = f.read()

    doc_hash = calc_doc_hash_bytes(data)
    index_key = f"signature_index:{doc_hash}:{username}"
    existing_sig = safe_load_data(index_key, None)
    if existing_sig:
        raise ValueError("Пользователь уже подписывал этот документ")

    private_key_bytes = bytes.fromhex(keys["private_key"])
    signature_raw = hashlib.sha256(bytes.fromhex(doc_hash) + private_key_bytes).hexdigest()

    signature = {
        "doc_hash": doc_hash,
        "username": username,
        "signature": signature_raw,
        "timestamp": now_iso(),
        "doc_id": doc_id,
    }

    sig_id = f"signature:{os.path.basename(file_path)}:{signature['timestamp']}"
    safe_save_data(sig_id, signature)
    if doc_id:
        safe_save_data(f"signature_doc_index:{doc_id}", sig_id)
    safe_save_data(index_key, sig_id)

    log_event(username, "sign", "ok", doc_id=doc_id or os.path.basename(file_path), extra={"sig_id": sig_id})
    return sig_id


def verify_signature(file_path: str, sig_path: str) -> bool:
    sig = safe_load_data(sig_path, {})
    username = sig.get("username")
    if not username:
        return False

    keys = load_keys(username)
    with open(file_path, "rb") as f:
        data = f.read()

    doc_hash = calc_doc_hash_bytes(data)
    if doc_hash != sig.get("doc_hash"):
        return False

    private_key_bytes = bytes.fromhex(keys["private_key"])
    expected_sig = hashlib.sha256(bytes.fromhex(doc_hash) + private_key_bytes).hexdigest()
    return expected_sig == sig.get("signature")


def xor_cipher(data: bytes, key: bytes) -> bytes:
    res = bytearray()
    key_len = len(key)
    for i, b in enumerate(data):
        res.append(b ^ key[i % key_len])
    return bytes(res)


def encrypt_file(username: str, file_path: str, doc_id: Optional[str] = None) -> str:
    with open(file_path, "rb") as f:
        data = f.read()

    sym_key = secrets.token_bytes(32)
    plain_hash = calc_doc_hash_bytes(data)

    encrypted = xor_cipher(data, sym_key)
    mac = hmac.new(sym_key, encrypted, hashlib.sha256).hexdigest()

    created_at = now_iso()
    safe_ts = created_at.replace(":", "-")
    enc_filename = f"{os.path.basename(file_path)}.{safe_ts}.enc.json"
    enc_path = os.path.join(ENCRYPTED_DIR, enc_filename)

    packet = {
        "sym_key": base64.b64encode(sym_key).decode("ascii"),
        "data": base64.b64encode(encrypted).decode("ascii"),
        "original_name": os.path.basename(file_path),
        "plain_hash": plain_hash,
        "hmac_sha256": mac,
        "created_at": created_at,
    }

    enc_id = f"encrypted:{os.path.basename(file_path)}:{packet['created_at']}"
    safe_save_data(enc_id, {**packet, "__file_path": enc_path})

    with open(enc_path, "w", encoding="utf-8") as f:
        json.dump(packet, f, ensure_ascii=False, indent=2)

    log_event(
        username,
        "encrypt",
        "ok",
        doc_id=doc_id or os.path.basename(file_path),
        extra={"enc_id": enc_id, "enc_file": enc_path},
    )
    return enc_path


def decrypt_file(username: str, enc_path: str, doc_id: Optional[str] = None) -> str:
    packet = {}
    if os.path.isfile(enc_path):
        with open(enc_path, "r", encoding="utf-8") as f:
            try:
                packet = json.load(f)
            except json.JSONDecodeError:
                packet = {}
    if not packet:
        packet = safe_load_data(enc_path, {})
        if isinstance(packet, dict):
            file_variant = packet.get("__file_path")
            if file_variant and os.path.isfile(file_variant):
                with open(file_variant, "r", encoding="utf-8") as f:
                    try:
                        packet = json.load(f)
                    except json.JSONDecodeError:
                        pass
    if not packet:
        raise ValueError("Некорректный пакет шифрования")

    sym_key = base64.b64decode(packet["sym_key"])
    encrypted = base64.b64decode(packet["data"])

    mac_expected = packet.get("hmac_sha256")
    mac_actual = hmac.new(sym_key, encrypted, hashlib.sha256).hexdigest()
    if mac_expected and mac_actual != mac_expected:
        log_event(
            username,
            "decrypt",
            "fail",
            doc_id=doc_id or packet.get("original_name"),
            extra={"reason": "HMAC mismatch"},
        )
        raise ValueError("Нарушена целостность: HMAC не совпадает")

    decrypted = xor_cipher(encrypted, sym_key)

    plain_hash_expected = packet.get("plain_hash")
    plain_hash_actual = calc_doc_hash_bytes(decrypted)
    if plain_hash_expected and plain_hash_actual != plain_hash_expected:
        log_event(
            username,
            "decrypt",
            "fail",
            doc_id=doc_id or packet.get("original_name"),
            extra={"reason": "Plain hash mismatch"},
        )
        raise ValueError("Нарушена целостность: хэш исходного документа не совпадает")

    original_name = packet.get("original_name", "decrypted.bin")
    out_name = "decrypted_" + original_name
    out_path = os.path.join(DECRYPTED_DIR, out_name)
    with open(out_path, "wb") as f:
        f.write(decrypted)

    log_event(username, "decrypt", "ok", doc_id=doc_id or original_name, extra={"dec_file": out_path})
    return out_path
