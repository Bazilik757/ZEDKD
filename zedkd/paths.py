import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STORAGE_DIR = os.path.join(BASE_DIR, "storage")
DB_PATH = os.path.join(STORAGE_DIR, "storage.db")

KEYS_DIR = os.path.join(STORAGE_DIR, "keys")
DOCUMENTS_DIR = os.path.join(STORAGE_DIR, "documents")
ENCRYPTED_DIR = os.path.join(STORAGE_DIR, "encrypted")
SIGNED_DIR = os.path.join(STORAGE_DIR, "signed")
DECRYPTED_DIR = os.path.join(STORAGE_DIR, "decrypted")
ARCHIVE_DIR = os.path.join(STORAGE_DIR, "archive")
FORMS_DIR = os.path.join(STORAGE_DIR, "forms")

AUDIT_LOG_PATH = "audit_log"
DOCS_DB_PATH = "documents_db"
SEQ_PATH = "sequences"


__all__ = [
    "BASE_DIR",
    "STORAGE_DIR",
    "DB_PATH",
    "KEYS_DIR",
    "DOCUMENTS_DIR",
    "ENCRYPTED_DIR",
    "SIGNED_DIR",
    "DECRYPTED_DIR",
    "ARCHIVE_DIR",
    "FORMS_DIR",
    "AUDIT_LOG_PATH",
    "DOCS_DB_PATH",
    "SEQ_PATH",
    "ensure_storage",
]


def ensure_storage() -> None:
    for path in [
        STORAGE_DIR,
        KEYS_DIR,
        DOCUMENTS_DIR,
        ENCRYPTED_DIR,
        SIGNED_DIR,
        DECRYPTED_DIR,
        ARCHIVE_DIR,
        FORMS_DIR,
    ]:
        os.makedirs(path, exist_ok=True)


ensure_storage()
