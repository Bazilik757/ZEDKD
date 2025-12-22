import secrets
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import List

from .paths import DOCS_DB_PATH
from .utils import safe_load_data, safe_save_data

__all__ = [
    "DOC_TYPES",
    "ORDER_WORKFLOW_STEPS",
    "DocumentRecord",
    "load_documents_db",
    "save_documents_db",
    "generate_doc_id",
]

DOC_TYPES = ["Приказ", "Инструкция", "Протокол"]

ORDER_WORKFLOW_STEPS = [
    "Согласование: юридическая проверка",
    "Согласование: финансовая проверка",
    "Утверждение: подписание директором",
    "Утверждение: шифрование",
    "Исполнение: доведение до исполнителей",
    "Исполнение: проверка подписи",
    "В дело: архивирование",
    "ПДЭК: заседание и протокол",
    "Через 1 год: рассекретить (подготовка)",
    "Рассекретить: акт передачи в открытое делопроизводство",
]


@dataclass
class DocumentRecord:
    doc_id: str
    doc_type: str
    title: str
    author: str
    department: str
    confidentiality: str
    created_at: str
    status: str
    step_index: int
    file_name: str
    stored_path: str
    hash_value: str
    copies: str
    pages_per_copy: str
    recipients: str

    order_reg_no: str = ""
    carrier_no: str = ""
    sig_path: str = ""
    enc_path: str = ""
    archived_path: str = ""
    pdek_protocol_path: str = ""
    declass_act_path: str = ""


def load_documents_db() -> List[DocumentRecord]:
    raw = safe_load_data(DOCS_DB_PATH, [])
    docs: List[DocumentRecord] = []
    for entry in raw:
        try:
            docs.append(DocumentRecord(**entry))
        except Exception:
            pass
    return docs


def save_documents_db(docs: List[DocumentRecord]):
    safe_save_data(DOCS_DB_PATH, [asdict(doc) for doc in docs])


def generate_doc_id() -> str:
    suffix = secrets.token_hex(2).upper()
    return f"DOC-{datetime.now().strftime('%Y%m%d')}-{suffix}"
