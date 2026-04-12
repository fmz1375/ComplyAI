import os
import shutil
import sqlite3
import threading
import uuid
import json
from urllib.parse import urlparse
from urllib.request import urlopen
from datetime import datetime
from pathlib import Path
import traceback
from typing import Any, Dict, List, Optional, Tuple

from security_utils import InputValidation

from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.document_loaders import PyPDFLoader
from langchain_community.vectorstores import FAISS
from langchain_ollama import OllamaEmbeddings
from langchain_core.documents import Document

DB_PATH = "project.db"
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UPLOAD_TEMP = os.path.join(BASE_DIR, "uploads", "framework_tmp")
VECTOR_STORE_BASE = os.path.join(BASE_DIR, "faiss_index")


def _get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init():
    # Ensure folders exist
    os.makedirs(UPLOAD_TEMP, exist_ok=True)
    os.makedirs(VECTOR_STORE_BASE, exist_ok=True)
    try:
        from migrations.create_framework_table import run as run_framework_migration
        run_framework_migration()
    except Exception:
        pass


class FrameworkService:
    """Singleton-style helper for framework lifecycle management.

    Responsibilities:
    - Manage single-row `framework_config`
    - Start background rebuilds safely (no concurrent rebuilds)
    - Build embeddings & FAISS index into a new folder
    - Atomically update active framework path in DB
    - Audit logging
    """

    lock = threading.Lock()

    @staticmethod
    def init():
        init()

    @staticmethod
    def get_config():
        conn = _get_conn()
        cur = conn.cursor()
        cur.execute("SELECT * FROM framework_config WHERE id = 1")
        row = cur.fetchone()
        conn.close()
        return row

    @staticmethod
    def get_framework_version(version_id: str):
        conn = _get_conn()
        cur = conn.cursor()
        cur.execute("SELECT * FROM framework_versions WHERE version_id = ?", (version_id,))
        row = cur.fetchone()
        conn.close()
        return row

    @staticmethod
    def get_active_framework_version():
        conn = _get_conn()
        cur = conn.cursor()
        cur.execute("SELECT * FROM framework_versions WHERE is_active = 1 ORDER BY created_at DESC LIMIT 1")
        row = cur.fetchone()
        conn.close()
        return row

    @staticmethod
    def resolve_framework(version_id: Optional[str] = None) -> Dict[str, Any]:
        if version_id:
            row = FrameworkService.get_framework_version(version_id)
            if not row:
                raise RuntimeError(f"Framework version not found: {version_id}")
            return {
                "framework_name": row["framework_name"],
                "version_id": row["version_id"],
                "version_label": row["version_label"],
                "vector_store_path": row["vector_store_path"],
                "embedding_model": row["embedding_model"],
            }

        active = FrameworkService.get_active_framework_version()
        if active:
            return {
                "framework_name": active["framework_name"],
                "version_id": active["version_id"],
                "version_label": active["version_label"],
                "vector_store_path": active["vector_store_path"],
                "embedding_model": active["embedding_model"],
            }

        cfg = FrameworkService.get_config()
        if not cfg:
            raise RuntimeError("No framework_config available")

        return {
            "framework_name": cfg["name"] or "NIST CSF",
            "version_id": cfg["version_id"] or cfg["version"] or "default",
            "version_label": cfg["version"] or "unknown",
            "vector_store_path": cfg["vector_store_path"],
            "embedding_model": cfg["embedding_model"],
        }

    @staticmethod
    def set_status(status: str, updated_by: str = None, **fields):
        conn = _get_conn()
        cur = conn.cursor()
        now = datetime.utcnow().isoformat()
        updates = ["last_updated_at = ?", "status = ?"]
        params = [now, status]
        for k, v in fields.items():
            updates.append(f"{k} = ?")
            params.append(v)
        params.append(1)
        sql = f"UPDATE framework_config SET {', '.join(updates)}, updated_by = ? WHERE id = ?"
        # place updated_by before id
        params.insert(-1, updated_by)
        cur.execute(sql, params)
        conn.commit()
        conn.close()

    @staticmethod
    def audit(event_type: str, message: str, performed_by: str = None):
        conn = _get_conn()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO framework_audit_log (event_type, message, performed_by) VALUES (?, ?, ?)",
            (event_type, message, performed_by),
        )
        conn.commit()
        conn.close()

    @staticmethod
    def _slugify(value: str) -> str:
        cleaned = "".join(ch.lower() if ch.isalnum() else "-" for ch in (value or ""))
        while "--" in cleaned:
            cleaned = cleaned.replace("--", "-")
        return cleaned.strip("-") or "framework"

    @staticmethod
    def _build_documents_from_json_payload(payload: Any, source_label: str = "json") -> List[Document]:
        if isinstance(payload, str):
            payload = json.loads(payload)

        if isinstance(payload, dict):
            controls = payload.get("controls")
            if controls is None:
                controls = payload.get("items")
            if controls is None:
                controls = payload.get("data")
            if controls is None:
                controls = [payload]
        elif isinstance(payload, list):
            controls = payload
        else:
            raise RuntimeError("Unsupported JSON payload for framework ingestion")

        docs: List[Document] = []
        for idx, item in enumerate(controls):
            if isinstance(item, dict):
                control_id = str(item.get("id") or item.get("control_id") or item.get("identifier") or f"CTRL-{idx+1}")
                title = str(item.get("title") or item.get("name") or "")
                body = str(item.get("description") or item.get("text") or item.get("content") or "")
                if not title and not body:
                    body = json.dumps(item, ensure_ascii=False)
                prefix = f"{control_id}: {title}".strip()
                page_content = f"{prefix}\n{body}" if body else prefix
                metadata = {"source": source_label, "source_type": "json", "item_index": idx}
                docs.append(Document(page_content=page_content, metadata=metadata))
            else:
                docs.append(
                    Document(
                        page_content=str(item),
                        metadata={"source": source_label, "source_type": "json", "item_index": idx},
                    )
                )

        if not docs:
            raise RuntimeError("No framework controls found in JSON payload")
        return docs

    @staticmethod
    def _download_source(url: str, temp_dir: str) -> Tuple[str, str]:
        # Validate URL to prevent SSRF attacks
        try:
            validated_url = InputValidation.validate_url(url)
        except ValueError as e:
            raise ValueError(f"Invalid or blocked URL: {str(e)}")
        
        # Add size limit to prevent large file downloads
        MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB max
        
        parsed = urlparse(validated_url)
        ext = Path(parsed.path).suffix.lower()
        if ext not in (".pdf", ".json"):
            ext = ".json"
        
        out_path = os.path.join(temp_dir, f"downloaded_source{ext}")
        
        # Download with size limit
        with urlopen(validated_url, timeout=30) as resp:
            total_size = 0
            with open(out_path, 'wb') as f:
                while True:
                    chunk = resp.read(8192)  # Read in 8KB chunks
                    if not chunk:
                        break
                    total_size += len(chunk)
                    if total_size > MAX_FILE_SIZE:
                        raise ValueError(f"Downloaded file exceeds {MAX_FILE_SIZE} bytes limit")
                    f.write(chunk)
            
            content_type = (resp.headers.get("Content-Type") or "").lower()

        if "application/pdf" in content_type and ext != ".pdf":
            ext = ".pdf"
            out_path = os.path.join(temp_dir, f"downloaded_source{ext}")

        return out_path, ext

    @staticmethod
    def _build_index_from_documents(
        documents: List[Document],
        framework_name: str,
        version_id: str,
        created_at: str,
        embedding_model: str = "qwen3-embedding",
        chunk_size: int = 1000,
        chunk_overlap: int = 200,
        out_dir: Optional[str] = None,
    ):
        if out_dir is None:
            out_dir = os.path.join(VECTOR_STORE_BASE, f"faiss_{uuid.uuid4().hex}")
        os.makedirs(out_dir, exist_ok=False)

        splitter = RecursiveCharacterTextSplitter(chunk_size=chunk_size, chunk_overlap=chunk_overlap)
        split_docs = splitter.split_documents(documents)

        for idx, chunk in enumerate(split_docs):
            metadata = dict(chunk.metadata or {})
            metadata["framework_name"] = framework_name
            metadata["version_id"] = version_id
            metadata["created_at"] = created_at
            metadata["chunk_index"] = idx
            chunk.metadata = metadata

        embeddings = OllamaEmbeddings(model=embedding_model)
        faiss_store = FAISS.from_documents(split_docs, embeddings)
        faiss_store.save_local(out_dir)
        return out_dir, len(split_docs)

    @staticmethod
    def _build_index_from_pdfs(
        pdf_paths,
        framework_name: str,
        version_id: str,
        created_at: str,
        embedding_model="qwen3-embedding",
        chunk_size=1000,
        chunk_overlap=200,
        out_dir=None,
    ):
        documents = []
        for p in pdf_paths:
            loader = PyPDFLoader(str(p))
            docs = loader.load()
            documents.extend(docs)

        return FrameworkService._build_index_from_documents(
            documents=documents,
            framework_name=framework_name,
            version_id=version_id,
            created_at=created_at,
            embedding_model=embedding_model,
            chunk_size=chunk_size,
            chunk_overlap=chunk_overlap,
            out_dir=out_dir,
        )

    @staticmethod
    def _validate_index(index_dir: str, embedding_model: str):
        expected_files = [os.path.join(index_dir, "index.faiss"), os.path.join(index_dir, "index.pkl")]
        for ef in expected_files:
            if not os.path.exists(ef):
                raise RuntimeError(f"Missing FAISS file after build: {ef}")

        embeddings = OllamaEmbeddings(model=embedding_model)
        store = FAISS.load_local(index_dir, embeddings, allow_dangerous_deserialization=True)
        _ = store.similarity_search("access control", k=1)

    @classmethod
    def start_rebuild(cls, uploaded_files, name, version, description, embedding_model, user, timeout_seconds=1800):
        return cls.start_shadow_rebuild(
            name=name,
            version_label=version,
            description=description,
            embedding_model=embedding_model,
            user=user,
            uploaded_files=uploaded_files,
            timeout_seconds=timeout_seconds,
        )

    @classmethod
    def start_shadow_rebuild(
        cls,
        name: str,
        version_label: str,
        description: str,
        embedding_model: str,
        user: str,
        uploaded_files: Optional[List[str]] = None,
        source_url: Optional[str] = None,
        source_json: Optional[Any] = None,
        version_id: Optional[str] = None,
        timeout_seconds: int = 1800,
    ):
        """Starts background rebuild. Returns a job id (uuid hex)."""
        # Prevent concurrent rebuilds using DB status
        with cls.lock:
            cfg = cls.get_config()
            if cfg and cfg["status"] == "processing":
                raise RuntimeError("Another rebuild is already in progress")
            # mark processing
            cls.set_status("processing", updated_by=user)

        job_id = uuid.uuid4().hex
        created_at = datetime.utcnow().isoformat()
        resolved_version_id = version_id or f"{cls._slugify(name)}-{cls._slugify(version_label)}"

        def _job():
            tmp_dir = os.path.join(UPLOAD_TEMP, f"{job_id}")
            os.makedirs(tmp_dir, exist_ok=True)
            try:
                shadow_out = os.path.join(VECTOR_STORE_BASE, f"shadow_{job_id}")

                if source_url:
                    downloaded_path, ext = cls._download_source(source_url, tmp_dir)
                    if ext == ".pdf":
                        new_dir, chunk_count = cls._build_index_from_pdfs(
                            [downloaded_path],
                            framework_name=name,
                            version_id=resolved_version_id,
                            created_at=created_at,
                            embedding_model=embedding_model,
                            out_dir=shadow_out,
                        )
                        source_type = "url_pdf"
                    else:
                        with open(downloaded_path, "r", encoding="utf-8") as fp:
                            payload = json.load(fp)
                        docs = cls._build_documents_from_json_payload(payload, source_label=source_url)
                        new_dir, chunk_count = cls._build_index_from_documents(
                            docs,
                            framework_name=name,
                            version_id=resolved_version_id,
                            created_at=created_at,
                            embedding_model=embedding_model,
                            out_dir=shadow_out,
                        )
                        source_type = "url_json"
                    source_ref = source_url
                elif source_json is not None:
                    docs = cls._build_documents_from_json_payload(source_json, source_label="inline_json")
                    new_dir, chunk_count = cls._build_index_from_documents(
                        docs,
                        framework_name=name,
                        version_id=resolved_version_id,
                        created_at=created_at,
                        embedding_model=embedding_model,
                        out_dir=shadow_out,
                    )
                    source_type = "json"
                    source_ref = None
                else:
                    if not uploaded_files:
                        raise RuntimeError("No framework source provided. Use uploaded files, source_url, or source_json")
                    pdf_paths = []
                    for f in uploaded_files:
                        dest = os.path.join(tmp_dir, os.path.basename(f))
                        shutil.copyfile(f, dest)
                        pdf_paths.append(dest)

                    new_dir, chunk_count = cls._build_index_from_pdfs(
                        pdf_paths,
                        framework_name=name,
                        version_id=resolved_version_id,
                        created_at=created_at,
                        embedding_model=embedding_model,
                        out_dir=shadow_out,
                    )
                    source_type = "pdf_upload"
                    source_ref = None

                # Validate shadow index before swap
                cls._validate_index(new_dir, embedding_model)

                # Atomically update active framework pointer and keep old versions intact
                conn = _get_conn()
                cur = conn.cursor()

                cur.execute("UPDATE framework_versions SET is_active = 0")
                cur.execute(
                    """
                    INSERT INTO framework_versions (
                        version_id, framework_name, version_label, description, embedding_model,
                        vector_store_path, created_at, created_by, source_type, source_ref,
                        chunk_count, status, is_active
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ready', 1)
                    ON CONFLICT(version_id) DO UPDATE SET
                        framework_name=excluded.framework_name,
                        version_label=excluded.version_label,
                        description=excluded.description,
                        embedding_model=excluded.embedding_model,
                        vector_store_path=excluded.vector_store_path,
                        created_at=excluded.created_at,
                        created_by=excluded.created_by,
                        source_type=excluded.source_type,
                        source_ref=excluded.source_ref,
                        chunk_count=excluded.chunk_count,
                        status='ready',
                        is_active=1
                    """,
                    (
                        resolved_version_id,
                        name,
                        version_label,
                        description,
                        embedding_model,
                        new_dir,
                        created_at,
                        user,
                        source_type,
                        source_ref,
                        chunk_count,
                    ),
                )

                cur.execute(
                    "UPDATE framework_config SET name = ?, version = ?, version_id = ?, description = ?, embedding_model = ?, vector_store_path = ?, last_updated_at = ?, status = 'ready', updated_by = ? WHERE id = 1",
                    (name, version_label, resolved_version_id, description, embedding_model, new_dir, created_at, user),
                )
                conn.commit()
                conn.close()

                cls.audit(
                    "shadow_swap_success",
                    f"Activated framework {name}@{version_label} (version_id={resolved_version_id}, chunks={chunk_count})",
                    performed_by=user,
                )
            except Exception as exc:
                # On failure, set status failed and keep old vector store intact
                tb = traceback.format_exc()
                cls.set_status("failed", updated_by=user)
                cls.audit("shadow_swap_failed", str(exc) + "\n" + tb, performed_by=user)
            finally:
                # cleanup temp uploads
                try:
                    shutil.rmtree(tmp_dir)
                except Exception:
                    pass

        t = threading.Thread(target=_job, daemon=True)
        t.start()
        return job_id


init()
