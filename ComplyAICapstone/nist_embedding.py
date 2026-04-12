# -*- coding: utf-8 -*-
"""Dynamic framework ingestion utility for ComplyAI."""

import argparse
import json
import time
from pathlib import Path

from services.framework_service import FrameworkService


def _collect_pdf_paths(folder: str):
    return [str(p) for p in Path(folder).glob("*.pdf")]


def main():
    parser = argparse.ArgumentParser(description="ComplyAI dynamic framework ingestion")
    parser.add_argument("--name", default="NIST CSF", help="Framework name")
    parser.add_argument("--version", default="latest", help="Framework version label (e.g., 2.1)")
    parser.add_argument("--version-id", default=None, help="Stable version id for retrieval filtering")
    parser.add_argument("--description", default="Ingested via nist_embedding.py")
    parser.add_argument("--embedding-model", default="qwen3-embedding")
    parser.add_argument("--user", default="system")

    parser.add_argument("--pdf-folder", default="nist_docs", help="Folder with PDF files")
    parser.add_argument("--source-url", default=None, help="Remote URL to PDF/JSON framework")
    parser.add_argument("--source-json", default=None, help="Inline JSON payload")
    parser.add_argument("--source-json-file", default=None, help="Path to JSON file payload")

    parser.add_argument("--wait-timeout", type=int, default=1800, help="Seconds to wait for background job")
    args = parser.parse_args()

    FrameworkService.init()

    source_json_payload = None
    if args.source_json:
        source_json_payload = json.loads(args.source_json)
    elif args.source_json_file:
        with open(args.source_json_file, "r", encoding="utf-8") as fp:
            source_json_payload = json.load(fp)

    uploaded_files = None
    if not args.source_url and source_json_payload is None:
        uploaded_files = _collect_pdf_paths(args.pdf_folder)
        if not uploaded_files:
            raise RuntimeError(f"No PDFs found in folder: {args.pdf_folder}")

    print("Starting shadow ingestion job...")
    job_id = FrameworkService.start_shadow_rebuild(
        name=args.name,
        version_label=args.version,
        version_id=args.version_id,
        description=args.description,
        embedding_model=args.embedding_model,
        user=args.user,
        uploaded_files=uploaded_files,
        source_url=args.source_url,
        source_json=source_json_payload,
    )
    print(f"Job started: {job_id}")

    start = time.time()
    while True:
        cfg = FrameworkService.get_config()
        status = cfg["status"] if cfg else "unknown"
        if status in ("ready", "failed"):
            break
        if time.time() - start > args.wait_timeout:
            raise TimeoutError("Timed out waiting for framework ingestion")
        time.sleep(2)

    cfg = FrameworkService.get_config()
    if not cfg or cfg["status"] != "ready":
        raise RuntimeError("Framework ingestion failed. Check framework_audit_log for details.")

    print("✓ Shadow swap complete")
    print(f"  Name: {cfg['name']}")
    print(f"  Version: {cfg['version']}")
    print(f"  Version ID: {cfg['version_id']}")
    print(f"  Vector Store: {cfg['vector_store_path']}")


if __name__ == "__main__":
    main()
