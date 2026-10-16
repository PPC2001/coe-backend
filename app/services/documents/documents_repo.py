"""SharePoint Document Metadata & Access Control List (ACL) Repository.

Provides local search indexing, permission evaluation, and live OBO stream verification.
"""

from dataclasses import dataclass
import logging
import sqlite3
import uuid
from typing import Any

from app.core.config import get_settings

logger = logging.getLogger("coe.documents.repo")


@dataclass
class DocumentRecord:
    id: str
    library_id: str
    drive_id: str
    item_id: str
    title: str
    sharepoint_url: str | None
    mime: str | None
    language: str | None
    status: str
    has_unique_acl: bool


def init_documents_db() -> None:
    s = get_settings()
    try:
        conn = sqlite3.connect(s.identity_db_path, check_same_thread=False)
        with conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS libraries (
                    id TEXT PRIMARY KEY,
                    drive_id TEXT NOT NULL,
                    site_id TEXT NOT NULL,
                    name TEXT NOT NULL
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS library_acl (
                    library_id TEXT REFERENCES libraries(id),
                    principal_id TEXT NOT NULL,
                    principal_type TEXT NOT NULL CHECK (principal_type IN ('group','user','everyone')),
                    synced_at TEXT DEFAULT (datetime('now')),
                    PRIMARY KEY (library_id, principal_id)
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS documents (
                    id TEXT PRIMARY KEY,
                    library_id TEXT REFERENCES libraries(id),
                    item_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    sharepoint_url TEXT,
                    mime TEXT,
                    language TEXT,
                    status TEXT DEFAULT 'active',
                    has_unique_acl INTEGER NOT NULL DEFAULT 0
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS document_acl (
                    document_id TEXT REFERENCES documents(id),
                    principal_id TEXT NOT NULL,
                    principal_type TEXT NOT NULL,
                    synced_at TEXT DEFAULT (datetime('now')),
                    PRIMARY KEY (document_id, principal_id)
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS document_sections (
                    id TEXT PRIMARY KEY,
                    document_id TEXT REFERENCES documents(id),
                    title TEXT,
                    content TEXT NOT NULL
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_lib_acl_principal ON library_acl (principal_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_doc_acl_principal ON document_acl (principal_id);")

            # Seed default test libraries and documents if empty
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM libraries")
            if cur.fetchone()[0] == 0:
                lib1_id = "lib-policies-001"
                lib2_id = "lib-hr-confidential-002"
                lib3_id = "lib-urban-projects-003"
                conn.execute(
                    "INSERT INTO libraries (id, drive_id, site_id, name) VALUES (?, ?, ?, ?)",
                    (lib1_id, "drive-dev-docs", "site-coe-dev", "Policies & Handbooks"),
                )
                conn.execute(
                    "INSERT INTO libraries (id, drive_id, site_id, name) VALUES (?, ?, ?, ?)",
                    (lib2_id, "drive-hr", "site-hr", "HR Confidential"),
                )
                conn.execute(
                    "INSERT INTO libraries (id, drive_id, site_id, name) VALUES (?, ?, ?, ?)",
                    (lib3_id, "drive-urban", "site-urban", "Urban Projects"),
                )

                # Policies is available to ALL_EMPLOYEES
                conn.execute(
                    "INSERT INTO library_acl (library_id, principal_id, principal_type) VALUES (?, ?, ?)",
                    (lib1_id, "ALL_EMPLOYEES", "everyone"),
                )
                # HR Confidential is restricted to HR group
                conn.execute(
                    "INSERT INTO library_acl (library_id, principal_id, principal_type) VALUES (?, ?, ?)",
                    (lib2_id, "group-hr-analytics", "group"),
                )
                # Urban Projects is restricted to Urban division group
                conn.execute(
                    "INSERT INTO library_acl (library_id, principal_id, principal_type) VALUES (?, ?, ?)",
                    (lib3_id, "group-urban-division", "group"),
                )

                doc1_id = "doc-policy-2026"
                conn.execute(
                    """
                    INSERT INTO documents (id, library_id, item_id, title, sharepoint_url, mime, language, status, has_unique_acl)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 'active', 0)
                    """,
                    (
                        doc1_id,
                        lib1_id,
                        "item-code-of-conduct-pdf",
                        "ELAN Group Code of Conduct 2026.pdf",
                        "https://elan.sharepoint.com/sites/dev/policies/code-of-conduct.pdf",
                        "application/pdf",
                        "en",
                    ),
                )
                conn.execute(
                    """
                    INSERT INTO document_sections (id, document_id, title, content)
                    VALUES (?, ?, ?, ?)
                    """,
                    ("sec-1", doc1_id, "Code of Conduct", "ELAN Group values integrity, excellence, and security."),
                )

                doc2_id = "doc-hr-salaries"
                conn.execute(
                    """
                    INSERT INTO documents (id, library_id, item_id, title, sharepoint_url, mime, language, status, has_unique_acl)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 'active', 0)
                    """,
                    (
                        doc2_id,
                        lib2_id,
                        "item-hr-comp-2026",
                        "Executive Compensation Review Q3.xlsx",
                        "https://elan.sharepoint.com/sites/hr/comp.xlsx",
                        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        "en",
                    ),
                )
        conn.close()
    except Exception as e:
        logger.warning("Could not initialize documents schema: %s", e)


class DocumentRepository:
    def __init__(self, db_path: str | None = None):
        self.db_path = db_path or get_settings().identity_db_path

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def get_document(self, document_id: str) -> DocumentRecord | None:
        conn = self._conn()
        try:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT d.id, d.library_id, l.drive_id, d.item_id, d.title, d.sharepoint_url,
                       d.mime, d.language, d.status, d.has_unique_acl
                FROM documents d
                JOIN libraries l ON l.id = d.library_id
                WHERE d.id = ? AND d.status = 'active'
                """,
                (document_id,),
            )
            row = cur.fetchone()
            if not row:
                return None
            return DocumentRecord(
                id=row["id"],
                library_id=row["library_id"],
                drive_id=row["drive_id"],
                item_id=row["item_id"],
                title=row["title"],
                sharepoint_url=row["sharepoint_url"],
                mime=row["mime"],
                language=row["language"],
                status=row["status"],
                has_unique_acl=bool(row["has_unique_acl"]),
            )
        finally:
            conn.close()

    def can_read(self, doc: DocumentRecord, principal_ids: list[str]) -> bool:
        """Evaluates whether the caller's principal list matches the library or document ACL."""
        if not principal_ids:
            return False

        conn = self._conn()
        try:
            placeholders = ",".join("?" for _ in principal_ids)
            cur = conn.cursor()
            if not doc.has_unique_acl:
                query = f"""
                SELECT 1 FROM library_acl
                WHERE library_id = ? AND principal_id IN ({placeholders})
                LIMIT 1
                """
                cur.execute(query, [doc.library_id, *principal_ids])
            else:
                query = f"""
                SELECT 1 FROM document_acl
                WHERE document_id = ? AND principal_id IN ({placeholders})
                LIMIT 1
                """
                cur.execute(query, [doc.id, *principal_ids])
            return cur.fetchone() is not None
        finally:
            conn.close()

    def search_documents(self, query: str, principal_ids: list[str], limit: int = 20) -> list[dict[str, Any]]:
        """ACL-trimmed document and section search: filters visible items before ranking and limit."""
        if not principal_ids:
            return []

        conn = self._conn()
        try:
            placeholders = ",".join("?" for _ in principal_ids)
            if query.strip():
                escaped = (
                    query.strip()
                    .lower()
                    .replace("\\", "\\\\")
                    .replace("%", "\\%")
                    .replace("_", "\\_")
                )
                clean_q = f"%{escaped}%"
            else:
                clean_q = "%"

            sql = f"""
            WITH visible AS (
                SELECT d.id
                FROM documents d
                WHERE d.status = 'active'
                  AND (
                    (d.has_unique_acl = 0 AND EXISTS (
                        SELECT 1 FROM library_acl la
                        WHERE la.library_id = d.library_id AND la.principal_id IN ({placeholders})
                    ))
                    OR
                    (d.has_unique_acl = 1 AND EXISTS (
                        SELECT 1 FROM document_acl da
                        WHERE da.document_id = d.id AND da.principal_id IN ({placeholders})
                    ))
                  )
            )
            SELECT d.id, d.title, d.sharepoint_url, d.mime, d.language, l.name AS library_name
            FROM documents d
            JOIN visible v ON v.id = d.id
            JOIN libraries l ON l.id = d.library_id
            WHERE lower(d.title) LIKE ? ESCAPE '\\'
            LIMIT ?;
            """
            cur = conn.cursor()
            params = [*principal_ids, *principal_ids, clean_q, limit]
            cur.execute(sql, params)
            results = []
            for r in cur.fetchall():
                results.append({
                    "id": r["id"],
                    "title": r["title"],
                    "sharepoint_url": r["sharepoint_url"],
                    "mime": r["mime"],
                    "language": r["language"],
                    "library_name": r["library_name"],
                })
            return results
        finally:
            conn.close()

    def flag_acl_drift(self, document_id: str) -> None:
        """Records an event indicating that SharePoint denied access, noting ACL drift."""
        logger.warning("ACL drift detected for document %s against SharePoint Online permissions", document_id)


repo = DocumentRepository()
