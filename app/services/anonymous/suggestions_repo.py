import logging
import sqlite3

from app.core.config import get_settings

logger = logging.getLogger("coe.anonymous.repo")


def init_suggestions_db() -> None:
    s = get_settings()
    try:
        conn = sqlite3.connect(s.identity_db_path, check_same_thread=False)
        with conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS anonymous_suggestions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    submission_date TEXT NOT NULL,
                    category TEXT NOT NULL,
                    suggestion_text TEXT NOT NULL
                );
                """
            )
        conn.close()
    except Exception as e:
        logger.warning("Could not initialize anonymous suggestions table: %s", e)
