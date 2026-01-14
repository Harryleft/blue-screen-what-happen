"""
Database manager for storing crash history.

Uses SQLite to persist crash analysis results.
"""

import sqlite3
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional
from loguru import logger

from bsod_analyzer.database.models import AnalysisResult, CrashHistory
from bsod_analyzer.utils.config import get_config


class DatabaseManager:
    """Manager for crash history database."""

    def __init__(self, db_path: Optional[Path] = None):
        """Initialize the database manager.

        Args:
            db_path: Path to database file (optional, uses config default)
        """
        if db_path is None:
            config = get_config()
            db_path = config.get_database_path()

        self.db_path = db_path
        self._ensure_database()

    def _ensure_database(self):
        """Create database and tables if they don't exist."""
        # Create parent directory
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Create crash_history table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS crash_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                dump_file_path TEXT NOT NULL,
                crash_time TIMESTAMP NOT NULL,
                bugcheck_code INTEGER NOT NULL,
                bugcheck_name TEXT NOT NULL,
                suspected_driver TEXT,
                confidence REAL DEFAULT 0.0,
                analysis_result TEXT,
                ai_analysis TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Create indexes for common queries
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_crash_time
            ON crash_history(crash_time DESC)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_bugcheck_code
            ON crash_history(bugcheck_code)
        """)

        conn.commit()
        conn.close()

        logger.debug(f"Database initialized: {self.db_path}")

    def save_analysis(self, result: AnalysisResult) -> int:
        """Save analysis result to database.

        Args:
            result: AnalysisResult to save

        Returns:
            ID of inserted record
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Serialize analysis result to JSON
        analysis_json = json.dumps({
            "suspected_cause": result.suspected_cause,
            "recommendations": result.recommendations,
            "loaded_drivers": [
                {
                    "name": d.name,
                    "base_address": d.base_address,
                    "size": d.size,
                }
                for d in result.loaded_drivers
            ],
        }, ensure_ascii=False)

        cursor.execute("""
            INSERT INTO crash_history (
                dump_file_path, crash_time, bugcheck_code, bugcheck_name,
                suspected_driver, confidence, analysis_result, ai_analysis
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            result.dump_file,
            result.minidump_info.timestamp,
            result.crash_info.bugcheck_code,
            result.crash_info.bugcheck_name,
            result.suspected_driver.name if result.suspected_driver else None,
            result.confidence,
            analysis_json,
            result.ai_analysis,
        ))

        record_id = cursor.lastrowid
        conn.commit()
        conn.close()

        logger.info(f"Saved analysis to database (ID: {record_id})")
        return record_id

    def get_crash_history(self, limit: int = 20, days: Optional[int] = None) -> List[CrashHistory]:
        """Get crash history from database.

        Args:
            limit: Maximum number of records to return
            days: Only include crashes from last N days (optional)

        Returns:
            List of CrashHistory records
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        query = "SELECT * FROM crash_history"
        params = []

        if days is not None:
            cutoff_time = datetime.now() - timedelta(days=days)
            query += " WHERE crash_time >= ?"
            params.append(cutoff_time.isoformat())

        query += " ORDER BY crash_time DESC LIMIT ?"
        params.append(limit)

        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()

        records = []
        for row in rows:
            records.append(CrashHistory(
                id=row[0],
                dump_file_path=row[1],
                crash_time=datetime.fromisoformat(row[2]),
                bugcheck_code=row[3],
                bugcheck_name=row[4],
                suspected_driver=row[5],
                confidence=row[6],
                analysis_result=row[7],
            ))

        logger.debug(f"Retrieved {len(records)} crash records")
        return records

    def get_statistics(self, days: int = 30) -> dict:
        """Get crash statistics.

        Args:
            days: Number of days to analyze

        Returns:
            Dictionary with statistics
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cutoff_time = datetime.now() - timedelta(days=days)

        # Total crashes
        cursor.execute("""
            SELECT COUNT(*) FROM crash_history
            WHERE crash_time >= ?
        """, (cutoff_time.isoformat(),))
        total = cursor.fetchone()[0]

        # Most common bugcheck codes
        cursor.execute("""
            SELECT bugcheck_code, bugcheck_name, COUNT(*) as count
            FROM crash_history
            WHERE crash_time >= ?
            GROUP BY bugcheck_code, bugcheck_name
            ORDER BY count DESC
            LIMIT 5
        """, (cutoff_time.isoformat(),))
        bugcheck_stats = cursor.fetchall()

        # Most common drivers
        cursor.execute("""
            SELECT suspected_driver, COUNT(*) as count
            FROM crash_history
            WHERE crash_time >= ? AND suspected_driver IS NOT NULL
            GROUP BY suspected_driver
            ORDER BY count DESC
            LIMIT 5
        """, (cutoff_time.isoformat(),))
        driver_stats = cursor.fetchall()

        conn.close()

        return {
            "period_days": days,
            "total_crashes": total,
            "bugcheck_distribution": [
                {"code": f"0x{row[0]:02X}", "name": row[1], "count": row[2]}
                for row in bugcheck_stats
            ],
            "driver_distribution": [
                {"driver": row[0], "count": row[1]}
                for row in driver_stats
            ],
        }

    def clear_old_records(self, days: int = 90) -> int:
        """Delete records older than specified days.

        Args:
            days: Delete records older than this many days

        Returns:
            Number of deleted records
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cutoff_time = datetime.now() - timedelta(days=days)

        cursor.execute("""
            DELETE FROM crash_history
            WHERE crash_time < ?
        """, (cutoff_time.isoformat(),))

        deleted_count = cursor.rowcount
        conn.commit()
        conn.close()

        logger.info(f"Deleted {deleted_count} old crash records")
        return deleted_count

    def get_by_id(self, record_id: int) -> Optional[CrashHistory]:
        """Get a specific crash record by ID.

        Args:
            record_id: ID of the record

        Returns:
            CrashHistory record or None
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT * FROM crash_history WHERE id = ?
        """, (record_id,))
        row = cursor.fetchone()
        conn.close()

        if row:
            return CrashHistory(
                id=row[0],
                dump_file_path=row[1],
                crash_time=datetime.fromisoformat(row[2]),
                bugcheck_code=row[3],
                bugcheck_name=row[4],
                suspected_driver=row[5],
                confidence=row[6],
                analysis_result=row[7],
            )
        return None
