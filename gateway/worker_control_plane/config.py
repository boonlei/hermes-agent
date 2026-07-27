"""Constructor-injected test-only settings."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


_PRODUCTION_DB_NAMES = {
    "hermes.db",
    "kanban.db",
    "sessions.db",
    "state.db",
}

PILOT_DATA_DIRECTORY = Path("/home/boonl/.hermes/worker-control-plane-pilot")
PILOT_DATABASE_PATH = PILOT_DATA_DIRECTORY / "worker-control-plane.db"


def resolve_test_database_path(
    approved_test_root: Path,
    db_path: Path,
    *,
    allow_test_pilot_filename: bool = False,
) -> tuple[Path, Path]:
    """Resolve and confine a test database path without creating anything."""
    raw_root = Path(approved_test_root)
    raw_db = Path(db_path)
    if ".." in raw_root.parts or ".." in raw_db.parts:
        raise ValueError("database traversal is not allowed")
    try:
        root = raw_root.resolve(strict=True)
    except (OSError, RuntimeError):
        raise ValueError("approved test root must already exist") from None
    if not root.is_dir():
        raise ValueError("approved test root must be a directory")
    try:
        parent = raw_db.parent.resolve(strict=False)
        resolved_db = (parent / raw_db.name).resolve(strict=False)
        relative = resolved_db.relative_to(root)
    except (OSError, RuntimeError, ValueError):
        raise ValueError("test database must be inside the approved test root") from None
    if relative == Path("."):
        raise ValueError("database path must name a file below the approved root")
    forbidden_name = resolved_db.name.lower() in _PRODUCTION_DB_NAMES
    if forbidden_name or ".hermes" in resolved_db.parts:
        raise ValueError("production-like Hermes database paths are forbidden")
    return root, resolved_db


def resolve_pilot_database_path(
    approved_root: Path, db_path: Path
) -> tuple[Path, Path]:
    """Accept only the single literal and canonical production pilot path."""
    raw_root = Path(approved_root)
    raw_db = Path(db_path)
    if ".." in raw_root.parts or ".." in raw_db.parts:
        raise ValueError("pilot database traversal is not allowed")
    if raw_root != PILOT_DATA_DIRECTORY or raw_db != PILOT_DATABASE_PATH:
        raise ValueError("fixed pilot database path is required")
    try:
        root = raw_root.resolve(strict=True)
        parent = raw_db.parent.resolve(strict=True)
        resolved_db = (parent / raw_db.name).resolve(strict=False)
    except (OSError, RuntimeError):
        raise ValueError("fixed pilot database path is unavailable") from None
    if root != PILOT_DATA_DIRECTORY or parent != root or resolved_db != PILOT_DATABASE_PATH:
        raise ValueError("fixed pilot database path is required")
    return root, resolved_db


@dataclass(frozen=True)
class WorkerControlPlaneSettings:
    enabled: bool
    test_mode: bool
    db_path: Path
    approved_test_root: Path
    pilot_mode: bool = False
    test_pilot_mode: bool = False
    token_ttl_seconds: int = 300
    heartbeat_seconds: int = 30
    ack_deadline_seconds: int = 10
    lease_seconds: int = 60
    max_poll_wait_seconds: int = 0
    # Bounded transport envelope for a 32 KiB decoded result, including
    # worst-case JSON escaping and the fixed protocol metadata.
    max_body_bytes: int = 256 * 1024
    max_stdout_bytes: int = 4096
    max_stderr_bytes: int = 4096
    max_attempts: int = 3

    def __post_init__(self) -> None:
        if not self.enabled or self.test_mode == self.pilot_mode:
            raise ValueError(
                "Worker Control Plane requires exactly one enabled isolated mode"
            )
        if self.test_pilot_mode and not self.pilot_mode:
            raise ValueError("test pilot mode requires pilot mode")
        for name in (
            "token_ttl_seconds", "heartbeat_seconds", "ack_deadline_seconds",
            "lease_seconds", "max_body_bytes", "max_stdout_bytes",
            "max_stderr_bytes", "max_attempts",
        ):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be positive")
        if self.max_poll_wait_seconds != 0:
            raise ValueError("M2B-1 supports only zero-second polling")
        if self.pilot_mode and not self.test_pilot_mode:
            root, db_path = resolve_pilot_database_path(
                self.approved_test_root, self.db_path
            )
        else:
            root, db_path = resolve_test_database_path(
                self.approved_test_root,
                self.db_path,
                allow_test_pilot_filename=self.test_pilot_mode,
            )
        object.__setattr__(self, "approved_test_root", root)
        object.__setattr__(self, "db_path", db_path)

    @classmethod
    def for_test(
        cls, db_path: Path, *, approved_test_root: Path
    ) -> "WorkerControlPlaneSettings":
        return cls(
            enabled=True,
            test_mode=True,
            db_path=db_path,
            approved_test_root=approved_test_root,
        )

    @classmethod
    def for_pilot(cls, **overrides) -> "WorkerControlPlaneSettings":
        return cls(
            enabled=True,
            test_mode=False,
            pilot_mode=True,
            db_path=PILOT_DATABASE_PATH,
            approved_test_root=PILOT_DATA_DIRECTORY,
            **overrides,
        )

    @classmethod
    def for_test_pilot(
        cls, data_dir: Path, **overrides
    ) -> "WorkerControlPlaneSettings":
        root = Path(data_dir)
        return cls(
            enabled=True,
            test_mode=False,
            pilot_mode=True,
            test_pilot_mode=True,
            db_path=root / "worker-control-plane.db",
            approved_test_root=root,
            **overrides,
        )
