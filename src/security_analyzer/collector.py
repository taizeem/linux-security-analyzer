import os
from pathlib import Path
from typing import Iterator, Tuple, Union

from security_analyzer.logger import get_logger


logger = get_logger(__name__)


def validate_log_file(file_path: Union[str, Path]) -> Path:
    """Validate that a log path exists, is a regular file, and is readable.

    Raises:
        FileNotFoundError: If the path does not exist.
        IsADirectoryError: If the path points to a directory.
        PermissionError: If the current user lacks read permission.
        ValueError: If the path is not a regular file.
    """
    resolved = Path(file_path).expanduser().resolve()

    if not resolved.exists():
        raise FileNotFoundError(f"Authentication log file not found: {resolved}")

    if resolved.is_dir():
        raise IsADirectoryError(
            f"Expected a log file but found a directory: {resolved}"
        )

    if not resolved.is_file():
        raise ValueError(f"Log path is not a regular file: {resolved}")

    if not os.access(resolved, os.R_OK):
        raise PermissionError(
            f"Permission denied reading log file: {resolved}. "
            "Verify file permissions or 'adm' group membership."
        )

    return resolved


def read_log_lines(
    file_path: Union[str, Path],
    encoding: str = "utf-8",
) -> Iterator[Tuple[int, str]]:
    """Stream non-empty (line_number, stripped_line) tuples from a log file."""
    validated_path = validate_log_file(file_path)
    logger.debug("Streaming authentication log from %s", validated_path)

    with open(
        validated_path,
        mode="r",
        encoding=encoding,
        errors="replace",
    ) as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            cleaned = raw_line.rstrip("\r\n")
            if not cleaned.strip():
                continue
            yield line_number, cleaned