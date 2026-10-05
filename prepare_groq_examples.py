from pathlib import Path
import shutil


# ============================================================
# CONFIGURATION
# ============================================================

PROJECT_ROOT = Path(r"C:\ai_security_warning_log_analyzer")

FOLDERS = [
    PROJECT_ROOT / "examples",
    PROJECT_ROOT / "examples mixed",
    PROJECT_ROOT / "examples unstruc",
    PROJECT_ROOT / "mock_logs",
]

# Keep each individual example safely below Groq's
# current 8,000 TPM free-tier request limit.
#
# 2,000 characters is intentionally conservative.
MAX_EXAMPLE_CHARACTERS = 2_000

# Create backups before modifying anything.
BACKUP_ROOT = PROJECT_ROOT / "_example_backups"


# File extensions that will be processed.
TEXT_EXTENSIONS = {
    ".txt",
    ".log",
    ".json",
    ".jsonl",
    ".csv",
    ".md",
    ".xml",
    ".yaml",
    ".yml",
}


# ============================================================
# HELPERS
# ============================================================

def is_text_file(path: Path) -> bool:
    """
    Determine whether the file should be processed.
    """

    return (
        path.is_file()
        and path.suffix.lower() in TEXT_EXTENSIONS
    )


def read_text(path: Path) -> str:
    """
    Read a text file using UTF-8, falling back safely if needed.
    """

    try:
        return path.read_text(
            encoding="utf-8"
        )

    except UnicodeDecodeError:
        return path.read_text(
            encoding="utf-8",
            errors="replace",
        )


def make_backup(path: Path) -> None:
    """
    Create a backup of the original example.
    """

    relative = path.relative_to(
        PROJECT_ROOT
    )

    backup_path = (
        BACKUP_ROOT / relative
    )

    backup_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    shutil.copy2(
        path,
        backup_path,
    )


def split_line_aware(
    text: str,
    max_chars: int,
):
    """
    Split text into chunks without unnecessarily cutting
    through individual log lines.
    """

    if len(text) <= max_chars:
        return [text]

    lines = text.splitlines(
        keepends=True
    )

    chunks = []

    current = []

    current_length = 0

    for line in lines:

        # If one individual line is larger than the limit,
        # split that line safely.
        if len(line) > max_chars:

            if current:

                chunks.append(
                    "".join(current)
                )

                current = []
                current_length = 0

            for start in range(
                0,
                len(line),
                max_chars,
            ):

                chunks.append(
                    line[
                        start:start + max_chars
                    ]
                )

            continue

        if (
            current
            and current_length + len(line)
            > max_chars
        ):

            chunks.append(
                "".join(current)
            )

            current = []
            current_length = 0

        current.append(
            line
        )

        current_length += len(
            line
        )

    if current:

        chunks.append(
            "".join(current)
        )

    return chunks


def process_file(path: Path):
    """
    Process one example file.

    Files already within the safe size are left unchanged.

    Files larger than the limit are converted into multiple
    smaller example files so that test coverage is preserved.
    """

    text = read_text(
        path
    )

    original_length = len(
        text
    )

    if original_length <= MAX_EXAMPLE_CHARACTERS:

        return {
            "status": "OK",
            "path": path,
            "original": original_length,
            "created": 1,
        }

    # --------------------------------------------------------
    # Backup original.
    # --------------------------------------------------------

    make_backup(
        path
    )

    # --------------------------------------------------------
    # Split original into safe examples.
    # --------------------------------------------------------

    chunks = split_line_aware(
        text,
        MAX_EXAMPLE_CHARACTERS,
    )

    stem = path.stem

    suffix = path.suffix

    # --------------------------------------------------------
    # Keep the first chunk in the original filename.
    # --------------------------------------------------------

    first_chunk = chunks[0]

    path.write_text(
        first_chunk,
        encoding="utf-8",
    )

    # --------------------------------------------------------
    # Create remaining chunks as separate examples.
    # --------------------------------------------------------

    created_files = 1

    for index, chunk in enumerate(
        chunks[1:],
        start=2,
    ):

        new_path = (
            path.parent
            / f"{stem}_part_{index}{suffix}"
        )

        # Avoid overwriting an unrelated existing file.
        counter = 1

        while new_path.exists():

            new_path = (
                path.parent
                / (
                    f"{stem}_part_{index}"
                    f"_{counter}{suffix}"
                )
            )

            counter += 1

        new_path.write_text(
            chunk,
            encoding="utf-8",
        )

        created_files += 1

    return {
        "status": "SPLIT",
        "path": path,
        "original": original_length,
        "created": created_files,
    }


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print("=" * 70)
    print("GROQ FREE-TIER EXAMPLE PREPARATION")
    print("=" * 70)
    print()
    print(
        f"Maximum example size: "
        f"{MAX_EXAMPLE_CHARACTERS:,} characters"
    )
    print(
        "Groq model: openai/gpt-oss-120b"
    )
    print(
        "Target TPM: 8,000"
    )
    print()

    total_files = 0
    changed_files = 0
    created_parts = 0

    for folder in FOLDERS:

        print(
            f"\nFolder: {folder}"
        )

        if not folder.exists():

            print(
                "  WARNING: folder does not exist."
            )

            continue

        files = [
            path
            for path in folder.rglob("*")
            if is_text_file(path)
        ]

        if not files:

            print(
                "  No supported text files found."
            )

            continue

        for path in sorted(
            files
        ):

            # Do not process files already generated
            # by this script.
            if "_part_" in path.stem:
                continue

            total_files += 1

            result = process_file(
                path
            )

            if result["status"] == "OK":

                print(
                    f"  OK     "
                    f"{path.name:<45} "
                    f"{result['original']:,} chars"
                )

            else:

                changed_files += 1

                created_parts += (
                    result["created"]
                )

                print(
                    f"  SPLIT  "
                    f"{path.name:<45} "
                    f"{result['original']:,} chars "
                    f"-> "
                    f"{result['created']} examples"
                )

    print()
    print("=" * 70)
    print("DONE")
    print("=" * 70)
    print()
    print(
        f"Files checked:       {total_files}"
    )
    print(
        f"Files modified:      {changed_files}"
    )
    print(
        f"Example files made:  {created_parts}"
    )
    print()
    print(
        f"Backups are stored in:"
    )
    print(
        f"  {BACKUP_ROOT}"
    )
    print()
    print(
        "All generated example files are "
        f"{MAX_EXAMPLE_CHARACTERS:,} characters or smaller."
    )
    print()


if __name__ == "__main__":
    main()
