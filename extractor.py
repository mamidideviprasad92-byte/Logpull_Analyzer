import zipfile
import py7zr
import tarfile
import tempfile
import os
from typing import List


def extract_archive(file_bytes, filename: str) -> str:
    """
    Extracts ZIP, 7z, TGZ, TAR.GZ, TAR archives from uploaded bytes.
    Returns the path to the extraction directory.
    """
    temp_dir = tempfile.mkdtemp(prefix="logpull_")

    # Save uploaded bytes to a temporary file
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(file_bytes)
        tmp.flush()
        temp_path = tmp.name

    # ZIP
    if filename.lower().endswith(".zip"):
        with zipfile.ZipFile(temp_path, "r") as zf:
            zf.extractall(temp_dir)

    # 7Z
    elif filename.lower().endswith(".7z"):
        with py7zr.SevenZipFile(temp_path, mode="r") as z:
            z.extractall(path=temp_dir)

    # TAR / TGZ / TAR.GZ
    elif filename.lower().endswith((".tgz", ".tar.gz", ".tar")):
        with tarfile.open(temp_path, "r:*") as tar:
            tar.extractall(path=temp_dir)

    else:
        raise ValueError("Unsupported archive format. Use .zip, .7z, .tgz, .tar.gz, or .tar")

    return temp_dir


def list_log_files(root_dir: str) -> List[str]:
    """
    Recursively list all files that look like logs.
    Includes:
      - .log
      - .txt
      - files with NO extension (e.g., messages_0_20250924)
      - syslog-style files
    """
    log_files = []
    for dirpath, _, filenames in os.walk(root_dir):
        for f in filenames:
            lower = f.lower()
            full_path = os.path.join(dirpath, f)

            # Accept .log and .txt
            if lower.endswith((".log", ".txt")):
                log_files.append(full_path)
                continue

            # Accept files with NO extension
            if "." not in f:
                log_files.append(full_path)
                continue

            # Accept known log names
            if any(x in lower for x in ["messages", "syslog", "boot", "kernel", "dmesg"]):
                log_files.append(full_path)
                continue

    return log_files