"""
magika_exec_scanner.py
=====================
Pre-execution file security scanner for OpenClaw exec commands.

Usage:
    python magika_exec_scanner.py "python script.py --arg1"
    python magika_exec_scanner.py "node index.js"
    python magika_exec_scanner.py "powershell script.ps1"

Returns:
    exitcode 0  = ALLOW  (safe to execute)
    exitcode 1  = WARN   (questionable, manual confirm needed)
    exitcode 2  = BLOCK  (dangerous, do not execute)
    exitcode 3  = ERROR  (scan failed)
"""

import sys
import os
from typing import Optional

try:
    from magika import Magika
    _MAGIKA_AVAILABLE = True
except ImportError:
    _MAGIKA_AVAILABLE = False


# Configuration

SCRIPT_EXTENSIONS = {
    ".py": "python", ".js": "javascript", ".mjs": "javascript",
    ".ts": "javascript", ".ps1": "powershell", ".psm1": "powershell",
    ".sh": "shell", ".bash": "shell", ".bat": "batch",
    ".cmd": "batch", ".rb": "ruby", ".php": "php",
    ".pl": "perl", ".lua": "lua", ".vbs": "vbscript",
}

DANGEROUS_TYPES = {
    "executable", "msi", "elf", "PE", "Mach-O", "DEX",
    "compiled", "object", "library", "binary", "PE32", "PE32+",
    "office", "docx", "xlsx", "pdf", "archive", "zip", "rar",
}

ALLOWED_AS_SCRIPT = {
    "python", "javascript", "shell", "batch", "powershell",
    "ruby", "php", "perl", "lua", "vbscript", "ewin",
    "markdown", "json", "yaml", "xml", "text", "plain-text",
    "html", "css", "sql",
}

TRANSFORMABLE = {
    "markdown": "python",
    "json": "javascript",
    "text": "shell",
}

ALLOW_ON_MIMETYPE = {
    "text/x-python", "text/x-java", "text/x-php",
    "application/x-sh", "text/x-shellscript",
    "application/x-powershell", "text/x-ruby",
    "text/plain", "text/markdown", "application/json",
    "text/x-yaml", "text/html", "text/css", "text/sql",
}


class ExecScanner:
    def __init__(self):
        self.magika = Magika() if _MAGIKA_AVAILABLE else None

    def extract_file_paths(self, command: str) -> list[str]:
        """Extract file paths with known script extensions from command."""
        tokens = command.split()
        paths = []
        for token in tokens:
            t = token.strip('"\'')
            ext = os.path.splitext(t)[1].lower()
            if ext in SCRIPT_EXTENSIONS:
                n = t.replace('/', os.sep)
                if os.path.exists(n):
                    absp = os.path.abspath(n)
                    if absp not in paths:
                        paths.append(absp)
        return paths

    def scan_file(self, path: str) -> dict:
        """Scan a single file with Magika."""
        absp = os.path.abspath(path.replace('/', os.sep))
        if not os.path.exists(absp):
            return {"path": absp, "status": "not_found",
                    "predicted_label": "unknown", "mime_type": "unknown",
                    "allowed": True}
        if not _MAGIKA_AVAILABLE:
            return {"path": absp, "status": "magika_unavailable",
                    "predicted_label": "unknown", "mime_type": "unknown",
                    "allowed": True}
        try:
            r = self.magika.identify_path(absp)
            pred = r.prediction.output
            ext = os.path.splitext(absp)[1].lower()
            return {
                "path": absp,
                "file_name": os.path.basename(absp),
                "extension": ext,
                "expected_type": SCRIPT_EXTENSIONS.get(ext, "unknown"),
                "predicted_label": pred.label.lower(),
                "mime_type": pred.mime_type or "",
                "score": r.score,
                "is_text": pred.is_text,
                "status": "scanned",
            }
        except Exception as e:
            return {"path": absp, "status": "error",
                    "error": str(e), "allowed": True}

    def classify_threat(self, scan: dict) -> tuple[str, str]:
        """Determine execution strategy based on Magika scan result."""
        if scan["status"] in ("not_found", "error", "magika_unavailable"):
            return "ALLOW", f"skip_{scan['status']}"

        label = scan["predicted_label"]
        expected = scan["expected_type"]
        ext = scan["extension"]
        mime = scan["mime_type"]

        # CASE 1: Binary disguised as script extension -> BLOCK
        if ext in SCRIPT_EXTENSIONS:
            if label in DANGEROUS_TYPES:
                return "BLOCK", f"binary({label})_disguised_as_{ext[1:]}"
            if not scan.get("is_text", True):
                if label not in ALLOWED_AS_SCRIPT:
                    return "BLOCK", f"non_script_content({label})_masquerading_as_{ext[1:]}"

        # CASE 2: Verified script type matching extension -> ALLOW
        if label == expected or expected == "unknown":
            if label in ALLOWED_AS_SCRIPT or mime in ALLOW_ON_MIMETYPE:
                return "ALLOW", f"verified_{label}_script"

        # CASE 3: Extension/content mismatch -> WARN or TRANSFORM
        if ext in SCRIPT_EXTENSIONS and label not in ALLOWED_AS_SCRIPT:
            if label in TRANSFORMABLE:
                return "TRANSFORM", f"content({label})_vs_ext({ext})_transformable"
            return "WARN", f"mismatch_expected_{expected}_got_{label}"

        # CASE 4: Script content in non-standard file -> TRANSFORM
        if label in ALLOWED_AS_SCRIPT and ext not in SCRIPT_EXTENSIONS:
            if ext in (".txt", ".text", ".log"):
                return "TRANSFORM", f"script_in_{ext}_consider_rename"
            return "WARN", f"script_content({label})_no_standard_ext"

        return "ALLOW", "no_issue"

    def scan_command(self, command: str) -> dict:
        """Main entry point. Returns full scan report."""
        paths = self.extract_file_paths(command)
        if not paths:
            return {"command": command, "files": [], "decision": "ALLOW",
                    "reason": "no_script_files_found", "exit_code": 0}

        results = []
        decisions = []
        for p in paths:
            scan = self.scan_file(p)
            decision, reason = self.classify_threat(scan)
            scan["decision"] = decision
            scan["reason"] = reason
            results.append(scan)
            decisions.append(decision)

        # Aggregate
        if "BLOCK" in decisions:
            decision, exit_code = "BLOCK", 2
        elif "WARN" in decisions:
            decision, exit_code = "WARN", 1
        elif "TRANSFORM" in decisions:
            decision, exit_code = "TRANSFORM", 0
        else:
            decision, exit_code = "ALLOW", 0

        reason = "; ".join(r["reason"] for r in results)
        return {"command": command, "files": results, "decision": decision,
                "reason": reason, "exit_code": exit_code}


def main():
    if len(sys.argv) < 2:
        print("Usage: python magika_exec_scanner.py <command>")
        sys.exit(3)

    command = " ".join(sys.argv[1:])
    scanner = ExecScanner()
    result = scanner.scan_command(command)

    # ASCII-safe output (CP950 compatible)
    print("")
    print("[Magika Pre-Execution Scan]")
    print("=" * 50)
    print(f"Command: {result['command']}")
    print(f"Files:   {len(result['files'])}")

    for f in result["files"]:
        print(f"")
        print(f"  {f.get('file_name', f['path'])}")
        print(f"    Extension:  {f.get('extension', 'N/A')}")
        print(f"    Predicted: {f.get('predicted_label', 'N/A')} | {f.get('mime_type', 'N/A')}")
        if f.get('score'):
            print(f"    Score:     {f['score']:.4f}")
        print(f"    -> {f.get('decision', 'UNKNOWN')}: {f.get('reason', 'N/A')}")

    print(f"")
    print("=" * 50)
    print(f"[{result['decision']}] {result['reason']}")
    print(f"Exit Code: {result['exit_code']}  ({'SAFE' if result['exit_code']==0 else 'REVIEW' if result['exit_code']==1 else 'BLOCK' if result['exit_code']==2 else 'ERROR'})")
    print("")

    sys.exit(result["exit_code"])


if __name__ == "__main__":
    main()
