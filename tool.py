#!/usr/bin/env python3
"""Offline, bounded contract audit. Python 3.12 standard library only."""
import argparse
import json
import math
import sys
from pathlib import Path

MAX_BYTES = 2 * 1024 * 1024
MAX_ITEMS = 10000
class BadInput(ValueError):
    pass
class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise BadInput("invalid command arguments")

def require(condition, message):
    if not condition:
        raise BadInput(message)

def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, "duplicate JSON object key")
        result[key] = value
    return result

def reject_constant(value):
    raise BadInput("nonfinite JSON number")

def read_text(path):
    require(Path(path).is_file(), "input must be a regular file")
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    require(len(raw) <= MAX_BYTES, "input exceeds 2 MiB limit")
    return raw.decode("utf-8-sig")

def finite_float(value):
    parsed = float(value)
    require(math.isfinite(parsed), "nonfinite JSON number")
    return parsed

def load_json(path):
    return json.loads(read_text(path), object_pairs_hook=pairs, parse_constant=reject_constant, parse_float=finite_float)

def report(findings, **summary):
    return {"schema_version": 1, "tool": TOOL, "status": "findings" if findings else "pass", "summary": summary, "findings": findings}

def finding(code, **where):
    return {"code": code, **where}

def run(build_parser, action):
    try:
        parser = Parser(description=__doc__)
        build_parser(parser)
        result = action(parser.parse_args())
        status = 1 if result["status"] == "findings" else 0
    except (ValueError, OSError, UnicodeError, RecursionError, OverflowError) as exc:
        message = str(exc) if isinstance(exc, BadInput) else "unreadable or malformed input"
        result = {"schema_version": 1, "tool": TOOL, "status": "error", "error": message}
        status = 2
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, allow_nan=False))
    return status

import re
TOOL = "unified-diff-preflight"
HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?:.*)$")

def unsafe_path(path):
    if path == "/dev/null":
        return False
    if path.startswith(("a/", "b/")):
        path = path[2:]
    return (not path or path.startswith(("/", '"')) or "\\" in path or re.match(r"^[A-Za-z]:", path) is not None or any(part in ("", ".", "..") for part in path.split("/")) or any(ord(c) < 32 or ord(c) == 127 for c in path))

def audit(text):
    require(isinstance(text, str) and len(text.encode("utf-8")) <= MAX_BYTES, "expected diff text up to 2 MiB")
    require("\x00" not in text, "NUL bytes are not supported")
    # split only LF: other Unicode separators can occur in legitimate source lines.
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    require(len(lines) <= 100000, "line budget exceeded")
    lines = [line[:-1] if line.endswith("\r") else line for line in lines]
    findings, files, hunks, i = [], 0, 0, 0
    current, previous, seen_paths, hunk_seen = None, None, set(), False
    pending_git_line = None
    def finish_file():
        if current is not None and not hunk_seen:
            findings.append(finding("file_without_hunks", file_index=files-1))
    while i < len(lines):
        line = lines[i]
        if line.startswith("diff --git "):
            # A new Git section must never inherit the preceding text file's
            # header or range state. Finish that section exactly once.
            finish_file()
            if pending_git_line is not None:
                findings.append(finding("file_without_text_headers", line=pending_git_line))
            current, previous, hunk_seen = None, None, False
            pending_git_line = i + 1
            i += 1
            continue
        if line.startswith("--- "):
            finish_file()
            require(i+1 < len(lines) and lines[i+1].startswith("+++ "), "old file header requires following new file header")
            old, new = line[4:].split("\t", 1)[0], lines[i+1][4:].split("\t", 1)[0]
            require(not (old == new == "/dev/null"), "both paths cannot be /dev/null")
            files += 1; require(files <= 1000, "file budget exceeded")
            current = (old, new); previous = None; hunk_seen = False
            pending_git_line = None
            if unsafe_path(old) or unsafe_path(new):
                findings.append(finding("unsafe_or_unsupported_path", file_index=files-1, line=i+1))
            key = new if new != "/dev/null" else old
            if key in seen_paths:
                findings.append(finding("repeated_file_section", file_index=files-1))
            seen_paths.add(key); i += 2; continue
        if line.startswith("@@"):
            require(current is not None, "hunk outside file section")
            match = HUNK.fullmatch(line); require(match is not None, "malformed or unsupported combined hunk header")
            values = match.groups()
            require(all(v is None or len(v) <= 12 for v in values), "hunk position too large")
            old_start, old_count, new_start, new_count = int(values[0]), int(values[1] or 1), int(values[2]), int(values[3] or 1)
            require(max(old_start, old_count, new_start, new_count) <= 10**9, "hunk position exceeds limit")
            hunks += 1; require(hunks <= 10000, "hunk budget exceeded"); hunk_seen = True
            if (old_count and old_start == 0) or (new_count and new_start == 0):
                findings.append(finding("invalid_nonempty_range", hunk_index=hunks-1, line=i+1))
            if current[0] == "/dev/null" and (old_start or old_count):
                findings.append(finding("creation_old_range_not_empty", hunk_index=hunks-1))
            if current[1] == "/dev/null" and (new_start or new_count):
                findings.append(finding("deletion_new_range_not_empty", hunk_index=hunks-1))
            # Convert to zero-based boundaries, including empty ranges after a line.
            old_begin = old_start-1 if old_count else old_start
            new_begin = new_start-1 if new_count else new_start
            if previous is not None:
                po, pn = previous
                if old_begin < po or new_begin < pn:
                    findings.append(finding("overlapping_or_out_of_order_hunks", hunk_index=hunks-1))
                elif old_begin-po != new_begin-pn:
                    findings.append(finding("inconsistent_hunk_gap", hunk_index=hunks-1))
            elif old_begin != new_begin:
                findings.append(finding("inconsistent_initial_position", hunk_index=hunks-1))
            previous = (old_begin+old_count, new_begin+new_count)
            observed_old = observed_new = 0; i += 1; body = False; last_was_marker = False
            while i < len(lines):
                content = lines[i]
                if content.startswith("@@") or content.startswith("diff --git "):
                    break
                if content.startswith("--- ") and i+1 < len(lines) and lines[i+1].startswith("+++ "):
                    # Once declared ranges are consumed this is the next file header.
                    if observed_old >= old_count and observed_new >= new_count:
                        break
                if content == "\\ No newline at end of file":
                    require(body and not last_was_marker, "misplaced no-newline marker")
                    last_was_marker = True; i += 1; continue
                if not content or content[0] not in " +-":
                    break
                prefix = content[0]; body = True; last_was_marker = False
                observed_old += prefix in " -"; observed_new += prefix in " +"; i += 1
            if (observed_old, observed_new) != (old_count, new_count):
                findings.append(finding("hunk_count_mismatch", hunk_index=hunks-1, declared_old=old_count, observed_old=observed_old, declared_new=new_count, observed_new=observed_new))
            if old_count == new_count == 0:
                findings.append(finding("empty_hunk", hunk_index=hunks-1))
            continue
        if line.startswith(("GIT binary patch", "Binary files ")):
            findings.append(finding("binary_patch_unsupported", line=i+1)); i += 1
            pending_git_line = None  # Explicitly classified non-text section.
            # Remaining binary payload is never interpreted as text hunks.
            while i < len(lines) and not lines[i].startswith(("diff --git ", "--- ")):
                i += 1
            continue
        if line.startswith(("index ", "new file mode ", "deleted file mode ", "old mode ", "new mode ", "similarity index ", "dissimilarity index ", "rename from ", "rename to ", "copy from ", "copy to ")):
            if line.startswith(("old mode ", "new mode ", "rename ", "copy ")):
                findings.append(finding("metadata_operation_not_validated", line=i+1))
            i += 1; continue
        if line == "":
            i += 1; continue
        raise BadInput("unexpected line outside supported diff structure")
    finish_file()
    if pending_git_line is not None:
        findings.append(finding("file_without_text_headers", line=pending_git_line))
    if not files and not findings:
        findings.append(finding("no_file_sections"))
    return report(findings, files=files, hunks=hunks, lines=len(lines))

def configure(parser):
    parser.add_argument("input", help="local conventional unified diff")
if __name__ == "__main__":
    sys.exit(run(configure, lambda args: audit(read_text(args.input))))
