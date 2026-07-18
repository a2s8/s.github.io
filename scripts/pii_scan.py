#!/usr/bin/env python3
"""Fail a static-site build when likely PII or booking secrets are present."""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path


TEXT_SUFFIXES = {
    ".css",
    ".csv",
    ".htm",
    ".html",
    ".js",
    ".json",
    ".md",
    ".svg",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}

PATTERNS = {
    "email address": re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I),
    "US phone number": re.compile(
        r"(?<!\d)(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]\d{3}[-. ]\d{4}(?!\d)"
    ),
    "street address": re.compile(
        r"\b\d{2,6}\s+[A-Z0-9 .'-]+\s(?:STREET|ST|AVENUE|AVE|ROAD|RD|DRIVE|DR|"
        r"LANE|LN|COURT|CT|WAY|BOULEVARD|BLVD)\b",
        re.I,
    ),
    "US ZIP code": re.compile(r"\b\d{5}(?:-\d{4})?\b"),
    "payment field": re.compile(
        r"\b(?:CARD NUMBER|CVV|CVC|PAYMENT METHOD|DEPOSIT PAID|BALANCE DUE)\b", re.I
    ),
    "reservation detail": re.compile(
        r"\b(?:CONFIRMATION|RESERVATION)\s*(?:NUMBER|NO\.?|#|:)\s*[A-Z0-9-]{5,}\b",
        re.I,
    ),
    "precise coordinates": re.compile(
        r"(?<!\d)-?\d{1,3}\.\d{5,}\s*[,/]\s*-?\d{1,3}\.\d{5,}(?!\d)"
    ),
}


def iter_files(root: Path):
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        if any(part in {".git", "node_modules", "dist", "build"} for part in path.parts):
            continue
        yield path


def load_private_terms() -> list[str]:
    raw = os.environ.get("PII_PRIVATE_TERMS", "")
    return [
        term.strip().casefold()
        for term in re.split(r"[\n|,]+", raw)
        if term.strip()
    ]


def scan(root: Path) -> list[tuple[Path, int, str]]:
    findings: list[tuple[Path, int, str]] = []
    private_terms = load_private_terms()

    for path in iter_files(root):
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError:
            continue

        for line_number, line in enumerate(lines, start=1):
            for label, pattern in PATTERNS.items():
                if pattern.search(line):
                    findings.append((path, line_number, label))
            folded = line.casefold()
            if any(term in folded for term in private_terms):
                findings.append((path, line_number, "private denylist term"))

    return findings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default=".")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    findings = scan(root)

    if findings:
        print("PII scan failed. Matching values are intentionally not printed.")
        for path, line_number, label in findings:
            print(f"{path.relative_to(root)}:{line_number}: {label}")
        return 1

    print("PII scan passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
