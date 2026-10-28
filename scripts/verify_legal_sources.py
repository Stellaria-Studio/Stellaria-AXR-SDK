# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
"""Verify owner-supplied legal bytes and readable transcriptions, not signatures."""
from pathlib import Path
import hashlib
import json
import tomllib
import xml.etree.ElementTree as ET
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]
NS = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}

def verify():
    manifest = json.loads((ROOT / "legal/source-manifest.json").read_text())
    assert len(manifest["documents"]) == 2
    for record in manifest["documents"]:
        source = ROOT / record["source_file"]
        assert hashlib.sha256(source.read_bytes()).hexdigest() == record["source_sha256"]
        with ZipFile(source) as archive:
            document = ET.fromstring(archive.read("word/document.xml"))
            assert not document.findall(".//w:ins", NS) and not document.findall(".//w:del", NS)
            paragraphs = ["".join(t.text or "" for t in p.findall(".//w:t", NS))
                          for p in document.findall(".//w:p", NS)]
            paragraphs = [p for p in paragraphs if p]
        assert len(paragraphs) == record["paragraphs"]
        assert hashlib.sha256("\n".join(paragraphs).encode()).hexdigest() == record["paragraph_text_sha256"]
        readable = (ROOT / record["readable_file"]).read_text()
        transcribed = [line.lstrip("# ") if line.startswith("#") else line
                       for line in readable.splitlines() if line]
        assert transcribed == paragraphs
    metadata = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert metadata["project"]["license"] == "AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0"
    print("Two legal originals and their complete transcriptions verified; this is not a signature check.")

if __name__ == "__main__":
    verify()
