"""CSV ingestion. Flattens rows to text for entity extraction."""
import csv
from pathlib import Path


def extract_text(path: Path) -> str:
    rows: list[str] = []
    with path.open(encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.reader(f)
        headers: list[str] = []
        for i, row in enumerate(reader):
            if i == 0:
                headers = [h.strip() for h in row]
                continue
            cells = []
            for j, cell in enumerate(row):
                header = headers[j] if j < len(headers) else f"col{j}"
                cells.append(f"{header}: {cell}")
            rows.append(" | ".join(cells))
    return "\n".join(rows)
