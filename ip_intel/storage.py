from __future__ import annotations

from pathlib import Path
from typing import Optional

import pandas as pd


DEFAULT_COLUMNS = [
    "saved_at",
    "ip",
    "source",
    "ip_type",
    "risk_score",
    "risk_flags",
    "country",
    "region",
    "city",
    "org",
    "asn",
    "hostname",
    "tag",
    "notes",
    "error",
]


class InvestigationStorage:
    def __init__(self, file_path: str = "data/investigations.csv") -> None:
        self.file_path = Path(file_path)
        self.file_path.parent.mkdir(parents=True, exist_ok=True)

        if not self.file_path.exists():
            pd.DataFrame(columns=DEFAULT_COLUMNS).to_csv(self.file_path, index=False)

    def load(self) -> pd.DataFrame:
        if not self.file_path.exists():
            return pd.DataFrame(columns=DEFAULT_COLUMNS)

        try:
            df = pd.read_csv(self.file_path)
        except Exception:
            df = pd.DataFrame(columns=DEFAULT_COLUMNS)

        for col in DEFAULT_COLUMNS:
            if col not in df.columns:
                df[col] = ""

        return df[DEFAULT_COLUMNS]

    def save_record(self, record: dict) -> None:
        df = self.load()
        new_df = pd.DataFrame([record])

        for col in DEFAULT_COLUMNS:
            if col not in new_df.columns:
                new_df[col] = ""

        new_df = new_df[DEFAULT_COLUMNS]
        df = pd.concat([df, new_df], ignore_index=True)
        df.to_csv(self.file_path, index=False)

    def overwrite(self, df: pd.DataFrame) -> None:
        for col in DEFAULT_COLUMNS:
            if col not in df.columns:
                df[col] = ""
        df = df[DEFAULT_COLUMNS]
        df.to_csv(self.file_path, index=False)

    def filter_by_ip(self, ip: str) -> pd.DataFrame:
        df = self.load()
        if "ip" not in df.columns:
            return pd.DataFrame(columns=DEFAULT_COLUMNS)
        return df[df["ip"].astype(str) == str(ip)].copy()

    def latest_record_for_ip(self, ip: str) -> Optional[dict]:
        filtered = self.filter_by_ip(ip)
        if filtered.empty:
            return None
        return filtered.iloc[-1].to_dict()
    
    