#!/usr/bin/env python3
"""
Download and prepare CICIDS2017 and CSE-CIC-IDS2018 datasets.

Datasets:
- CICIDS2017: https://www.unb.ca/cic/datasets/ids-2017.html
- CSE-CIC-IDS2018: https://www.unb.ca/cic/datasets/ids-2018.html

Usage:
    python download_datasets.py --dataset cicids2017
    python download_datasets.py --dataset all
"""

import argparse
import os
from pathlib import Path
import urllib.request
import zipfile
from tqdm import tqdm

# Dataset URLs (AWS mirrors)
DATASETS = {
    "cicids2017": {
        "url": "https://iscxdownloads.cs.unb.ca/iscxdownloads/CIC-IDS-2017/MachineLearningCSV.zip",
        "description": "CICIDS2017 - 2.8M flow records, 80+ features",
        "size_mb": 350,
    },
    # CSE-CIC-IDS2018 requires AWS CLI due to size
    "cse-cic-ids2018": {
        "url": "aws",  # Requires: aws s3 sync --no-sign-request s3://cse-cic-ids2018/
        "description": "CSE-CIC-IDS2018 - 16M flow records (requires AWS CLI)",
        "size_mb": 8000,
    },
}

DATA_DIR = Path(__file__).parent / "raw"


class DownloadProgressBar(tqdm):
    """Progress bar for urllib downloads."""
    
    def update_to(self, b=1, bsize=1, tsize=None):
        if tsize is not None:
            self.total = tsize
        self.update(b * bsize - self.n)


def download_file(url: str, output_path: Path) -> None:
    """Download file with progress bar."""
    with DownloadProgressBar(unit='B', unit_scale=True, miniters=1, desc=output_path.name) as t:
        urllib.request.urlretrieve(url, filename=output_path, reporthook=t.update_to)


def download_cicids2017() -> None:
    """Download and extract CICIDS2017 dataset."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    
    zip_path = DATA_DIR / "cicids2017.zip"
    extract_dir = DATA_DIR / "cicids2017"
    
    if extract_dir.exists():
        print(f"[✓] CICIDS2017 already exists at {extract_dir}")
        return
    
    print(f"[↓] Downloading CICIDS2017 (~350MB)...")
    download_file(DATASETS["cicids2017"]["url"], zip_path)
    
    print(f"[⚙] Extracting to {extract_dir}...")
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(extract_dir)
    
    # Clean up zip
    zip_path.unlink()
    print(f"[✓] CICIDS2017 ready at {extract_dir}")


def download_cse_cic_ids2018() -> None:
    """Instructions for CSE-CIC-IDS2018 (requires AWS CLI)."""
    print("[!] CSE-CIC-IDS2018 is ~8GB and requires AWS CLI.")
    print("    Run the following command:")
    print()
    print("    aws s3 sync --no-sign-request \\")
    print("        s3://cse-cic-ids2018/Processed\\ Traffic\\ Data\\ for\\ ML\\ Algorithms/ \\")
    print(f"        {DATA_DIR / 'cse-cic-ids2018'}/")
    print()


def main():
    parser = argparse.ArgumentParser(description="Download IDS datasets")
    parser.add_argument(
        "--dataset",
        choices=["cicids2017", "cse-cic-ids2018", "all"],
        default="cicids2017",
        help="Dataset to download",
    )
    args = parser.parse_args()
    
    if args.dataset in ["cicids2017", "all"]:
        download_cicids2017()
    
    if args.dataset in ["cse-cic-ids2018", "all"]:
        download_cse_cic_ids2018()


if __name__ == "__main__":
    main()
