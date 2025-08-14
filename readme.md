# SiteSifter

Recursive **directory fuzzer + file downloader** with progress bars.  
It fuzzes directories using a wordlist (recursively), crawls discovered pages,
and downloads files that match extensions from your list — respecting `robots.txt`.

> **Use responsibly.** Only scan targets you own or have explicit permission to test.

---

## Features

- 🔁 **Recursive dir fuzzing (BFS)** across all discovered dirs (`--dir-depth`).
- 🔎 **HTML crawl** from each discovered directory (`--crawl-depth`).
- 🎯 **Extension filter from file** (`extensions.txt`)
- ⏱️ **Progress bars** for probing, crawling, and downloading (`tqdm`).
- ⚡ **Concurrency control** with `-c/--concurrency`.
- 🗂️ Saves with host-based path structure inside your destination folder.

---

## Requirements

- Python **3.8+**
- See [`requirements.txt`](requirements.txt)

Install:
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
