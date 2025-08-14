# SiteSifter

Recursive **directory fuzzer + file downloader** with progress bars.  
It fuzzes directories using a wordlist (recursively), crawls discovered pages,
and downloads files that match extensions from your list.

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
```
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```
Help:
```
python3 sitesifter.py -h
```
<img width="1300" height="338" alt="image" src="https://github.com/user-attachments/assets/45707957-a76f-44c2-bf09-c7da74c54e1c" />

Usage (full)
```
python3 sitesifter.py -u http://example.com -d /home/kali/
```
<img width="1904" height="143" alt="image" src="https://github.com/user-attachments/assets/72d7fcc7-ac3f-405b-af9e-ab4488b39752" />
