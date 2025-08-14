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

└─$ python3 sitesifter.py -h
usage: sitesifter.py [-h] -u URL -d DEST [-w WORDLIST] [-e EXT_FILE] [-c CONCURRENCY] [--timeout TIMEOUT] [--dir-depth DIR_DEPTH] [--crawl-depth CRAWL_DEPTH]

Recursive dir fuzzer + live downloader (HTML crawl + word×ext brute).

options:
  -h, --help            show this help message and exit
  -u, --url URL         Base host/URL (schema optional, e.g., example.com). (default: None)
  -d, --dest DEST       Directory to save downloaded files. (default: None)
  -w, --wordlist WORDLIST
                        Wordlist file (one path per line). If omitted, ./wordlist.txt is used. (default: None)
  -e, --ext-file EXT_FILE
                        Extensions file (one per line, without a dot). If omitted, ./extensions.txt is used. (default: None)
  -c, --concurrency CONCURRENCY
                        Number of threads. (default: 16)
  --timeout TIMEOUT     HTTP timeout in seconds. (default: 12)
  --dir-depth DIR_DEPTH
                        Depth for recursive directory fuzzing via wordlist. (default: 1)
  --crawl-depth CRAWL_DEPTH
                        HTML crawl depth (0 = only dir page; 1 = one level). (default: 1)
```
<img width="1285" height="333" alt="image" src="https://github.com/user-attachments/assets/a1a439f8-cf37-4bb7-8c49-69e03764f98d" />


Usage (full)
```
python3 sitesifter.py -u http://example.com -d /home/kali/
```
<img width="1904" height="143" alt="image" src="https://github.com/user-attachments/assets/72d7fcc7-ac3f-405b-af9e-ab4488b39752" />
