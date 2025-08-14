from __future__ import annotations

import argparse
import concurrent.futures as cf
import itertools
import queue
import random
import re
import sys
import time
from threading import Lock, Thread
from collections import deque
from pathlib import Path
from urllib.parse import urljoin, urlparse, urldefrag

import requests
from bs4 import BeautifulSoup
from tqdm import tqdm
from urllib.robotparser import RobotFileParser

UA = "SiteSifter/2.0 (+https://example.local)"
OK = {200, 301, 302, 303, 307, 308, 401, 403}
CHUNK = 64 * 1024

TQDM_KW = dict(dynamic_ncols=True, mininterval=0.1, miniters=1, leave=False, file=sys.stdout)

MAX_FILE_PROBES = 200_000



def require_file(cli_value: str | None, fallback: str, purpose: str) -> Path:
    path = Path(cli_value) if cli_value else Path(fallback)
    if not path.exists():
        print(f"[!] Missing {purpose} file: '{path}'. Provide it via flag or create '{fallback}' in CWD.", file=sys.stderr)
        sys.exit(2)
    return path


def read_lines(path: Path) -> list[str]:
    out: list[str] = []
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = raw.strip()
        if s and not s.startswith("#"):
            out.append(s)
    return out


def load_exts(path: Path) -> set[str]:
    raw = {ln.lower().lstrip(".") for ln in read_lines(path)}
    return {e for e in raw if re.fullmatch(r"[a-z0-9]{1,10}", e)}


def normalize_base(u: str) -> str:
    u = u.strip()
    if not re.match(r"^https?://", u, re.I):
        u = "https://" + u
    return u.rstrip("/")


def robots_for(base: str) -> RobotFileParser | None:
    p = urlparse(base)
    rp = RobotFileParser()
    try:
        rp.set_url(f"{p.scheme}://{p.netloc}/robots.txt")
        rp.read()
        return rp
    except Exception:
        return None


def allowed(rp: RobotFileParser | None, url: str) -> bool:
    try:
        return True if rp is None else rp.can_fetch(UA, url)
    except Exception:
        return True


def head_or_get(session: requests.Session, url: str, timeout: int) -> requests.Response | None:
    try:
        r = session.head(url, allow_redirects=True, timeout=timeout)
    except Exception:
        r = None
    if (r is None) or (r.status_code not in OK):
        try:
            r = session.get(url, stream=True, allow_redirects=True, timeout=timeout)
        except Exception:
            return None
    return r


def is_dirlike(resp: requests.Response, final_url: str) -> bool:
    if final_url.endswith("/"):
        return True
    ctype = (resp.headers.get("Content-Type") or "").lower()
    if "text/html" in ctype:
        name = Path(urlparse(final_url).path).name
        return "." not in name
    return False



def _soft404_signature(resp: requests.Response) -> tuple[int, bool, int, int]:
    status = resp.status_code
    ctype = (resp.headers.get("Content-Type") or "").lower()
    is_html = "text/html" in ctype or "text/plain" in ctype
    try:
        body = resp.text if is_html else ""
    except Exception:
        body = ""
    length_bucket = len(body) // 128
    txt = body.lower()
    kw_flag = 1 if any(k in txt for k in ("404", "not found", "page not found", "nie znaleziono", "strona nie", "страница не найдена", "не найдено")) else 0
    return (status, is_html, length_bucket, kw_flag)


def build_soft404_detector(session: requests.Session, base: str, timeout: int):
    base_slash = base.rstrip("/") + "/"
    samples = []
    for _ in range(3):
        token = f"__no_such_{int(time.time())}_{random.randint(10**6, 10**7)}__"
        for suf in (token, token + "/"):
            url = urljoin(base_slash, suf)
            try:
                r = session.get(url, allow_redirects=True, timeout=timeout)
                samples.append(_soft404_signature(r))
            except Exception:
                pass
    sigs = set(samples)

    def is_soft404(resp: requests.Response) -> bool:
        return _soft404_signature(resp) in sigs

    return is_soft404


def local_path(dest: Path, base_netloc: str, file_url: str) -> Path:
    rel = Path(urlparse(file_url).path.lstrip("/"))
    full = dest / base_netloc / rel
    full.parent.mkdir(parents=True, exist_ok=True)
    return full


def download_one(session: requests.Session, url: str, out_path: Path, timeout: int) -> tuple[str, bool, str]:
    """Download a single URL. Save whatever content the server returns (even HTML)."""
    try:
        if out_path.exists():
            return url, False, "exists"
        with session.get(url, stream=True, timeout=timeout) as r:
            if r.status_code != 200:
                return url, False, f"http {r.status_code}"
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with open(out_path, "wb") as fh:
                for chunk in r.iter_content(CHUNK):
                    if chunk:
                        fh.write(chunk)
        return url, True, "ok"
    except Exception as e:
        return url, False, str(e)


class LiveDownloader:
    """Threaded downloader with a dynamic tqdm total."""
    def __init__(self, session: requests.Session, dest: Path, base_netloc: str, timeout: int, workers: int):
        self.session = session
        self.dest = dest
        self.base_netloc = base_netloc
        self.timeout = timeout
        self.q: queue.Queue[str | None] = queue.Queue()
        self.pbar = tqdm(total=0, desc="Download", unit="file", **TQDM_KW)
        self.ok = 0
        self.skip = 0
        self.err = 0
        self.lock = Lock()
        self.workers: list[Thread] = []
        for _ in range(max(1, workers)):
            t = Thread(target=self._worker, daemon=True)
            t.start()
            self.workers.append(t)

    def enqueue(self, url: str):
        # Increase total dynamically
        with self.lock:
            self.pbar.total += 1
            self.pbar.refresh()
        self.q.put(url)

    def _worker(self):
        while True:
            url = self.q.get()
            if url is None:
                self.q.task_done()
                break
            outp = local_path(self.dest, self.base_netloc, url)
            u, good, msg = download_one(self.session, url, outp, self.timeout)
            with self.lock:
                self.pbar.update(1)
                if good:
                    self.ok += 1
                else:
                    self.skip += 1
                    tqdm.write(f"[-] SKIP  {u} ({msg})")
            self.q.task_done()

    def finish(self):
        self.q.join()
        for _ in self.workers:
            self.q.put(None)
        for t in self.workers:
            t.join()
        self.pbar.close()



def extract_links(html: str, base_url: str) -> list[str]:
    soup = BeautifulSoup(html, "html.parser")
    out: list[str] = []
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if href.startswith(("mailto:", "javascript:")):
            continue
        abs_url = urljoin(base_url, href)
        abs_url, _ = urldefrag(abs_url)
        out.append(abs_url)
    return out


def scan_dir_for_files(dir_url: str, session: requests.Session, exts: set[str], rp: RobotFileParser | None, timeout: int) -> list[str]:
    """Parse one directory page and return links to files with required extensions (same host)."""
    if not allowed(rp, dir_url):
        return []
    try:
        r = session.get(dir_url, timeout=timeout)
    except Exception:
        return []
    if r.status_code != 200:
        return []
    if "text/html" not in (r.headers.get("Content-Type") or "").lower():
        return []
    links = extract_links(r.text, r.url)
    host = urlparse(r.url).netloc
    hits: list[str] = []
    for link in links:
        if urlparse(link).netloc != host:
            continue
        path = urlparse(link).path.lower()
        if any(path.endswith("." + e) for e in exts):
            hits.append(link)
    return hits


def collect_files(start_dirs: set[str], session: requests.Session, exts: set[str], rp: RobotFileParser | None, timeout: int, depth: int) -> list[str]:
    """Crawl multiple levels of HTML pages starting from given directories."""
    seen_html: set[str] = set()
    files: list[str] = []
    level: list[str] = list(start_dirs)

    def visit(u: str) -> tuple[list[str], list[str]]:
        if not allowed(rp, u):
            return [], []
        try:
            r = session.get(u, timeout=timeout)
        except Exception:
            return [], []
        if r.status_code != 200:
            return [], []
        if "text/html" not in (r.headers.get("Content-Type") or "").lower():
            return [], []
        links = extract_links(r.text, r.url)
        next_pages: list[str] = []
        found: list[str] = []
        host = urlparse(r.url).netloc
        for link in links:
            if urlparse(link).netloc != host:
                continue
            path = urlparse(link).path.lower()
            if any(path.endswith("." + e) for e in exts):
                found.append(link)
            else:
                next_pages.append(link)
        return next_pages, found

    for d in range(depth + 1):
        with tqdm(total=len(level), desc=f"Crawl L{d}", unit="page", **TQDM_KW) as pbar:
            next_level = []
            for u in level:
                if u in seen_html:
                    pbar.update(1)
                    continue
                seen_html.add(u)
                nxt, found = visit(u)
                files.extend(found)
                if d < depth:
                    nxt = [x for x in nxt if "." not in Path(urlparse(x).path).name]
                    next_level.extend(nxt)
                pbar.update(1)
        level = next_level

    uniq: set[str] = set()
    out: list[str] = []
    for f in files:
        if f not in uniq:
            uniq.add(f)
            out.append(f)
    return out


def fuzz_files_from_words(dirs: set[str], words: list[str], exts: set[str], session: requests.Session, rp: RobotFileParser | None, timeout: int, concurrency: int, max_probes: int) -> list[str]:
    """Try <dir>/<word>.<ext> under each dir (capped)."""
    if not max_probes:
        return []
    dirs_list = list(dirs)
    words_norm = [w.strip().strip("/") for w in words if w.strip()]
    exts_list = list(exts)

    total_guess = len(dirs_list) * len(words_norm) * len(exts_list)
    total = min(total_guess, max_probes)

    def gen_candidates():
        count = 0
        for d in dirs_list:
            for w in words_norm:
                for e in exts_list:
                    yield urljoin(d, f"{w}.{e}")
                    count += 1
                    if count >= total:
                        return

    def probe(u: str) -> str | None:
        if not allowed(rp, u):
            return None
        r = head_or_get(session, u, timeout)
        if not r or r.status_code != 200:
            return None
        return r.url  # do not second-guess content-type

    found: list[str] = []
    with tqdm(total=total, desc="Fuzz files (word×ext)", unit="probe", **TQDM_KW) as pbar:
        with cf.ThreadPoolExecutor(max_workers=concurrency) as ex:
            it = itertools.islice(gen_candidates(), total)
            inflight: set[cf.Future] = set()
            for _ in range(min(concurrency, total)):
                try:
                    u = next(it)
                except StopIteration:
                    break
                inflight.add(ex.submit(probe, u))
            while inflight:
                done, inflight = cf.wait(inflight, return_when=cf.FIRST_COMPLETED)
                for fut in done:
                    res = fut.result()
                    pbar.update(1)
                    if res:
                        found.append(res)
                    try:
                        u = next(it)
                        inflight.add(ex.submit(probe, u))
                    except StopIteration:
                        pass

    uniq: set[str] = set()
    out: list[str] = []
    for u in found:
        if u not in uniq:
            uniq.add(u)
            out.append(u)
    return out


def fuzz_dirs_recursive(base: str, words: list[str], session: requests.Session, rp: RobotFileParser | None, timeout: int, concurrency: int, depth: int, is_soft404, exts: set[str], enqueue_file) -> set[str]:
    """
    Recursively fuzz directories using the wordlist (BFS).
    Print dirs as soon as found AND immediately enqueue files from the directory page.
    """
    base = base.rstrip("/") + "/"
    discovered: set[str] = {base}
    seen_parents: set[str] = set()
    q: deque[tuple[str, int]] = deque([(base, 0)])

    tqdm.write(f"[+] dir: {base}")
    # Immediate scan of root page
    for f in scan_dir_for_files(base, session, exts, rp, timeout):
        enqueue_file(f)

    def probe(u: str) -> tuple[str, str | None]:
        if not allowed(rp, u):
            return u, None
        r = head_or_get(session, u, timeout)
        if not r:
            return u, None
        if r.status_code in OK and is_dirlike(r, r.url):
            try:
                gr = session.get(r.url, allow_redirects=True, timeout=timeout)
            except Exception:
                return u, None
            if is_soft404(gr):
                return u, None
            return u, gr.url.rstrip("/") + "/"
        return u, None

    pbar = tqdm(total=0, desc="Fuzz dirs (recursive)", unit="probe", **TQDM_KW)
    try:
        while q:
            parent, level = q.popleft()
            if parent in seen_parents:
                continue
            seen_parents.add(parent)

            cand: set[str] = set()
            parent_slash = parent
            for w in words:
                w = w.strip().strip("/")
                if not w:
                    continue
                cand.add(urljoin(parent_slash, w))
                cand.add(urljoin(parent_slash, w + "/"))

            pbar.total += len(cand)
            pbar.set_postfix(level=level, dirs=len(discovered), queued=len(q) + len(cand))
            pbar.refresh()

            with cf.ThreadPoolExecutor(max_workers=concurrency) as ex:
                futs = [ex.submit(probe, u) for u in cand]
                for f in cf.as_completed(futs):
                    _orig, found = f.result()
                    pbar.update(1)
                    if found and found not in discovered:
                        discovered.add(found)
                        tqdm.write(f"[+] dir: {found}")
                        # immediate scan of that directory page and enqueue files
                        for file_url in scan_dir_for_files(found, session, exts, rp, timeout):
                            enqueue_file(file_url)
                        if level < depth:
                            q.append((found, level + 1))
    finally:
        pbar.close()

    return discovered



def main() -> None:
    parser = argparse.ArgumentParser(
        description="Recursive dir fuzzer + live downloader (HTML crawl + word×ext brute).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("-u", "--url", required=True, help="Base host/URL (schema optional, e.g., example.com).")
    parser.add_argument("-d", "--dest", required=True, help="Directory to save downloaded files.")
    parser.add_argument("-w", "--wordlist", help="Wordlist file (one path per line). If omitted, ./wordlist.txt is used.")
    parser.add_argument("-e", "--ext-file", help="Extensions file (one per line, without a dot). If omitted, ./extensions.txt is used.")
    parser.add_argument("-c", "--concurrency", type=int, default=16, help="Number of threads.")
    parser.add_argument("--timeout", type=int, default=12, help="HTTP timeout in seconds.")
    parser.add_argument("--dir-depth", type=int, default=1, help="Depth for recursive directory fuzzing via wordlist.")
    parser.add_argument("--crawl-depth", type=int, default=1, help="HTML crawl depth (0 = only dir page; 1 = one level).")
    parser.add_argument("--depth", type=int, dest="crawl_depth", help=argparse.SUPPRESS)

    args = parser.parse_args()

    base = normalize_base(args.url)
    dest = Path(args.dest).resolve()
    dest.mkdir(parents=True, exist_ok=True)

    wordlist_path = require_file(args.wordlist, "wordlist.txt", "wordlist")
    exts_path = require_file(args.ext_file, "extensions.txt", "extensions")
    wordlist = read_lines(wordlist_path)
    exts = load_exts(exts_path)

    session = requests.Session()
    session.headers.update({"User-Agent": UA})
    rp = robots_for(base)

    print(f"[i] Base URL: {base}")
    print(f"[i] Output directory: {dest}")
    print(f"[i] Wordlist: {wordlist_path} ({len(wordlist)} entries)")
    print(f"[i] Extensions: {exts_path} ({', '.join(sorted(exts))})")
    print("[i] robots.txt:", "will be respected" if rp else "not found or unreadable")

    is_soft404 = build_soft404_detector(session, base, args.timeout)

    base_netloc = urlparse(base).netloc
    dloader = LiveDownloader(session=session, dest=dest, base_netloc=base_netloc, timeout=args.timeout, workers=args.concurrency)

    seen_files: set[str] = set()
    seen_lock = Lock()

    def enqueue_file(url: str):
        if not allowed(rp, url):
            return
        with seen_lock:
            if url in seen_files:
                return
            seen_files.add(url)
        dloader.enqueue(url)

    t0 = time.time()
    all_dirs = fuzz_dirs_recursive(
        base=base,
        words=wordlist,
        session=session,
        rp=rp,
        timeout=args.timeout,
        concurrency=args.concurrency,
        depth=args.dir_depth,
        is_soft404=is_soft404,
        exts=exts,
        enqueue_file=enqueue_file,
    )

    print(f"[i] Discovered directories (recursive): {len(all_dirs)}")

    crawl_hits = collect_files(start_dirs=all_dirs, session=session, exts=exts, rp=rp, timeout=args.timeout, depth=args.crawl_depth)
    for u in crawl_hits:
        enqueue_file(u)

    brute_hits = fuzz_files_from_words(dirs=all_dirs, words=wordlist, exts=exts, session=session, rp=rp, timeout=args.timeout, concurrency=args.concurrency, max_probes=MAX_FILE_PROBES)
    for u in brute_hits:
        enqueue_file(u)

    dloader.finish()

    dt = time.time() - t0
    print(f"[✓] Done. Success: {dloader.ok}, skipped/errors: {dloader.skip}, elapsed: {dt:.1f}s")
    print(f"[→] Files saved under: {dest}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user", file=sys.stderr)
        sys.exit(1)
