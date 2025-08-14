import argparse
import concurrent.futures as cf
import re
import sys
import time
from collections import deque
from pathlib import Path
from urllib.parse import urljoin, urlparse, urldefrag

import requests
from bs4 import BeautifulSoup
from tqdm import tqdm
from urllib.robotparser import RobotFileParser

UA = "SiteSifter/1.3 (+https://example.local)"
OK_STATUSES = {200, 301, 302, 303, 307, 308, 401, 403}
CHUNK = 64 * 1024



def require_file(cli_value, fallback, purpose):
    """Resolve a required file path or exit with a clear message."""
    path = Path(cli_value) if cli_value else Path(fallback)
    if not path.exists():
        print(
            f"[!] Missing {purpose} file: '{path}'. "
            f"Provide it via flag or create '{fallback}' in CWD.",
            file=sys.stderr,
        )
        sys.exit(2)
    return path


def read_lines(path):
    """Read non-empty, non-comment lines."""
    lines = []
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = raw.strip()
        if s and not s.startswith("#"):
            lines.append(s)
    return lines


def load_exts(path):
    """Load set of normalized extensions (without dots)."""
    raw = {ln.lower().lstrip(".") for ln in read_lines(path)}
    return {e for e in raw if re.fullmatch(r"[a-z0-9]{1,10}", e)}


def normalize_base(u):
    """Ensure scheme and strip trailing slash."""
    u = u.strip()
    if not re.match(r"^https?://", u, re.I):
        u = "https://" + u
    return u.rstrip("/")


def robots_for(base):
    """Create a robots.txt parser (best-effort)."""
    p = urlparse(base)
    rp = RobotFileParser()
    try:
        rp.set_url(f"{p.scheme}://{p.netloc}/robots.txt")
        rp.read()
        return rp
    except Exception:
        return None


def allowed(rp, url):
    """Check robots.txt permission if available."""
    try:
        return True if rp is None else rp.can_fetch(UA, url)
    except Exception:
        return True


def head_or_get(session, url, timeout):
    """
    Try HEAD first; if it fails or returns an unhelpful status,
    fall back to GET (streaming).
    """
    try:
        r = session.head(url, allow_redirects=True, timeout=timeout)
    except Exception:
        r = None
    if (r is None) or (r.status_code not in OK_STATUSES):
        try:
            r = session.get(
                url, stream=True, allow_redirects=True, timeout=timeout
            )
        except Exception:
            return None
    return r


def is_dirlike(resp, final_url):
    """Heuristic: looks like a directory or HTML page without extension."""
    if final_url.endswith("/"):
        return True
    ctype = (resp.headers.get("Content-Type") or "").lower()
    if "text/html" in ctype:
        name = Path(urlparse(final_url).path).name
        return "." not in name
    return False


def fuzz_dirs_recursive(base, words, session, rp, timeout, concurrency, depth):
    """
    Recursively fuzz directories using the wordlist (BFS).
    Returns a set of normalized directories (ending with '/').
    Shows a live progress bar with a dynamic total.
    """
    base = base.rstrip("/") + "/"
    discovered = {base}
    seen_parents = set()
    q = deque([(base, 0)])

    def probe(u):
        if not allowed(rp, u):
            return u, None
        r = head_or_get(session, u, timeout)
        if not r:
            return u, None
        if r.status_code in OK_STATUSES and is_dirlike(r, r.url):
            return u, r.url.rstrip("/") + "/"
        return u, None

    pbar = tqdm(
        total=0,  # dynamic total grows before each batch
        desc="Fuzz dirs (recursive)",
        unit="probe",
        dynamic_ncols=True,
        mininterval=0.1,
        miniters=1,
        leave=True,
    )

    try:
        while q:
            parent, level = q.popleft()
            if parent in seen_parents:
                continue
            cand = set()
            parent_slash = parent
            for w in words:
                w = w.strip().strip("/")
                if not w:
                    continue
                cand.add(urljoin(parent_slash, w))
                cand.add(urljoin(parent_slash, w + "/"))
            pbar.total += len(cand)
            pbar.set_postfix(
                level=level,
                dirs=len(discovered),
                queued=len(q) + len(cand),
            )
            pbar.refresh()
            with cf.ThreadPoolExecutor(max_workers=concurrency) as ex:
                futs = [ex.submit(probe, u) for u in cand]
                for f in cf.as_completed(futs):
                    _orig, found = f.result()
                    pbar.update(1)
                    if found and found not in discovered:
                        discovered.add(found)
                        if level < depth:
                            q.append((found, level + 1))
    finally:
        pbar.close()

    return discovered


def extract_links(html, base_url):
    """Extract absolute links from HTML."""
    soup = BeautifulSoup(html, "html.parser")
    out = []
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if href.startswith(("mailto:", "javascript:")):
            continue
        abs_url = urljoin(base_url, href)
        abs_url, _ = urldefrag(abs_url)
        out.append(abs_url)
    return out


def collect_files(start_dirs, session, exts, rp, timeout, depth):
    """
    Crawl HTML pages starting from start_dirs up to `depth` levels,
    collect file URLs that match given extensions. Only same host is followed.
    """
    seen_html = set()
    files = []
    level = list(start_dirs)

    def visit(u):
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
        next_pages, found = [], []
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
        with tqdm(total=len(level), desc=f"Crawl L{d}", unit="page") as pbar:
            next_level = []
            for u in level:
                if u in seen_html:
                    pbar.update(1)
                    continue
                seen_html.add(u)
                nxt, found = visit(u)
                files.extend(found)
                if d < depth:
                    nxt = [
                        x for x in nxt
                        if "." not in Path(urlparse(x).path).name
                    ]
                    next_level.extend(nxt)
                pbar.update(1)
        level = next_level
    uniq, out = set(), []
    for f in files:
        if f not in uniq:
            uniq.add(f)
            out.append(f)
    return out



def local_path(dest, base_netloc, file_url):
    """Map remote file URL to destination path."""
    rel = Path(urlparse(file_url).path.lstrip("/"))
    full = dest / base_netloc / rel
    full.parent.mkdir(parents=True, exist_ok=True)
    return full


def download_one(session, url, out_path, timeout):
    """Download a single file with basic checks."""
    try:
        if out_path.exists():
            return url, False, "exists"
        with session.get(url, stream=True, timeout=timeout) as r:
            if r.status_code != 200:
                return url, False, f"http {r.status_code}"
            if "text/html" in (r.headers.get("Content-Type") or "").lower():
                return url, False, "html"
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with open(out_path, "wb") as fh:
                for chunk in r.iter_content(CHUNK):
                    if chunk:
                        fh.write(chunk)
        return url, True, "ok"
    except Exception as e:
        return url, False, str(e)



def main():
    parser = argparse.ArgumentParser(
        description="Recursive directory fuzzer and file downloader.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-u", "--url", required=True,
        help="Base host/URL (schema optional, e.g., example.com).",
    )
    parser.add_argument(
        "-d", "--dest", required=True,
        help="Directory to save downloaded files.",
    )
    parser.add_argument(
        "-w", "--wordlist",
        help=("Wordlist file (one path per line). "
              "If omitted, ./wordlist.txt is used."),
    )
    parser.add_argument(
        "-e", "--ext-file",
        help=("Extensions file (one per line, without a dot). "
              "If omitted, ./extensions.txt is used."),
    )
    parser.add_argument(
        "-c", "--concurrency", type=int, default=16,
        help="Number of threads.",
    )
    parser.add_argument(
        "--timeout", type=int, default=12,
        help="HTTP timeout in seconds.",
    )
    parser.add_argument(
        "--dir-depth", type=int, default=1,
        help=("Depth for recursive directory fuzzing via wordlist: "
              "0 = only under base; 1 = also under each found dir; etc."),
    )
    # Backward-compatible alias for HTML crawl depth
    parser.add_argument(
        "--crawl-depth", type=int, default=1,
        help=("HTML crawl depth (0 = only the directory page; "
              "1 = one level of nested HTML pages)."),
    )
    parser.add_argument(
        "--depth", type=int, dest="crawl_depth",
        help=argparse.SUPPRESS,
    )

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
    print(
        "[i] robots.txt:",
        "will be respected" if rp else "not found or unreadable",
    )

    t0 = time.time()
    all_dirs = fuzz_dirs_recursive(
        base=base,
        words=wordlist,
        session=session,
        rp=rp,
        timeout=args.timeout,
        concurrency=args.concurrency,
        depth=args.dir_depth,
    )
    print(f"[i] Discovered directories (recursive): {len(all_dirs)}")
    for d in sorted(all_dirs):
        print(f"    - {d}")
    files = collect_files(
        start_dirs=all_dirs,
        session=session,
        exts=exts,
        rp=rp,
        timeout=args.timeout,
        depth=args.crawl_depth,
    )
    if not files:
        print("[!] No matching files found.")
        return

    print(f"[i] Files to download: {len(files)}")

    base_netloc = urlparse(base).netloc
    with tqdm(total=len(files), desc="Download", unit="file") as pbar:
        with cf.ThreadPoolExecutor(max_workers=args.concurrency) as ex:
            futs = []
            for u in files:
                outp = local_path(dest, base_netloc, u)
                futs.append(
                    ex.submit(download_one, session, u, outp, args.timeout)
                )
            ok = skip = 0
            for f in cf.as_completed(futs):
                url, good, msg = f.result()
                pbar.update(1)
                if good:
                    ok += 1
                else:
                    skip += 1
                    tqdm.write(f"[-] SKIP  {url} ({msg})")

    dt = time.time() - t0
    print(
        f"[✓] Done. Success: {ok}, skipped/errors: {skip}, "
        f"elapsed: {dt:.1f}s"
    )
    print(f"[→] Files saved under: {dest}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user", file=sys.stderr)
        sys.exit(1)
