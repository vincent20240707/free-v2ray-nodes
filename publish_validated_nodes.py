"""Commit validated nodes and push normally; reject concurrent remote changes."""
import datetime as dt
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).parent


def git(*args):
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()


def main():
    lines = (ROOT / "validated-nodes.txt").read_text(encoding="utf-8").splitlines()
    assert 0 < len(lines) <= 20
    assert len(lines) == len(set(lines))
    assert all(line.startswith(("vmess://", "vless://", "ss://", "trojan://", "hysteria2://", "hy2://", "tuic://")) for line in lines)
    if git("status", "--porcelain", "--untracked-files=no"):
        raise RuntimeError("tracked files changed before publishing")
    now = dt.datetime.now(dt.timezone(dt.timedelta(hours=8)))
    day = now.date().isoformat()
    git("fetch", "origin", "main")
    if git("rev-parse", "HEAD") != git("rev-parse", "origin/main"):
        remote_marker = subprocess.run(["git", "show", "origin/main:last-validation.json"], cwd=ROOT, capture_output=True, text=True)
        if remote_marker.returncode == 0 and json.loads(remote_marker.stdout).get("date_cst") == day:
            print("ALREADY_VALIDATED_BY_OTHER_RUN")
            return
        raise RuntimeError("remote main changed; pull and revalidate before publishing")
    source = os.environ.get("VALIDATION_SOURCE", "local")
    if source not in ("local", "cloud"):
        raise ValueError("invalid validation source")
    new_bytes = ("\n".join(lines) + "\n").encode()
    nodes = ROOT / "nodes.txt"
    marker = ROOT / "last-validation.json"
    state = {"date_cst": day, "source": source, "count": len(lines), "time_cst": now.isoformat()}
    if nodes.read_bytes() == new_bytes and marker.exists() and json.loads(marker.read_text(encoding="utf-8")).get("date_cst") == day:
        print(f"ALREADY_VALIDATED={len(lines)}")
        return
    nodes.write_bytes(new_bytes)
    marker.write_text(json.dumps(state, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    git("add", "--", "nodes.txt", "last-validation.json")
    git("commit", "-m", f"Update {len(lines)} dual-validated nodes ({source})", "-m", f"Validated-On: {day}")
    commit = git("rev-parse", "HEAD")
    git("push", "origin", "HEAD:main")
    git("fetch", "origin", "main")
    assert git("rev-parse", "origin/main") == commit
    assert subprocess.run(["git", "show", "origin/main:nodes.txt"], cwd=ROOT, capture_output=True, check=True).stdout == new_bytes
    print(f"UPDATED={len(lines)} COMMIT={commit} SOURCE={source}")


if __name__ == "__main__":
    main()
