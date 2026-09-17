"""Validate subscription URIs with TCP and Mihomo's real HTTP proxy probe."""
import base64
import concurrent.futures
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import urllib.parse
from pathlib import Path

import requests
import yaml

ROOT = "https://raw.githubusercontent.com/vincent20240707/free-v2ray-nodes/main/"
SCHEMES = ("vmess://", "vless://", "ss://", "trojan://", "hysteria2://", "hy2://", "tuic://")
CORE = Path(os.environ.get("MIHOMO_BIN", r"C:\Program Files\Clash Verge\verge-mihomo.exe"))
URL = "https://www.gstatic.com/generate_204"
TARGET = 50


def decode64(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)).decode("utf-8", "replace")


def fetch(url):
    for attempt in range(3):
        try:
            r = requests.get(url, timeout=20, headers={"User-Agent": "node-validator/1"})
            r.raise_for_status()
            return r.text
        except requests.RequestException:
            if attempt == 2:
                raise


def extract(text):
    texts = [text]
    compact = "".join(text.split())
    if len(compact) > 40 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", compact):
        try:
            texts.append(decode64(compact))
        except Exception:
            pass
    out = []
    for value in texts:
        for line in value.splitlines():
            for match in re.finditer(r"(?:vmess|vless|ss|trojan|hysteria2|hy2|tuic)://[^\s\"'<>]+", line, re.I):
                out.append(match.group(0).rstrip(",;]})"))
    return out


def parse(uri):
    if uri.startswith("vmess://"):
        d = json.loads(decode64(uri[8:].split("#")[0]))
        host, port = d["add"], int(d["port"])
        p = {"type": "vmess", "server": host, "port": port, "uuid": d["id"], "alterId": int(d.get("aid") or 0), "cipher": d.get("scy") or "auto"}
        net = d.get("net") or "tcp"
        if net != "tcp":
            p["network"] = net
        if net == "ws":
            p["ws-opts"] = {"path": d.get("path") or "/", "headers": {"Host": d.get("host") or host}}
        if net == "grpc":
            p["grpc-opts"] = {"grpc-service-name": d.get("path") or ""}
        if d.get("tls") == "tls":
            p["tls"] = True
            p["servername"] = d.get("sni") or d.get("host") or host
        return host, port, p
    u = urllib.parse.urlsplit(uri)
    typ = u.scheme.lower()
    q = dict(urllib.parse.parse_qsl(u.query))
    host, port = u.hostname, u.port
    if not host or not port:
        raise ValueError("missing host or port")
    password = urllib.parse.unquote(u.username or "")
    p = {"type": "hysteria2" if typ == "hy2" else typ, "server": host, "port": port}
    if typ == "vless":
        p.update(uuid=password, tls=q.get("security") in ("tls", "reality"))
        if q.get("type", "tcp") != "tcp":
            p["network"] = q["type"]
        if q.get("type") == "ws":
            p["ws-opts"] = {"path": q.get("path", "/"), "headers": {"Host": q.get("host", host)}}
        if q.get("type") == "grpc":
            p["grpc-opts"] = {"grpc-service-name": q.get("serviceName", "")}
        if q.get("security") == "reality":
            p["reality-opts"] = {"public-key": q.get("pbk", ""), "short-id": q.get("sid", "")}
        if q.get("flow"):
            p["flow"] = q["flow"]
    elif typ == "trojan":
        p["password"] = password
        p["sni"] = q.get("sni") or q.get("peer") or host
        if q.get("type") == "ws":
            p["network"] = "ws"
            p["ws-opts"] = {"path": q.get("path", "/"), "headers": {"Host": q.get("host", host)}}
    elif typ == "ss":
        creds = u.netloc.rsplit("@", 1)[0]
        if ":" not in creds:
            creds = decode64(creds)
        else:
            creds = urllib.parse.unquote(creds)
        p["cipher"], p["password"] = creds.split(":", 1)
    elif typ in ("hy2", "hysteria2"):
        p["password"] = password
        p["sni"] = q.get("sni") or host
    elif typ == "tuic":
        p["uuid"] = password
        p["password"] = urllib.parse.unquote(u.password or "")
        p["sni"] = q.get("sni") or host
        p["alpn"] = [q.get("alpn", "h3")]
    else:
        raise ValueError("unsupported")
    if q.get("sni") and typ == "vless":
        p["servername"] = q["sni"]
    if q.get("allowInsecure") == "1" or q.get("insecure") == "1":
        p["skip-cert-verify"] = True
    return host, port, p


def tcp(item):
    uri, host, port, proxy = item
    try:
        with socket.create_connection((host, port), timeout=2):
            return item
    except OSError:
        return None


def main():
    prior_file = Path(__file__).with_name("validated-nodes.txt")
    if not prior_file.exists():
        prior_file = Path(__file__).with_name("nodes.txt")
    prior = prior_file.read_text(encoding="utf-8").splitlines() if prior_file.exists() else []
    prior_set = set(prior)
    if "--recheck" in sys.argv:
        links, results = [], []
    else:
        links = [x.strip() for x in fetch(ROOT + "subscriptions.txt").splitlines() if x.strip().startswith("http")]
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(lambda link: (link, fetch(link)), links))
    sources = [extract(body) for _, body in results]
    sources.sort(key=lambda source: len(set(source) & prior_set) / max(len(source), 1), reverse=True)
    source_uris = list(dict.fromkeys(uri for source in sources for uri in source))
    uris = list(dict.fromkeys([*(uri for uri in prior if uri in source_uris), *source_uris])) if sources else prior
    items = []
    for uri in uris:
        try:
            host, port, p = parse(uri)
            items.append((uri, host, port, p))
        except (ValueError, KeyError, json.JSONDecodeError, UnicodeError):
            continue
    print(f"subscriptions={len(links)} candidates={len(uris)} parseable={len(items)}", flush=True)
    valid = []
    with tempfile.TemporaryDirectory() as tmp:
        config = Path(tmp) / "config.yaml"
        def test_proxy_batch(batch, offset):
            proxies = []
            for n, (_, _, _, p) in enumerate(batch):
                proxies.append({"name": f"p{n}", **p})
            data = {"mixed-port": 19098, "external-controller": "127.0.0.1:19099", "log-level": "silent", "proxies": proxies, "proxy-groups": [{"name": "test", "type": "select", "proxies": [p["name"] for p in proxies]}], "rules": ["MATCH,test"]}
            config.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
            check = subprocess.run([str(CORE), "-t", "-f", str(config)], capture_output=True, text=True, timeout=15)
            if check.returncode:
                print(f"config rejected batch {offset}: {check.stderr[-250:]}", flush=True)
                return
            proc = subprocess.Popen([str(CORE), "-f", str(config)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                import time
                for _ in range(30):
                    try:
                        requests.get("http://127.0.0.1:19099/version", timeout=1).raise_for_status()
                        break
                    except requests.RequestException:
                        time.sleep(.2)
                def probe(pair):
                    n, item = pair
                    try:
                        r = requests.get(f"http://127.0.0.1:19099/proxies/p{n}/delay", params={"url": URL, "timeout": 3000}, timeout=5)
                        return (n, item) if r.ok and r.json().get("delay", 0) > 0 else None
                    except (requests.RequestException, ValueError):
                        return None
                with concurrent.futures.ThreadPoolExecutor(max_workers=30) as pool:
                    delay_pass = [x for x in pool.map(probe, enumerate(batch)) if x]
                print(f"delay_pass={len(delay_pass)}", flush=True)
                for n, item in delay_pass:
                    try:
                        selected = requests.put("http://127.0.0.1:19099/proxies/test", json={"name": f"p{n}"}, timeout=2)
                        selected.raise_for_status()
                        with requests.Session() as session:
                            session.trust_env = False
                            response = session.get("https://www.cloudflare.com/cdn-cgi/trace", proxies={"http": "http://127.0.0.1:19098", "https": "http://127.0.0.1:19098"}, timeout=5)
                        if response.ok and "ip=" in response.text and "h=www.cloudflare.com" in response.text:
                            valid.append(item[0])
                    except requests.RequestException:
                        continue
                    if len(valid) >= TARGET:
                        break
                print(f"proxy_pass={len(valid)} after_tcp={offset + len(batch)}", flush=True)
            finally:
                proc.terminate()
                proc.wait(timeout=5)
        tcp_count = 0
        for start in range(0, len(items), 100):
            with concurrent.futures.ThreadPoolExecutor(max_workers=100) as pool:
                reachable = [x for x in pool.map(tcp, items[start:start + 100]) if x]
            tcp_count += len(reachable)
            print(f"tcp_pass={tcp_count} candidates_checked={min(start + 100, len(items))}", flush=True)
            for offset in range(0, len(reachable), 20):
                test_proxy_batch(reachable[offset:offset + 20], offset)
                if len(valid) >= TARGET:
                    break
            if len(valid) >= TARGET:
                break
    valid = valid[:TARGET]
    if len(valid) < TARGET:
        raise RuntimeError(f"only {len(valid)} of {tcp_count} TCP nodes passed both proxy requests; refusing overwrite")
    output = Path(__file__).with_name("validated-nodes.txt")
    output.write_text("\n".join(valid) + "\n", encoding="utf-8")
    print(f"VALIDATED={len(valid)} OUTPUT={output}", flush=True)


if __name__ == "__main__":
    main()
