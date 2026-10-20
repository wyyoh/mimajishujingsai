"""Preserve primary public source responses and retrieval status; no login or submission."""
import hashlib
import json
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

root = Path(__file__).resolve().parents[1]
out = root / "references/web"
out.mkdir(parents=True, exist_ok=True)
sources = {
    "competition_news": "https://chinacodes.com.cn/news/lookAllNews.do",
    "competition_initial": "https://www.chinacodes.com.cn/news/findNewsByTitle.do?id=254",
    "reference37_abstract": "https://www.acsac.org/2021/program/final/s91.html",
}
records = []
for name, url in sources.items():
    item = {"url": url, "retrieved_at": datetime.now(timezone.utc).isoformat()}
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=20) as res:
            body = res.read(8 * 1024 * 1024)
            item.update(status=res.status, final_url=res.url, sha256=hashlib.sha256(body).hexdigest())
        path = out / (name + ".html")
        path.write_bytes(body)
        item["saved_file"] = str(path.relative_to(root))
    except Exception as exc:
        item.update(status="UNAVAILABLE", error=str(exc))
    records.append(item)
(out / "retrieval.json").write_text(json.dumps(records, ensure_ascii=False, indent=2), encoding="utf-8")
print(json.dumps(records, ensure_ascii=False))
