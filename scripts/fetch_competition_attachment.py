import hashlib
import json
import re
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path, PurePosixPath
from lxml import html

root = Path(__file__).resolve().parents[1]
doc = html.fromstring((root / "references/web/competition_news.html").read_bytes())
form = doc.xpath('//form[@id="news_form0"]')[0]
fields = {v.attrib['name']: v.attrib.get('value','') for v in form.xpath('.//input[@name]')}
url = "https://chinacodes.com.cn/news/appendixdown.do"
req = urllib.request.Request(url, data=urllib.parse.urlencode(fields).encode(),
                             headers={"User-Agent":"Mozilla/5.0", "Referer":"https://chinacodes.com.cn/news/lookAllNews.do"})
with urllib.request.urlopen(req, timeout=25) as res:
    body = res.read(32*1024*1024)
assert body[:2] == b'PK', 'Response is not an attachment ZIP'
out = root/'references/competition'
out.mkdir(parents=True, exist_ok=True)
(out/'2026-semifinal-official.zip').write_bytes(body)
names=[]
with zipfile.ZipFile(BytesIO(body)) as archive:
    for item in archive.infolist():
        name=item.filename
        if not item.flag_bits & 0x800:
            try: name=name.encode('cp437').decode('gbk')
            except (UnicodeError, LookupError): pass
        path=PurePosixPath(name.replace('\\','/'))
        assert not path.is_absolute() and '..' not in path.parts
        if item.is_dir():continue
        target=out/'official-attachments'/path
        target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(archive.read(item))
        names.append(str(path))
record={'source':url,'notice_source':'https://chinacodes.com.cn/news/lookAllNews.do',
        'notice_title':fields['title'],'retrieved_at':datetime.now(timezone.utc).isoformat(),
        'sha256':hashlib.sha256(body).hexdigest(),'files':names,'status':'DOWNLOADED_UNEXECUTED_REFERENCE'}
(out/'manifest.json').write_text(json.dumps(record,ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps(record,ensure_ascii=False))
