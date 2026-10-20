"""Collect redistributed dependency notices and the LGPL gmpy2 corresponding source."""
import email
import hashlib
import json
import shutil
import sys
import urllib.request
import zipfile
from pathlib import Path

root=Path(__file__).resolve().parents[1]
out=root/'.build/licenses'
out.mkdir(parents=True,exist_ok=True)
rows=[]
for wheel in sorted((root/'.build/wheelhouse').glob('*.whl')):
    with zipfile.ZipFile(wheel) as z:
        metadata=email.message_from_bytes(z.read(next(n for n in z.namelist() if n.endswith('.dist-info/METADATA'))))
        name=metadata['Name'];version=metadata['Version']
        license_name=metadata.get('License-Expression') or metadata.get('License') or 'See included notices'
        license_name=license_name.splitlines()[0][:100]
        files=[]
        for entry in z.namelist():
            lower=entry.lower()
            if not entry.endswith('/') and any(v in lower for v in ('license','copying','notice')):
                relative=Path('python')/(name+'-'+version)/entry
                target=out/relative;target.parent.mkdir(parents=True,exist_ok=True)
                target.write_bytes(z.read(entry));files.append(str(relative))
        rows.append({'ecosystem':'python','name':name,'version':version,'license':license_name,'notices':files})
web=root/'apps/web/node_modules'
for pkg in sorted(web.glob('*/package.json'))+sorted(web.glob('@*/*/package.json')):
    data=json.loads(pkg.read_text(encoding='utf-8'))
    name=data.get('name',pkg.parent.name);version=data.get('version','unknown')
    relative=Path('npm')/name.replace('/','__')
    files=[]
    for item in pkg.parent.iterdir():
        if item.is_file() and any(v in item.name.lower() for v in ('license','copying','notice')):
            target=out/relative/item.name;target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(item,target);files.append(str(relative/item.name))
    rows.append({'ecosystem':'npm','name':name,'version':version,'license':data.get('license','See included notices'),'notices':files})
mcl=out/'mcl';mcl.mkdir(exist_ok=True)
shutil.copyfile(root/'third_party/mcl/COPYRIGHT',mcl/'COPYRIGHT')
sources=root/'.build/sources';sources.mkdir(exist_ok=True)
with urllib.request.urlopen('https://pypi.org/pypi/gmpy2/2.2.1/json',timeout=20) as response:
    metadata=json.load(response)
sdist=next(x for x in metadata['urls'] if x['packagetype']=='sdist')
dest=sources/sdist['filename']
if not dest.exists():
    with urllib.request.urlopen(sdist['url'],timeout=30) as response:dest.write_bytes(response.read())
assert hashlib.sha256(dest.read_bytes()).hexdigest()==sdist['digests']['sha256']
(sources/'manifest.json').write_text(json.dumps({'gmpy2':{'url':sdist['url'],'sha256':sdist['digests']['sha256'],'filename':sdist['filename']}},indent=2),encoding='utf-8')
(out/'manifest.json').write_text(json.dumps(rows,ensure_ascii=False,indent=2),encoding='utf-8')
lines=['# 第三方软件与研究来源','',
       'PFDAM为本团队自主研究方案，论文作者为团队成员，DOI 10.1109/JIOT.2024.3356593；论文用于解释前期研究。OpenSSL、mcl及其他第三方组件按原许可署名，引用37具体参数论证仍待独立审查。',
       '', 'mcl v3.08，提交 a8cad811f720264e6e140f54c66463be60189789，BSD-3-Clause；原始 COPYRIGHT 和对应源码随包保留。OpenSSL3.5.5、GMP及C/C++运行库动态使用宿主安装，不随包复制系统二进制。OpenSSL 项目采用 Apache-2.0；系统组件以各自许可为准。',
       '', 'Python wheels 与前端依赖的原始许可证/NOTICE 摘录至 software/licenses。gmpy2 2.2.1 按 LGPL-3.0-or-later 提供原始 sdist、构建脚本及可替换的动态扩展；其他依赖按其实际元数据和随附原文处理。字体使用系统字体，不打包字体文件。',
       '', '| 生态 | 包 | 版本 | 元数据许可 |','|---|---|---|---|']
for r in rows:lines.append(f"| {r['ecosystem']} | {r['name']} | {r['version']} | {str(r['license']).replace('|','/')} |")
lines += ['', '元数据摘要用于查阅，许可条款以原始文件为准。项目本身的对外授权由权利人确定；本次仅生成本地审阅与参赛准备包，不自动公开发布。']
(root/'docs/THIRD_PARTY_NOTICES.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
print(json.dumps({'dependency_records':len(rows),'gmpy2_source':dest.name}))
