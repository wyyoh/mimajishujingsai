"""Fill a working copy of the official template; preserve opaque source parts."""
import copy
import hashlib
import json
import re
import zipfile
from datetime import datetime
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont
from docx import Document
from docx.shared import Inches, Pt
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.text.paragraph import Paragraph
from docx.enum.text import WD_ALIGN_PARAGRAPH
from lxml import etree

root=Path(__file__).resolve().parents[1]
template=next((root/'references/competition/official-attachments/expanded').rglob('*模板*.docx'))
out=root/'materials';out.mkdir(exist_ok=True)
tmp=root/'.build/materials';tmp.mkdir(parents=True,exist_ok=True)
fig=root/'artifacts/figures'
data=json.loads((root/'artifacts/benchmarks/analysis.json').read_text(encoding='utf-8'))
fontfile='C:/Windows/Fonts/msyh.ttc'
def diagram(name,kind):
    im=Image.new('RGB',(1400,720),'white');d=ImageDraw.Draw(im)
    font=ImageFont.truetype(fontfile,29);big=ImageFont.truetype(fontfile,38)
    blue='#18344F';teal='#159895'
    if kind=='architecture':
        d.text((65,35),'实际进程与端口',font=big,fill=blue)
        d.rectangle((440,120,960,240),fill='#EFF6F7');d.text((470,155),'TA 初始化后退出常驻流程',font=font,fill=blue)
        blocks=[(60,'Source','模拟120节点\n读数与标签'),(520,'GW','联合检查\n密文选择聚合'),(980,'UC','双签授权\n验证恢复发布')]
        for x,title,body in blocks:
            d.rectangle((x,350,x+340,540),fill='#F3F7FA',outline='#C8D8E3',width=2)
            d.text((x+28,375),title,font=big,fill=blue);d.multiline_text((x+28,438),body,font=font,fill=blue,spacing=8)
        for x,label in ((407,'L1'),(867,'L2')):
            d.line((x,430,x+95,430),fill=teal,width=5);d.polygon([(x+95,430),(x+77,420),(x+77,440)],fill=teal)
            d.text((x,290),label,font=font,fill=teal)
        d.text((65,595),'L1/L2：每次任务分配回环端口，实际 TLS1.3 混合 mTLS',font=font,fill=blue)
        d.text((65,650),'本机控制入口：127.0.0.1:8580；秘密位于源码树外',font=font,fill=blue)
    else:
        d.text((65,35),'被外层双签保护的规范对象',font=big,fill=blue)
        for x,title,body in ((65,'任务授权','对象类型 / 任务 / 运行\n窗口 / 指标 / 参数 / 档位\n接收方 / 有效期 / key epoch\npolicy_ref / token_bundle'),
                             (740,'聚合回执','对象类型 / 任务 / 运行\n窗口 / 授权摘要 / 参数 / 档位\n聚合密文 / 原生签名 / 计数\n输入摘要 / 快照 / key epoch')):
            d.text((x,145),title,font=big,fill=teal);d.multiline_text((x,230),body,font=font,fill=blue,spacing=35)
        d.text((65,620),'同一规范 payload：ECDSA P-256 AND ML-DSA-65；独立域分离',font=font,fill=blue)
    im.save(fig/(name+'.png'))
diagram('architecture','architecture');diagram('object_protection','objects')

doc=Document(template)
original=list(doc.paragraphs)
heading1=copy.deepcopy(original[27]._p);heading2=copy.deepcopy(original[31]._p);body=copy.deepcopy(original[32]._p)
def replace(p,text):
    nodes=p._p.xpath('.//w:t')
    if nodes:
        nodes[0].text=text
        for n in nodes[1:]:n.text=''
    else:p.add_run(text)
replace(original[0],'作品编号：待填写系统编号')
replace(original[3],'☑密码应用技术  □其它')
replace(original[14],'作品题目：面向新型电网的细粒度密态聚合与可信数据协同平台')
replace(original[17],'B类自拟选题  软件0.1.0  本地工程候选')
replace(original[22],datetime.now().strftime('%Y年%m月%d日'))
cells=[row.cells[0] for row in doc.tables[0].rows]
abstract=('本团队提出PFDAM细粒度密态聚合方案，并构建本地可复跑的密码应用系统。Source生成全部120个合成节点报告，GW按授权执行真实配对联合检查与密文聚合，UC验证回执后恢复群体功率。任务与回执同时要求ECDSA P-256和Pure ML-DSA-65，两段业务链路实际协商TLS1.3 X25519MLKEM768并双向认证。平台提供三页界面、六种真实受控情境、独立参与集合和整数和核对、快照幂等、崩溃终结恢复及公开证据导出。正式四档实验各30次全部功能核对通过，耗时按实测表报告；节点及策略扫描另列。新目录、新环境和新密钥的断网SAB复跑通过。本文记录授权策略及特定条件下报告类别可被候选识别，不宣称这两类隐藏；引用37已采用摘要回退，具体参数安全仍待独立审查，配对与Paillier及证书身份仍为经典密码。本次贡献为任务一致性、角色分离、双签与严格传输集成、失败关闭和可复验验证，前期方案与本次系统迭代分别说明，不宣称真实电网部署或整体后量子安全。')
for cell,text in zip(cells[1:],('编号：待填写系统编号','作品题目：面向新型电网的细粒度密态聚合与可信数据协同平台','作品类别：☑密码应用技术  □软件设计  □硬件制作  □工程实践  □其它','作品内容摘要：\n'+abstract,'关键词（五个）：密态聚合  PFDAM  双签名  混合TLS  可复验')):
    first=cell.paragraphs[0];replace(first,text)
    for paragraph in list(cell.paragraphs[1:]):paragraph._p.getparent().remove(paragraph._p)
replace(cells[3].paragraphs[0],'作品类别：')
run=cells[3].paragraphs[0].add_run('□软件设计  □硬件制作  □工程实践  ☑密码应用技术  □其它')
run.font.size=Pt(12);run.font.name='宋体';run._r.get_or_add_rPr().rFonts.set(qn('w:eastAsia'),'宋体')
# Replace only the template's body slots, retaining all three source section definitions.
for paragraph in original[27:]:
    if not paragraph._p.xpath('.//w:sectPr'):paragraph._p.getparent().remove(paragraph._p)

def add(text,level=0):
    node=copy.deepcopy(heading1 if level==1 else heading2 if level==2 else body)
    rpr=node.xpath('./w:r/w:rPr')
    rpr=copy.deepcopy(rpr[0]) if rpr else None
    for child in list(node):
        if child.tag!=qn('w:pPr'):node.remove(child)
    run=OxmlElement('w:r')
    if rpr is not None:run.append(rpr)
    t=OxmlElement('w:t');t.text=text;run.append(t);node.append(run)
    doc._body._body.insert(len(doc._body._body)-1,node)
    p=Paragraph(node,doc._body)
    if level:p.paragraph_format.keep_with_next=True
    else:
        p.paragraph_format.space_after=Pt(6)
        p.paragraph_format.first_line_indent=Pt(28)
        p.paragraph_format.line_spacing=1.35
    return p
def image(name,caption):
    p=doc.add_paragraph();p.paragraph_format.keep_with_next=True
    p.add_run().add_picture(str(fig/(name+'.png')),width=Inches(6.2))
    p=add(caption);p.paragraph_format.first_line_indent=Pt(0)

blocks=(root/'docs/DESIGN_REPORT.md').read_text(encoding='utf-8').split('\n\n')
for block in blocks:
    if block.startswith('# ') or block.startswith('作品类别：'):continue
    if block.startswith('## '):
        title=block[3:]
        if title=='研究来源与开发披露':title='6 研究来源与开发披露'
        add(title,1)
    elif block.startswith('### '):
        title=block[4:]
        if title.startswith('2.2'):
            image('architecture','图1  实际四角色、常驻进程和端口')
            image('object_protection','图2  双签覆盖的授权与回执字段')
        add(title,2)
    else:
        value=re.sub(r'\[([^\]]+)\]\(([^)]+)\)',r'\1（\2）',block).replace('`','').replace('\n',' ').replace('10^9','10⁹')
        p=add(value)
        if value.startswith(('团队前期研究','Huanyu','算法身份')):p.alignment=WD_ALIGN_PARAGRAPH.LEFT
add('7 正式性能记录',1)
add('四档各30次，120节点、4窗口；失败0。持续时间口径见正文；p90采用向上分位点。')
for profile,v in data['profiles'].items():add(f"{profile}：中位数 {v['median']/1e9:.3f} 秒，p90 {v['p90']/1e9:.3f} 秒。")
for name,caption in [('end_to_end','图3 四档端到端中位数及p90'),('object_signatures','图4 两类对象签验各100次，含密钥读取'),('tls_handshake_bytes','图5 每档每链路30次完整握手BIO字节，客户端视角'),('node_scale','图6 节点扫描各3次、1窗口，范围线'),('policy_scale','图7 互异实验策略扫描各3次、60报告，只计GW内核')]:image(name,caption)
doc.core_properties.author='';doc.core_properties.last_modified_by='';doc.core_properties.title='新型电网平台作品设计报告'
draft=tmp/'report-working.docx';doc.save(draft)
# Keep opaque original components byte-identical (including source logo, styles,
# header/footer, numbering and section-associated relationships).
changed={'word/document.xml','word/_rels/document.xml.rels','[Content_Types].xml','docProps/core.xml','docProps/app.xml'}
final=out/'作品设计报告_待编号.docx'
with zipfile.ZipFile(template) as source,zipfile.ZipFile(draft) as generated,zipfile.ZipFile(final,'w',zipfile.ZIP_DEFLATED) as target:
    for item in generated.infolist():
        content=source.read(item.filename) if item.filename in source.namelist() and item.filename not in changed else generated.read(item)
        if item.filename=='docProps/app.xml':
            props=etree.fromstring(content)
            for element in props:
                if etree.QName(element).localname in ('Company','Manager'):element.text=None
            content=etree.tostring(props,xml_declaration=True,encoding='UTF-8',standalone=True)
        target.writestr(item.filename,content)
    for item in source.infolist():
        if item.filename not in generated.namelist():target.writestr(item,source.read(item))
with zipfile.ZipFile(template) as source,zipfile.ZipFile(final) as result:
    preserved=[n for n in source.namelist() if n not in changed]
    assert all(source.read(n)==result.read(n) for n in preserved)
assert len(Document(final).sections)==3
record={'template_sha256':hashlib.sha256(template.read_bytes()).hexdigest(),'preserved_parts':preserved,'sections':3,'final':str(final),
        'intentional_changes':['fill cover and basic information','replace body slots with implementation and actual evidence','add real figures','remove identifying core metadata'],
        'needs_user_input':['system work number']}
(tmp/'report_fidelity.json').write_text(json.dumps(record,ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps({'final':str(final),'opaque_parts_preserved':len(preserved)}))
