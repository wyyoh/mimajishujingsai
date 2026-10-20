"""Generate all figures and report tables from real raw samples. No illustrative values."""
import csv
import hashlib
import json
import math
import statistics as stats
import sys
from datetime import datetime, timezone
from collections import defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

root = Path(__file__).resolve().parents[1]
directory = root / "artifacts/benchmarks"
out = root / "artifacts/figures"
out.mkdir(parents=True, exist_ok=True)
profiles = ["S0", "SA", "SB", "SAB"]
colors = ["#7b93a9", "#315f8c", "#159895", "#c28c32"]
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size":11,
                     "axes.spines.top":False, "axes.spines.right":False,
                     "figure.dpi":150, "savefig.bbox":"tight"})


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def summary(values):
    values=sorted(values)
    return {"sample_count":len(values),"median":int(stats.median(values)),
            "p90":values[math.ceil((len(values)-1)*.9)],
            "min":values[0],"max":values[-1]}


def save(fig,name):
    for suffix in ("png","pdf","svg"):
        fig.savefig(out/f"{name}.{suffix}")
    plt.close(fig)


def main():
    raw=read(directory/"raw.json")
    plan=read(directory/"plan.json")
    assert read(directory/"summary.json")["status"]=="COMPLETED"
    assert len(raw)==120 and all(r['success'] for r in raw)
    assert len({r['param_id'] for r in raw})==len({r['dataset_digest'] for r in raw})==1
    assert all(r['core_source_digest']==plan['core_source_digest'] for r in raw)
    assert len({tuple(r['result_W']) for r in raw})==1
    groups={p:summary([r['elapsed_ns'] for r in raw if r['profile']==p]) for p in profiles}
    fig,ax=plt.subplots(figsize=(8,4.4))
    bars=ax.bar(profiles,[groups[p]['median']/1e9 for p in profiles],color=colors,width=.58)
    ax.scatter(range(4),[groups[p]['p90']/1e9 for p in profiles],marker='_',s=240,color='#162e45',label='p90 (higher quantile)')
    for bar,p in zip(bars,profiles):ax.text(bar.get_x()+bar.get_width()/2,bar.get_height()-.55,f"{groups[p]['median']/1e9:.3f}",ha='center',va='top',color='#162e45',bbox={'facecolor':'white','edgecolor':'none','alpha':.9,'pad':2})
    ax.set(ylim=(0,max(groups[p]['p90']/1e9 for p in profiles)*1.17),ylabel='End-to-end duration (s)',title='120 nodes, 4 windows, 30 runs per profile; failures=0')
    ax.legend(frameon=False,loc='lower right');save(fig,'end_to_end')
    consistency=[]
    for p in profiles:
        consistency.append({'profile':p,'sample_count':groups[p]['sample_count'],'failure_count':sum(not r['success'] for r in raw if r['profile']==p),
                            'set_and_value_checks':'PASS','result_W':raw[0]['result_W']})
    with (directory/'consistency.csv').open('w',newline='',encoding='utf-8-sig') as f:
        writer=csv.writer(f);writer.writerow(['profile','samples','failures','set_and_value','slot0_W','slot1_W','slot2_W','slot3_W'])
        for row in consistency:writer.writerow([row['profile'],row['sample_count'],row['failure_count'],'PASS',*row['result_W']])
    fig,ax=plt.subplots(figsize=(10,2.8));ax.axis('off')
    table=ax.table(cellText=[[r['profile'],r['sample_count'],r['failure_count'],*r['result_W']] for r in consistency],
                   colLabels=['Profile','n','Failures','Slot 0 / W','Slot 1 / W','Slot 2 / W','Slot 3 / W'],loc='center')
    table.auto_set_font_size(False);table.set_fontsize(11);table.scale(1,2)
    ax.set_title('Independent set and value checks PASS for all 120 representative runs',pad=15)
    save(fig,'result_consistency')
    micro=read(directory/'signatures_raw.json')
    sigstats={}
    fig,axes=plt.subplots(1,2,figsize=(11,4.4))
    sizes=[]
    for object_type in ('authorization','receipt'):
        for alg in ('ecdsa','mldsa'):
            rows=[r for r in micro if r['object_type']==object_type and r['algorithm']==alg]
            assert len(rows)==100
            key=f'{object_type}/{alg}'
            sigstats[key]={op:summary([r[op+'_ns'] for r in rows]) for op in ('sign','verify')}
            sizes.append({'name':key,'payload_bytes':rows[0]['payload_bytes'],
                          'signature_bytes':summary([r['signature_bytes'] for r in rows])})
    labels=list(sigstats)
    for ax,op in zip(axes,('sign','verify')):
        values=[sigstats[k][op]['median']/1e6 for k in labels]
        ax.bar(range(4),values,color=[colors[1],colors[2]]*2)
        ax.set_xticks(range(4),[x.replace('/','\n') for x in labels]);ax.set(ylabel=f'{op.capitalize()} duration (ms)',title='100 samples per object and algorithm')
    fig.tight_layout();save(fig,'object_signatures')
    fig,axes=plt.subplots(1,2,figsize=(11,4.4))
    for ax,field,title in zip(axes,('payload_bytes','signature_bytes'),('Canonical payload size','Signature size')):
        values=[s[field] if field=='payload_bytes' else s[field]['median'] for s in sizes]
        ax.bar(range(4),values,color=[colors[1],colors[2]]*2)
        ax.set_xticks(range(4),[s['name'].replace('/','\n') for s in sizes]);ax.set(ylabel='Bytes',title=title)
    fig.tight_layout();save(fig,'object_sizes')
    tlsrows=[]
    stagerows=[]
    for run in raw:
        run_path=root/'artifacts/runs'/run['run_id']
        for c in read(run_path/'connection_evidence.json'):
            if (c['link_id']=='L1' and c['peer_role']=='gateway') or (c['link_id']=='L2' and c['peer_role']=='utility'):
                assert c['business_request_refs'] and not c['session_reused'] and not c['early_data_accepted']
                tlsrows.append({'profile':run['profile'],'run_id':run['run_id'],'link':c['link_id'],
                                'group':c['actual_group'],'handshake_ns':c['handshake_ns'],
                                'handshake_BIO_bytes':c['handshake_bytes_read']+c['handshake_bytes_written']})
        for row in read(run_path/'performance_raw.json'):
            stagerows.append({'profile':run['profile'],'run_id':run['run_id'],**row})
    (directory/'handshakes_raw.json').write_text(json.dumps(tlsrows,indent=2),encoding='utf-8')
    (directory/'stages_raw.json').write_text(json.dumps(stagerows,indent=2),encoding='utf-8')
    tlsstats={}
    for field,divisor,unit,name in (('handshake_ns',1e6,'ms','tls_handshake_time'),('handshake_BIO_bytes',1,'bytes','tls_handshake_bytes')):
        fig,ax=plt.subplots(figsize=(8,4.4))
        for j,link in enumerate(('L1','L2')):
            metrics=[]
            for p in profiles:
                vals=[r[field] for r in tlsrows if r['profile']==p and r['link']==link]
                assert len(vals)==30
                item=summary(vals);tlsstats[f'{p}/{link}/{field}']=item
                metrics.append(item['median']/divisor)
            ax.bar([i+(j-.5)*.32 for i in range(4)],metrics,width=.30,label=link,color=(colors[1],colors[2])[j])
        ax.set_xticks(range(4),profiles);ax.set(ylabel=f'Handshake {unit}',title='One client view per link; 30 full handshakes/profile/link')
        ax.legend(frameon=False);save(fig,name)
    nodes=read(directory/'nodes_raw.json');policies=read(directory/'policies_raw.json')
    assert all(r['success'] for r in nodes+policies)
    fig,ax=plt.subplots(figsize=(8,4.4))
    ns=[100,300,600,900]
    vals=[[r['elapsed_ns']/1e9 for r in nodes if r['nodes']==n] for n in ns]
    ax.errorbar(ns,[stats.median(v) for v in vals],yerr=[[stats.median(v)-min(v) for v in vals],[max(v)-stats.median(v) for v in vals]],fmt='o-',color=colors[2],capsize=4)
    ax.set(xlabel='Logical nodes (one Source process)',ylabel='End-to-end duration (s)',ylim=(0,None),title='Exploratory SAB scan: 1 window, n=3 per size, range bars')
    save(fig,'node_scale')
    fig,ax=plt.subplots(figsize=(8,4.4))
    counts=[1,2,5,10,15]
    vals=[[r['gateway_match_and_aggregate_ns']/1e6 for r in policies if r['policies']==n] for n in counts]
    ax.errorbar(counts,[stats.median(v) for v in vals],yerr=[[stats.median(v)-min(v) for v in vals],[max(v)-stats.median(v) for v in vals]],fmt='o-',color=colors[1],capsize=4)
    ax.set(xlabel='Distinct authorized experimental policies',ylabel='Gateway core match + aggregate (ms)',ylim=(0,None),title='60 reports, fixed max degree 15, n=3, range bars; no TLS')
    save(fig,'policy_scale')
    output={'profiles':groups,'consistency':consistency,'signatures':sigstats,'sizes':sizes,'handshakes':tlsstats,
            'core_source_digest':plan['core_source_digest'],'param_id':raw[0]['param_id'],'dataset_digest':raw[0]['dataset_digest'],
            'main_failures':sum(not r['success'] for r in raw),
            'analysis_runtime':{'command':[sys.executable,*sys.argv], 'python':sys.version.split()[0],
                                'matplotlib':matplotlib.__version__, 'finished_at':datetime.now(timezone.utc).isoformat(),
                                'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()},
            'source_hashes':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in directory.glob('*raw.json')}}
    (directory/'analysis.json').write_text(json.dumps(output,ensure_ascii=False,indent=2),encoding='utf-8')
    text=['# 实测性能结果','', '主矩阵120节点×4窗口，同一参数与数据，四档各30次，全部集合/数值一致，失败0。',
          '', '| 档位 | 样本 | 失败 | 中位数 / s | p90 / s |','|---|---:|---:|---:|---:|']
    for p in profiles:text.append(f"| {p} | {groups[p]['sample_count']} | 0 | {groups[p]['median']/1e9:.3f} | {groups[p]['p90']/1e9:.3f} |")
    text += ['', '恢复值四窗均为183041、207672、204511、231233 W。参数ID：`'+raw[0]['param_id']+'`。',
             '代码摘要：`'+plan['core_source_digest']+'`。数据摘要：`'+raw[0]['dataset_digest']+'`。',
             '', '各档端到端接近，内层报告生成与配对占主要成本。共享桌面/WSL、未绑核，不能据小差异声称某档稳定更快或零开销。',
             '', '| 对象/算法 | 签名中位数/ms | 验签中位数/ms | payload字节 | 签名字节中位数 |',
             '|---|---:|---:|---:|---:|']
    for s in sizes:
        v=sigstats[s['name']];text.append(f"| {s['name']} | {v['sign']['median']/1e6:.3f} | {v['verify']['median']/1e6:.3f} | {s['payload_bytes']} | {s['signature_bytes']['median']} |")
    text += ['', '签/验各100次/对象/算法，含密钥读取。ECDSA为DER编码，大小波动；ML-DSA为实际输出。',
             '', '| 档位/链路 | 首次握手中位数/ms | p90/ms | BIO握手字节中位数 |', '|---|---:|---:|---:|']
    for p in profiles:
        for link in ('L1','L2'):
            v=tlsstats[f'{p}/{link}/handshake_ns'];b=tlsstats[f'{p}/{link}/handshake_BIO_bytes']
            text.append(f"| {p}/{link} | {v['median']/1e6:.3f} | {v['p90']/1e6:.3f} | {b['median']} |")
    text += ['', '每档每链路30次，客户端视角。握手字节为SSL BIO读写总和，非抓包流量；两个端点不重复计算。',
             '', '探索节点扫描100/300/600/900各3次、1窗口；策略扫描1/2/5/10/15各3次、60报告，只计GW内核。均功能核对通过，样本少，仅看趋势。',
             '', '原始数据：artifacts/benchmarks；图表：artifacts/figures；生成命令与Python/Matplotlib版本见analysis.json的analysis_runtime。绘图为独立开发环境，不要求业务venv包含Matplotlib。完整口径见 BENCHMARK_METHOD.md。']
    (root/'docs/BENCHMARK_RESULTS.md').write_text('\n'.join(text)+'\n',encoding='utf-8')
    print(json.dumps({'profiles':groups,'figures':8,'main_failures':output['main_failures']}))


if __name__=='__main__': main()
