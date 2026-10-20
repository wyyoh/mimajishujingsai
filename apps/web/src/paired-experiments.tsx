import React,{useState} from 'react';
import {api} from './http';
import {StatusTag,HashValue} from './presentation';

type Numeric=number|string;
type Arm={samples:number;median_elapsed_ns:Numeric;min_elapsed_ns:number;max_elapsed_ns:number};
type Series={nodes:number;core_source_digest:string;current_version_matches:boolean;formal_pairs:number;warmup_pairs:number;failures:number;median_paired_difference_ns:Numeric;median_paired_overhead_ratio:Numeric;arms:{C0:Arm;C1:Arm};main_latency_goal_observed:number|null};
type Measurements={status:string;current_version_matches:boolean;uniform_source_version?:boolean;measurement_amendment_note?:string;configurations:Series[]};
const seconds=(value:Numeric)=>(Number(value)/1e9).toFixed(2);

export function PairedExperiments() {
  const [record,setRecord]=useState<Measurements>(),[busy,setBusy]=useState(false),[error,setError]=useState('');
  async function load(){setBusy(true);setError('');try{setRecord(await api<Measurements>('/lab/publication/benchmarks'));}catch(value){setError(String(value));}finally{setBusy(false);}}
  function download(){const blob=new Blob([JSON.stringify(record,null,2)],{type:'application/json'}),url=URL.createObjectURL(blob),link=document.createElement('a');link.href=url;link.download='grid-publication-paired-measurements.json';link.click();URL.revokeObjectURL(url);}
  return <section className="ui-panel response-measurements" aria-label="发布保护同条件实验"><div className="ui-panel-heading"><div><h3>发布保护的同条件实测</h3><p>同一批输入、三数据源、四日期16个窗口，两组均完成真实密码计算。</p></div><div className="v41-actions"><button className="v41-primary" disabled={busy} onClick={()=>void load()}>{busy?'读取中…':'读取成对实验'}</button>{record&&<button className="v41-secondary" onClick={download}>下载实验摘要</button>}</div></div>
    {error&&<p role="alert">{error}</p>}
    {record?.configurations.length?<><div className="grid-benchmark-heading"><StatusTag tone={record.current_version_matches?'good':'warn'}>{record.current_version_matches?'当前版本实测':record.uniform_source_version===false?'分版本实测':'历史版本实测'}</StatusTag></div><div className="v41-table-wrap"><table><thead><tr><th>输入计量点</th><th>正式配对 / 正式失败</th><th>启用保护</th><th>实验对照</th><th>逐对差值中位数</th></tr></thead><tbody>{record.configurations.map(row=><tr key={row.nodes}><td>{row.nodes}</td><td>{row.formal_pairs} / {row.failures}</td><td>{seconds(row.arms.C1.median_elapsed_ns)}秒</td><td>{seconds(row.arms.C0.median_elapsed_ns)}秒</td><td>{seconds(row.median_paired_difference_ns)}秒（{(Number(row.median_paired_overhead_ratio)*100).toFixed(2)}%）</td></tr>)}</tbody></table></div><details><summary>样本范围与预设目标</summary>{record.measurement_amendment_note&&<p>{record.measurement_amendment_note}</p>}{record.configurations.map(row=><div key={row.nodes}><p>{row.nodes}点：保护组{seconds(row.arms.C1.min_elapsed_ns)}—{seconds(row.arms.C1.max_elapsed_ns)}秒；对照组{seconds(row.arms.C0.min_elapsed_ns)}—{seconds(row.arms.C0.max_elapsed_ns)}秒。另做{row.warmup_pairs}对预热，不计入正式样本。{row.main_latency_goal_observed!==null&&`保护组${row.main_latency_goal_observed}/${row.formal_pairs}次在180秒内完成；事前目标为至少9/10。`}</p><HashValue label={`${row.nodes}点代码${row.current_version_matches?'（当前）':'（历史）'}`} value={row.core_source_digest}/></div>)}</details></>:<div className="response-empty"><div><strong>{record?'尚无正式成对实验记录':'查看发布保护的同条件对照'}</strong><p>读取正式样本，查看启用保护与实验对照的耗时差异。</p></div></div>}
    <details><summary>实验配置与计时口径</summary><p>C1执行发布检查与历史事务；C0为隔离实验对照。两组采用相同输入、密码配置、加密、签名及核验次数，实验数值保存在私有记录。</p><p>计时覆盖任务接纳后的密态计算、内部核验与证据收集。同一WSL主机串行运行，逐配置保留构建版本与正式样本，表格采用中位数等描述统计。</p></details>
  </section>;
}
