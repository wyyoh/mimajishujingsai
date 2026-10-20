import React, {useEffect,useState} from 'react';
import {api} from './http';
import {GridIcon,StatusTag,HashValue} from './presentation';
import './response-workspace.css';

type Rational={numerator:string;denominator:string};
type Point={slot:{slot_start:string;slot_end:string};baseline_W:Rational;event_W:number;difference_W:Rational};
type Evaluation={mode:string;simulation_basis_points:number;metrics:{mean_reduction_kW:Rational;relative_change_percent:Rational|null;energy_difference_kWh:Rational;registered_metering_points:number;coverage_basis_points:number;curve:Point[]}};
type RecordView={run_id:string;status:string;dataset_id?:string;node_count?:number;logical_source_process_count?:number;evaluation_id?:string;publication_status?:string;children?:{day:number;status:string}[]};
type Dataset={dataset_id:string;source:string;node_counts:number[]};
const numeric=(value:Rational|null)=>value?Number(value.numerator)/Number(value.denominator):null;
const display=(value:Rational|null)=>{const n=numeric(value);return n===null?'不适用':n.toLocaleString('zh-CN',{maximumFractionDigits:2});};

export function ReleaseNotice({status}:{status?:string}) {
  if(!status)return null;
  const published=status==='PUBLISHED';
  return <div className={`release-notice ${published?'is-published':''}`} role="status"><GridIcon name={published?'check':'shield'} size={21}/><div><strong>{published?'结果已通过发布检查':status==='WAITING_FOR_EVALUATION'?'计算进行中，结果尚未发布':status==='WITHHELD'?'本次结果未发布':'本次未产生公开结果'}</strong><p>{published?'按完整分组核对参与规模，并关联发布记录与签名声明。':'发布检查核对群体规模、完整上报与历史记录，通过后展示结果及公开证据。'}</p></div></div>;
}

export function ResponseWorkspace({datasets,region,run,disabled,onRun,onVerify,onCancel,onReset}:{datasets:Dataset[];region:string;run?:RecordView;disabled:boolean;onRun:(body:Record<string,unknown>)=>Promise<void>;onVerify:()=>void;onCancel:()=>void;onReset:()=>void}) {
  const [dataset,setDataset]=useState('SYN-WEEK-V42'),[nodes,setNodes]=useState(300),[sourceCount,setSourceCount]=useState(3);
  const [result,setResult]=useState<{evaluation:Evaluation|null}>(),[error,setError]=useState('');
  const active=run?.evaluation_id?run:undefined;
  useEffect(()=>{if(active){if(active.dataset_id)setDataset(active.dataset_id);if(active.node_count)setNodes(active.node_count);if(active.logical_source_process_count)setSourceCount(active.logical_source_process_count);}},[active?.run_id]);
  useEffect(()=>{setResult(undefined);setError('');if(!active||active.status==='RUNNING')return;let live=true;api<{evaluation:Evaluation|null}>(`/api/runs/${active.run_id}/evaluation`).then(value=>{if(live)setResult(value);}).catch(value=>{if(live)setError(String(value));});return()=>{live=false;};},[active?.run_id,active?.status]);
  const options=datasets.find(item=>item.dataset_id===dataset)?.node_counts||[120,300,900];
  const evaluation=result?.evaluation,metrics=evaluation?.metrics;
  const eventDate=metrics?.curve[0]?.slot.slot_start;
  const referenceDates=eventDate?[3,2,1].map(days=>new Date(new Date(eventDate).getTime()-days*86400000).toISOString().slice(0,10)):[];
  const submit=()=>onRun({dataset_id:dataset,nodes,source_count:sourceCount,scene_id:'park',region,function:'SUM',asset_id:'household-load-demo',algorithm_suite:'V41_HYBRID_SM',day:4,periods:[68,69,70,71],request_nonce:crypto.randomUUID().replaceAll('-','')});
  return <section className="response-workspace" aria-label="园区需求响应评估"><div className="response-heading"><div><h3>用群体负荷评估响应变化</h3><p>三个参考日、一个事件日，同一群体完成密态计算与指标核验。</p></div><StatusTag tone="blue">{dataset==='SYN-WEEK-V42'?'受控响应模拟':'历史负荷对比'}</StatusTag></div>
    <div className="response-settings"><label>数据<select aria-label="评估数据" value={dataset} disabled={disabled} onChange={event=>{setDataset(event.target.value);setNodes(300);onReset();}}><option value="SYN-WEEK-V42">合成园区负荷</option>{datasets.some(item=>item.dataset_id.startsWith('UCI'))&&<option value="UCI370-WEEK-20130603-V1">UCI公开负荷</option>}</select></label><label>输入规模<select aria-label="评估规模" value={nodes} disabled={disabled} onChange={event=>{setNodes(Number(event.target.value));onReset();}}>{options.map(value=><option key={value} value={value}>{value}个计量点</option>)}</select></label><label>数据源<select aria-label="评估数据源数量" value={sourceCount} disabled={disabled} onChange={event=>{setSourceCount(Number(event.target.value));onReset();}}>{[1,2,3].map(value=><option key={value} value={value}>{value}个独立进程</option>)}</select></label><div className="response-protection"><GridIcon name="shield" size={18}/><span>混合密码与国密增强<br/><small>固定分组，至少10个计量点，完整上报</small></span></div></div>
    <div className="response-execution"><ol aria-label="四日期任务进度">{['参考日一','参考日二','参考日三','事件日'].map((label,index)=>{const done=!!active?.children?.[index]&&active.children[index].status==='COMPUTED';return <li key={label} className={done?'is-ready':''}><GridIcon name={done?'check':'clock'} size={17}/><span>{label}</span><small>4个时段</small></li>;})}</ol><button className="v41-primary" disabled={disabled} onClick={()=>void submit()}><GridIcon name="run" size={17}/>{active?.status==='RUNNING'?'正在完成四日期评估…':'运行园区评估'}</button>{active?.status==='RUNNING'&&<button className="v41-secondary" onClick={onCancel}>取消评估</button>}</div>
    <p className="response-scope">{dataset==='SYN-WEEK-V42'?'合成园区场景采用预设10%响应输入。':'UCI公开读数按模拟园区分组比较历史负荷。'}本机独立Source进程协同计算，获准参与人数随结果展示。</p>
    <ReleaseNotice status={active?.publication_status}/>{error&&<p role="alert">{error}</p>}
    {metrics?<><div className="response-metrics"><div><span>平均降负荷</span><strong>{display(metrics.mean_reduction_kW)}<small>kW</small></strong></div><div><span>相对参考变化</span><strong>{display(metrics.relative_change_percent)}<small>{metrics.relative_change_percent?'%':''}</small></strong></div><div><span>窗口能量差</span><strong>{display(metrics.energy_difference_kWh)}<small>kWh</small></strong></div><div><span>有效覆盖</span><strong>{(metrics.coverage_basis_points/100).toFixed(0)}<small>%</small></strong></div></div>
      <ResponseChart points={metrics.curve}/><div className="response-result-foot"><span>{metrics.registered_metering_points}个登记计量点。负值表示事件负荷较参考水平增加。</span><button className="v41-link" onClick={onVerify}>核验发布决定与指标</button></div><details className="response-method"><summary>指标算法与数据说明</summary><p>参考日期（UTC区间）：{referenceDates.join("、")}；事件日期：{eventDate?.slice(0,10)}。</p><p>参考负荷取前三个指定工作日同一时段的均值；平均降负荷与相对变化据此计算。功率差按每时段900秒积分形成窗口能量差。合成事件的10%为预设输入，估算结果同时受参考日负荷影响。</p><p>四项指标从统计端签名输入精确复算；发布检查关联完整分组、参与规模及共享发布历史。</p><HashValue label="任务" value={active?.run_id}/></details></>:<div className="response-empty"><GridIcon name="chart" size={31}/><div><strong>{active?.publication_status==='WITHHELD'?'未满足发布条件，指标暂不提供':active?.status==='RUNNING'?'正在完成参考日与事件日的密态计算':'运行后查看参考负荷与事件负荷'}</strong><p>使用同一组计量点完成16个窗口。全部结果通过发布检查后，再展示对比曲线。</p></div></div>}
  </section>;
}

function ResponseChart({points}:{points:Point[]}) {
  const maximum=Math.max(1,...points.flatMap(point=>[numeric(point.baseline_W)||0,point.event_W]));
  const x=(index:number)=>65+index*210,y=(value:number)=>215-value/maximum*165;
  const baseline=points.map((point,index)=>`${x(index)},${y(numeric(point.baseline_W)||0)}`).join(' ');
  const event=points.map((point,index)=>`${x(index)},${y(point.event_W)}`).join(' ');
  return <figure className="response-chart"><figcaption><strong>参考负荷与事件负荷</strong><span><i className="reference"/>三日参考<i className="observed"/>事件负荷</span></figcaption><svg viewBox="0 0 760 265" role="img" aria-label="四个已核验事件时段的参考负荷与事件负荷，单位千瓦"><text x="18" y="24">kW</text>{[0,1,2,3].map(index=><g className="response-axis" key={index}><line x1="65" x2="695" y1={215-index*55} y2={215-index*55}/><text x="53" y={219-index*55} textAnchor="end">{(maximum*index/3000).toFixed(1)}</text></g>)}<polygon points={`${baseline} ${points.slice().reverse().map((point,index)=>`${x(3-index)},${y(point.event_W)}`).join(' ')}`}/><polyline className="reference" points={baseline}/><polyline className="observed" points={event}/>{points.map((point,index)=><g key={point.slot.slot_start}><circle cx={x(index)} cy={y(point.event_W)} r="4"/><text x={x(index)} y="244" textAnchor="middle">{point.slot.slot_start.slice(11,16)} UTC</text></g>)}</svg></figure>;
}
