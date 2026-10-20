import React from 'react';
export type ScaleRow = { axis: string; nodes: number; source_count: number; samples: number; median_elapsed_ns: number; min_elapsed_ns?: number; max_elapsed_ns?: number };
export function ScaleCharts({ rows }: { rows: ScaleRow[] }) {
  return <div className="v42-scale-charts">{(['nodes','sources'] as const).map(axis=>{
    const values=rows.filter(row=>row.axis===axis).sort((a,b)=>axis==='nodes'?a.nodes-b.nodes:a.source_count-b.source_count);
    if(!values.length)return null;
    const maximum=Math.max(...values.map(row=>row.max_elapsed_ns||row.median_elapsed_ns),1);
    const maxX=axis==='nodes'?Math.max(...values.map(row=>row.nodes)):Math.max(...values.map(row=>row.source_count));
    const x=(row:ScaleRow)=>60+(axis==='nodes'?row.nodes:row.source_count)/maxX*680;
    const y=(value:number)=>210-value/maximum*175;
    return <div key={axis}><h3>{axis==='nodes'?'节点规模与任务耗时':'数据源数量与任务耗时'}</h3><svg viewBox="0 0 800 260" role="img" aria-label={axis==='nodes'?'节点规模与任务耗时':'数据源数量与任务耗时'}>{[0,1,2,3,4].map(i=><g key={i}><line x1="60" x2="750" y1={210-i*175/4} y2={210-i*175/4} stroke="#e4ecef"/><text x="49" y={214-i*175/4} textAnchor="end" fontSize="12" fill="#688b9b">{(maximum*i/4/1e9).toFixed(1)}</text></g>)}<text x="16" y="20" fontSize="12" fill="#688b9b">秒</text><polyline points={values.map(row=>`${x(row)},${y(row.median_elapsed_ns)}`).join(' ')} fill="none" stroke="#168e80" strokeWidth="2"/>{values.map(row=><g key={`${row.nodes}-${row.source_count}`}><line x1={x(row)} x2={x(row)} y1={y(row.min_elapsed_ns||row.median_elapsed_ns)} y2={y(row.max_elapsed_ns||row.median_elapsed_ns)} stroke="#6caaa0" strokeWidth="3"/><circle cx={x(row)} cy={y(row.median_elapsed_ns)} r="5" fill="#168e80"><title>{axis==='nodes'?row.nodes:row.source_count} · {row.samples}次 · 中位数{(row.median_elapsed_ns/1e9).toFixed(2)}秒</title></circle><text x={x(row)} y={y(row.median_elapsed_ns)-12} textAnchor="middle" fontSize="12" fill="#33586b">{(row.median_elapsed_ns/1e9).toFixed(2)}</text><text x={x(row)} y="239" textAnchor="middle" fontSize="12" fill="#688b9b">{axis==='nodes'?`${row.nodes}节点`:`${row.source_count}个源`}</text></g>)}</svg><p className="v41-muted">圆点表示耗时中位数，竖线表示样本的最小值至最大值，不是置信区间。{axis==='nodes'?'数据源数量固定为3个独立Source进程。':'逻辑节点数量固定为120个。'}</p></div>;
  })}</div>;
}
