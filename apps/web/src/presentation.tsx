import React from 'react';

export type Tone = 'neutral' | 'blue' | 'good' | 'warn' | 'bad';

export function GridIcon({ name, size = 20 }: { name: string; size?: number }) {
  const paths: Record<string, React.ReactNode> = {
    grid: <><path d="M4 5h16M4 12h16M4 19h16M7 3v18M17 3v18"/><circle cx="7" cy="12" r="2.5"/><circle cx="17" cy="5" r="2.5"/></>,
    home: <><path d="m3 11 9-8 9 8M5 10v11h14V10M10 21v-7h4v7"/></>,
    park: <><path d="M3 21h18M5 21V9l7 3V4h7v17M8 15v2M15 8h1M15 12h1M15 16h1"/></>,
    charging: <><path d="M5 21V5a2 2 0 0 1 2-2h7a2 2 0 0 1 2 2v16M3 21h15M16 9h2l3 4v5a2 2 0 0 1-4 0v-4M9 6l-2 4h4l-2 4"/></>,
    chart: <><path d="M4 3v18h17M7 15l4-6 4 3 5-7"/></>,
    task: <><rect x="5" y="4" width="14" height="17" rx="2"/><path d="M9 3h6v4H9zM9 12h6M9 16h4"/></>,
    source: <><ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v7c0 4 16 4 16 0V5M4 12v7c0 4 16 4 16 0v-7"/></>,
    shield: <><path d="m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6l8-3Z"/><path d="m8 12 3 3 5-6"/></>,
    receipt: <><path d="M6 3h12v18l-3-2-3 2-3-2-3 2V3Z"/><path d="M9 7h6M9 11h6M9 15h3"/></>,
    check: <path d="m5 12 4 4L19 6"/>,
    clock: <><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></>,
    lock: <><rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v3"/></>,
    audit: <><path d="M7 4h13M7 12h13M7 20h13"/><circle cx="3" cy="4" r="1"/><circle cx="3" cy="12" r="1"/><circle cx="3" cy="20" r="1"/></>,
    info: <><circle cx="12" cy="12" r="9"/><path d="M12 11v6M12 7h.01"/></>,
    run: <path d="m8 4 12 8-12 8V4Z"/>,
    download: <><path d="M12 3v12m-5-5 5 5 5-5M4 17v4h16v-4"/></>,
    arrow: <path d="M4 12h16m-6-6 6 6-6 6"/>,
    close: <path d="m6 6 12 12M6 18 18 6"/>,
  };
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[name] || paths.info}</svg>;
}

export function StatusTag({ children, tone = 'neutral' }: { children: React.ReactNode; tone?: Tone }) {
  return <span className={`ui-tag ui-tag-${tone}`}><span aria-hidden="true"/>{children}</span>;
}

export function EmptyState({ title, children, action }: { title: string; children?: React.ReactNode; action?: React.ReactNode }) {
  return <div className="ui-empty"><GridIcon name="task" size={30}/><strong>{title}</strong>{children && <p>{children}</p>}{action}</div>;
}

export function HashValue({ value, label }: { value?: string; label?: string }) {
  return <span className="ui-hash" title={value}>{label && <small>{label}</small>}<code>{value ? `${value.slice(0, 16)}…${value.slice(-8)}` : '尚无记录'}</code></span>;
}

export function SingleLineFlow({ sourceCount = 1, completed = false, running = false, onNavigate, compact = false }: {
  sourceCount?: number; completed?: boolean; running?: boolean; onNavigate?: (role: 'source' | 'gateway' | 'utility') => void; compact?: boolean;
}) {
  return <figure className={`grid-flow ${compact ? 'grid-flow-compact' : ''}`} aria-label="数据源、聚合网关和统计端的密态统计流程">
    <figcaption><span>一次协同统计怎样完成</span><StatusTag tone={completed ? 'good' : running ? 'blue' : 'neutral'}>{completed ? '已有实际运行记录' : running ? '任务正在执行' : '流程示意'}</StatusTag></figcaption>
    <div className="grid-flow-line">
      <div className="grid-flow-sources">{Array.from({ length: sourceCount }, (_, index) => <button className="grid-flow-source" key={index} onClick={() => onNavigate?.('source')} type="button"><GridIcon name="source"/><span>数据源{sourceCount > 1 ? ` ${index + 1}` : ''}<small>明细在源侧加密</small></span><i aria-hidden="true"/></button>)}</div>
      <div className="grid-flow-wire"><span>密文报告</span><svg viewBox="0 0 100 30" aria-hidden="true"><path d="M0 15h98m-7-6 7 6-7 6"/><circle cx="14" cy="15" r="3"/></svg><small>身份与授权检查</small></div>
      <button type="button" className="grid-flow-actor" onClick={() => onNavigate?.('gateway')}><span className="grid-flow-icon"><GridIcon name="shield" size={27}/></span><strong>聚合网关</strong><small>按授权选择密文<br/>计算群体统计</small><em>GW</em></button>
      <div className="grid-flow-wire"><span>聚合密文</span><svg viewBox="0 0 100 30" aria-hidden="true"><path d="M0 15h98m-7-6 7 6-7 6"/><circle cx="14" cy="15" r="3"/></svg><small>签名回执随行</small></div>
      <button type="button" className="grid-flow-actor grid-flow-utility" onClick={() => onNavigate?.('utility')}><span className="grid-flow-icon"><GridIcon name="chart" size={27}/></span><strong>统计端</strong><small>核验回执<br/>解密群体结果</small><em>UC</em></button>
    </div>
    <div className="grid-flow-foot"><span><GridIcon name="lock" size={15}/>网关只接触密文和获准的任务信息</span><span>{sourceCount}个Source进程，同一物理主机</span></div>
  </figure>;
}

export type DisplayResult = { slot_id: string; value_W?: number | null; published_value?: { value: string | null; unit: string; function: string; numerator?: number; denominator?: number } };
export function numericResult(result: DisplayResult) {
  const value = result.published_value;
  if (value ? value.value === null : result.value_W === null) return null;
  if (value?.function === 'AVG' && value.denominator && value.numerator !== undefined) return value.numerator / value.denominator;
  const raw = value?.value ?? result.value_W;
  if (typeof raw === 'string' && raw.includes('/')) { const [n, d] = raw.split('/').map(Number); return d ? n / d : null; }
  const number = Number(raw);
  return Number.isFinite(number) ? number : null;
}

export function resultDisplay(result: DisplayResult) {
  const value = numericResult(result);
  if (value === null) return { value: '无有效数据', unit: '' };
  if (result.published_value?.unit === 'reports') return { value: value.toLocaleString('zh-CN'), unit: '份报告' };
  return { value: value.toLocaleString('zh-CN', { maximumFractionDigits: 2 }), unit: result.published_value?.unit || 'W' };
}

export function ResultCurve({ results, selected, onSelect }: { results: DisplayResult[]; selected: number; onSelect: (index: number) => void }) {
  const values = results.map(numericResult);
  const count = results[0]?.published_value?.unit === 'reports';
  const divisor = count ? 1 : 1000;
  const maximum = Math.max(...values.map(value => (value ?? 0) / divisor), 1);
  const x = (index: number) => results.length === 1 ? 385 : 58 + index / (results.length - 1) * 650;
  const y = (value: number) => 175 - value / divisor / maximum * 130;
  return <div className="ui-result-curve"><svg viewBox="0 0 760 225" role="img" aria-label="本次任务各时段的实际统计结果">
    <text x="16" y="22">{count ? '份报告' : 'kW'}</text>
    {[0,1,2,3].map(index => <g key={index}><line x1="58" x2="710" y1={175-index*130/3} y2={175-index*130/3}/><text x="47" y={179-index*130/3} textAnchor="end">{(maximum*index/3).toFixed(count ? 0 : 1)}</text></g>)}
    {values.every(value => value !== null) && <polyline points={values.map((value, index) => `${x(index)},${y(value!)}`).join(' ')}/>}
    {values.map((value, index) => <g key={results[index].slot_id}><text x={x(index)} y="205" textAnchor="middle">时段{index+1}</text>{value !== null && <circle cx={x(index)} cy={y(value)} r={selected === index ? 7 : 5}><title>{`时段${index+1}：${resultDisplay(results[index]).value} ${resultDisplay(results[index]).unit}`}</title></circle>}</g>)}
  </svg><div className="ui-segmented" aria-label="选择结果时段">{results.map((value,index) => <button type="button" key={value.slot_id} aria-pressed={selected===index} onClick={() => onSelect(index)}>时段{index+1}</button>)}</div></div>;
}
