import { GridIcon, HashValue, StatusTag, type Tone } from './presentation';
import { checkText } from './wording';
import './self-check.css';

type CheckItem = { id: string; label: string; status: string; category?: string; summary?: string; risk: string; recommendation?: string; evidence?: Record<string, unknown> };
export type CheckReport = {
  checked_at?: string; run_id?: string | null; selection?: string; version_matches?: boolean;
  core_source_digest?: string; functional_overall?: string;
  counts?: { functional_pass: number; functional_total: number; functional_not_applicable: number; open_assurance: number };
  checks: CheckItem[];
};
const names: Record<string, string> = { PASS: '检查通过', FAIL: '检查未通过', PARTIAL: '部分完成', PENDING: '待进一步论证', STALE: '历史版本证据', NOT_RUN: '缺少任务证据', NOT_APPLICABLE: '本任务不适用' };
const tones: Record<string, Tone> = { PASS: 'good', FAIL: 'bad', STALE: 'blue', NOT_APPLICABLE: 'neutral' };

function Item({ item }: { item: CheckItem }) {
  return <article data-check-id={item.id} data-check-status={item.status}>
    <div><h4>{checkText(item.label)}</h4><StatusTag tone={tones[item.status] || 'warn'}>{names[item.status] || item.status}</StatusTag></div>
    <p>{item.summary || '执行检查后查看当前结果。'}</p>
    {typeof item.evidence?.error === 'string' && <code className="self-check-error">{item.evidence.error}</code>}
    <details><summary>检查范围与记录</summary>
      <p>检查结果与当前代码、任务和实际执行记录关联。</p>
      {item.evidence && <details><summary>查看验证字段</summary><pre>{JSON.stringify(item.evidence, null, 2)}</pre></details>}
    </details>
  </article>;
}

export function SelfCheckResults({ report }: { report: CheckReport }) {
  const functional = report.checks.filter(item => !item.category || item.category === 'functional');
  const passed = report.functional_overall === 'PASS';
  const failed = report.functional_overall === 'FAIL';
  const count = report.counts?.functional_pass ?? functional.filter(item => item.status === 'PASS').length;
  return <div className="self-check-results" aria-live="polite">
    <div className={`self-check-lead ${passed ? 'passed' : ''}`}>
      <GridIcon name={failed ? 'info' : 'shield'} size={30}/>
      <div><h4>{passed ? '本机功能检查通过' : failed ? '有功能检查未通过' : '部分检查仍需当前任务证据'}</h4>
        <p>{count}项通过，共{functional.length}项功能检查{report.counts?.functional_not_applicable ? `；${report.counts.functional_not_applicable}项不适用于本任务` : ''}。每项均可查看检查记录。</p>
      </div><StatusTag tone={passed ? 'good' : failed ? 'bad' : 'warn'}>{passed ? '功能验证通过' : '需要继续核对'}</StatusTag>
    </div>
    <div className="self-check-context">
      <span>{report.selection === 'LATEST_AUTHORIZED' ? '自动选取本账户可访问的任务' : report.run_id ? '核对当前选中的任务' : '尚无可用任务，请先运行一次协同任务'}</span>
      {report.run_id && <code title={report.run_id}>{report.run_id.slice(0, 12)}</code>}
      {report.run_id && <StatusTag tone={report.version_matches ? 'blue' : 'warn'}>{report.version_matches ? '当前代码版本' : '任务来自历史代码版本'}</StatusTag>}
      <HashValue value={report.core_source_digest} label="检查代码"/>
    </div>
    <div className="grid-check-list">{functional.map(item => <Item key={item.id} item={item}/>)}</div>
  </div>;
}
