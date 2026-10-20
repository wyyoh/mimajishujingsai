import React, { useEffect, useState, useRef } from "react";
import { createRoot } from "react-dom/client";
import "./style.css";
import { V41App } from "./v41";
import { ExpansionApp } from './expansion';
import { api, requestJSON, LOGIN_REQUIRED_EVENT } from "./http";
import { OperatorLogin, type OperatorSession } from "./operator-login";
import { errorText, subjectName } from "./wording";
import "./compatibility.css";

type Config = {
  lab_enabled: boolean;
  param_id: string;
  core_version: string;
  core_audit_status: string;
};
type Result = {
  slot_id: string;
  value_W: number | null;
  counts: {
    received: number;
    accepted: number;
    joint_check_failed: number;
    invalid: number;
    duplicate: number;
  };
  expected_target_count: number;
  coverage_basis_points: number | null;
  status: string;
};
type Run = {
  run_id: string;
  task_id?: string;
  status: string;
  security_profile: string;
  execution_mode: string;
  data_source: string;
  dataset_id?: string;
  elapsed_ns?: number;
  node_count: number;
  slot_count: number;
  results: Result[];
  oracle_match?: boolean;
  errors?: { code: string; message: string; role: string }[];
  started_at?: string;
  display_policy?: { region: string; resources: string[] };
};
type Event = {
  role: string;
  stage: string;
  slot_id?: string;
  report_count?: number;
  at: string;
  sequence: number;
};
type Connection = {
  link_id: string;
  actual_group: string;
  tls_version: string;
  peer_verified: boolean;
  peer_identity_verified: boolean;
  connection_id: string;
  handshake_ns: number;
  business_request_refs: string[];
  record_cipher: string;
  certificate_signature_algorithm: string;
};
type Sig = {
  signature_valid: boolean;
  ecdsa_valid: boolean | null;
  mldsa_valid: boolean | null;
  context_valid?: boolean;
  native_verification_valid?: boolean;
  slot_id?: string;
};
type Evidence = {
  connection_evidence: Connection[] | null;
  signature_evidence: Sig[] | null;
  authorization_evidence: Sig | null;
  rejection_evidence?: Record<
    string,
    { code: string; signature_evidence: Sig | null }
  > | null;
  oracle_summary?: {
    slot_id: string;
    set_match: boolean;
    value_match: boolean;
    expected_sum_W: number | null;
    actual_sum_W: number | null;
  }[];
};
type Bench = {
  status: string;
  profiles: {
    profile: string;
    sample_count: number;
    failure_count: number;
    median_ns: number;
    p90_ns: number;
  }[];
};
const title = "面向新型电网的细粒度密态聚合与可信数据协同平台";
const names: Record<string, string> = {
  residential: "居民负荷",
  commercial: "工商业负荷",
  charging: "充电设施",
};
const states: Record<string, string> = {
  RUNNING: "执行中",
  COMPLETED: "已完成",
  PARTIAL: "部分完成",
  REJECTED: "未通过",
  FAILED: "执行失败",
  CANCELLED: "已取消",
};
const stages: Record<string, string> = {
  AUTH_READY: "授权已就绪",
  COLLECTING: "正在收集报告",
  REPORTS_READY: "报告已生成",
  SEALED: "密文快照已生成",
  AGGREGATED: "密文聚合已完成",
  PUBLISHED: "结果已验证并发布",
  FAILED: "检查未通过",
  COMPLETED: "阶段已完成",
};
const scenarios = [
  ["normal", "正常统计"],
  ["modified_report", "修改报告"],
  ["missing", "20%目标报告缺失"],
  ["invalid_authorization", "授权内容被修改"],
  ["invalid_receipt", "回执内容被修改"],
  ["incompatible_tls", "通信保护不符"],
];
const icons: Record<string, React.ReactNode> = {
  bolt: <path d="m14 2-8 11h6l-2 9 8-12h-6l2-8Z" />,
  arrow: (
    <>
      <path d="M4 12h16m-6-6 6 6-6 6" />
    </>
  ),
  check: <path d="m5 12 4 4 10-10" />,
  shield: (
    <>
      <path d="m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6l8-3Z" />
      <path d="m8 12 3 3 5-6" />
    </>
  ),
  chart: (
    <>
      <path d="M4 4v16h17M7 15l4-5 4 3 5-7" />
    </>
  ),
  filter: <path d="M3 4h18l-7 8v7l-4 2v-9L3 4Z" />,
  download: <path d="M12 3v12m-5-5 5 5 5-5M4 16v5h16v-5" />,
  close: <path d="m6 6 12 12M6 18 18 6" />,
  info: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 11v6m0-10v1" />
    </>
  ),
  clock: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 7v5l3 2" />
    </>
  ),
};
function Icon({ name, size = 20 }: { name: string; size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {icons[name] ?? icons.info}
    </svg>
  );
}
async function get<T>(url: string): Promise<T> {
  return requestJSON<T>(url);
}
function Badge({
  value,
  label,
}: {
  value: boolean | null | undefined;
  label: string;
}) {
  return (
    <span
      className={
        "badge " +
        (value === true ? "good" : value === false ? "bad" : "neutral")
      }
    >
      <span className="dot" />
      {label}
    </span>
  );
}
function Chart({
  results,
  active,
  onSelect,
  slots,
}: {
  results: Result[];
  active: number;
  onSelect: (n: number) => void;
  slots: number;
}) {
  const values = results.map((r) =>
    r.value_W === null ? null : r.value_W / 1000,
  );
  const max = Math.max(
    50,
    Math.ceil(
      Math.max(...values.filter((v): v is number => v !== null), 0) / 50,
    ) * 50,
  );
  const x = (i: number) => (slots === 1 ? 370 : 80 + i * (570 / (slots - 1)));
  const y = (v: number) => 208 - (v / max) * 150;
  return (
    <div className="chart">
      <div className="chart-heading">
        <div>
          <h3>授权群体分时负荷</h3>
          <p>15分钟平均有功功率 · {slots}个统计时段</p>
        </div>
        <span className="small-tag">kW</span>
      </div>
      <svg
        viewBox="0 0 730 260"
        role="img"
        aria-label={`${slots}个统计窗口的群体负荷曲线`}
      >
        {[0, 1, 2, 3].map((i) => (
          <g key={i}>
            <line
              x1="70"
              x2="670"
              y1={208 - i * 50}
              y2={208 - i * 50}
              stroke="#e5edf3"
              strokeDasharray="4 5"
            />
            <text
              x="55"
              y={213 - i * 50}
              textAnchor="end"
              fill="#71879b"
              fontSize="12"
            >
              {Math.round((max * i) / 3)}
            </text>
          </g>
        ))}
        {values.length > 0 && (
          <polyline
            points={values
              .map((v, i) => (v === null ? "" : `${x(i)},${y(v)}`))
              .filter(Boolean)
              .join(" ")}
            fill="none"
            stroke="#159895"
            strokeWidth="3"
          />
        )}
        {Array.from({ length: slots }, (_, i) => i).map((i) => (
          <g key={i} onClick={() => onSelect(i)} style={{ cursor: "pointer" }}>
            {values[i] !== undefined && values[i] !== null && (
              <>
                <circle
                  cx={x(i)}
                  cy={y(values[i]!)}
                  r={active === i ? 8 : 5}
                  fill={active === i ? "#159895" : "white"}
                  stroke="#159895"
                  strokeWidth="3"
                />
                <text
                  x={x(i)}
                  y={y(values[i]!) - 17}
                  textAnchor="middle"
                  fontSize="14"
                  fill="#18344f"
                >
                  {values[i]!.toFixed(2)}
                </text>
              </>
            )}
            <text
              x={x(i)}
              y="243"
              textAnchor="middle"
              fill="#637a90"
              fontSize="13"
            >
              {["18:00–18:15", "18:15–18:30", "18:30–18:45", "18:45–19:00"][i]}
            </text>
          </g>
        ))}
        {!results.length && (
          <text
            x="370"
            y="125"
            textAnchor="middle"
            fill="#8194a6"
            fontSize="16"
          >
            运行后显示真实恢复结果
          </text>
        )}
      </svg>
    </div>
  );
}
function App() {
  const [session, setSession] = useState<OperatorSession>({ authenticated: false, subject: null });
  const [loginOpen, setLoginOpen] = useState(false), [loginNotice, setLoginNotice] = useState("");
  const [config, setConfig] = useState<Config | null>(null),
    [page, setPage] = useState(0),
    [region, setRegion] = useState("A"),
    [resources, setResources] = useState(["residential", "charging"]),
    [scenario, setScenario] = useState("normal"),
    [lab, setLab] = useState(false),
    [run, setRun] = useState<Run | null>(null),
    [events, setEvents] = useState<Event[]>([]),
    [evidence, setEvidence] = useState<Evidence | null>(null),
    [active, setActive] = useState(0),
    [drawer, setDrawer] = useState<"scope" | "evidence" | null>(null),
    [error, setError] = useState(""),
    [starting, setStarting] = useState(false),
    [reportTab, setReportTab] = useState(0),
    [bench, setBench] = useState<Bench | null>(null),
    [viewMode, setViewMode] = useState<"REAL" | "REPLAY">("REAL"),
    [historyRecords, setHistoryRecords] = useState<Partial<Run>[]>([]);
  const generation = useRef(0);
  const resumeRun = useRef<string | null>(new URLSearchParams(location.search).get("run"));
  const running = starting || run?.status === "RUNNING";
  const current = run?.results[active];
  useEffect(() => {
    api<OperatorSession>("/api/session").then(setSession).catch(e => setError(errorText(e)));
    const requireLogin = () => {
      resumeRun.current = new URLSearchParams(location.search).get("run");
      generation.current++;
      setSession(previous => ({ authenticated: false, subject: previous.subject }));
      setLoginNotice("登录已失效或尚未登录，请重新登录后继续操作。");
      setLoginOpen(true); setRun(null); setEvidence(null); setEvents([]); setHistoryRecords([]);
    };
    window.addEventListener(LOGIN_REQUIRED_EVENT, requireLogin);
    return () => window.removeEventListener(LOGIN_REQUIRED_EVENT, requireLogin);
  }, []);
  useEffect(() => {
    get<Config>("/api/config")
      .then(setConfig)
      .catch(() => setError("暂时无法连接本地服务，请确认服务已启动后重试。"));
  }, []);
  useEffect(() => {
    const id = resumeRun.current;
    if (session.authenticated && id) { resumeRun.current = null; loadRecord(id, 1); }
  }, [session.authenticated]);
  useEffect(() => {
    if (page === 2 && session.authenticated)
      get<Partial<Run>[]>("/api/runs")
        .then(setHistoryRecords)
        .catch(() => setHistoryRecords([]));
  }, [page, run?.status, session.authenticated]);
  useEffect(() => {
    if (page === 2 && reportTab === 2 && lab)
      get<Bench>("/lab/benchmarks")
        .then(setBench)
        .catch(() => setBench(null));
  }, [page, reportTab, lab]);
  useEffect(() => {
    if (!session.authenticated || !run?.run_id || run.status !== "RUNNING") return;
    let stopped = false;
    const id = run.run_id;
    const tick = async () => {
      try {
        const [next, ev] = await Promise.all([
          get<Run>(`/api/runs/${id}`),
          get<Event[]>(`/api/runs/${id}/events`),
        ]);
        if (stopped) return;
        setRun(next);
        setEvents(ev);
      } catch (e) {
        if (!stopped) setError(errorText(e));
      }
    };
    tick();
    const timer = setInterval(tick, 700);
    return () => {
      stopped = true;
      clearInterval(timer);
    };
  }, [run?.run_id, run?.status, session.authenticated]);
  useEffect(() => {
    if (!session.authenticated || !run?.run_id || run.status === "RUNNING") return;
    let stopped = false;
    get<Evidence>(`/api/runs/${run.run_id}/evidence`)
      .then((e) => {
        if (!stopped) setEvidence(e);
      })
      .catch((e) => {
        if (!stopped) setError(errorText(e));
      });
    return () => {
      stopped = true;
    };
  }, [run?.run_id, run?.status, session.authenticated]);
  function clear() {
    generation.current++;
    setViewMode("REAL");
    history.replaceState(null, "", "?legacy=1");
    resumeRun.current = null;
    setRun(null);
    setEvidence(null);
    setEvents([]);
    setActive(0);
    setError("");
  }
  function toggle(r: string) {
    if (running) return;
    clear();
    setResources((old) =>
      old.includes(r) ? old.filter((x) => x !== r) : [...old, r],
    );
  }
  async function start() {
    if (!session.authenticated) {
      setLoginNotice("请先登录，再运行协同任务。当前选择的数据范围将保留。");
      setLoginOpen(true); return;
    }
    generation.current++;
    setViewMode("REAL");
    setStarting(true);
    setError("");
    setRun(null);
    setEvidence(null);
    setEvents([]);
    setActive(0);
    try {
      const body = await requestJSON<{ run_id: string }>(lab ? "/lab/runs" : "/api/runs", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": crypto.randomUUID(),
        },
        body: JSON.stringify({
          region,
          resources,
          scenario: lab ? scenario : "normal",
          nodes: 120,
          slots: 4,
        }),
      });
      history.replaceState(null, "", `?legacy=1&run=${body.run_id}`);
      setRun({
        run_id: body.run_id,
        status: "RUNNING",
        security_profile: "SAB",
        execution_mode: "REAL",
        data_source: "SYNTHETIC",
        node_count: 120,
        slot_count: 4,
        results: [],
      });
    } catch (e) {
      setError(errorText(e));
    } finally {
      setStarting(false);
    }
  }
  async function loadRecord(id: string, targetPage = 2) {
    const ticket = ++generation.current;
    setStarting(true);
    setError("");
    try {
      const [record, storedEvents, storedEvidence] = await Promise.all([
        get<Run>(`/api/runs/${id}`),
        get<Event[]>(`/api/runs/${id}/events`),
        get<Evidence>(`/api/runs/${id}/evidence`),
      ]);
      if (ticket !== generation.current) return;
      if (record.display_policy) {
        setRegion(record.display_policy.region);
        setResources(record.display_policy.resources);
      }
      setRun(record);
      setEvents(storedEvents);
      setEvidence(storedEvidence);
      setActive(0);
      setPage(targetPage);
      setViewMode(record.status === "RUNNING" ? "REAL" : "REPLAY");
      history.replaceState(null, "", `?legacy=1&run=${id}`);
    } catch (e) {
      if (ticket === generation.current) setError(errorText(e));
    } finally {
      if (ticket === generation.current) setStarting(false);
    }
  }
  const last = events.filter((e) => e.stage !== "COMPLETED").at(-1);
  const received = events
    .filter((e) => e.stage === "REPORTS_READY")
    .reduce((n, e) => n + (e.report_count ?? 0), 0);
  const auth =
    evidence?.authorization_evidence ??
    evidence?.rejection_evidence?.gateway?.signature_evidence;
  const receipt =
    evidence?.signature_evidence?.[active] ??
    evidence?.rejection_evidence?.utility?.signature_evidence;
  const link = (id: string) =>
    evidence?.connection_evidence?.find((c) => c.link_id === id);
  const security = [
    [
      "任务授权签名",
      auth?.signature_valid,
      auth?.signature_valid
        ? auth?.mldsa_valid
          ? "ECDSA ＋ ML-DSA-65"
          : "ECDSA-P256-SHA256"
        : auth?.signature_valid === false
          ? "实际验签未通过"
          : "等待实际验签",
    ],
    [
      "L1 源侧 → 网关",
      link("L1")?.peer_verified,
      link("L1")?.actual_group ?? "等待连接证据",
    ],
    [
      "L2 网关 → 统计端",
      link("L2")?.peer_verified,
      link("L2")?.actual_group ?? "等待连接证据",
    ],
    [
      "聚合回执签名",
      receipt?.signature_valid,
      receipt?.signature_valid
        ? receipt?.mldsa_valid
          ? "ECDSA ＋ ML-DSA-65"
          : "ECDSA-P256-SHA256"
        : receipt?.signature_valid === false
          ? "实际验签未通过"
          : "等待实际验签",
    ],
  ] as const;
  return (
    <>
      <header className="header">
        <div className="brand">
          <span className="brand-mark">
            <Icon name="bolt" size={26} />
          </span>
          <div>
            <p>自主 PFDAM 方案 · 密码应用验证平台</p>
            <h1>{title}</h1>
          </div>
        </div>
        <div className="header-tools">
          <button className="outline legacy-account" title={session.subject || "登录账户"} onClick={() => { setLoginNotice(""); setLoginOpen(true); }}>
            {session.authenticated ? subjectName(session.subject) : "登录账户"}
          </button>
          <span className="mode">
            <span className="dot" />
            {viewMode} · 合成负荷数据
          </span>
          {config?.lab_enabled && (
            <button
              className={"text-button " + (lab ? "selected" : "")}
              onClick={() => {
                if (!running) {
                  clear();
                  setLab(!lab);
                  setScenario("normal");
                }
              }}
            >
              {lab ? "退出实验入口" : "实验入口"}
            </button>
          )}
          <button className="outline" onClick={() => setDrawer("scope")}>
            保护范围 <Icon name="info" size={16} />
          </button>
        </div>
      </header>
      <nav className="nav" aria-label="主要导航">
        {["协同总览", "聚合工作台", "验证与报告"].map((p, i) => (
          <button
            className={page === i ? "active" : ""}
            onClick={() => setPage(i)}
            key={p}
          >
            <span>0{i + 1}</span>
            {p}
          </button>
        ))}
        <span className="nav-note">
          <span className="dot" />
          {running ? "真实任务执行中" : "本地执行环境"}
        </span>
      </nav>
      <main>
        <div className="research-note">
          <Icon name="info" size={16} />
          <span>
            研究边界：授权策略与报告类别存在候选识别限制；内层参数安全仍待复核。
          </span>
          <button onClick={() => setDrawer("scope")}>
            了解保护范围 <span>↗</span>
          </button>
        </div>
        {viewMode === "REPLAY" && run && (
          <p className="replay-note">
            历史记录回放 · 原始运行 {run.run_id} ·{" "}
            {run.started_at
              ? new Date(run.started_at).toLocaleString("zh-CN", {
                  timeZone: "Asia/Shanghai",
                  hour12: false,
                })
              : "未记录原始时间"}{" "}
            · {run.security_profile}
          </p>
        )}
        {page === 0 && (
          <>
            <section className="hero">
              <div>
                <span className="eyebrow">按授权范围统计加密数据</span>
                <h2>
                  按授权汇总负荷，
                  <br />
                  <em>用电明细由源侧保管。</em>
                </h2>
                <p>
                  源侧生成加密报告，网关按授权选择并聚合，
                  <br className="desktop" />
                  统计端验证群体结果。运行后可查看各处理步骤的记录。
                </p>
                <div className="hero-actions">
                  <button className="primary" onClick={() => setPage(1)}>
                    进入聚合工作台 <Icon name="arrow" size={18} />
                  </button>
                  <button
                    className="text-button"
                    onClick={() => setDrawer("scope")}
                  >
                    查看各角色可见内容
                  </button>
                </div>
              </div>
              <div className="scenario-card">
                <span className="eyebrow subtle">
                  面向需求响应分析的统计输入
                </span>
                <h3>按类别和时段汇总群体负荷</h3>
                <div className="tags">
                  <span>区域 A / B</span>
                  <span>居民 / 工商业 / 充电设施</span>
                  <span>18:00至19:00</span>
                </div>
                <div className="scene-numbers">
                  <div>
                    <strong>120</strong>
                    <span>逻辑模拟节点</span>
                  </div>
                  <div>
                    <strong>4</strong>
                    <span>15分钟时段</span>
                  </div>
                  <div>
                    <strong>3</strong>
                    <span>资源类别</span>
                  </div>
                </div>
                <p>合成读数用于可复现实验；密码和指定通信链路真实执行。</p>
              </div>
            </section>
            <section className="panel architecture">
              <div className="section-head">
                <div>
                  <h3>数据怎样成为可使用的结果</h3>
                  <p>数据源上传密文，网关按授权聚合，统计端核验后恢复结果。</p>
                </div>
                <span className="small-tag">业务流程示意</span>
              </div>
              <div className="topology">
                <div className="sources">
                  <span className="step-label">01 / 源侧报告</span>
                  {Object.entries(names).map(([key, label]) => (
                    <div className={"source " + key} key={key}>
                      <span>{label}</span>
                      <div className="node-dots">
                        {Array.from({ length: 8 }, (_, i) => (
                          <i key={i} />
                        ))}
                      </div>
                      <small>原始读数保留在源侧</small>
                    </div>
                  ))}
                </div>
                <div className="link-label">
                  <span>L1</span>
                  <i />
                  <small>混合 mTLS</small>
                </div>
                <div className="role-card">
                  <Icon name="filter" size={28} />
                  <span className="step-label">02 / 聚合网关 GW</span>
                  <h4>授权筛选与密态聚合</h4>
                  <p>
                    PFDAM 联合检查
                    <br />
                    不加载单户明文与恢复密钥
                  </p>
                </div>
                <div className="link-label">
                  <span>L2</span>
                  <i />
                  <small>混合 mTLS</small>
                </div>
                <div className="role-card teal">
                  <Icon name="shield" size={28} />
                  <span className="step-label">03 / 授权统计端 UC</span>
                  <h4>验证与结果恢复</h4>
                  <p>
                    任务与回执双签名
                    <br />
                    发布获准的群体统计
                  </p>
                </div>
              </div>
              <div className="architecture-footer">
                <span>TA 负责可信初始化 · 明文真值工具在隔离实验路径运行</span>
                <button
                  className="text-button"
                  onClick={() => setDrawer("scope")}
                >
                  展开保护范围 ↗
                </button>
              </div>
            </section>
            <div className="value-grid">
              {[
                [
                  "01",
                  "按授权选择",
                  "按区域和资源类别的组合条件选择报告，未获授权的报告不计入统计。",
                ],
                [
                  "02",
                  "异常有对应证据",
                  "分别核对报告、授权、回执和通信，保留各自的失败原因。",
                ],
                [
                  "03",
                  "统计结果与报告覆盖率",
                  "同时检查参与集合与统计值，缺报后展示实际覆盖。",
                ],
              ].map(([n, h, p]) => (
                <article className="value-card" key={n}>
                  <span>{n}</span>
                  <div>
                    <h3>{h}</h3>
                    <p>{p}</p>
                  </div>
                </article>
              ))}
            </div>
          </>
        )}
        {page === 1 && (
          <>
            <div className="page-heading">
              <div>
                <span className="eyebrow">协同统计任务</span>
                <h2>聚合工作台</h2>
                <p>选择统计范围，运行完整的 SAB 任务。</p>
              </div>
              <Badge
                value={
                  run
                    ? run.status === "COMPLETED"
                      ? true
                      : run.status === "REJECTED" || run.status === "FAILED"
                        ? false
                        : null
                    : null
                }
                label={run ? (states[run.status] ?? run.status) : "待运行"}
              />
            </div>
            <div className="workspace">
              <aside className="panel controls">
                <div className="section-head">
                  <h3>
                    {viewMode === "REPLAY" ? "下一次任务配置" : "统计任务"}
                  </h3>
                  <Icon name="filter" />
                </div>
                <label>实验区域</label>
                <div className="segmented">
                  {["A", "B"].map((r) => (
                    <button
                      disabled={!!running}
                      className={region === r ? "selected" : ""}
                      onClick={() => {
                        clear();
                        setRegion(r);
                      }}
                      key={r}
                    >
                      区域 {r}
                    </button>
                  ))}
                </div>
                <label>
                  资源类别 <span>多选为“或”</span>
                </label>
                <div className="resource-options">
                  {Object.entries(names).map(([r, label]) => (
                    <button
                      disabled={!!running}
                      aria-pressed={resources.includes(r)}
                      className={resources.includes(r) ? "selected" : ""}
                      onClick={() => toggle(r)}
                      key={r}
                    >
                      <span className="checkbox">
                        {resources.includes(r) && (
                          <Icon name="check" size={13} />
                        )}
                      </span>
                      {label}
                    </button>
                  ))}
                </div>
                <label>统计窗口</label>
                <div className="window-box">
                  <Icon name="clock" />
                  <div>
                    <strong>18:00 — 19:00</strong>
                    <small>4个连续15分钟时段</small>
                  </div>
                </div>
                <div className="profile-box">
                  <Icon name="shield" />
                  <div>
                    <strong>SAB · 双增强</strong>
                    <small>双签名 ＋ 混合 mTLS</small>
                  </div>
                </div>
                {lab && (
                  <>
                    <label>实验情境</label>
                    <div className="scenario-options">
                      {scenarios.map(([key, label]) => (
                        <button
                          disabled={!!running}
                          className={scenario === key ? "selected" : ""}
                          key={key}
                          onClick={() => {
                            clear();
                            setScenario(key);
                          }}
                        >
                          {label}
                        </button>
                      ))}
                    </div>
                    <p className="hint">
                      故障在本地受控路径注入，调用真实检查函数。
                    </p>
                    <div className="guide-actions">
                      <button
                        className="text-button"
                        disabled={!!running}
                        onClick={() => {
                          const next =
                            (scenarios.findIndex(([key]) => key === scenario) +
                              1) %
                            scenarios.length;
                          clear();
                          setScenario(scenarios[next][0]);
                        }}
                      >
                        下一幕
                      </button>
                      <button
                        className="text-button"
                        disabled={!!running}
                        onClick={() => {
                          clear();
                          setScenario("normal");
                        }}
                      >
                        返回正常
                      </button>
                      <button
                        className="text-button"
                        disabled={!run}
                        onClick={() => setDrawer("evidence")}
                      >
                        查看证据
                      </button>
                    </div>
                  </>
                )}
                <button
                  className="primary run-button"
                  disabled={!!running || !resources.length || !config}
                  onClick={start}
                >
                  {running ? (
                    <span className="spinner" />
                  ) : (
                    <Icon name="bolt" />
                  )}
                  {running ? "任务正在执行" : "运行 SAB 任务"}
                </button>
                {run?.status === "RUNNING" && (
                  <button
                    className="text-button cancel"
                    onClick={() =>
                      requestJSON(`/api/runs/${run.run_id}/cancel`, {
                        method: "POST",
                      }).catch(e => setError(errorText(e)))
                    }
                  >
                    取消当前任务
                  </button>
                )}
                <p className="hint">
                  更改条件后创建新任务。执行与测量时刻独立于历史负荷窗口。
                </p>
              </aside>
              <div className="workspace-main">
                <section className="panel execution">
                  <div className="section-head">
                    <h3>
                      {viewMode === "REPLAY" ? "历史执行证据" : "真实执行链路"}
                    </h3>
                    <span className="small-tag">
                      {run
                        ? "run / " + run.run_id.slice(0, 12)
                        : "等待创建任务"}
                    </span>
                  </div>
                  <div className="execution-steps">
                    {[
                      ["AUTH_READY", "任务授权"],
                      ["REPORTS_READY", "加密报告"],
                      ["AGGREGATED", "选择聚合"],
                      ["PUBLISHED", "验证恢复"],
                    ].map(([stage, label], i) => (
                      <div
                        key={stage}
                        className={
                          events.some((e) => e.stage === stage) ? "done" : ""
                        }
                      >
                        <span>
                          {events.some((e) => e.stage === stage) ? (
                            <Icon name="check" size={17} />
                          ) : (
                            i + 1
                          )}
                        </span>
                        <strong>{label}</strong>
                      </div>
                    ))}
                  </div>
                  <div className="execution-caption">
                    <span>
                      {running
                        ? last
                          ? (stages[last.stage] ?? last.stage)
                          : "正在启动角色服务"
                        : run
                          ? states[run.status]
                          : "等待启动真实计算"}
                    </span>
                    <span>
                      {running
                        ? `已生成 ${received} 份报告`
                        : run?.elapsed_ns
                          ? `端到端 ${(run.elapsed_ns / 1e9).toFixed(2)} s`
                          : "尚无结果的项目保持待验证"}
                    </span>
                  </div>
                </section>
                {(error || run?.errors?.length) && (
                  <div className="error-panel" role="alert">
                    <Icon name="info" />
                    <div>
                      <strong>{error || "本次任务未通过检查"}</strong>
                      {run?.errors?.slice(0, 2).map((e, i) => (
                        <p key={i}>
                          {e.role} · {e.code}
                        </p>
                      ))}
                    </div>
                  </div>
                )}
                <div className="metric-grid">
                  <article className="metric panel">
                    <span>本时段群体负荷</span>
                    <strong>
                      {current?.value_W === null
                        ? "无有效数据"
                        : current?.value_W !== undefined
                          ? (current.value_W / 1000).toFixed(2)
                          : "—"}
                      {current?.value_W !== null &&
                        current?.value_W !== undefined && <small>kW</small>}
                    </strong>
                    <p>{current ? "统计端恢复值" : "真实恢复完成后显示"}</p>
                  </article>
                  <article className="metric panel">
                    <span>纳入统计的报告数</span>
                    <strong>
                      {current?.counts.accepted ?? "—"}
                      <small>份</small>
                    </strong>
                    <p>
                      {current
                        ? `收到 ${current.counts.received} · 未纳入 ${current.counts.received - current.counts.accepted}`
                        : "由内核执行联合检查"}
                    </p>
                  </article>
                  <article className="metric panel">
                    <span>目标报告覆盖率</span>
                    <strong>
                      {current?.coverage_basis_points !== undefined &&
                      current.coverage_basis_points !== null
                        ? (current.coverage_basis_points / 100).toFixed(1) + "%"
                        : "—"}
                    </strong>
                    <p>
                      {current
                        ? `${current.counts.accepted} / ${current.expected_target_count} 个预期目标`
                        : "应报数量按授权范围计算"}
                    </p>
                  </article>
                </div>
                <section className="panel chart-panel">
                  <div className="slot-tabs">
                    {Array.from(
                      { length: run?.slot_count ?? 4 },
                      (_, i) => i,
                    ).map((i) => (
                      <button
                        className={active === i ? "selected" : ""}
                        onClick={() => setActive(i)}
                        key={i}
                      >
                        窗口 {i + 1}
                      </button>
                    ))}
                  </div>
                  <Chart
                    results={run?.results ?? []}
                    active={active}
                    onSelect={setActive}
                    slots={run?.slot_count ?? 4}
                  />
                </section>
                <section className="panel security">
                  <div className="section-head">
                    <h3>安全执行详情</h3>
                    <button
                      className="text-button"
                      onClick={() => setDrawer("evidence")}
                    >
                      查看原始证据 ↗
                    </button>
                  </div>
                  <div className="security-grid">
                    {security.map(([label, value, detail]) => (
                      <div key={label}>
                        <span>{label}</span>
                        <Badge
                          value={value}
                          label={
                            value === true
                              ? "已验证"
                              : value === false
                                ? "未通过"
                                : "待验证"
                          }
                        />
                        <small>{detail}</small>
                      </div>
                    ))}
                  </div>
                </section>
              </div>
            </div>
          </>
        )}
        {page === 2 && (
          <>
            <div className="page-heading">
              <div>
                <span className="eyebrow">结果与运行证据</span>
                <h2>验证与报告</h2>
                <p>核对统计结果、实际签名和业务连接，并查看历史性能对照。</p>
              </div>
              <select
                className="history-select"
                aria-label="选择历史运行"
                value=""
                disabled={!!running}
                onChange={(e) => {
                  if (e.target.value) loadRecord(e.target.value);
                }}
              >
                <option value="">读取真实历史记录</option>
                {historyRecords.map((record) => (
                  <option value={record.run_id} key={record.run_id}>
                    {record.security_profile} ·{" "}
                    {states[record.status ?? ""] ?? record.status} ·{" "}
                    {record.run_id?.slice(0, 10)}
                  </option>
                ))}
              </select>
              {run && run.status !== "RUNNING" && (
                <a className="primary" href={`/api/runs/${run.run_id}/export`}>
                  <Icon name="download" size={18} />
                  导出公开证据包
                </a>
              )}
            </div>
            <div className="report-tabs">
              {["结果一致性", "签名与链路", "四组对照"].map((s, i) => (
                <button
                  key={s}
                  onClick={() => setReportTab(i)}
                  className={i === reportTab ? "selected" : ""}
                >
                  {s}
                </button>
              ))}
            </div>
            <section className="panel report-panel">
              {reportTab === 0 && (
                <>
                  <div className="section-head">
                    <div>
                      <h3>参与范围与统计值核对</h3>
                      <p>
                        独立实验真值从源侧私有数据与注入计划计算，不采用网关输出作为答案。
                      </p>
                    </div>
                    <Badge
                      value={run?.oracle_match}
                      label={
                        run?.oracle_match === true
                          ? "两项断言一致"
                          : "等待独立验证"
                      }
                    />
                  </div>
                  {evidence?.oracle_summary?.length ? (
                    <div className="table-scroll">
                      <table>
                        <thead>
                          <tr>
                            <th>统计窗口</th>
                            <th>参与集合一致</th>
                            <th>独立预期 / W</th>
                            <th>实际恢复 / W</th>
                            <th>数值一致</th>
                          </tr>
                        </thead>
                        <tbody>
                          {evidence.oracle_summary.map((r, i) => (
                            <tr key={r.slot_id}>
                              <td>窗口 {i + 1}</td>
                              <td>
                                <Badge
                                  value={r.set_match}
                                  label={r.set_match ? "一致" : "不一致"}
                                />
                              </td>
                              <td>{r.expected_sum_W ?? "无有效数据"}</td>
                              <td>{r.actual_sum_W ?? "无有效数据"}</td>
                              <td>
                                <Badge
                                  value={r.value_match}
                                  label={r.value_match ? "一致" : "不一致"}
                                />
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    <Empty
                      text={
                        run && !lab
                          ? "普通业务入口只发布获准结果；独立真值在隔离实验入口展示。"
                          : "从实验入口运行任务后，显示实际集合与数值对照。"
                      }
                    />
                  )}
                  <div className="scope-note">
                    <Icon name="info" />
                    <p>
                      部分缺报时统计针对实际有效集合，不补造缺失读数。签名有效性、统计正确性与当前受理资格分别判断。
                    </p>
                  </div>
                </>
              )}
              {reportTab === 1 && (
                <>
                  <div className="section-head">
                    <div>
                      <h3>要求的配置与实际证据</h3>
                      <p>协商组来自承载本次业务消息的 SSL 连接。</p>
                    </div>
                    <button
                      className="outline"
                      onClick={() => setDrawer("evidence")}
                    >
                      展开证据
                    </button>
                  </div>
                  <div className="table-scroll">
                    <table>
                      <thead>
                        <tr>
                          <th>检查项</th>
                          <th>{run?.security_profile ?? "SAB"} 要求</th>
                          <th>实际结果</th>
                          <th>状态</th>
                        </tr>
                      </thead>
                      <tbody>
                        {security.map(([label, value, detail]) => (
                          <tr key={label}>
                            <td>{label}</td>
                            <td>
                              {label.includes("L1") || label.includes("L2")
                                ? `TLS 1.3 / ${["S0", "SA"].includes(run?.security_profile ?? "SAB") ? "X25519" : "X25519MLKEM768"}`
                                : ["S0", "SB"].includes(
                                      run?.security_profile ?? "SAB",
                                    )
                                  ? "ECDSA-P256-SHA256"
                                  : "ECDSA ＋ ML-DSA-65"}
                            </td>
                            <td>{detail}</td>
                            <td>
                              <Badge
                                value={value}
                                label={
                                  value === true
                                    ? "已验证"
                                    : value === false
                                      ? "未通过"
                                      : "待验证"
                                }
                              />
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  <div className="scope-note">
                    <Icon name="info" />
                    <p>
                      混合密钥建立增强指定链路；经典 mTLS 认证和内层 PFDAM
                      的安全边界单独保留，不宣称整个系统后量子化。
                    </p>
                  </div>
                </>
              )}
              {reportTab === 2 && (
                <>
                  <div className="section-head">
                    <div>
                      <h3>历史四组对照</h3>
                      <p>
                        同一历史版本下对照四组配置，比较签名和通信保护的开销；这些记录不代表当前版本性能。
                      </p>
                    </div>
                    <span className="small-tag">真实测量 · 含失败记录</span>
                  </div>
                  <div className="profile-legend">
                    {[
                      ["S0", "工程基线"],
                      ["SA", "签名增强"],
                      ["SB", "通信增强"],
                      ["SAB", "双增强"],
                    ].map(([a, b]) => (
                      <span key={a}>
                        <b>{a}</b>
                        {b}
                      </span>
                    ))}
                  </div>
                  {bench?.profiles?.length ? (
                    <div className="benchmark-chart">
                      {bench.profiles.map((p) => (
                        <div className="benchmark-row" key={p.profile}>
                          <strong>{p.profile}</strong>
                          <div>
                            <i
                              style={{
                                width: `${Math.max(2, (p.median_ns / Math.max(...bench.profiles.map((x) => x.median_ns))) * 100)}%`,
                              }}
                            />
                          </div>
                          <span>{(p.median_ns / 1e9).toFixed(2)} s</span>
                          <small>
                            n={p.sample_count} · 失败 {p.failure_count}
                          </small>
                        </div>
                      ))}
                      <p>
                        端到端耗时中位数，横轴从0起；运行环境为本机 WSL Ubuntu。
                      </p>
                    </div>
                  ) : (
                    <Empty
                      text={
                        lab
                          ? "尚无四组测量记录。运行实验命令后显示，图表不填充预造数据。"
                          : "四组实验与原始测量在实验入口中查看。"
                      }
                    />
                  )}
                </>
              )}
            </section>
          </>
        )}
        <footer>
          <span>
            {run?.dataset_id ?? "SYN-120-V3"} · 合成数据 · 非真实电网接入
          </span>
          <span>
            参数 {config?.param_id.slice(0, 12) ?? "待初始化"} · PFDAM
            内层保持经典密码边界
          </span>
        </footer>
      </main>
      {drawer && (
        <div className="drawer-backdrop" onClick={() => setDrawer(null)}>
          <aside
            className="drawer"
            role="dialog"
            aria-modal="true"
            aria-label={drawer === "scope" ? "保护范围" : "实际运行证据"}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="section-head">
              <h2>
                {drawer === "scope" ? "保护范围与研究边界" : "本次运行证据"}
              </h2>
              <button
                className="icon-button"
                aria-label="关闭"
                onClick={() => setDrawer(null)}
              >
                <Icon name="close" />
              </button>
            </div>
            {drawer === "scope" ? (
              <>
                <p className="drawer-intro">
                  每一层解决明确的问题，每一种结论都保留适用条件。
                </p>
                {[
                  [
                    "PFDAM · 选择性密态聚合",
                    "源侧持有读数，GW执行联合检查和密文聚合，UC恢复群体值。TA可信，参与方遵循协议，GW与UC不串谋。",
                  ],
                  [
                    "A · 任务与回执双签名",
                    "ECDSA与ML-DSA-65保护规范对象的来源和完整性；签名不证明物理读数真实或计算一定正确。",
                  ],
                  [
                    "B · 两段混合 mTLS",
                    "L1和L2要求X25519MLKEM768，不兼容时拒绝。经典证书认证不会因此自动后量子化。",
                  ],
                  [
                    "已复现的限制",
                    "单标签与多标签令牌均支持候选授权策略匹配。至少两个策略且相关系数非零等条件下，还可候选识别报告类别；这不等于恢复读数或识别真实设备。完整优化Paillier参数依据仍待复核。",
                  ],
                  [
                    "部署范围",
                    "单机多进程隔离业务路径；不承诺抵抗同一操作系统用户或宿主机管理员。公开导出不包含令牌正文、私钥与单户数据。",
                  ],
                ].map(([h, p]) => (
                  <div className="scope-block" key={h}>
                    <h3>{h}</h3>
                    <p>{p}</p>
                  </div>
                ))}
              </>
            ) : (
              <>
                <p className="drawer-intro">
                  {run ? `run_id / ${run.run_id}` : "尚未创建任务"}
                </p>
                {evidence ? (
                  <>
                    <h3>实际连接</h3>
                    <pre>
                      {JSON.stringify(evidence.connection_evidence, null, 2)}
                    </pre>
                    <h3>授权验签</h3>
                    <pre>
                      {JSON.stringify(evidence.authorization_evidence, null, 2)}
                    </pre>
                    <h3>回执验签</h3>
                    <pre>
                      {JSON.stringify(evidence.signature_evidence, null, 2)}
                    </pre>
                  </>
                ) : (
                  <Empty text="完成任务后，可在此查看允许公开的运行记录。" />
                )}
              </>
            )}
          </aside>
        </div>
      )}
      <OperatorLogin open={loginOpen} session={session} notice={loginNotice} onClose={() => setLoginOpen(false)}
        onLogin={next => {
          if (session.subject && session.subject !== next.subject) clear();
          setSession(next); setRegion(next.grant?.regions?.[0] || "A"); setLoginOpen(false); setError("");
        }}
        onLogout={() => { clear(); setSession({ authenticated: false, subject: null }); setLoginOpen(false); setHistoryRecords([]); }} />
    </>
  );
}
function Empty({ text }: { text: string }) {
  return (
    <div className="empty">
      <Icon name="chart" size={38} />
      <p>{text}</p>
    </div>
  );
}
const entry = new URLSearchParams(location.search);
const historical=entry.get('legacy')==='1'||entry.get('v41')==='1';
createRoot(document.getElementById("root")!).render(<>{historical&&<div className="historical-workspace-notice" role="note">历史研究页面。新任务请使用包含发布保护的工作台；原归档继续支持离线核验。<a href="/?v42=1">打开当前工作台</a></div>}{entry.get('legacy') === '1' ? <App /> : entry.get('v41') === '1' ? <V41App /> : <ExpansionApp />}</>);
