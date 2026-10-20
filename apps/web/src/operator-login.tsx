import React, { useEffect, useRef, useState } from "react";
import { api } from "./http";
import { errorText } from "./wording";

export type OperatorSession = { authenticated: boolean; subject: string | null; grant?: { regions: string[] }; subjects?: { id: string; name: string }[] };

export function OperatorLogin({ open, session, notice, onClose, onLogin, onLogout }: {
  open: boolean;
  session: OperatorSession;
  notice: string;
  onClose: () => void;
  onLogin: (session: OperatorSession) => void;
  onLogout: () => void;
}) {
  const [subject, setSubject] = useState(session.subject || "grid_operator_A");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const form = useRef<HTMLFormElement>(null);
  useEffect(() => {
    setPassword(""); setError("");
    if (open) setSubject(session.subject || "grid_operator_A");
  }, [open, session.subject]);
  useEffect(() => {
    if (!open) return;
    const previous = document.activeElement, overflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    const timer = requestAnimationFrame(() => form.current?.querySelector<HTMLSelectElement>('select')?.focus());
    return () => { cancelAnimationFrame(timer); document.body.style.overflow = overflow; if (previous instanceof HTMLElement && previous.isConnected) previous.focus(); };
  }, [open]);
  if (!open) return null;
  async function submit(event: React.FormEvent) {
    event.preventDefault(); setBusy(true); setError("");
    try { const next = await api<OperatorSession>("/api/session", { subject, password }); setPassword(""); onLogin(next); }
    catch (value) { setError(errorText(value)); }
    finally { setBusy(false); }
  }
  async function logout() {
    setBusy(true); setError("");
    try { await api("/api/session/logout", {}); setPassword(""); onLogout(); }
    catch (value) { setError(errorText(value)); }
    finally { setBusy(false); }
  }
  return <div className="v41-modal-backdrop" onMouseDown={event => { if (event.target === event.currentTarget && !busy) onClose(); }}><form ref={form} className="v41-login" role="dialog" aria-modal="true" aria-labelledby="operator-login-title" aria-describedby="operator-login-description" onSubmit={submit} onKeyDown={event => {
    if (event.key === 'Escape' && !busy) { event.preventDefault(); onClose(); }
    if (event.key !== 'Tab') return;
    const elements = Array.from(form.current?.querySelectorAll<HTMLElement>('button:not(:disabled),input:not(:disabled),select:not(:disabled)') || []);
    const first = elements[0], last = elements.at(-1);
    if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
    else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
  }}>
    <button type="button" className="v41-modal-close" aria-label="关闭登录窗口" disabled={busy} onClick={onClose}>×</button>
    <span className="v41-badge blue">本机业务账户</span>
    <h2 id="operator-login-title">{session.authenticated ? "切换账户" : "登录协同工作台"}</h2>
    {notice && <p className="v41-login-notice" role="status">{notice}</p>}
    {error && <div role="alert" className="v41-error">{error}</div>}
    <p id="operator-login-description">使用本机生成的口令登录。账户权限决定可访问的数据范围和统计方式。</p>
    <label>登录账户<select aria-label="登录账户" value={subject} disabled={busy} onChange={e => setSubject(e.target.value)}>
      <option value="grid_operator_A">A区协同运营方</option><option value="grid_operator_B">B区协同运营方</option><option value="grid_analyst_A">A区公开数据分析方</option>
    </select></label>
    <label>本机访问口令<input aria-label="本机访问口令" type="password" value={password} disabled={busy} autoComplete="current-password" onChange={e => setPassword(e.target.value)} required /></label>
    <small>在本机终端运行 <code>.\scripts\project.ps1 access</code> 查看口令。登录后即可按账户权限发起所选操作。</small>
    <button className="v41-primary" type="submit" disabled={busy}>{busy ? "处理中…" : "登录"}</button>
    {session.authenticated && <button className="v41-secondary" type="button" disabled={busy} onClick={logout}>退出当前账户</button>}
  </form></div>;
}
