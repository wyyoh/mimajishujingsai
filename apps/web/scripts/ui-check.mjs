import { chromium, expect } from "@playwright/test";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { uiFingerprint } from "./ui-fingerprint.mjs";
import {execFileSync} from "node:child_process";
const root = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../..",
);
const executionStamp = new Date().toISOString().replaceAll(":","-");
const screenshots = path.join(root, "artifacts/iterations/overview-refinement/legacy-ui", executionStamp);
const inputFingerprint = await uiFingerprint(root);
await fs.mkdir(screenshots, { recursive: true });
const executable =
  process.env.PLAYWRIGHT_EXECUTABLE ??
  "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
const browser = await chromium.launch({
  executablePath: executable,
  headless: true,
});
const page = await browser.newPage({
  viewport: { width: 1366, height: 768 },
  deviceScaleFactor: 1,
});
const errors = [];
page.on("pageerror", (e) => errors.push(String(e)));
let overflow = false;
async function shot(name, width, height) {
  await page.setViewportSize({ width, height });
  await page.screenshot({
    path: path.join(screenshots, name + ".png"),
    fullPage: true,
  });
  result.screenshots.push(path.relative(root,path.join(screenshots,name+'.png')).replaceAll('\\','/'));
  const dimensions = await page.evaluate(() => ({
    scroll: document.documentElement.scrollWidth,
    width: innerWidth,
  }));
  if (dimensions.scroll > dimensions.width + 1) overflow = true;
}
const result = {
  command: "node scripts/ui-check.mjs",
  started_at: new Date().toISOString(),
  versions: { node: process.version, browser: browser.version() },
  no_horizontal_overflow: false,
  real_failure_kept: false,
  condition_change_clears_metrics: false,
  replay_preserves_source: false,
  screenshots: [],
};
try {
  const credentials=JSON.parse(execFileSync('wsl',['-d','Ubuntu','--cd','/mnt/c/Users/Lenovo/Desktop/密码技术竞赛','--','.venv/bin/python','-c','from services.sessions import ACCESS_PATH; from services.storage import read; import json; print(json.dumps(read(ACCESS_PATH)["accounts"]))'],{encoding:'utf8'}));
  result.interface_scope='Legacy workbench compatibility; V4.1 eight-page validation is recorded separately';
  await page.goto("http://127.0.0.1:8580/?legacy=1", { waitUntil: "networkidle" });
  let submissions=0;
  page.on('request',request=>{if(request.method()==='POST'&&/\/(api|lab)\/runs$/.test(new URL(request.url()).pathname))submissions++;});
  const login=async()=>{
    await page.getByLabel('登录账户',{exact:true}).selectOption('grid_operator_A');
    await page.getByLabel('本机访问口令',{exact:true}).fill(credentials.grid_operator_A);
    await page.getByRole('button',{name:'登录',exact:true}).click();
    await expect(page.locator('.v41-modal-backdrop')).toHaveCount(0);
    await expect(page.locator('.legacy-account')).toHaveAttribute('title','grid_operator_A');
  };
  await page.getByRole('navigation').getByRole('button',{name:/聚合工作台/}).click();
  await page.getByRole('button',{name:'运行 SAB 任务',exact:true}).click();
  await expect(page.getByRole('dialog')).toBeVisible();
  await expect(page.getByRole('status')).toContainText('请先登录');
  if(submissions!==0)throw new Error('Anonymous legacy UI submitted a protected task');
  result.anonymous_run_opens_login=true;
  await login();
  const invalidated=await page.request.post('http://127.0.0.1:8580/api/session/logout',{data:{}});
  if(!invalidated.ok())throw new Error('Could not invalidate actual legacy session');
  const unauthorized=page.waitForResponse(response=>response.url().endsWith('/api/runs')&&response.status()===401);
  await page.getByRole('button',{name:'运行 SAB 任务',exact:true}).click();
  if((await (await unauthorized).json()).detail!=='LOCAL_OPERATOR_LOGIN_REQUIRED')throw new Error('Expected real legacy session rejection');
  await expect(page.getByRole('dialog')).toBeVisible();
  await expect(page.getByRole('status')).toContainText('登录已失效');
  await login();
  if(submissions!==1)throw new Error('Legacy login silently repeated task submission');
  result.invalidated_session_opens_login=true;
  result.session_recovery_does_not_auto_submit=true;
  result.session_recovery_scope='Real server logout/cookie invalidation and 401, not a timed 30-minute expiry wait';
  await page.getByRole('navigation').getByRole('button',{name:/协同总览/}).click();
  await expect(page.getByRole("heading", { level: 1 })).toContainText(
    "面向新型电网",
  );
  for (const [width, height] of [
    [1920, 1080],
    [1366, 768],
    [390, 844],
  ])
    await shot(`overview-${width}`, width, height);
  await page.setViewportSize({ width: 1366, height: 768 });
  await page
    .getByRole("navigation")
    .getByRole("button", { name: /聚合工作台/ })
    .click();
  await expect(
    page.getByRole("button", { name: "运行 SAB 任务" }),
  ).toBeEnabled();
  await shot("workbench-initial-1366", 1366, 768);
  await page.getByRole("button", { name: "实验入口", exact: true }).click();
  const created = page.waitForResponse(
    (r) => r.url().endsWith("/lab/runs") && r.request().method() === "POST",
  );
  await page.getByRole("button", { name: "运行 SAB 任务" }).click();
  const creation = await (await created).json();
  await expect(page.locator(".page-heading .badge")).toHaveText("已完成", {
    timeout: 120000,
  });
  const run = await (
    await page.request.get(`http://127.0.0.1:8580/api/runs/${creation.run_id}`)
  ).json();
  if (
    !run.oracle_match ||
    !run.results.every(
      (r) => r.counts.received === 120 && r.counts.accepted === 40,
    )
  )
    throw new Error("Actual 120-node oracle assertion failed");
  result.normal_run_id = run.run_id;
  result.core_source_digest = run.core_source_digest;
  await shot("workbench-completed-1920", 1920, 1080);
  await shot("workbench-completed-1366", 1366, 768);
  await shot("workbench-completed-390", 390, 844);
  await page.setViewportSize({ width: 1366, height: 768 });
  await page
    .getByRole("navigation")
    .getByRole("button", { name: /验证与报告/ })
    .click();
  await expect(page.locator("tbody tr")).toHaveCount(4);
  await shot("report-consistency-1366", 1366, 768);
  await page.getByRole("button", { name: "签名与链路", exact: true }).click();
  await shot("report-security-1366", 1366, 768);
  await page
    .getByRole("navigation")
    .getByRole("button", { name: /聚合工作台/ })
    .click();
  await page.getByRole("button", { name: "区域 B", exact: true }).click();
  await expect(page.locator(".metric strong").first()).toHaveText("—");
  result.condition_change_clears_metrics = true;
  await page.getByRole("button", { name: "区域 A", exact: true }).click();
  await page.getByRole("button", { name: "回执内容被修改", exact: true }).click();
  const failed = page.waitForResponse(
    (r) => r.url().endsWith("/lab/runs") && r.request().method() === "POST",
  );
  await page.getByRole("button", { name: "运行 SAB 任务" }).click();
  result.failed_run_id = (await (await failed).json()).run_id;
  await expect(page.locator(".page-heading .badge")).toHaveText("未通过", {
    timeout: 120000,
  });
  await expect(page.locator(".mode")).toContainText("REAL");
  await expect(page.locator(".error-panel")).toContainText(
    "OBJECT_SIGNATURE_INVALID",
  );
  result.real_failure_kept = true;
  await shot("workbench-receipt-rejected-1366", 1366, 768);
  await page
    .getByRole("button", { name: /保护范围/ })
    .first()
    .click();
  await expect(page.getByRole("dialog")).toContainText("候选授权策略");
  await shot("scope-drawer-1366", 1366, 768);
  await page.goto(`http://127.0.0.1:8580/?legacy=1&run=${result.normal_run_id}`, {
    waitUntil: "networkidle",
  });
  await expect(page.locator(".mode")).toContainText("REPLAY");
  await expect(page.locator(".replay-note")).toContainText(
    result.normal_run_id,
  );
  await page
    .getByRole("navigation")
    .getByRole("button", { name: /验证与报告/ })
    .click();
  await expect(page.locator("tbody tr")).toHaveCount(4);
  result.replay_preserves_source = true;
  await shot("report-replay-1366", 1366, 768);
  result.no_horizontal_overflow = !overflow;
  result.browser_errors = errors;
  result.finished_at = new Date().toISOString();
  const finalFingerprint = await uiFingerprint(root);
  if (finalFingerprint.sha256 !== inputFingerprint.sha256) throw new Error("UI inputs changed during browser verification");
  result.ui_fingerprint = finalFingerprint;
  result.exit_code = 0;
  if (overflow || errors.length)
    throw new Error(JSON.stringify({ overflow, errors }));
  await fs.mkdir(path.join(root, "artifacts/iterations/overview-refinement/current"), { recursive: true });
  await fs.writeFile(
    path.join(root, "artifacts/iterations/overview-refinement/current/legacy-browser.json"),
    JSON.stringify(result, null, 2),
  );
  console.log(JSON.stringify({exit_code:result.exit_code,normal_run_id:result.normal_run_id,failure:result.error}));
} catch (error) {
  result.exit_code = 1;
  result.error = String(error);
  result.finished_at = new Date().toISOString();
  await fs.mkdir(path.join(root, "artifacts/iterations/overview-refinement/current"), { recursive: true });
  await fs.writeFile(
    path.join(root, "artifacts/iterations/overview-refinement/current/legacy-browser.json"),
    JSON.stringify(result, null, 2),
  );
  throw error;
} finally {
  await browser.close();
}
