import { chromium, expect } from '@playwright/test';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { uiFingerprint } from './ui-fingerprint.mjs';

const filename = fileURLToPath(import.meta.url);
const root = path.resolve(path.dirname(filename), '../../..');
const family = path.join(root, 'artifacts/iterations/showcase/2026-10-18');
const out = path.join(family, 'browser', new Date().toISOString().replaceAll(':', '-'));
await fs.mkdir(out, { recursive: true });
const baseline = JSON.parse(await fs.readFile(path.join(family, 'before/core-validation.json'), 'utf8'));
const base = 'http://127.0.0.1:8580';
const sha = buffer => createHash('sha256').update(buffer).digest('hex');
const beforeUI = await uiFingerprint(root);
const accounts = JSON.parse(execFileSync('wsl', ['-d', 'Ubuntu', '--cd', '/mnt/c/Users/Lenovo/Desktop/密码技术竞赛', '--exec',
  'env', 'GRID_RUNTIME=/home/jazz/.local/share/grid-collaboration/edeee4306203', '.venv/bin/python', '-c',
  'from services.sessions import ACCESS_PATH;from services.storage import read;import json;print(json.dumps(read(ACCESS_PATH)["accounts"]))'], { encoding: 'utf8' }));
const browser = await chromium.launch({ executablePath: 'C:/Program Files/Google/Chrome/Application/chrome.exe', headless: true });
const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
const errors = [], external = [], businessPosts = [];
page.on('pageerror', error => errors.push(String(error)));
page.on('request', request => {
  if (/^https?:/.test(request.url()) && new URL(request.url()).origin !== base) external.push(request.url());
  if (request.method() === 'POST' && /\/(collaborations|evaluations)$/.test(new URL(request.url()).pathname)) businessPosts.push(request.url());
});
const report = {
  schema: 'GRID_SHOWCASE_PRESENTATION_REVIEW_V1', command: ['node', 'apps/web/scripts/showcase-review.mjs'],
  started_at: new Date().toISOString(), versions: { node: process.version, browser: browser.version() },
  core_source_digest: baseline.core_source_digest, inputs: { existing_run_id: '67027b12c5884f9f8f3ce99415bc58c3', widths: [1440, 1024, 390, 320] },
  screenshots: [], errors, external_requests: external, new_business_posts: businessPosts, exit_code: 1,
};
async function nav(name) {
  await page.getByRole('navigation', { name: '扩展主导航' }).getByRole('button', { name, exact: true }).click();
  await expect(page.locator('.grid-page-heading h2')).toHaveText(name);
}
async function shot(name, width = 1440, height = 900) {
  await page.setViewportSize({ width, height });
  await page.evaluate(() => {
    if (document.activeElement instanceof HTMLElement) document.activeElement.blur();
    window.scrollTo({ top: 0, left: 0, behavior: 'instant' });
  });
  await expect.poll(() => page.evaluate(() => window.scrollY)).toBe(0);
  const file = path.join(out, `${name}-${width}.png`);
  await page.screenshot({ path: file, fullPage: true, animations: 'disabled' });
  if (await page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 1)) throw Error('Page overflow: ' + name + ' at ' + width);
  report.screenshots.push(path.relative(root, file).replaceAll('\\', '/'));
}
async function responseFor(url, button) {
  const pending = page.waitForResponse(response => response.url().endsWith(url) && response.request().method() === 'POST', { timeout: 120000 });
  await button.click();
  const response = await pending;
  if (!response.ok()) throw Error('Request rejected: ' + url + ' HTTP ' + response.status());
  return response.json();
}
try {
  for (const [file, expected] of Object.entries(baseline.core_source_files)) {
    if (sha(await fs.readFile(path.join(root, file))) !== expected) throw Error('Core changed: ' + file);
  }
  report.core_files_unchanged = Object.keys(baseline.core_source_files).length;
  if (sha(await fs.readFile(path.join(root, '.build/libgridcrypto.so'))) !== baseline.native_library_sha256) throw Error('Native library changed');
  report.native_library_unchanged = true;
  await page.goto(base + '/?v42=1', { waitUntil: 'networkidle' });
  await expect(page.getByRole('heading', { name: '读数源侧加密，负荷按需汇总', exact: true })).toBeVisible();
  await expect(page.locator('.grid-page-state')).toContainText('PREVIEW');
  await expect(page.locator('.overview-recent')).not.toHaveAttribute('open');
  const body = await page.locator('main').innerText();
  report.overview_visible_chinese_characters = (body.match(/[\u4e00-\u9fff]/g) || []).length;
  if (report.overview_visible_chinese_characters > 300) throw Error('Overview became too dense');
  await page.emulateMedia({ reducedMotion: 'reduce' });
  for (const width of report.inputs.widths) await shot('overview', width, width < 500 ? 844 : 900);
  await page.setViewportSize({ width: 1440, height: 900 });
  for (const [name, count] of [['区域居民负荷', 1], ['园区多主体协同', 3], ['充电设施高峰', 1]]) {
    await page.getByRole('button', { name, exact: true }).click();
    await expect(page.getByRole('button', { name, exact: true })).toHaveAttribute('aria-pressed', 'true');
    await expect(page.locator('.overview-source-stack>button')).toHaveCount(count);
  }
  await page.getByRole('button', { name: '园区多主体协同', exact: true }).focus();
  await page.keyboard.press('Enter');
  await page.getByRole('button', { name: '创建协同任务', exact: true }).click();
  await expect(page.getByLabel('评估规模', { exact: true })).toHaveValue('300');
  await expect(page.getByLabel('评估数据源数量', { exact: true })).toHaveValue('3');
  await nav('场景总览');
  await page.getByRole('button', { name: '区域居民负荷', exact: true }).click();
  await page.getByRole('button', { name: '平均值（AVG）', exact: true }).click();
  await page.getByRole('button', { name: '查看统计结果', exact: true }).click();
  await expect(page.getByLabel('统计方式', { exact: true })).toHaveValue('AVG');
  report.scene_and_function_bindings = true;
  await page.getByRole('button', { name: '运行协同任务', exact: true }).click();
  await expect(page.getByRole('dialog')).toBeVisible();
  await shot('login', 390, 844);
  await page.getByLabel('登录账户', { exact: true }).selectOption('grid_operator_A');
  await page.getByLabel('本机访问口令', { exact: true }).fill(accounts.grid_operator_A);
  await page.getByRole('button', { name: '登录', exact: true }).click();
  await expect(page.getByRole('dialog')).toHaveCount(0);
  report.login_and_no_automatic_submission = businessPosts.length === 0;
  if (businessPosts.length) throw Error('Login submitted a business task');

  const identifier = report.inputs.existing_run_id;
  await page.goto(base + '/?v42=1&run=' + identifier, { waitUntil: 'domcontentloaded' });
  await expect(page.locator('.grid-page-state')).toContainText('REPLAY');
  const run = await (await page.request.get(base + '/api/runs/' + identifier)).json();
  if (run.status !== 'COMPLETED' || run.core_source_digest !== baseline.core_source_digest) throw Error('Existing task mismatch');
  report.existing_real_run_replayed = { run_id: identifier, original_execution_mode: run.execution_mode, status: run.status, windows: run.total_computed_intervals };
  await nav('协同任务');
  await expect(page.locator('.response-metrics>div')).toHaveCount(4);
  await expect(page.locator('.response-heading')).toContainText('受控响应模拟');
  await expect(page.locator('.response-scope')).toContainText('预设10%响应输入');
  await page.getByRole('button', { name: '核验发布决定与指标', exact: true }).click();
  const verified = await responseFor('/api/runs/' + identifier + '/expansion/verify', page.getByRole('button', { name: '验证当前回执', exact: true }));
  if (!verified.release_decision_verified || !verified.business_metrics_recomputed) throw Error('Existing evaluation did not verify');
  report.existing_release_and_metrics_verified = true;
  await expect(page.locator('.grid-verification-summary')).toContainText('发布决定与评估指标核验通过');
  await expect(page.getByRole('link', { name: '下载公开证据', exact: true })).toHaveAttribute('href', '/api/runs/' + identifier + '/export');

  await nav('规模实验');
  await page.getByRole('button', { name: '读取成对实验', exact: true }).click();
  await expect(page.locator('.response-measurements tbody tr')).toHaveCount(3);
  await expect(page.locator('.response-measurements')).toContainText('分版本实测');
  await page.getByRole('button', { name: '读取规模实验', exact: true }).click();
  await expect(page.locator('.v42-scale-charts').or(page.locator('.v42-scale-chart')).first()).toBeVisible({ timeout: 5000 }).catch(async () => {
    await expect(page.getByRole('columnheader', { name: '耗时中位数', exact: true })).toBeVisible();
  });
  report.historical_measurement_labels_preserved = true;

  await nav('安全自检');
  const checked = await responseFor('/api/self-check', page.getByRole('button', { name: '执行安全自检', exact: true }));
  if (checked.run_id !== identifier || checked.functional_overall !== 'PASS' || checked.counts.functional_pass !== 12) throw Error('Existing task self-check failed');
  if (!checked.checks.some(row => row.id === 'confidentiality' && row.status === 'PENDING')) throw Error('Technical research state changed');
  report.functional_checks_passed = checked.counts.functional_pass;
  report.technical_research_state_preserved = true;
  await expect(page.locator('[data-check-status="PASS"]')).toHaveCount(12);
  await expect(page.locator('[data-check-id="confidentiality"]')).toHaveCount(0);

  const pages = ['场景总览', '数据与曲线', '协同任务', '数据源', '密码能力', '回执与审计', '规模实验', '安全自检'];
  for (let index = 0; index < pages.length; index++) {
    await nav(pages[index]);
    if (index === 4) {
      await expect(page.locator('.scheme-story-roles article')).toHaveCount(4);
      const detail = page.locator('.grid-connection-detail');
      await expect(detail).not.toHaveAttribute('open');
      await detail.locator('summary').click();
      await expect(detail.locator('tbody tr')).toHaveCount(32);
      await detail.locator('summary').click();
      report.endpoint_detail_progressive_disclosure = true;
    }
    for (const width of [1440, 390, 320]) await shot('page-' + index, width, width < 500 ? 844 : 900);
  }
  await page.setViewportSize({ width: 1440, height: 900 });
  for (const [role, name] of [['source', '查看数据源1'], ['gateway', '查看PFDAM密码能力'], ['utility', '查看统计结果']]) {
    await nav('场景总览'); await page.getByRole('button', { name, exact: true }).click();
    await expect(page.locator('.grid-page-heading h2')).toHaveText(role === 'source' ? '数据源' : role === 'gateway' ? '密码能力' : '协同任务');
  }
  report.role_path_navigation = true;
  report.reduced_motion_and_responsive_pages = true;
  report.ui_fingerprint = await uiFingerprint(root);
  if (report.ui_fingerprint.sha256 !== beforeUI.sha256 || errors.length || external.length || businessPosts.length) throw Error('Unexpected changes or browser requests');
  report.exit_code = 0;
} catch (error) {
  report.failure = String(error);
} finally {
  for (const value of Object.values(accounts)) if (report.failure) report.failure = report.failure.replaceAll(value, '[REDACTED]');
  report.finished_at = new Date().toISOString();
  report.driver_sha256 = sha(await fs.readFile(filename));
  await fs.writeFile(path.join(out, 'validation.json'), JSON.stringify(report, null, 2));
  await browser.close();
  console.log(JSON.stringify({ exit_code: report.exit_code, record: path.relative(root, path.join(out, 'validation.json')), failure: report.failure }));
}
process.exitCode = report.exit_code;
