import {chromium,expect} from '@playwright/test';
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {uiFingerprint} from './ui-fingerprint.mjs';

const filename=fileURLToPath(import.meta.url),root=path.resolve(path.dirname(filename),'../../..');
const stamp=new Date().toISOString().replaceAll(':','-'),out=path.join(root,'artifacts/iterations/frontend-refresh/interaction',stamp);
await fs.mkdir(out,{recursive:true});await fs.mkdir(path.join(root,'artifacts/iterations/frontend-refresh/current'),{recursive:true});
// Capture private credentials in memory only. No filled login screenshots or credential output.
const accounts=JSON.parse(execFileSync('wsl',['-d','Ubuntu','--cd',root,'--exec','.venv/bin/python','-c','from services.sessions import ACCESS_PATH; from services.storage import read; import json; print(json.dumps(read(ACCESS_PATH)["accounts"]))'],{encoding:'utf8'}));
const browser=await chromium.launch({executablePath:'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',headless:true});
const page=await browser.newPage({viewport:{width:1366,height:900}});
const errors=[],external=[];page.on('pageerror',value=>errors.push(String(value)));page.on('request',r=>{if(/^https?:/.test(r.url())&&new URL(r.url()).hostname!=='127.0.0.1')external.push(new URL(r.url()).origin);});
const result={schema:'GRID_FRONTEND_INTERACTION_REVIEW_V1',started_at:new Date().toISOString(),command:['node','apps/web/scripts/frontend-review.mjs'],versions:{node:process.version,browser:browser.version()},screenshots:[],errors,exit_code:1};
const before=await uiFingerprint(root);
async function nav(name){await page.getByRole('navigation',{name:'扩展主导航'}).getByRole('button',{name,exact:true}).click();}
async function shot(name,width=1366,height=900){await page.setViewportSize({width,height});await page.screenshot({path:path.join(out,name+'.png'),fullPage:true});const size=await page.evaluate(()=>({width:innerWidth,scroll:document.documentElement.scrollWidth}));if(size.scroll>size.width+1)throw Error(`${name}: ${size.scroll}/${size.width} overflow`);result.screenshots.push(path.relative(root,path.join(out,name+'.png')).replaceAll('\\','/'));}
async function login(subject){await page.locator('.v41-account').click();await page.getByLabel('登录账户',{exact:true}).selectOption(subject);await page.getByLabel('本机访问口令',{exact:true}).fill(accounts[subject]);await page.getByRole('button',{name:'登录',exact:true}).click();await expect(page.getByRole('dialog')).toHaveCount(0);await expect(page.locator('.v41-account')).toHaveAttribute('title',subject);}
async function create(endpoint){const response=page.waitForResponse(r=>r.url().endsWith(endpoint)&&r.request().method()==='POST',{timeout:30000});await page.getByRole('button',{name:'运行协同任务',exact:true}).click();const received=await response;if(!received.ok())throw Error('Task creation failed '+received.status());const {run_id}=await received.json();return run_id;}
try {
  await page.goto('http://127.0.0.1:8580/',{waitUntil:'networkidle'});
  await expect(page.getByRole('navigation',{name:'扩展主导航'})).toBeVisible();
  await page.keyboard.press('Tab');await expect(page.locator('.ui-skip')).toBeFocused();await page.keyboard.press('Enter');await expect(page.locator('#grid-main')).toBeFocused();result.keyboard_skip_link=true;
  await page.locator('.v41-account').click();await expect(page.getByLabel('登录账户',{exact:true})).toBeFocused();
  const close=page.getByRole('button',{name:'关闭登录窗口',exact:true});await close.focus();await page.keyboard.press('Shift+Tab');await expect(page.getByRole('button',{name:'登录',exact:true})).toBeFocused();await page.keyboard.press('Tab');await expect(close).toBeFocused();await page.keyboard.press('Escape');await expect(page.getByRole('dialog')).toHaveCount(0);await expect(page.locator('.v41-account')).toBeFocused();result.dialog_keyboard_and_focus_return=true;
  for(const width of [1920,1366,768,390,320]){await shot('overview-'+width,width,width<500?844:900);if(width<500){for(const b of await page.getByRole('navigation',{name:'扩展主导航'}).getByRole('button').all()){const box=await b.boundingBox();if(!box||box.x<0||box.x+box.width>width+1)throw Error('Mobile navigation is clipped');}}}result.all_mobile_navigation_visible=true;
  await page.emulateMedia({reducedMotion:'reduce'});result.reduced_motion=await page.evaluate(()=>matchMedia('(prefers-reduced-motion: reduce)').matches);await page.setViewportSize({width:1366,height:900});
  await login('grid_operator_A');await nav('协同任务');
  await page.getByLabel('统计方式',{exact:true}).selectOption('COUNT');await page.locator('.grid-lab-options summary').click();await page.getByLabel('启用独立核对（实验）',{exact:true}).uncheck();
  result.count_run_id=await create('/api/expansion/collaborations');await expect(page.locator('.grid-run-strip')).toContainText('已完成',{timeout:120000});
  const run=await(await page.request.get(`http://127.0.0.1:8580/api/runs/${result.count_run_id}`)).json();
  if(run.protocol_version!==4||!run.uc_result_signatures_verified||run.algorithm_suite!=='V41_HYBRID_SM'||run.oracle_match!==undefined)throw Error('Ordinary business metadata is incorrect');
  const display=await page.locator('.grid-result-value').innerText();const actual=run.results[0].published_value;if(actual.function!=='COUNT'||actual.unit!=='reports'||!display.includes(actual.value)||!display.includes('份报告')||display.includes(' W'))throw Error('COUNT value or unit is incorrect');
  const top=await page.locator('.grid-results').boundingBox(),form=await page.locator('.grid-task-layout').boundingBox();if(!top||!form||top.y>=form.y)throw Error('Results are not before the next task form');
  await page.getByText('查看精确值和原始结果字段',{exact:true}).click();const raw=JSON.parse(await page.locator('.grid-results pre').innerText());if(JSON.stringify(raw)!==JSON.stringify(run.results))throw Error('Exact raw results were changed');
  result.core_source_digest=run.core_source_digest;result.ordinary_business_count_units_and_raw_results=true;result.results_before_next_task=true;
  await shot('count-result');await shot('count-result-mobile',390,844);await page.setViewportSize({width:1366,height:900});
  await page.reload({waitUntil:'networkidle'});await nav('协同任务');await expect(page.getByText('历史回放 REPLAY',{exact:true})).toBeVisible();await expect(page.getByLabel('统计方式',{exact:true})).toHaveValue('COUNT');result.replay_restores_actual_configuration=true;
  await page.getByLabel('统计方式',{exact:true}).selectOption('AVG');await expect(page.locator('.grid-run-strip')).toHaveCount(0);await expect(page.locator('.grid-result-value')).toHaveCount(0);result.changed_conditions_clear_old_results=true;
  await page.locator('.grid-lab-options summary').click();await page.getByLabel('启用独立核对（实验）',{exact:true}).check();await page.getByLabel('安全测试场景',{exact:true}).selectOption('invalid_receipt');
  result.rejected_run_id=await create('/lab/expansion/collaborations');await expect(page.locator('.grid-run-strip')).toContainText('已拒绝',{timeout:120000});await expect(page.getByText('实际运行 REAL',{exact:true})).toBeVisible();await expect(page.locator('.ui-task-error')).toBeVisible();await expect(page.locator('.grid-result-value')).toHaveCount(0);await page.getByText('查看错误代码',{exact:true}).click();await expect(page.locator('.ui-task-error')).toContainText('OBJECT_SIGNATURE_INVALID');result.real_rejection_not_replaced_with_preview=true;await shot('rejected');
  await nav('数据与曲线');
  // Delay delivery of a genuine server response, then switch account before it arrives.
  let release,received;const delivered=new Promise(r=>release=r),ready=new Promise(r=>received=r);
  await page.route('**/lab/expansion/curve',async route=>{const response=await route.fetch();received();await delivered;await route.fulfill({response});});
  await page.getByRole('button',{name:'查看全天曲线',exact:true}).click();await ready;await login('grid_operator_B');release();await expect(page.getByRole('button',{name:'查看全天曲线',exact:true})).toBeEnabled();await expect(page.locator('.v42-curve')).toHaveCount(0);await expect(page.locator('.grid-run-strip')).toHaveCount(0);await page.unroute('**/lab/expansion/curve');
  const denied=await page.request.get(`http://127.0.0.1:8580/api/runs/${result.count_run_id}`);if(denied.status()!==403)throw Error('Other account could read the task');result.account_switch_discards_delayed_response=true;result.cross_account_read_denied=true;
  if(external.length)throw Error('Unexpected external UI requests');if(errors.length)throw Error('Browser errors');result.no_external_ui_dependencies=true;result.ui_fingerprint=await uiFingerprint(root);if(result.ui_fingerprint.sha256!==before.sha256)throw Error('UI changed during review');result.exit_code=0;
} catch(error) {result.failure=String(error);process.exitCode=1;if(!await page.getByRole('dialog').count())await page.screenshot({path:path.join(out,'failure.png'),fullPage:true}).catch(()=>{});}
finally {result.finished_at=new Date().toISOString();result.driver_sha256=createHash('sha256').update(await fs.readFile(filename)).digest('hex');if(result.failure)for(const secret of Object.values(accounts))result.failure=result.failure.replaceAll(secret,'[REDACTED]');await fs.writeFile(path.join(out,'validation.json'),JSON.stringify(result,null,2));await fs.writeFile(path.join(root,'artifacts/iterations/frontend-refresh/current/interaction-browser.json'),JSON.stringify(result,null,2));await browser.close();console.log(JSON.stringify({exit_code:result.exit_code,record:path.relative(root,path.join(out,'validation.json')),failure:result.failure}));}
