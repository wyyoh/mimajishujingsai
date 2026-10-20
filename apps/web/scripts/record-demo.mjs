import {chromium,expect} from '@playwright/test';
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../../..');
const out=path.join(root,'materials/video');await fs.mkdir(out,{recursive:true});
const browser=await chromium.launch({executablePath:process.env.PLAYWRIGHT_EXECUTABLE??'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',headless:true});
const context=await browser.newContext({viewport:{width:1366,height:768},recordVideo:{dir:out,size:{width:1366,height:768}}});
const page=await context.newPage();const video=page.video();const started=performance.now();const chapters=[];const errors=[];const recordedRuns=[];
page.on('pageerror',e=>errors.push(String(e)));
async function caption(value){await page.evaluate(value=>{let bar=document.getElementById('recording-caption');if(!bar){bar=document.createElement('div');bar.id='recording-caption';Object.assign(bar.style,{position:'fixed',bottom:'12px',left:'18px',right:'18px',padding:'16px 22px',background:'#18344fed',color:'white',fontSize:'19px',zIndex:'9999',borderRadius:'8px',pointerEvents:'none',fontFamily:'Microsoft YaHei,sans-serif'});document.body.append(bar);}bar.textContent='自动操作实录（无解说音轨）  '+value;},value);}
async function chapter(name,seconds,action){const at=performance.now();await caption(name);await action();chapters.push({title:name,at_ms:Math.round(at-started),budget_seconds:seconds});const wait=Math.max(0,seconds*1000-(performance.now()-at));await new Promise(r=>setTimeout(r,wait));}
async function nav(label){await page.getByRole('navigation').getByRole('button',{name:new RegExp(label)}).click();await page.evaluate(()=>window.scrollTo(0,0));}
async function runScene(label){await nav('聚合工作台');await page.getByRole('button',{name:label,exact:true}).click();const pending=page.waitForResponse(r=>r.url().endsWith('/lab/runs')&&r.request().method()==='POST');await page.getByRole('button',{name:'运行 SAB 任务',exact:true}).click();const id=(await(await pending).json()).run_id;let record;const deadline=performance.now()+120000;do{const response=await page.request.get(`http://127.0.0.1:8580/api/runs/${id}`);record=await response.json();if(record.status!=='RUNNING')break;await new Promise(r=>setTimeout(r,500));}while(performance.now()<deadline);if(record.status==='RUNNING')throw new Error('Task did not finish');await expect(page.locator('.page-heading .badge')).toHaveText({COMPLETED:'已完成',PARTIAL:'部分完成',REJECTED:'未通过'}[record.status]);recordedRuns.push(record);return record;}
let normal;
try{
  await page.goto('http://127.0.0.1:8580/',{waitUntil:'networkidle'});
  await chapter('合成数据与真实密码执行；四角色、两个对象、两段业务连接。',25,async()=>{});
  await page.getByRole('button',{name:'实验入口',exact:true}).click();
  await chapter('正常 SAB：全部120报告由网关检查，默认纳入40个目标。',40,async()=>{normal=await runScene('正常统计');if(!normal.oracle_match)throw new Error('Normal oracle mismatch');await page.locator('.chart-panel').scrollIntoViewIfNeeded();});
  await chapter('参与集合与统计值分别由隔离 oracle 核对，不复用网关结果生成答案。',25,async()=>{await nav('验证与报告');await page.getByRole('button',{name:'结果一致性',exact:true}).click();});
  await chapter('查看实际签名与L1/L2组；required签名全部成立才受理，证书身份仍为经典算法。',25,async()=>{await page.getByRole('button',{name:'签名与链路',exact:true}).click();});
  await chapter('生成后修改目标CT；真实联合检查拒绝该报告，统计其余有效集合。',35,async()=>{const r=await runScene('修改报告');if(r.status!=='PARTIAL'||!r.oracle_match)throw new Error('Modified-report scenario failed');await page.locator('.metric-grid').scrollIntoViewIfNeeded();});
  await chapter('40个目标缺8个：收到112、纳入32、覆盖80%；没有插补。',35,async()=>{const r=await runScene('20%目标缺报');if(!r.results.every(x=>x.counts.accepted===32))throw new Error('Missing target count incorrect');await page.locator('.metric-grid').scrollIntoViewIfNeeded();});
  await chapter('非法授权：签后修改对象，GW拒绝，未进入报告聚合。',20,async()=>{const r=await runScene('非法授权');if(r.status!=='REJECTED')throw new Error('Invalid authorization accepted');});
  await chapter('非法回执：UC拒绝发布；页面保留REAL错误，不自动切回放。',25,async()=>{const r=await runScene('非法回执');if(r.status!=='REJECTED')throw new Error('Invalid receipt accepted');await expect(page.locator('.mode')).toContainText('REAL');});
  await chapter('经典组对端不满足SAB：TLS握手拒绝，没有静默回退。',20,async()=>{const r=await runScene('不合规链路');if(r.status!=='REJECTED')throw new Error('Incompatible TLS accepted');});
  await chapter('四档各30次真实测量；相同参数与数据，细小差异不作为速度优势。',20,async()=>{await nav('验证与报告');await page.getByRole('button',{name:'四组对照',exact:true}).click();await page.locator('.report-panel').scrollIntoViewIfNeeded();});
  await chapter('REPLAY明确标原任务；保留策略候选测试限制与参数待审说明。',30,async()=>{await page.goto(`http://127.0.0.1:8580/?run=${normal.run_id}`,{waitUntil:'networkidle'});await caption('REPLAY明确标原任务；保留策略候选测试限制与参数待审说明。');await expect(page.locator('.mode')).toContainText('REPLAY');await page.getByRole('button',{name:/保护范围/}).first().click();});
  if(recordedRuns.length!==6||recordedRuns.some(r=>r.core_source_digest!==normal.core_source_digest))throw new Error('Recording run provenance mismatch');
  const result={started_at:new Date(Date.now()-(performance.now()-started)).toISOString(),duration_ms:Math.round(performance.now()-started),chapters,normal_run_id:normal.run_id,core_source_digest:normal.core_source_digest,recorded_runs:recordedRuns.map(r=>({run_id:r.run_id,scenario:r.scenario,status:r.status,started_at:r.started_at,finished_at:r.finished_at,core_source_digest:r.core_source_digest})),recorded_run_metadata_source:'actual terminal records returned by this recording page',browser_errors:errors,scope:'automated live browser operation, no narration; not a human speaker rehearsal',exit_code:0};
  if(errors.length)throw new Error(JSON.stringify(errors));
  await context.close();await video.saveAs(path.join(out,'五分钟真实操作实录.webm'));
  await fs.writeFile(path.join(root,'artifacts/tests/video_recording.json'),JSON.stringify(result,null,2));console.log(JSON.stringify(result));
}catch(error){await fs.writeFile(path.join(root,'artifacts/tests/video_recording.json'),JSON.stringify({exit_code:1,error:String(error),chapters}));throw error;}finally{await browser.close();}
