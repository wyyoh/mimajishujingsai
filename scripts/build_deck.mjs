import fs from 'node:fs/promises';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
const runtimeModules=process.env.GRID_ARTIFACT_NODE_MODULES??path.join(path.dirname(path.dirname(process.execPath)),'node_modules');
const {Presentation, PresentationFile}=await import(pathToFileURL(path.join(runtimeModules,'@oai/artifact-tool/dist/artifact_tool.mjs')).href);
process.on('uncaughtException',error=>{console.error(error.message.slice(0,4500));process.exit(1);});

const root=process.env.GRID_ROOT;
const skill=process.env.GRID_PRESENTATION_SKILL;
const python=process.env.GRID_ARTIFACT_PYTHON;
if(!root||!skill||!python)throw new Error('Set GRID_ROOT, GRID_PRESENTATION_SKILL and GRID_ARTIFACT_PYTHON using the bundled workspace dependencies');
const {finalizePresentation,applyPresentationChartFont}=await import(pathToFileURL(path.join(skill,'container_tools/artifact_tool_utils.mjs')).href);
const tmp=path.join(root,'.build/materials');
const output=path.join(root,'materials');
await fs.mkdir(tmp,{recursive:true});await fs.mkdir(output,{recursive:true});
const bench=JSON.parse(await fs.readFile(path.join(root,'artifacts/benchmarks/analysis.json'),'utf8'));
const p=Presentation.create({slideSize:{width:1280,height:720}});
const font='Microsoft YaHei';
const blue='#18344F',teal='#159895',muted='#617B92',amber='#A76A12';
function text(s,value,x,y,w,h,size=28,color=blue,bold=false){
  const box=s.shapes.add({geometry:'textbox',position:{left:x,top:y,width:w,height:h},fill:'none',line:{fill:'none',width:0}});
  box.text=value;box.text.style={typeface:font,fontSize:size,color,bold};return box;
}
function shape(s,x,y,w,h,fill,geometry='rect'){
  return s.shapes.add({geometry,position:{left:x,top:y,width:w,height:h},fill,line:{fill:'none',width:0}});
}
function slide(title,source='docs/DESIGN_REPORT.md'){
  const s=p.slides.add();s.background.fill='#FFFFFF';
  text(s,title,72,48,1136,88,38,blue,true);
  shape(s,72,144,60,4,teal);
  text(s,String(p.slides.items.length).padStart(2,'0'),1160,666,45,28,16,muted);
  s.speakerNotes.text='来源：'+source+'。所有软件与数据演示均为本地研究原型。';
  return s;
}
let s=slide('');
text(s,'面向新型电网的\n细粒度密态聚合\n与可信数据协同平台',72,150,1100,260,48,blue,true);
text(s,'密码应用技术  B 类自拟选题',76,460,1050,44,26,teal);
text(s,'自主 PFDAM 方案  软件 0.1.0  合成数据与真实密码执行',76,526,1050,70,22,muted);
s=slide('细粒度密态聚合的方案与需求');
text(s,'我们的 PFDAM 方案\n授权选择与密态聚合\nUC 核验后恢复群体功率',72,210,720,280,35,blue,true);
text(s,'120',930,210,240,90,68,teal,true);text(s,'合成逻辑节点',930,310,260,44,24,muted);
text(s,'40',930,396,240,90,68,teal,true);text(s,'默认授权目标',930,496,260,44,24,muted);
text(s,'没有实际电网接入；120 节点由一个 Source 进程模拟。',72,610,1100,40,21,muted);
s=slide('四角色对应三个常驻业务进程','services/workers.py; services/orchestrator.py; native/grid_crypto.cpp');
shape(s,400,190,480,110,'#EFF6F7');text(s,'TA 可信初始化后退出常驻流程',426,213,430,70,27,blue,true);
for(const [i,name,desc] of [[0,'Source','读数与本地标签\n只读自己的秘密'],[1,'GW','令牌联合检查\n选择与密文聚合'],[2,'UC','授权、验证回执\n恢复群体结果']]){
  const x=72+i*400;shape(s,x,400,330,150,'#F3F7FA');text(s,name,x+20,417,290,45,30,blue,true);text(s,desc,x+20,476,290,70,24,muted);
}
for(const [x,label] of [[410,'L1 混合 mTLS'],[810,'L2 混合 mTLS']]){shape(s,x,445,55,22,teal,'rightArrow');text(s,label,x-22,340,190,44,20,teal);}
text(s,'Landlock 在角色内实际拒绝跨角色文件读取；宿主管理员不在此边界内。',72,606,1130,54,21,muted);
s=slide('同一任务语义绑定授权、报告与回执','services/schemas.py; services/encoding.py; services/workers.py');
text(s,'授权对象',72,204,500,50,30,blue,true);
text(s,'任务 / 运行 / 窗口 / 参数\n接收网关 / 有效期 / key epoch\n安全档位 / policy_ref / token_bundle',72,280,530,208,25,muted);
text(s,'聚合回执',680,204,500,50,30,blue,true);
text(s,'任务 / 窗口 / 授权摘要\n聚合密文 / 计数 / 输入摘要\n快照 / 原生签名 / 安全档位',680,280,530,208,25,muted);
text(s,'规范 JCS 字节与域分离签名；幂等发布以 payload 身份判断。',72,574,1130,60,26,teal,true);
s=slide('两个对象双签，两段链路严格协商','services/signatures.py; native/grid_crypto.cpp; artifacts/tests/acceptance_results.json');
text(s,'ECDSA P-256  AND  ML-DSA-65',72,210,1136,65,40,teal,true);
text(s,'任一 required 签名缺失或错误，授权或回执均拒绝。\n信任来自本地 role / key_id / epoch=1 注册表。',72,302,1136,108,27,blue);
text(s,'L1 / L2 实际组：X25519MLKEM768',72,452,1136,64,32,blue,true);
text(s,'TLS 1.3  双向证书与角色身份  无回退 / 恢复 / 0RTT\n证书身份仍为经典 ECDSA；内层配对与 Paillier 仍为经典密码。',72,548,1136,88,23,muted);
s=slide('工作台展示真实结果与真实失败','artifacts/tests/ui_results.json; artifacts/screenshots/workbench-completed-1920.png');
s.images.add({blob:new Uint8Array(await fs.readFile(path.join(root,'artifacts/screenshots/workbench-completed-1920.png'))),contentType:'image/png',alt:'真实SAB运行工作台截图',fit:'contain',position:{left:72,top:175,width:1136,height:435}});
text(s,'截图对应真实运行；20%目标缺报、报告修改及对象/链路拒绝分别展示。',72,627,1100,34,20,muted);
s=slide('四组均通过独立参与集合与数值核对','artifacts/benchmarks/raw.json; consistency.csv; tests/oracle/reference.py');
const values=[['档位','样本','窗1 / W','窗2 / W','窗3 / W','窗4 / W']];
for(const profile of ['S0','SA','SB','SAB'])values.push([profile,String(bench.profiles[profile].sample_count),...bench.consistency[0].result_W.map(String)]);
const table=s.tables.add({rows:5,columns:6,left:72,top:230,width:1136,height:300,columnWidths:[110,90,234,234,234,234],values});
table.borders.assign({fill:'#D9E3EC',width:1,style:'solid'});
table.cells.block({row:0,column:0,rowCount:5,columnCount:6}).assign({textStyle:{typeface:font,fontSize:23,color:blue},margins:{top:12,bottom:12,left:14,right:14}});
table.cells.block({row:0,column:0,rowCount:1,columnCount:6}).assign({fill:'#EAF3F5',textStyle:{typeface:font,fontSize:22,bold:true,color:blue}});
text(s,'相同参数与数据；每窗120报告、40目标；主矩阵失败0。',72,582,1130,45,25,teal,true);
s=slide('端到端成本接近，细项分开测量','artifacts/benchmarks/analysis.json; docs/BENCHMARK_METHOD.md');
const measuredChart=s.charts.add('bar',{position:{left:72,top:205,width:750,height:400},categories:['S0','SA','SB','SAB'],
  series:[{name:'Median duration (s)',values:['S0','SA','SB','SAB'].map(k=>bench.profiles[k].median/1e9),fill:teal}],
  hasLegend:false,barOptions:{direction:'column',grouping:'clustered',gapWidth:80},
  xAxis:{textStyle:{fontSize:22}},yAxis:{min:0,title:'Seconds',textStyle:{fontSize:19},majorGridlines:{fill:'#E1EAF1',width:1}},
  dataLabels:{showValue:true,position:'outEnd',numberFormatCode:'0.000',textStyle:{fontSize:20,fill:blue}}});
applyPresentationChartFont(measuredChart,{fontFamily:font});
text(s,'各30次\n120节点 × 4窗口\n完整 TLS 握手',866,240,340,170,28,blue,true);
text(s,'共享桌面与 WSL 未绑核。\n小差异不作为速度优势。\n签/验各100次另列；握手每链路30次。',866,452,340,155,22,muted);
s=slide('授权策略与报告类别的候选识别已复现','PFDAM V-B,V-D; DOI 10.1109/JIOT.2024.3356593; artifacts/probes/policy_audit.json; report_tag_audit.json');
text(s,'单 / 多标签的授权候选测试均成立\n多标签且系数可用时，还可识别报告类别',72,210,1136,150,35,amber,true);
text(s,'外层双签和混合 TLS 不修复该内层关系。\n未恢复读数，不据此认定识别了物理设备。\n引用[37]已采用摘要回退，具体参数安全仍待审。',72,405,1136,160,28,blue);
text(s,'PFDAM 为本团队方案；前期研究与本次系统迭代分别说明。',72,615,1136,32,19,muted);
s=slide('交付可复跑软件、来源与可核对证据','docs/USER_GUIDE.md; docs/CONTRIBUTIONS.md; artifacts/tests/cleanroom_result.json');
text(s,'离线软件与源码\n锁定依赖、原生库、静态界面\n新环境与新密钥真实复跑',72,215,600,180,31,blue,true);
text(s,'公开证据与原始数据\n签名回执、连接来源、性能图表\n归档外信任及签名元数据关联',72,440,600,166,29,blue);
text(s,'本次系统迭代',785,215,420,58,30,teal,true);
text(s,'任务绑定与角色分离\n双签与两段严格传输\n独立真值与失败关闭\n崩溃终结与快照保留\n15例标准向量与交叉验证\n18类改包或错任务拒绝',785,302,420,200,26,muted);
text(s,'团队方案与应用系统；作品编号、审批签字与讲解彩排由团队完成。',72,649,1100,28,19,muted);

const candidate=path.join(tmp,'candidate.pptx');
await(await PresentationFile.exportPptx(p)).save(candidate);
const final=path.join(output,'答辩演示稿_最终审阅.pptx');
await finalizePresentation({workspaceDir:root,candidatePath:candidate,finalPath:final,pythonExecutable:python,
  integrityValidatorPath:path.join(skill,'container_tools/inspect_presentation_package_integrity.py'),
  layoutValidatorPath:path.join(skill,'container_tools/inspect_presentation_layout_geometry.py'),
  layoutArgs:['--expected-slide-size-emu','12192000,6858000','--validate-heading-fit','--require-native-table-slide','7'],
  requiredNativeTableOwnerSlides:[7],requiredNativeChartOwnerSlides:[8],materializeLiteralChartWorkbooks:true,
  fontPolicy:{basis:'design',families:[font]},verifyArtifactToolImport:true,
  receiptPath:path.join(tmp,'deck.final.validation.json')});
for(const [i,sl] of p.slides.items.entries()){
  const b=await p.export({slide:sl,format:'png',scale:1});
  await fs.writeFile(path.join(tmp,`slide-${String(i+1).padStart(2,'0')}.png`),new Uint8Array(await b.arrayBuffer()));
}
console.log(JSON.stringify({final,slides:p.slides.items.length}));
