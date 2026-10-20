# 前端研发迭代记录

2026-10-17，按用户要求应用frontend-design分析与humanizer文案审校，完成主工作台的界面重构，并更新两个研究入口和共享登录窗口。本记录属于研发过程，最终提交材料、录制和发布继续暂停。

原界面的配置、统计结果和证据字段层级接近，讲解时需要在多处寻找主线。新版先说明业务问题，再展示数据源、聚合网关、统计端之间的数据流。总览采用电网单线图的分支结构，节点可以跳转到相应页面；运行标识来自实际记录，图形本身是流程说明。

界面以浅灰底、深蓝文字和蓝色操作色为主，绿色、琥珀色、红色分别用于已通过、待核对和拒绝状态。中文使用本机字体，数值采用独立数字字体；图标为本地SVG，无外部字体或图像请求。

| 页面 | 展示与操作重点 |
| --- | --- |
| 场景总览 | 三种业务需求、密态处理流程及近期任务；先显示五项记录，支持展开 |
| 数据与曲线 | 公开读数与模拟分组分别说明；全天96时段曲线明确标为PREVIEW |
| 协同任务 | 数据和统计范围、授权与密码保护分别配置；完成后先显示结果与实际曲线，再配置下一次任务 |
| 数据源 | 按源核对数据分配、证书指纹、实际连接和目录隔离记录 |
| 密码能力 | 按计算、签名和通信三层说明用途，再查看当前配置与实际连接 |
| 回执与审计 | 分开核对回执、统计端结果声明、指定任务及来源关联；按时段查看快照与审计 |
| 规模实验 | 展示原始实验的图表、版本和JSON记录；版本不一致时保留历史标识 |
| 安全自检 | 显示实际检查状态、限制及后续方向，不将研发自检写成正式认证 |

手机端直接显示八项导航。近期任务采用带字段名称的记录布局，复杂密码表格保留局部滚动。登录窗口支持键盘循环、Escape关闭和焦点返回，页面提供跳至正文入口，并遵循减少动态效果设置。更换任务条件会清除旧结果；回放恢复原任务配置。切换账户后，延迟返回的旧账户数据不会重新进入页面。

文案审校覆盖主工作台、图形组件、登录窗口、两个研究入口、图表、错误提示及安全检查的显示映射。操作使用常用动词，必要密码术语说明用途，例如将“本窗群体功率”改为“本时段群体负荷”，将“目标群体覆盖”改为“目标报告覆盖率”。原始签名字段、算法标识、命令、错误代码和下载数据保持原语义。文字清单由正则辅助抽取，包含重复文本与历史字段别名，清单条数不代表独立文案或修改数量。

类型检查和Vite生产构建通过。六组实际Chrome检查覆盖三个入口、公开曲线、真实三源AVG、普通业务COUNT、异常回执拒绝、主动核验、历史回放、真实401恢复、跨账户迟到响应、图表及下载。选定视口为320至1920像素，共截取62张截图；人工复核总览、任务、密码能力、核验、自检、规模和V4.1总览的代表截图。另有2项既有浏览器证据回归核对当前前端摘要、核心版本及运行引用。上述检查不是完整WCAG审核。

可复验命令：

```text
# apps/web目录，使用已配置的Node环境
node node_modules/typescript/bin/tsc --noEmit
node node_modules/vite/bin/vite.js build

# 项目根目录，按顺序执行；本机一次受理一个任务
node apps/web/scripts/v42-ui-check.mjs
node apps/web/scripts/v41-ui-check.mjs
node apps/web/scripts/ui-check.mjs
node apps/web/scripts/frontend-review.mjs
node apps/web/scripts/v42-scale-check.mjs
node apps/web/scripts/v41-benchmark-check.mjs

# WSL项目根目录；GRID_TEST_OUTPUT设置为本轮证据目录的绝对路径
.venv/bin/python -m pytest tests/test_acceptance.py::test_browser_state_and_failure_labels tests/test_expansion.py::test_expansion_browser_record -q
```

初次兼容检查因两项验证并行提交而触发RUN_IN_PROGRESS；改为顺序执行后通过。初次pytest追溯输出目录使用相对路径，与既有追溯工具要求不一致；改用绝对路径后通过。诊断记录分别保留，没有据此修改业务受理或密码规则。依赖产生一项既有Starlette弃用提示，本轮没有更换依赖。

核心仍为404317da、原生库f37f407d，PFDAM数学保持ed696e19原字节。本轮没有新的性能测量，也没有重跑此前79项完整密码回归。普通业务的ECDSA与ML-DSA-65联合验证、两段业务通信、网关秘密隔离和各版本验证规则保留。界面明确区分签名认证与解密正确性、上报完整性、测量真实性；参数安全、候选识别限制、统计发布隐私、同机宿主信任与经典证书身份继续说明。

完成索引为[completion.json](../artifacts/iterations/frontend-refresh/completion.json)，设计复核与文字审校分别见[design-review.json](../artifacts/iterations/frontend-refresh/design-review.json)和[copy-review.json](../artifacts/iterations/frontend-refresh/copy-review.json)。原界面与已修改文档的原字节副本保存在.build/frontend-refresh/before；旧实验和标准对齐记录保持各自时点。浏览器证据测试已指向本轮独立目录。

默认入口为http://127.0.0.1:8580/，兼容/?v42=1；分类授权与单源验证入口为/?v41=1，基础聚合入口为/?legacy=1。Windows启动器运行的是WSL服务，不新增原生Windows执行支持声明。
