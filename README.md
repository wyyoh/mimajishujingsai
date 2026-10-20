# 面向新型电网的细粒度密态聚合与可信数据协同平台

读数源侧加密，负荷按需汇总。

本作品面向居民用电、园区协同和充电设施负荷统计，以团队自主PFDAM方案连接数据源、聚合网关和统计端。数据源加密原始读数，网关按授权选择并聚合密文，统计端恢复群体结果并执行发布规则。业务人员按区域、类别和时段取得群体统计，查看负荷变化并核验对应记录。

## 核心能力

| 能力 | 已实现的业务作用 |
|---|---|
| 细粒度密态聚合 | 按授权筛选密文，支持总和、平均值与有效报告数 |
| 群体结果受控发布 | 固定分组、至少10个登记计量点、完整上报、共享发布历史 |
| 业务对象联合签名 | ECDSA与ML-DSA-65同时验证，国密增强配置加入SM2 |
| 混合密码通信 | 上传与聚合转发链路采用X25519MLKEM768，TLS内可叠加SM4-GCM |
| 业务证据核验 | 关联授权、逐源SM3密文快照、回执、统计结果与发布决定 |
| 园区需求响应评估 | 四日期16窗口计算，展示平均降负荷、相对变化、窗口能量差与覆盖率 |

平台同时提供软件密钥托管、可信登记、任务边界更新和撤销、管理审批审计与受保护备份恢复。本机标准对齐检查逐次执行选定算法向量与应用控制，关联真实任务记录。[作品介绍与展示顺序](docs/SHOWCASE_POSITIONING.md)

园区合成场景使用预设10%响应输入；UCI公开读数采用模拟分组进行历史负荷比较。真实运行、配置预览和历史回放分别标识为REAL、PREVIEW、REPLAY。

## 比赛材料

作品编号CACR2026E7YZBA。当前比赛材料为2026-10-18“优势强化版”：自主授权机制、精确发布、业务核验和实测效率贯穿摘要与正文，17页报告逐页检查完成，支撑ZIP已在全新目录完成依赖安装和证据核验。文件入口及签署事项见[材料说明](docs/SUBMISSION_MATERIALS.md)，可编辑正文源见[提交报告](docs/SUBMISSION_REPORT.md)。

## 项目与证据

仓库 main 分支归档当前源码、已构建前端和完整支撑证据。[仓库运行与核验说明](docs/GITHUB_REPOSITORY.md)提供源码构建与离线核验命令；[证据导读](evidence/competition/00_支撑材料导读.html)连接园区实例、同条件性能实验和本机密码功能验证。`evidence/competition/`与最新支撑ZIP逐字节对应，文件摘要见其中`06_索引与来源/evidence-manifest.json`。

## 本机运行

已验证环境为Windows + Ubuntu WSL x86_64：Python 3.14.4、OpenSSL 3.5.5、glibc 2.43、Linux Landlock ABI≥3。界面资源随项目本地提供，1至3个Source采用同机独立进程。WSL由Windows当前用户DPAPI保护独立托管根；纯Linux使用显式配置的托管解锁口令。

在 PowerShell 中运行：

```powershell
.\scripts\project.ps1 build
.\scripts\project.ps1 doctor
.\scripts\project.ps1 init --profile SAB
.\scripts\project.ps1 start
# 浏览器打开 http://127.0.0.1:8580/（也保留?v42=1）
```

Windows后台启动用`start`，研发实验用`start --lab`；用`status`查看状态、`stop`正常停止。重复启动不会新建实例，切换实验模式需先停止。后台WSL进程在启动命令退出后继续承载服务，电脑或WSL重启后需重新运行启动命令。前台运行仍可用`serve`或`serve --lab`，该终端需保持打开。普通业务入口固定 SAB。首次源码构建使用 `project.ps1 build`；归档证据的离线核验使用`evidence/competition/05_程序与源码/platform/`中的固定依赖与程序，见[仓库说明](docs/GITHUB_REPOSITORY.md)。详细环境、命令、异常处理见 [使用指南](docs/USER_GUIDE.md)。

浏览器默认打开多源协同工作台，运行与核验操作需要本机研发账户登录。用`.\scripts\project.ps1 access`在本机查看访问口令（私密内容，请勿分享或打包）。默认A区运营方；B区运营方只能访问B区，公开数据分析方只能访问一般级模拟资产。选择园区场景，在“协同任务”查看园区评估；“回执与审计”核对发布决定、统计签名和业务公式。“规模实验”的成对摘要明确各自代码版本和失败记录。`?v41=1`及`?legacy=1`为历史研究页面，旧业务创建入口已关闭；V1—V4原证据继续离线核验。

## 实验与技术资料

发布保护成对测量入口为`scripts/privacy_matched_benchmark.py`，各版本原始记录保存在`artifacts/iterations/privacy/benchmarks`。实验采用同机串行执行，并记录各配置的代码版本、输入、计时口径和原始样本。详见[发布保护与业务实验](docs/PRIVACY_SCENARIO_ITERATION.md)。V4.1历史实现与测量分别见[研发记录](docs/V41_ITERATION.md)及[密码应用设计](docs/V41_SECURITY_DESIGN.md)。

```powershell
.\scripts\project.ps1 smoke --real --nodes 12 --slots 2
.\scripts\project.ps1 demo --profile SAB --dataset SYN-120-V3
.\scripts\project.ps1 test --suite acceptance
.\scripts\project.ps1 ui-test
.\scripts\project.ps1 offline-test
```

- [团队方案与本次实现贡献](docs/CONTRIBUTIONS.md)
- [保护对象及算法清单](docs/CRYPTO_INVENTORY.json)
- [本机密码标准对齐](docs/LOCAL_STANDARD_PROFILE.md)
- [参数与安全目标复核](docs/PFDAM_SCOPE_DEEP_REVIEW.md)
- [威胁模型与角色职责](docs/THREAT_MODEL.md)
- [密钥、审批与恢复操作](docs/STANDARDS_OPERATIONS.md)

2026-10-18起暂停功能开发，作品展示及本地比赛材料已完成整理。原始研究材料、历史实现与各版本验证记录保留。运行状态见[STATUS](docs/STATUS.md)，后续范围见[NEXT](docs/NEXT.md)，技术复核见[CRYPTO_REVIEW](docs/CRYPTO_REVIEW.md)。审批签署、人工上传及录制彩排按团队后续安排开展。
