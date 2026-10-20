# GitHub 项目与证据

仓库：[wyyoh/mimajishujingsai](https://github.com/wyyoh/mimajishujingsai)，分支为 `main`。2026年10月20日按团队明确授权整理当前作品及其核验材料。功能开发保持暂停，本轮只整理仓库、运行入口和公开证据。

## 从哪里开始

| 入口 | 内容 |
|---|---|
| 仓库根目录 | 当前前后端、原生适配、协议模型、测试和开发脚本 |
| [作品正文](SUBMISSION_REPORT.md) | 自主方案、实现、业务场景、实验与应用价值 |
| [比赛材料说明](SUBMISSION_MATERIALS.md) | 编号 CACR2026E7YZBA 的设计报告、支撑包与审批页 |
| [证据导读](../evidence/competition/00_支撑材料导读.html) | 三项核心优势、实际界面、园区实例、性能和功能验证 |
| [文件核验清单](../evidence/github-upload-20261020/file-manifest.json) | 当前仓库归档文件的 SHA-256，清单本身不计入自身摘要 |

`evidence/competition/` 是2026年10月18日优势强化版支撑包的逐字节展开，共653个文件。原压缩包同时保存在 `materials/竞赛提交材料_CACR2026E7YZBA_优势强化版_20261018/`。其中 `06_索引与来源/evidence-manifest.json` 校验其余652个文件；签名归档、可信登记、公钥、源码和测量记录保持原字节。用浏览器阅读导读时，请先下载或克隆仓库，在本机打开 HTML。

当前53个核心源文件摘要为 `250da67238de715c9ffeb1d44a0d8c314a5cfc5e6d92b7cc045f4f20768ebe23`，与既有本机功能验证版本一致。120/300与900输入规模的性能记录继续保留各自构建版本；已有结果沿用原始计时口径。

## 从源码运行

已验证执行平台为 Ubuntu/WSL x86_64，Python 3.14.4、OpenSSL 3.5.5、glibc 2.43、Linux Landlock ABI至少3。Windows通过WSL启动；密码运算由Linux环境执行。构建需要 `git`、`make`、`g++`、Python venv及匹配版本的OpenSSL开发文件。

```powershell
git clone https://github.com/wyyoh/mimajishujingsai.git
cd mimajishujingsai
.\scripts\project.ps1 build
.\scripts\project.ps1 doctor
.\scripts\project.ps1 init --profile SAB
.\scripts\project.ps1 start
```

浏览器打开 `http://127.0.0.1:8580/`。在本机运行 `.\scripts\project.ps1 access` 查看初始化生成的访问账户；访问口令仅供本机使用。Linux用户可使用 `bash scripts/project` 对应命令。纯Linux的托管解锁配置见[使用指南](USER_GUIDE.md)和[密钥操作说明](STANDARDS_OPERATIONS.md)。

前端源码与 `apps/web/dist/` 已构建资源一并归档。修改前端时，在 `apps/web` 按 `package-lock.json` 安装依赖并运行 `npm run build`。原生依赖固定为 mcl v3.08，提交 `a8cad811f720264e6e140f54c66463be60189789`；构建脚本检查该版本。

## 离线核验已有园区证据

`evidence/competition/05_程序与源码/platform/` 保存配套程序、Linux原生库、依赖 wheel、mcl源码与许可证。以下步骤仅使用归档程序和公开信任材料核验已有结果，在上述匹配环境执行：

```bash
cd evidence/competition/05_程序与源码/platform
python3 -m venv .venv
.venv/bin/python -m pip --isolated install --no-index \
  --find-links .build/wheelhouse -r requirements.lock.txt
.venv/bin/python -m services.cli verify-export \
  --path ../../02_业务实例/park-evaluation-public-evidence.zip \
  --expect-run 67027b12c5884f9f8f3ce99415bc58c3 \
  --expect-profile SAB --expect-slots 4 \
  --trusted-pin ../../02_业务实例/trusted-pin.json \
  --trust-runtime ../../02_业务实例/trust-runtime
```

核验检查归档内容、指定任务、统计端声明、发布决定以及16份签名输入对应的业务指标复算。信任指纹来源与核对方法见 `02_业务实例/核验说明.txt`。验证已有证据无需创建业务任务或使用原运行账户。

## 归档范围

本次归档保留自主PFDAM和各标准组件的来源归属、公开签名证据、匿名验证记录、性能样本及历史修正说明。原始标准与论文文件通过来源索引查阅，标准全文合集、私有运行根、密钥托管根、访问凭据、会话、源侧逐点输入和私有oracle不进入仓库。完整本机开发历史继续保留在团队工作目录。

本轮上传检查及离线复验见 `evidence/github-upload-20261020/`。各项密码与性能结论继续对应其原验证记录，技术模型见[威胁模型](THREAT_MODEL.md)，第三方许可见[来源说明](THIRD_PARTY_NOTICES.md)及支撑包中原始许可证。
