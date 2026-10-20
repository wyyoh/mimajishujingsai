# 密码管理与故障恢复操作

本页对应标准对齐研发迭代，执行平台为 Linux/WSL。操作使用命令完成，业务界面继续集中展示授权、密态聚合和回执核验。所有口令在本机交互输入，不写入命令参数、代码、记录或公开证据。

## 身份与批准

| 身份 | 能力 | 约束 |
|---|---|---|
| `grid_operator_A / B`、`grid_analyst_A` | 原有分区、等级、函数权限内的业务操作 | 浏览器会话30分钟；禁用后旧会话失效，重新启用不能复活旧会话 |
| `grid_key_manager` | 提出并执行密钥、证书、程序批准、备份恢复等操作 | 每次重新鉴别；不能批准自己的请求 |
| `grid_security_approver` | 批准明确的操作单 | 独立账户；10分钟有效期内；批准绑定操作内容摘要，不能复用 |
| `grid_auditor` | 重新鉴别后核对管理审计 | 不得提出或执行密钥管理操作 |

这些是本地研发身份与职责控制。实测由验证程序分别使用不同账户，证明账户权限和状态机；不将其写成已由两名自然人履行岗位制度。主机和协调进程仍处于可信边界，同一主机管理员可接触本机凭据，软件无法据此抵抗该管理员。

Windows命令前缀为 `.\scripts\project.ps1`，WSL项目根目录为 `bash scripts/project`。在本机通过 `access` 查看相应随机访问口令；它会显示秘密，禁止将输出复制进公开日志。

```powershell
.\scripts\project.ps1 security status
.\scripts\project.ps1 security request --operation rotate-signing --reason "计划更新业务签名密钥"
# 使用上一命令实际返回的请求编号，分别由两个身份操作
.\scripts\project.ps1 security approve --request-id <请求编号> --subject grid_security_approver
.\scripts\project.ps1 security execute --request-id <请求编号> --subject grid_key_manager
.\scripts\project.ps1 security audit --subject grid_auditor
```

管理动作先等待当前任务释放执行锁，再切换未来任务使用的状态。撤销在该任务边界生效，不等于立即中断所有在途任务。发现正在发生的泄露时，先正常停服阻止继续受理，保存异常记录；再由独立身份批准撤销和替换，复核后恢复服务。管理审计异常时敏感操作停止。

## 密钥与证书

| 操作 | `--operation` / `--target` | 恢复后核对 |
|---|---|---|
| 更新对象签名密钥 | `rotate-signing`，无target | GW、UC的ECDSA、ML-DSA-65、SM2六把密钥共同进入新epoch；旧版本仅用于历史核验 |
| 撤销一把身份或签名密钥 | `revoke-key`，target为登记中的完整key_id | 当前业务不接纳撤销密钥；缺必需密钥停止业务，没有SAB降级 |
| 更新角色TLS身份 | `renew-tls`，target为source、source-1/2/3、gateway或utility | 新证书和私钥、登记指纹、实际mTLS对端一致；受当前CA有效期约束 |
| 登记提交中断恢复 | `recover-registry`，无target | 只接受双签有效且衔接当前独立锚的待提交版本，恢复后核对登记摘要与最高版本 |
| 删除已停用私钥 | `destroy-key`，target为已退休/撤销key_id | 保留公钥和历史登记；旧备份跳过已逻辑删除的私钥，不宣称物理介质清零 |
| 禁用/启用业务账户 | `disable-account` / `enable-account`，target为业务账户 | 旧会话不能重新使用；启用后重新登录 |

正常业务至少要求ECDSA与ML-DSA-65同时有效、两段业务链路实际协商混合组。增强配置另要求SM2及TLS内SM4-GCM。更新对象签名密钥不会更新PFDAM参数秘密、CA根或登记根；后者需要独立迁移设计，当前不提供自动根替换。

主运行环境保留epoch=1以维持旧入口新建任务的兼容；轮换、撤销和更新已在独立环境真实完成。V1/V2/V3按原字节历史验证，不会获得V4新增声明。旧规范固定epoch=1，轮换后新业务通过V4入口创建，不允许将旧规范密钥版本字段强改为新值。

## 托管与备份边界

当前WSL在Windows当前用户DPAPI下保护独立托管根；根位于 `~/.local/share/grid-custody/<runtime-path-hash>/root.json`，独立于代码和业务运行目录。纯Linux需显式提供至少16字符的 `GRID_CUSTODY_PASSPHRASE`，使用scrypt和SM4-GCM；缺少解锁条件就停止，不能退回明文。长随机秘密宜通过可信本机启动环境提供，不放入仓库或同目录配置。

角色进程只通过一次性管道取得自己的角色材料，父进程保留托管管理权。私钥为加密PKCS#8；私有JSON为绑定角色、路径和版本的SM4-GCM封装。角色管道、解锁材料与TLS exporter密钥均不写入证据。公开参数、公开研究数据、已发布群体结果和白名单证据按公开用途保存；历史实验私有目录没有被批量改写，不能称全盘或全部历史数据加密。

```powershell
.\scripts\project.ps1 security request --operation backup --target <32位小写十六进制备份编号> --reason "受保护秘密备份"
# 按上述独立批准流程approve/execute；execute交互输入独立备份口令
.\scripts\project.ps1 security request --operation restore --target <原备份编号> --reason "恢复损坏的秘密文件"
```

备份封装使用独立口令、scrypt、SM4-GCM，包含已知密钥和PFDAM秘密的加密文件及受保护角色材料；不包含TLS会话密钥。恢复先完整验证候选文件、私公钥对应、参数和当前信任状态，再写入秘密文件。备份口令错误、篡改或跨环境替换均拒绝。

这条恢复路径要求独立托管根、当前登记和公开参数仍可信且可用，只恢复秘密材料，不回退登记、账户、程序批准和审计锚。它不是整机灾备；根丢失/泄露、CA失陷、PFDAM秘密变更和全机同时回滚须另行处理。保护备份文件和备份口令需要真实保管措施，软件测试不代替这些措施。

## 程序与审计故障

程序批准指纹覆盖核心源码、依赖锁、原生库及四个关键入口。源码/库/入口变化后，业务会要求重新批准；先审查具体变更和验证结果，再通过 `security request --operation approve-program` 提出请求。不指定target时绑定当前实际指纹，核对返回的target后由独立身份批准；执行时指纹再次变化会拒绝。批准根存于独立托管根，仍依赖可信加载器、操作系统账户和协调进程；不声称覆盖完整系统、安装依赖二进制、浏览器资源或模块认证。

管理日志使用认证加密和HMAC-SM3事件链，独立根保存计数与链头。修改、截断、旧日志回滚和写入失败有故障用例。先保存损坏原件，不编辑计数或日志伪造连续历史。必要时使用 `security emergency-audit-reanchor`，命令分别要求管理者与审批者口令：保留受损密文、前一链头和计数，永久显示历史缺口；不能还原已经丢失的事件，也不称审计全部恢复。

## 公开核验与开发验证

`verify-export`可使用当前可信运行环境，也可提供 `--trust-runtime <仅公开资料目录> --trusted-pin <独立公开信任锚JSON>`。后者只需公开参数、登记、公钥和历史状态，不需要解锁角色秘密；信任锚必须经归档外的可信途径取得，不能把归档自带根自动接受为可信。

验证输出分别报告回执数学有效、当前密钥状态、UC结果签名与内容关联。撤销后的历史记录可以数学有效，但缺少独立可信签署时点时，不断言其在撤销前可信签署。UC结果签名不能证明解密正确、测量事实真实、源全集完整或发布隐私安全。

```bash
.venv/bin/python scripts/standards_vectors.py
.venv/bin/python scripts/security_validation.py
.venv/bin/python scripts/crypto_conformance.py
.venv/bin/python scripts/standards_regression.py tests -q
.venv/bin/python scripts/verify_acceptance_provenance.py --results artifacts/iterations/standards/regressions/<实际目录>/acceptance_results.json
```

独立算法对端是项目内局部构建的GmSSL 3.2.0；构建和来源摘要见 `references/standards/20261017/supplemental/GmSSL-build.json`，不安装替换全局密码库。每次验证生成新记录，旧测试和性能不覆盖、不重标。页面标准自检保持“部分完成”，最终提交材料与发布继续暂停。
