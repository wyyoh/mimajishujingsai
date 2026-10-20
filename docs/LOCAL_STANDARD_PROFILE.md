# 本机密码标准对齐检查

2026-10-18用户明确本轮目标：核对团队自研项目在本机软件范围内的适用密码功能与标准条款，不要求第三方认证、硬件设备或生产部署。

执行范围标识：`GRID_LOCAL_APPLICATION_STANDARD_PROFILE_V1`。自检报告升级为`GRID_APPLICATION_SELF_CHECK_V3`，业务签名对象版本不变。历史37项完整工程适用性对照保留原版本，不把未启用设备或不同产品范围强行加入本机功能通过门槛。

## 实际检查

每次执行自检时重新调用本机密码实现，而非读取一个固定“通过”标签：

| 本机算法检查 | 对照来源 | 实际行为 |
|---|---|---|
| SM3 | GB/T32905-2016 | abc及多分组公开例子逐字节比较 |
| SM2 | GB/T32918.2-2016、32918.5-2017 | 推荐曲线例子签名验证、身份和消息绑定、严格签名编码 |
| SM4 | GM/T0002-2012、GB/T36624-2018资料性C.5 | 单分组例子、GCM空/非空消息、恢复及认证上下文拒绝 |
| 密钥派生 | RFC5869 A.1 | HKDF公开例子的前16字节比较 |

共11项向量和边界检查。单分组例子中的ECB只存在于测试调用，不加入业务配置。应用启动另有RFC8998选定SM4-GCM向量；[RFC8998](https://www.rfc-editor.org/rfc/rfc8998.html)也规定完整TLS密码套件，该协议配置与“采用其中的算法例子”分开记录。

应用控制按照[GB/T39786-2021官方文本](https://www.jsmm.gov.cn/u/cms/www/202110/140914053ph6.pdf)中的相关应用主题及原工程映射，选择9组本机可核对项目：算法身份/签验与编码、运行前检查、活动密钥和证书登记、分类授权、业务链路保护、回执与密文快照、审计检查点、程序与管理审计、统计端结果签名。每组引用已有功能自检的真实结果；原工程编号表示需求追溯，不声称已覆盖对应标准的全部要求。

任何一项必需检查失败，标准对齐行即不能通过；缺少任务显示待运行，历史代码或原生库不匹配显示历史证据；未发布任务的数值结果检查明确不适用。本机适用检查通过时显示“本机密码标准对齐：检查通过”。

## 范围和证据

该项目自检对应本机软件适用功能及所选条款，不是模块/产品证书或完整信息系统评估结论。第三方不是本轮执行依赖；JSON中明确记录`third_party_assessment_required=false`、`whole_standard_conformance_claimed=false`和`formal_evaluation=false`。原有37项对照中的其他范围继续作为研发参考记录保存。

业务页面展示功能结果和检查记录；参数研究结论保留在研发文档与技术报告中，不计入本机功能通过率，也不由向量检查推导PFDAM安全证明。展示范围调整不是修复研究结论或增加标准认证。

实现见`services/standards_profile.py`和`services/selfcheck.py`；开发证据独立保存在`artifacts/iterations/local-standards/`。旧版本的46项针对性回归、43项管理观察和11项自检结果保留原摘要，不重标为本轮成绩。

## 本轮验证

当前核心`250da67238de715c9ffeb1d44a0d8c314a5cfc5e6d92b7cc045f4f20768ebe23`，PFDAM数学和原生库摘要不变。验证索引为`artifacts/iterations/local-standards/validation-index.json`。

- `regressions/2026-10-18T03-20-36.366Z/validation.json`：47项针对性测试通过、2项旧外部记录审查明确排除，355.74秒；源码执行中未变化。保留1条既有Starlette/httpx弃用警告。本次445份消耗证据引用核对通过，不声称重跑前轮101项全套验收。
- `browser/2026-10-18T03-21-11.699Z/validation.json`：真实Chrome普通业务任务`67027b12c5884f9f8f3ce99415bc58c3`，12项功能通过；标准向量数量、当前与历史区分、下载、自动选取、401/403、正面展示及1440/390/320宽度检查通过。技术报告仍保存原研究状态。
- `../standards/security/2026-10-18T03-22-23.890Z.json`：43项当前代码的密钥、管理及恢复观察通过；既有驱动使用V4对象，V5路径由本轮回归和浏览器分别验证。
- `../standards/vectors/2026-10-18T03-22-21.262Z.json`：8组补充向量和本机独立GmSSL实现互通通过。对端尾随签名字节的接受差异继续原样记录，不作为本机应用编码接受条件，也不是本轮第三方认证依赖。

实际命令：WSL中使用`GRID_VALIDATION_FAMILY=local-standards .venv/bin/python scripts/standards_regression.py tests/test_selfcheck.py tests/test_v41.py tests/test_standards.py tests/test_publication.py tests/test_publication_integration.py tests/test_private_storage_boundary.py -q -k 'not private_controls_and_availability_record and not original_signed_archive_history_record'`；另执行`scripts/security_validation.py`、`scripts/standards_vectors.py`、`scripts/parameter_scope_review.py`和`artifacts/iterations/local-standards/assemble_evidence.py`。Windows侧执行`node apps/web/scripts/local-standards-ui-check.mjs`，生产构建使用`apps/web`下的`npm run build`。新执行创建新结果，索引脚本拒绝覆盖既有索引。
