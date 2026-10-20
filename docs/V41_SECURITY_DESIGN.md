# V4.1密码应用设计与验证契约

本文件是研发设计说明，不是最终参赛材料。PFDAM为团队自主方案；原数学构造保持不变。V4.1增加业务治理和证据关联，保留参数安全PENDING、策略/类别候选识别、可信UC及GW诚实但好奇、不串谋等边界。

## 需求—实现—证据

| 研发需求 | 实现位置 | 验证方式 | 范围 |
|---|---|---|---|
| 模拟分类驱动保护 | governance.py::classify/decide | 三级标签、重要模拟场景弱套件拒绝 | 演示规则分，不是正式定级 |
| 谁可统计哪些数据 | sessions.py、governance.py、api.py/v41_api.py | 登录、区域/等级/函数越权、旧入口绕过与跨主体读记录拒绝 | 本机原型账户，不是企业IAM |
| 授权来源与上下文 | schemas.py/signatures.py的TaskAuthV2 | 三签AND、策略/期限/nonce/参数/窗口绑定 | 明文数据生成前不承诺事后快照根 |
| 源侧加密与密态选择 | pfdam.py、workers.py | 独立集合/整数和、修改密文拒绝 | 内层仍经典，参数论证未完成 |
| 业务通信 | native.py、grid_crypto.cpp/agility.cpp | L1/L2实际组、角色证书、SM4帧重放/认证失败 | 证书经典；SM4在TLS内，不是TLCP |
| 快照和包含证明 | merkle.py、Source/GW重算 | SM3域分离树、奇数叶/空集、数据/根/路径修改拒绝 | 只证明密文包含，不证明源集合完整 |
| 回执与结果关联 | AggregationReceiptV2、v41_evidence.py、evidence.py | 策略、计数、集合、密文摘要、快照与审计根逐项核对 | UC明文仍未被该GW签名认证 |
| 审计检查点 | audit.py | 事件修改、删除、重排及根锚定拒绝 | GW签名声明，普通进程事件另列 |
| 密码配置与密钥预检 | agility.py、key_readiness.py、selfcheck.py | 算法已知答案、密钥对应/权限/证书余量、真实运行关联 | 单epoch=1，未实现在线轮换/撤销/HSM |
| 复验与研发实验 | validate_runtime.py、v41_benchmarks.py、cleanroom.py | 独立测试运行目录、原始记录、无外部路由新环境 | 同一WSL主机，非第二台物理机 |

GB/T39786-2021、43207-2023、43206-2023分别作为基本要求、设计指南、测评要求的资料入口。已核对[官方标准元数据](https://std.samr.gov.cn/gb/search/gbDetailedCNF?id=BD89DE8E07393D08E05397BE0A0A4FAD)，未取得并审查所有适用条款全文。上表是工程需求映射，不能称为逐条符合性结论；自检将此项保留为PARTIAL。

## Provider配置

| 配置 | 对象签名要求 | TLS组 | 附加保护 | 是否普通业务可用 |
|---|---|---|---|---|
| V41_CLASSIC | ECDSA | X25519 | SM3快照/审计 | 否，仅实验 |
| V41_SM | ECDSA AND SM2 | X25519 | SM3、SM4-GCM应用帧 | 否，仅实验；不是纯国密TLS |
| V41_PQ | ECDSA AND ML-DSA-65 | MLKEM768 | SM3快照/审计 | 否，仅实验；证书仍经典 |
| V41_HYBRID | ECDSA AND ML-DSA-65 | X25519MLKEM768 | SM3快照/审计 | 是，最低SAB |
| V41_HYBRID_SM | ECDSA AND ML-DSA-65 AND SM2 | X25519MLKEM768 | SM3、SM4-GCM应用帧 | 是，重要模拟资产必须采用 |

策略、签名算法集合与本地传输配置必须一致；用户不能通过普通业务字段选择实验套件。V1签名对象和旧归档继续按原模式核对，不能用V1替换当前任务要求的V2。

## 数据与验证范围

PublicTaskV2与TaskAuthV2绑定模拟治理策略的SHA-384摘要，AggReceiptV2绑定SM3快照根、参与报告ID集合摘要、聚合密文摘要、计数和审计根。Source上传全部实际生成报告，GW核对Source根后进行PFDAM联合检查。UC先验签并核对关联，再验证原生聚合认证和恢复数值。

公开归档不包含授权token、逐户明文/ID映射、会话密钥或访问口令。实验界面的Source明文对照通过显式lab接口读取隔离合成fixture，不是网关获得明文。验证器从归档外取得可信公钥和预期任务；普通文件摘要即使被重算，签名关联不匹配仍拒绝。明文、性能、连接日志与运行状态继续列为未签名信息。

攻击页面仅修改临时归档副本，每次保存独立研发证据文件，原记录保持不变。生产安全或形式化正确性不能从这些有限测试自动推出。
