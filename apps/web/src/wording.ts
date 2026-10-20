// Display names only. Protocol values, signed objects and downloaded records stay unchanged.
export const suiteNames: Record<string, string> = {
  V41_CLASSIC: "经典密码",
  V41_SM: "国密业务增强",
  V41_PQ: "后量子密钥建立",
  V41_HYBRID: "混合密码",
  V41_HYBRID_SM: "混合密码＋国密增强",
};
export const assetNames: Record<string, string> = {
  "public-load-demo": "公开负荷数据（合成）",
  "household-load-demo": "用户用电数据（合成）",
  "critical-load-demo": "重要数据场景（模拟）",
};
export const assetDescriptions: Record<string, string> = {
  "public-load-demo": "一般数据的授权统计",
  "household-load-demo": "用户侧敏感数据的权限控制",
  "critical-load-demo": "重要数据场景的增强保护",
};
export const subjectNames: Record<string, string> = {
  grid_operator_A: "A区协同运营方",
  grid_operator_B: "B区协同运营方",
  grid_analyst_A: "A区公开数据分析方",
};
export const functionNames: Record<string, string> = {
  SUM: "负荷总和（SUM）", AVG: "平均负荷（AVG）", COUNT: "有效报告数（COUNT）",
};
export const modeNames: Record<string, string> = {
  REAL: "实际运行 REAL", PREVIEW: "配置预览 PREVIEW", REPLAY: "历史回放 REPLAY",
};
export const roleNames: Record<string, string> = {
  source: "数据源", gateway: "聚合网关", utility: "统计端（UC）", ta: "授权中心（TA）",
};
export const stageNames: Record<string, string> = {
  AUTH_READY: "任务授权已生成", COLLECTING: "正在接收密文报告", REPORTS_READY: "密文报告已生成",
  SEALED: "数据快照已生成", AGGREGATED: "密文聚合已完成", PUBLISHED: "统计结果已发布",
  FAILED: "处理失败", COMPLETED: "处理完成", CANCELLED: "任务已取消",
};
export const auditActionNames: Record<string, string> = {
  RECEIVED_CIPHERTEXT: "已接收密文报告", SNAPSHOT_SEALED: "已生成数据快照", AGGREGATED: "已完成密文聚合",
};
export function suiteName(value?: string) { return value ? suiteNames[value] || value : "尚未选择"; }
export function subjectName(value?: string | null) { return value ? subjectNames[value] || value : "未登录"; }
export function functionName(value: string) { return functionNames[value] || value; }
export function periodName(value?: string) {
  const match = value?.match(/^slot-(\d+)$/);
  return match ? `时段 ${Number(match[1]) + 1}` : value || "暂无";
}
export function groupName(value?: string) {
  if (value === "X25519MLKEM768") return "X25519 + ML-KEM-768";
  if (value === "MLKEM768") return "ML-KEM-768";
  return value || "等待连接记录";
}

const errors: Record<string, string> = {
  PROTECTED_WORKSPACE_REQUIRED:'新任务已启用统计发布保护，请进入当前协同工作台运行。',
  HISTORICAL_RECORD_OFFLINE_VERIFICATION_ONLY:'此记录使用旧格式，请通过离线验证工具核查；新工作台只提供受保护结果。',
  PRIVATE_SOURCE_PREVIEW_DISABLED:'受保护的合成数据不提供源侧明文曲线。可运行密态任务，或查看明确标记的公开数据预览。',
  RELEASE_CONDITIONS_NOT_MET:'本次结果未满足发布条件，数值暂不提供。请检查登记分组、上报完整性与发布记录。',
  EVALUATION_FIXED_EVENT_PERIODS_REQUIRED:'园区评估使用预先固定的一小时事件窗口，请按当前场景配置运行。',
  PARTICIPATION_DUPLICATE_CONTRIBUTOR:'同一计量点在一个时段出现多份有效报告，本次窗口已拒绝。',
  PARTICIPATION_MAPPING_INCOMPLETE:'部分有效报告缺少正式参与记录，本次结果不能发布。',
  EVALUATION_CHILD_NOT_READY:'一个参考日或事件日任务未完成核验，评估结果尚未发布。',
  RESTARTED_WITHOUT_COMMITTED_PUBLICATION:'任务在发布提交前中断，重启后保留未发布状态。',
  PUBLICATION_STAGED_CONTENT_CHANGED:'待恢复结果与受保护的发布记录不一致，已停止公开输出。',
  PROGRAM_APPROVAL_REQUIRED: '程序版本已变化，请先通过受控管理流程核对并批准，再重新启动。',
  BUSINESS_KEY_SET_INCOMPLETE: '当前有效签名密钥不完整，请先完成更新或恢复。系统不会降低签名要求。',
  KEY_RETIRED_REVOKED_OR_EXPIRED: '所用密钥已停用、撤销或到期，请核对可信登记后重新发起任务。',
  TRUST_REGISTRY_CHANGED: '密钥或证书登记已更新，请刷新授权预览后重新发起任务。',
  TLS_PEER_NOT_CURRENTLY_REGISTERED: '连接证书不在当前有效的可信登记中，已拒绝处理。',
  UC_RESULT_STATEMENT_MISMATCH: '统计端结果声明与结果内容或回执不一致，已拒绝发布。',
  SIGNING_KEY_EPOCH_MISMATCH: '当前接口的密钥版本与有效密钥不一致，请通过协同任务入口重新发起。',
  PRIVATE_STORAGE_PLAINTEXT_REJECTED: '受保护文件被替换为未加密内容，任务已停止，请先核对数据。',
  SOURCE_REPORT_IDENTITY_OR_CONTEXT_MISMATCH: '报告中的数据源标识或任务信息与实际连接不一致，已拒绝处理。',
  SOURCE_CERTIFICATE_BINDING_MISMATCH: '数据源证书与本次授权登记不一致，已拒绝连接。',
  SOURCE_SNAPSHOT_OR_PARTITION_MISMATCH: '数据源提交的密文快照或数据分片与授权记录不一致。',
  SOURCE_PRIVATE_DATA_BINDING_MISMATCH: '数据源持有的数据与本次签名授权不一致，任务已停止。',
  DATASET_PERIOD_SELECTION_INVALID: '请选择同一天内按时间排序的1至4个有效时段。',
  DATASET_SELECTION_INVALID: '该数据集不支持所选节点规模，请重新选择。',
  PUBLIC_DATA_IMPORT_DIGEST_MISMATCH: '公开负荷数据与导入记录不一致，请先核对数据来源与文件摘要。',
  PUBLIC_DATA_NOT_IMPORTED: '尚未导入公开负荷数据，可先使用合成负荷样例。',
  POLICY_SOURCE_IDENTITY_MISMATCH: '授权中的数据源证书与本机可信登记不一致。',
  RECEIPT_SOURCE_SNAPSHOT_MISMATCH: '回执中的数据源快照与实际密文记录不一致。',
  RECEIPT_DATASET_PERIOD_MISMATCH: '回执的数据版本或统计时段与授权不一致。',
  OPERATOR_CREDENTIALS_INVALID: "账户或登录口令不正确，请重新输入。",
  LOCAL_OPERATOR_LOGIN_REQUIRED: "请先登录，再进行操作。",
  LOCAL_LOGIN_RATE_LIMIT: "登录尝试过于频繁，请稍后再试。",
  POLICY_REGION_DENIED: "当前账户没有访问所选区域数据的权限。",
  POLICY_DATA_LEVEL_DENIED: "当前账户没有访问该等级数据的权限。",
  POLICY_FUNCTION_DENIED: "当前账户没有使用该统计方式的权限。",
  POLICY_RESOURCE_INVALID: "请选择允许访问的数据类别。",
  POLICY_CRYPTO_DOWNGRADE: "所选密码方案未达到该数据的保护要求，请使用更强的方案。",
  POLICY_VALIDITY_INVALID: "授权有效期不符合要求，请调整后重试。",
  POLICY_EXPIRED: "任务授权已过期，请重新创建任务。",
  POLICY_REQUEST_NONCE_REPLAY: "该请求已使用过，请重新创建任务。",
  POLICY_DIGEST_MISMATCH: "授权策略与原记录不一致，已拒绝处理。",
  POLICY_GRANT_MISMATCH: "任务授权与账户权限不一致，已拒绝处理。",
  RUN_SUBJECT_ACCESS_DENIED: "当前账户没有查看该任务的权限。",
  V41_RUN_ACCESS_DENIED: "当前账户没有查看该任务的权限。",
  RUN_NOT_FOUND: "没有找到该任务，请返回运行记录重新选择。",
  RUN_IN_PROGRESS: "已有任务正在执行，请等待完成后再提交。",
  RUN_ALREADY_FINISHED: "该任务已结束，无需再次取消。",
  IDEMPOTENCY_KEY_CONFLICT: "本次提交与已有请求不一致，请重新提交。",
  LAB_DISABLED: "当前环境未开启安全测试功能。",
  LAB_ENTRY_REQUIRED: "请从安全测试入口选择实验配置。",
  LAB_RECORD_ACCESS_DISABLED: "当前环境不允许查看实验记录。",
  V41_RECORD_REQUIRED: "请选择使用当前回执格式的任务记录。",
  COMPLETED_V41_RECORD_REQUIRED: "请先选择一个已发布结果的任务。",
  SOURCE_NOT_READY: "数据源尚未准备完成，请稍后再试。",
  ASSET_UNKNOWN: "没有找到所选数据资产，请重新选择。",
  OBJECT_SIGNATURE_INVALID: "数字签名验证未通过，相关记录已拒绝处理。",
  OBJECT_SCHEMA_INVALID: "记录格式不符合协议要求，已拒绝处理。",
  SNAPSHOT_ROOT_MISMATCH: "数据快照与原记录不一致，已检测到修改。",
  AGGREGATION_DIGEST_MISMATCH: "聚合密文与原记录不一致，已检测到修改。",
  AUDIT_CHAIN_INVALID: "审计记录的关联校验未通过。",
  AUTH_EXPIRED: "任务授权已过期。",
  TLS_HANDSHAKE_FAILED: "安全连接建立失败，请检查通信配置和证书。",
  TLS_GROUP_MISMATCH: "通信算法未达到任务要求，连接已拒绝。",
  SERVER_RESTARTED: "服务重启导致任务中断，请重新创建任务。",
};
export function errorExplanation(code: string) { return errors[code] || "操作未完成，请查看错误代码和相关记录。"; }
export function apiError(code: string) { return `${errorExplanation(code)}（${code}）`; }
export function errorText(value: unknown) {
  const message = value instanceof Error ? value.message : String(value);
  return message === "Failed to fetch" ? "暂时无法连接本地服务，请确认服务已启动后重试。" : message;
}

// Exact source-text aliases retain future server wording as a fallback instead of hiding changed risks.
const checkWording: Record<string, string> = {
  "国密原生能力": "国密算法功能",
  "实际业务通信": "业务通信保护",
  "结构化审计检查点": "审计记录关联",
  "密码敏捷与迁移": "密码方案切换与迁移",
  "密态计算安全边界": "密态计算的安全限制",
  "统计结果发布隐私": "统计结果的隐私风险",
  "密码应用标准映射": "密码应用标准对照",
  "密钥与证书": "密钥和证书管理",
  "统计端结果声明": "统计端结果签名",
  "管理操作与程序完整性": "管理操作与程序核对",
  "已接入软件托管及任务边界轮换/撤销；不抵抗完全控制操作系统账户的攻击者，也不代表硬件托管认证": "已接入软件密钥托管，支持在任务结束后更新或撤销密钥。保护仍依赖可信的操作系统账户；尚未取得硬件托管认证。",
  "本地独立管理账户与受保护审计；实际岗位分离和操作系统账户仍是部署条件": "本地管理账户分别承担申请、审批和审计职责，管理日志已有保护。实际人员分工与操作系统账户管理还需在部署时验证。",
  "认证结果声明的来源和内容；不证明解密正确或源全集完整": "结果签名核对统计端的声明来源和内容。解密是否正确、数据源是否完整，仍需独立核对。",
  "已形成适用性和关键条款工程映射；补充全文、产品证明和真实部署仍需分项核对，原型自检不替代正式密评": "已按适用范围对照关键条款和工程证据。部分标准全文、产品证明和真实部署尚待补充，研发自检不能替代正式密评。",
  "敏感操作核对独立审批，审计损坏时保留原件并显式记录恢复缺口": "敏感操作需由不同账户审批。审计损坏时保留原件，并明确记录无法恢复的历史缺口。",
  "继续使用隔离真值核对参与集合和整数和": "继续用隔离的参考数据，分别核对参与报告范围和整数和。",
  "按代码版本和实际证据更新工程状态，不计算标准符合率": "按代码版本更新验证记录。适用条款、自检结果和正式评估分别记录。",
  "本机OpenSSL配置的功能证据；没有算法或模块认证": "已检查本机OpenSSL的国密算法功能；这些检查不代表算法或密码模块认证。",
  "继续执行标准向量和业务负向验证": "继续使用标准测试数据，并验证错误输入能否被拒绝。",
  "单epoch=1，无在线轮换/撤销、HSM和宿主管理员隔离": "目前仅使用第1版密钥，尚未实现在线轮换、撤销和硬件密码设备（HSM）管理。主机管理员不在当前隔离保护范围内。",
  "依据计划使用日期复核有效期，保留历史公钥信任": "按实际使用日期检查证书有效期，并保留验证历史记录所需的可信公钥。",
  "模拟分类与本地账户授权，不是正式数据定级或企业身份系统": "当前使用模拟数据等级和本机账户权限；正式数据定级与企业身份管理尚未接入。",
  "使用真实会话和服务端主体表，验证越权/降级/过期拒绝": "按登录账户和服务端权限检查访问请求，验证越权、降低保护要求和过期授权能否被拒绝。",
  "签名和Merkle不独立证明源集合完整、读数真实或UC恢复明文正确": "签名与Merkle树可以核对记录关联，但不能单独证明原始数据完整、读数真实或统计端（UC）的解密结果正确。",
  "按组件验证，完整性和正确性分别展示": "分别展示签名、快照和结果核对的检查范围。",
  "证书身份仍为经典ECDSA；SM4为TLS内应用保护，不是TLCP": "身份认证仍使用经典ECDSA证书；SM4保护TLS连接内的业务数据，当前未实现TLCP国密传输协议。",
  "保留实际协商组、角色身份和业务请求关联": "记录实际使用的通信算法、连接双方身份及对应业务请求。",
  "GW签名锚定检查点；后续进程事件和宿主管理员行为未独立认证": "网关检查点由回执签名绑定；普通处理日志和主机管理员的操作尚未独立认证。",
  "按签名锚定范围展示，执行删除/修改/重排测试": "明确哪些记录受签名保护，并测试删除、修改或打乱顺序能否被检测。",
  "普通业务仅允许SAB最低保护；实验套件不能作为业务降级入口；PFDAM内核仍经典": "正常任务至少要求数字签名与混合通信，实验配置不能降低这一要求。PFDAM内核仍采用经典密码。",
  "逐个验证实际数据路径，实验说明保护差异": "逐项验证各密码方案的实际运行情况，并说明保护范围的区别。",
  "参数安全论证未完成；低熵策略和特定条件下类别可识别": "已确认候选数量较少的授权策略，以及特定条件下的数据类别可被识别；具体参数的安全性仍需论证。",
  "保留已证实限制，不由外层签名或TLS推导内核安全": "继续说明已确认的限制，分别评估聚合方案、数字签名和通信保护的安全性。",
  "小群体、单个有效报告及相邻查询差分可能泄漏个体信息": "少量用户的统计结果、仅一份有效报告的结果，以及前后查询结果之差，可能泄露个体信息。",
  "先论证业务发布条件与精度，不能任意设置阈值充当证明": "先评估什么情况下可以发布结果，以及统计精度与隐私保护如何平衡。",
  "仅核对官方标准元数据；原型检查不替代正式商用密码应用安全性评估": "目前仅核对标准名称、编号等官方信息，尚未逐条审查适用条款。原型自检不替代正式密评。",
  "取得适用全文后逐条建立需求/代码/证据映射": "取得适用标准全文后，逐条对照业务需求、功能实现和验证记录。",
};
export function checkText(value: string) { return checkWording[value] || value; }
