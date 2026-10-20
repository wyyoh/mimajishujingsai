"""Versioned, evidence-driven application checks with explicit assurance gaps."""
import hashlib
import secrets
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

from .agility import preflight, sm2_sign, sm2_verify, sm4_gcm
from .encoding import Rejected
from .initialization import ROOT, RUNTIME
from .native import utc
from .storage import read, write
from .versioning import source_version
from . import selfcheck_probes as probes


def _probe(call):
    try:
        return call(), None
    except (Rejected, OSError, ValueError, KeyError, TypeError, IndexError, subprocess.SubprocessError) as exc:
        # Exception strings can contain private UC data or subprocess output.
        error = getattr(exc, 'code', 'SELF_CHECK_'+type(exc).__name__.upper())
        return {'error': error}, error


def _primitives():
    checks = preflight()
    from .trust import lookup
    entry, public = lookup(RUNTIME, 'utility', 'sm2')
    data, identity = b'GRID-APPLICATION-SELF-CHECK', 'GRID-APPLICATION-SELF-CHECK'
    signature = sm2_sign(RUNTIME/'utility'/entry['private_key'], data, identity)
    checks.update(sm2_sign_verify=sm2_verify(public, data, identity, signature),
                  sm2_wrong_domain_rejected=not sm2_verify(public, data, identity+'-OTHER', signature),
                  sm2_modified_message_rejected=not sm2_verify(public, data+b'changed', identity, signature))
    key, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    ciphertext, tag = sm4_gcm(key, nonce, data, b'self-check')
    checks['sm4_gcm_roundtrip'] = sm4_gcm(key, nonce, ciphertext, b'self-check', tag) == data
    negative = probes.rejection('sm4_modified_aad', lambda: sm4_gcm(key, nonce, ciphertext, b'changed', tag), {'SM4_AUTHENTICATION_FAILED'})
    checks['sm4_modified_aad_rejected'] = negative['passed']
    probes.require(all(checks.values()), 'SELF_CHECK_PRIMITIVES_FAILED')
    return checks


def _keys():
    from .custody import enabled
    from .trust import current_binding
    path = ROOT/'artifacts/iterations/selfcheck/key-readiness'/f'{uuid.uuid4().hex}.json'
    process = subprocess.run([sys.executable, str(ROOT/'scripts/key_readiness.py'), '--output', str(path)], capture_output=True, timeout=40)
    readiness = read(path) if path.is_file() else {'issues': ['PRECHECK_FAILED']}
    probes.require(process.returncode == 0 and not readiness.get('issues') and enabled(RUNTIME), 'SELF_CHECK_KEY_READINESS_FAILED')
    binding = current_binding(RUNTIME)
    probes.require(len(readiness['trusted_public_keys']) >= 6 and all(row['private_public_match'] for row in readiness['trusted_public_keys'])
                   and all(row['ready_for_planned_horizon'] for row in readiness['certificates']), 'SELF_CHECK_KEY_BINDING_FAILED')
    return {'software_custody_enabled': True, 'binding': binding, 'certificates': readiness['certificates'],
            'signing_key_pairs_checked': len(readiness['trusted_public_keys']), 'issues': [],
            'readiness_record': str(path.relative_to(ROOT)), 'readiness_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
            'lifecycle_scope': 'Current active material only; rotation/revocation validated separately without mutating live keys during self-check'}


def _verify(run):
    from .evidence import verify_export
    expected = {key: run[key] for key in ('run_id', 'task_id', 'param_id', 'security_profile', 'algorithm_suite', 'policy_digest')}
    if run.get('protocol_version') == 5:
        from .publication_evidence import export_v5
        # An older cached ZIP must not mask corruption of current files.
        # A temporary archive preserves original historical archive bytes.
        with tempfile.TemporaryDirectory(prefix='grid-self-check-') as directory:
            archive = export_v5(run['run_id'], target=Path(directory)/'current.zip')
            verified = verify_export(archive, expected_context=expected)
            probes.require(verified.get('release_decision_verified'), 'SELF_CHECK_RELEASE_SIGNER_UNTRUSTED')
            return verified
    from .evidence import export_public
    archive = ROOT/'artifacts/exports'/f'{run["run_id"]}.zip'
    return verify_export(archive if archive.exists() else export_public(run['run_id']), expected_context=expected)


def check(run_id=None, *, subject=None):
    build = source_version()
    requested = run_id
    run_id = run_id or probes.choose_run(subject, build['core_source_digest'])
    if run_id:
        probes.require(bool(probes.RUN_ID.fullmatch(run_id)), 'RUN_NOT_FOUND')
    latest = read(ROOT/'artifacts/runs'/run_id/'run_manifest.json') if run_id else None
    if latest:
        probes.require(probes.RUN_ID.fullmatch(run_id) and latest.get('run_id') == run_id, 'RUN_NOT_FOUND')
        if subject is not None:
            probes.require(latest.get('requester_id') == subject, 'RUN_SUBJECT_ACCESS_DENIED')
        if latest.get('protocol_version') == 5:
            from .custody import trust_pin
            probes.require(latest.get('runtime_instance') == trust_pin(RUNTIME)['registry_pin'] and not latest.get('private_experiment')
                           and latest.get('parent_evaluation', 'none') == 'none', 'RUN_AUTHORITY_MISMATCH')
    fresh = bool(latest and latest.get('core_source_digest') == build['core_source_digest']
                 and latest.get('native_library_sha256') == build['native_library_sha256'])
    rows = []
    def row(identifier, label, status, evidence, summary, risk, recommendation, *, category='functional'):
        rows.append({'id': identifier, 'label': label, 'status': status, 'category': category, 'evidence': evidence,
                     'summary': summary, 'risk': risk, 'recommendation': recommendation})
    def live(identifier, label, call, summary, risk, recommendation):
        evidence, error = _probe(call)
        row(identifier, label, 'FAIL' if error else 'PASS', evidence, '检查未完成，请查看记录中的错误代码。' if error else summary, risk, recommendation)

    live('primitives', '国密算法功能', _primitives,
         'SM3、SM4-GCM标准向量通过；SM2签验、错误身份与改动消息测试通过。',
         '这些是本机密码算法功能检查，不代表算法或密码模块认证。', '继续按适用标准补充选定向量和独立实现互通记录。')
    live('keys', '密钥和证书管理', _keys,
         '软件托管已启用；有效密钥、公私钥对应、证书身份、有效期和私有目录权限核对通过。',
         '本次不轮换或撤销业务密钥；保护依赖可信操作系统账户，未取得硬件托管认证。', '部署时接入实际密钥管理设备，并核对人员分工和证书使用期限。')
    live('authorization', '分类与授权控制', probes.authorization,
         '允许的请求通过；跨区、越级、无权统计、过期授权和降低保护要求均被拒绝。',
         '当前使用模拟数据等级与本机账户权限；正式数据定级和企业身份系统仍是部署条件。', '接入企业身份后，使用实际岗位和数据等级复验。')

    verification, verification_error = (None, None)
    if latest and latest['status'] in ('COMPLETED', 'WITHHELD'):
        verification, verification_error = _probe(lambda: _verify(latest))
    verified = bool(verification and not verification_error and verification.get('release_decision_verified'))
    published = bool(verified and latest.get('publication_status') == 'PUBLISHED')
    withheld = bool(verified and latest.get('publication_status') == 'WITHHELD')
    def task_status(passed, error=None, *, needs_result=False):
        if error or verification_error:
            return 'FAIL'
        if needs_result and withheld:
            return 'NOT_APPLICABLE'
        return ('PASS' if fresh else 'STALE') if passed else 'NOT_RUN'
    groups = link_evidence = None
    link_error = None
    if published and latest.get('protocol_version') == 5:
        def check_links():
            nonlocal groups
            groups = probes.components(latest)
            return probes.links(groups)
        link_evidence, link_error = _probe(check_links)
    integrity_ok = bool(link_evidence and not link_error and link_evidence['all_source_and_period_bindings_verified']
                        and all(item['passed'] for item in link_evidence['snapshot_checks']))
    row('integrity', '回执与快照关联', task_status(integrity_ok, link_error or ('SELF_CHECK_SNAPSHOT_NEGATIVE_FAILED' if link_evidence and not integrity_ok else None), needs_result=True),
        link_evidence or verification or {},
        f'已核对{link_evidence["window_count"]}个时段的签名、逐源快照与统计范围；改动密文和删除参与记录均被拒绝。' if integrity_ok else '本任务未发布数值，无公开结果快照需要核对。' if withheld else '需要一份当前版本的已完成任务及完整快照。',
        '四日期评估额外核对本机UC保存的子任务快照；母归档本身不包含这些快照。签名与Merkle树不证明读数真实或解密正确。',
        '缺少子任务工作副本时恢复可信备份或重新运行；不得用母任务签名代替快照核验。')

    channel, channel_error = _probe(lambda: probes.communication(latest)) if verified else ({}, None)
    row('communication', '业务通信保护', task_status(bool(channel and not channel_error), channel_error), channel,
        f'已逐一核对{channel["connection_pairs"]}条连接的两端记录、身份、实际混合组和业务关联。' if channel and not channel_error else '需要实际业务连接及其两端记录。',
        '连接记录是可信宿主上的运行观察。证书身份为ECDSA；SM4用于TLS内业务保护，当前没有TLCP协议。', '在真实部署网络中补充独立对端验证。')
    audit_ok = bool(link_evidence and not link_error and link_evidence['all_audit_checkpoints_verified']
                    and all(item['passed'] for item in link_evidence['audit_checks']))
    row('audit', '审计记录关联', task_status(audit_ok, link_error or ('SELF_CHECK_AUDIT_NEGATIVE_FAILED' if link_evidence and not audit_ok else None), needs_result=True),
        {'window_count': link_evidence['window_count'], 'negative_checks': link_evidence['audit_checks']} if link_evidence and not link_error else link_evidence or {},
        '所有时段的回执审计锚核对通过；删除、修改和打乱记录顺序均被拒绝。' if audit_ok else '本任务未发布结果，不提供关联检查点。' if withheld else '需要完整的回执与对应审计检查点。',
        '检查范围是回执绑定的检查点；普通进程日志和主机管理员行为未逐条独立认证。', '在部署环境中接入外部日志系统，明确受认证记录的范围。')

    signature_evidence, signature_error = _probe(lambda: probes.signatures(latest)) if verified else ({}, None)
    row('agility', '密码方案切换与迁移', task_status(bool(signature_evidence and not signature_error and channel and not channel_error), signature_error or channel_error), signature_evidence,
        '当前业务路径使用SAB及实际混合通信；逐个删除或改动必需签名均被拒绝。' if signature_evidence and not signature_error else '需要已完成任务来核对当前实际密码路径与签名组合。',
        '本项核对当前选用路径和降级拒绝，不代表全部实验配置或PFDAM参数迁移完成；内核仍采用经典密码。', '更换算法实现、密钥版本或参数后分别保留旧验证能力和新运行证据。')

    rule_evidence, rule_error = _probe(probes.release_rules)
    commit_evidence, commit_error = _probe(lambda: probes.publication_commit(latest)) if verified else ({}, None)
    publication_ok = bool(verified and rule_evidence and not rule_error and commit_evidence and not commit_error)
    row('publication', '统计结果发布保护', task_status(publication_ok, rule_error or commit_error),
        {'release_decision_verified': verified, 'commit': commit_evidence, 'rule_probes': rule_evidence, 'differential_privacy': False},
        '发布决定与受保护历史一致；小组、漏报、重复计量点、分组变更及跨统计方式改值测试通过。' if publication_ok else '发布规则测试与实际发布决定需要同时通过。',
        '固定分组和共享历史约束精确查询；依赖可信UC、诚实Source与宿主，不保证任意背景知识或组合攻击下的隐私，也不是差分隐私。',
        '维持固定分组、完整上报和全部出口的统一发布控制。')

    if latest and latest.get('evaluation_id'):
        metric_ok = bool(verification and verification.get('business_metrics_recomputed') and not verification_error)
        row('response', '园区评估指标复算', task_status(metric_ok, needs_result=True), {'four_date_inputs_verified': metric_ok},
            '16份统计端签名输入与四日期关系核对通过，业务指标已按精确值重新计算。' if metric_ok else '需要完整发布的四日期评估输入。',
            '指标复算不证明解密、现场读数或调控因果；受控模拟与真实节能效果分开说明。', '接入实际计量和调控记录后再评估现场效果。')
    from .management import verify_audit, verify_program
    management, management_error = _probe(lambda: {'audit': verify_audit(), 'program': verify_program()})
    management_status = 'FAIL' if management_error else 'PARTIAL' if management['audit']['historical_gap_recorded'] else 'PASS'
    row('management', '管理操作与程序核对', management_status, management,
        '本地管理审计的认证链和独立锚核对通过；运行程序与已批准指纹一致。' if not management_error else '管理审计或已批准程序指纹核对失败。',
        '账户分别承担申请、审批和审计职责；实际人员分工与操作系统账户管理需在部署时验证。历史缺口不因恢复而消失。', '保留独立审批、单次授权和审计恢复记录。')
    result_ok = bool(verification and verification.get('uc_result_origin_and_integrity_verified') and verification.get('uc_result_keys_trusted_for_provided_state') and not verification_error)
    row('result_statement', '统计端结果签名', task_status(result_ok, needs_result=True),
        {'origin_and_content_verified': result_ok, 'expected_context_checked': bool(verification and verification.get('expected_context_checked'))},
        '统计端结果签名、结果内容、指定任务与可信公钥登记核对通过。' if result_ok else '本任务未发布数值，不存在统计结果签名；发布决定已单独核验。' if withheld else '需要已发布的统计端结果声明。',
        '结果签名认证声明来源和内容；不能单独证明解密正确或源数据完整真实。', '继续用隔离参考数据分别核对参与集合和整数和。')

    row('confidentiality', '密态计算的安全限制', 'PENDING',
        {'parameter_security': 'PENDING', 'policy_hiding': 'DEMONSTRATED_LIMITATION', 'report_class_hiding': 'DEMONSTRATED_LIMITATION'},
        '该项尚不能通过：参数安全论证未完成，已确认的候选识别限制继续保留。',
        '低熵候选策略及特定条件下的数据类别可被识别。外层签名和TLS不能修复这一内核限制。', '独立开展参数与攻击面论证；改变实质协议需另行设计和评审。', category='research')
    mapping, mapping_error = _probe(lambda: read(ROOT/'docs/STANDARDS_ALIGNMENT_EXECUTION.json'))
    from .standards_profile import evaluate as evaluate_standards
    alignment, alignment_error = _probe(lambda: evaluate_standards(rows, mapping)) if not mapping_error else (mapping, mapping_error)
    row('standards', '本机密码标准对齐', 'FAIL' if alignment_error else alignment['status'], alignment,
        'SM2、SM3、SM4与密钥派生的11项向量和边界检查通过；9组本机应用控制已关联实际任务证据。' if not alignment_error and alignment['status']=='PASS' else '按本机适用标准检查算法、密钥、授权、通信和审计，结果随实际证据更新。',
        '检查范围为本机软件适用功能与所选标准条款。37项原始工程对照另行保留，用于需求追溯。',
        '每次检查重新执行标准向量，使用当前任务核对应用控制。')

    stable = source_version() == build
    if not stable:
        for item in rows:
            if item['category'] == 'functional' and item['status'] == 'PASS':
                item.update(status='STALE', summary='检查期间代码发生变化，请在稳定版本上重新执行。')
    functional = [item for item in rows if item['category'] == 'functional']
    statuses = {item['status'] for item in functional}
    functional_overall = 'FAIL' if 'FAIL' in statuses else 'PASS' if statuses <= {'PASS', 'NOT_APPLICABLE'} else 'STALE' if 'STALE' in statuses else 'NOT_RUN'
    identifier = uuid.uuid4().hex
    path = ROOT/'artifacts/iterations/selfcheck/reports'/f'{identifier}.json'
    result = {'schema': 'GRID_APPLICATION_SELF_CHECK_V3', 'display_scope': 'LOCAL_APPLICATION_FUNCTIONS', 'check_id': identifier, 'checked_at': utc(),
              'run_id': run_id, 'selection': 'EXPLICIT' if requested else 'LATEST_AUTHORIZED' if run_id else 'NO_ELIGIBLE_RUN',
              'version_matches': fresh, 'source_stable_during_check': stable, **build,
              'overall': 'HAS_OPEN_ITEMS', 'functional_overall': functional_overall, 'formal_evaluation': False,
              'counts': {'functional_pass': sum(item['status'] == 'PASS' for item in functional),
                         'functional_total': len(functional), 'functional_not_applicable': sum(item['status'] == 'NOT_APPLICABLE' for item in functional),
                         'open_assurance': sum(item['status'] != 'PASS' for item in rows if item['category'] != 'functional')},
              'checks': rows, 'record_path': str(path.relative_to(ROOT)),
              'scope': 'Local application enforcement and authorized task evidence. Open research/deployment conditions are not passed or certified.'}
    write(path, result)
    return result
