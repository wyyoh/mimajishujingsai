"""Consolidate existing measured evidence without rerunning or rewriting it."""
import hashlib
import json
import sys
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from services.initialization import ROOT
from services.storage import read, write
from services.versioning import source_version
from scripts.verify_acceptance_provenance import verify as verify_provenance


def main():
    version = source_version()
    digest = version['core_source_digest']
    plan = read(ROOT / 'artifacts/benchmarks/plan.json')
    analysis = read(ROOT / 'artifacts/benchmarks/analysis.json')
    assert analysis['core_source_digest'] == digest
    assert hashlib.sha256((ROOT / 'scripts/analyze_benchmarks.py').read_bytes()).hexdigest() == analysis['analysis_runtime']['script_sha256']
    acceptance = read(ROOT / 'artifacts/tests/acceptance_results.json')
    conformance = read(ROOT / 'artifacts/tests/crypto_conformance.json')
    assert conformance['exit_code'] == 0 and conformance['core_source_digest'] == digest
    assert len(conformance['official_vector_cases']) == 15 and conformance['official_valid'] == 3 and conformance['official_invalid'] == 12
    assert len(conformance['application_cross_checks']) == 4
    assert hashlib.sha256((ROOT / 'scripts/crypto_conformance.py').read_bytes()).hexdigest() == conformance['probe_script_sha256']
    for entry in conformance['vector_source']['files'].values():
        assert hashlib.sha256((ROOT / entry['path']).read_bytes()).hexdigest() == entry['sha256']
    for name, script in (('export_postpatch_audit.json', 'export_audit.py'), ('key_readiness.json', 'key_readiness.py')):
        audit = read(ROOT / 'artifacts/tests' / name)
        assert audit['exit_code'] == 0 and audit['core_source_digest'] == digest
        assert hashlib.sha256((ROOT / 'scripts' / script).read_bytes()).hexdigest() == audit['probe_script_sha256']
    assert read(ROOT / 'artifacts/tests/export_postpatch_audit.json')['rejected'] == 18
    readiness = read(ROOT / 'artifacts/tests/key_readiness.json')
    assert not readiness['issues'] and len(readiness['certificates']) == 4
    assert all(r['private_public_match'] for r in readiness['trusted_public_keys'])
    future = read(ROOT / 'artifacts/tests/key_readiness_future.json')
    assert future['exit_code'] == 1 and future['core_source_digest'] == digest
    assert len(future['issues']) == 4 and all(not r['ready_for_planned_horizon'] for r in future['certificates'])
    assert future['probe_script_sha256'] == readiness['probe_script_sha256']
    ui = read(ROOT / 'artifacts/tests/ui_results.json')
    ui_files = ui['ui_fingerprint']['files']
    assert hashlib.sha256(json.dumps(ui_files, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()).hexdigest() == ui['ui_fingerprint']['sha256']
    assert all(hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == sha for name, sha in ui_files.items())
    clean = read(ROOT / 'artifacts/tests/cleanroom_result.json')
    video = read(ROOT / 'artifacts/tests/video_recording.json')
    assert digest == plan['core_source_digest'] == acceptance['build']['core_source_digest']
    assert all(r['core_source_digest'] == digest for r in (ui, clean, video))
    assert version['native_library_sha256'] == plan['native_library_sha256'] == acceptance['build']['native_library_sha256'] == clean['native_library_sha256']
    assert acceptance['exit_code'] == ui['exit_code'] == clean['exit_code'] == video['exit_code'] == 0
    assert acceptance['counts'] == {'BLOCKED': 0, 'FAIL': 0, 'NOT_RUN': 0, 'PASS': 60}
    assert len(acceptance['cases']) == 60 and all(c['status'] == 'PASS' for c in acceptance['cases'])
    provenance_result = verify_provenance(ROOT)
    assert acceptance['test_execution_count'] == 44
    assert len(acceptance['recovery_cases']) == 6 and all(c['status']=='PASS' for c in acceptance['recovery_cases'])
    raw = read(ROOT / 'artifacts/benchmarks/raw.json')
    assert len(raw) == 120 and all(r['success'] and r['core_source_digest'] == digest for r in raw)
    profiles = Counter(r['profile'] for r in raw)
    assert profiles == {'S0': 30, 'SA': 30, 'SB': 30, 'SAB': 30}
    assert len({r['param_id'] for r in raw}) == len({r['dataset_digest'] for r in raw}) == 1
    assert len({json.dumps(r['result_W'], sort_keys=True) for r in raw}) == 1
    signatures = read(ROOT / 'artifacts/benchmarks/signatures_raw.json')
    sig_counts = Counter((r['object_type'], r['algorithm']) for r in signatures)
    assert len(signatures) == 400 and len(sig_counts) == 4 and set(sig_counts.values()) == {100}
    handshakes = read(ROOT / 'artifacts/benchmarks/handshakes_raw.json')
    hs_counts = Counter((r['profile'], r['link']) for r in handshakes)
    assert len(handshakes) == 240 and len(hs_counts) == 8 and set(hs_counts.values()) == {30}
    nodes = read(ROOT / 'artifacts/benchmarks/nodes_raw.json')
    policies = read(ROOT / 'artifacts/benchmarks/policies_raw.json')
    assert Counter(r['nodes'] for r in nodes) == {100: 3, 300: 3, 600: 3, 900: 3}
    assert Counter(r['policies'] for r in policies) == {1: 3, 2: 3, 5: 3, 10: 3, 15: 3}
    assert all(r['success'] for r in nodes) and all(r['success'] and r['set_match'] and r['value_match'] for r in policies)
    scenarios = read(ROOT / 'artifacts/tests/scenario_catalog.json')
    assert len(scenarios) == 6 and all(r['passed'] and r['core_source_digest'] == digest for r in scenarios)
    assert all(ui[k] for k in ('no_horizontal_overflow', 'real_failure_kept', 'condition_change_clears_metrics', 'replay_preserves_source'))
    assert not ui['browser_errors'] and not video['browser_errors']
    assert video['duration_ms'] >= 300000 and len(video['recorded_runs']) == 6
    assert all(r['core_source_digest'] == digest for r in video['recorded_runs'])
    rehearsals=[read(ROOT/f'artifacts/tests/rehearsal_{minutes}min.json') for minutes in (8,3)]
    for minutes,rehearsal in zip((8,3),rehearsals):
        assert rehearsal['exit_code']==0 and rehearsal['core_source_digest']==digest
        assert rehearsal['duration_ms']>=minutes*60000 and rehearsal['target_seconds']==minutes*60
        assert len(rehearsal['recorded_runs'])==(7 if minutes==8 else 2)
        assert all(r['core_source_digest']==digest for r in rehearsal['recorded_runs'])
        assert rehearsal['export_sha256'] and not rehearsal['browser_errors']
    media=json.loads((ROOT/'artifacts/tests/media_review.json').read_text(encoding='utf-8'))
    assert media['exit_code']==0 and len(media['recordings'])==3
    assert all(r['core_source_digest']==digest and hashlib.sha256((ROOT/r['file']).read_bytes()).hexdigest()==r['sha256'] for r in media['recordings'])
    fidelity = read(ROOT / '.build/materials/report_fidelity.json')
    template = ROOT / 'references/competition/official-attachments/expanded/复赛通知附件/附件二---作品设计报告（模板）.docx'
    report = ROOT / 'materials/作品设计报告_待编号.docx'
    assert hashlib.sha256(template.read_bytes()).hexdigest() == fidelity['template_sha256']
    with zipfile.ZipFile(template) as original, zipfile.ZipFile(report) as generated:
        assert all(original.read(n) == generated.read(n) for n in fidelity['preserved_parts'])
    render = read(ROOT / '.build/materials/report-final-render/render_record.json')
    report_pages=render['pages']
    assert report_pages>=1 and len(render['page_images'])==report_pages
    assert all((ROOT/f'.build/materials/report-final-render/page-{i}.png').is_file() for i in range(1,report_pages+1))
    rendered_pdf = ROOT / '.build/materials/report-final-render/作品设计报告_待编号.pdf'
    assert rendered_pdf.read_bytes() == (ROOT / 'materials/作品设计报告_待编号.pdf').read_bytes()
    deck = ROOT / 'materials/答辩演示稿_最终审阅.pptx'
    deck_check = json.loads((ROOT / '.build/materials/deck.final.validation.json').read_text(encoding='utf-8'))
    assert hashlib.sha256(deck.read_bytes()).hexdigest() == deck_check['finalSha256']
    assert deck_check['packageIntegrity']['finding_count'] == deck_check['presentationLayout']['finding_count'] == 0
    assert deck_check['packageIntegrity']['slide_count'] == 10
    release = read(ROOT / 'artifacts/tests/release_check.json')
    assert release['engineering_checks_ready'] and not release['formal_release_ready']
    assert release['issues'] == ['CORE_PARAMETER_REVIEW_PENDING']
    result = {
        'schema': 'GRID_FINAL_LOCAL_REVIEW_V1',
        'finished_at': datetime.now(timezone.utc).isoformat(),
        'command': ['.venv/bin/python', 'scripts/final_review.py'],
        'core_source_digest': digest,
        'native_library_sha256': version['native_library_sha256'],
        'acceptance_cases_passed': 60,
        'recovery_cases_passed': 6,
        'test_execution_count': 44,
        'acceptance_provenance': provenance_result,
        'formal_matrix': dict(profiles),
        'formal_same_parameters_data_and_results': True,
        'signature_samples': len(signatures),
        'official_ml_dsa_sigver_vectors': 15,
        'object_algorithm_cli_adapter_cross_checks': 4,
        'export_repackaging_and_context_rejections': 18,
        'key_readiness_checked': True,
        'client_handshake_samples': len(handshakes),
        'node_scan_samples': len(nodes),
        'policy_scan_samples': len(policies),
        'scenario_checks_passed': 6,
        'browser_and_clean_install_checks_passed': True,
        'report_pages': report_pages,
        'template_preserved_parts': len(fidelity['preserved_parts']),
        'presentation_slides': 10,
        'rendered_visual_review': 'Agent reviewed all report pages and slide images; this is not human approval or native PowerPoint execution.',
        'video_duration_ms': video['duration_ms'],
        'video_scope': video['scope'],
        'automated_timed_rehearsal_seconds': [r['target_seconds'] for r in rehearsals],
        'recording_decode_and_frame_review': 'Three recordings decoded, duration and digest checked; Agent inspected extracted frames. No human narrator approval claimed.',
        'materials_sha256': {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in (ROOT / 'materials').rglob('*') if p.is_file()},
        'engineering_checks_ready': True,
        'formal_release_ready': False,
        'reference37_scope': 'User authorized official-abstract fallback after unsuccessful legal full-text search; concrete parameter security remains unreviewed',
        'remaining': ['concrete parameter security certification (not claimed)', 'work number', 'human review and signed approval', 'human narration rehearsal and competition submission'],
        'exact_final_zip_install': 'See separate package_verification.json, authenticated by the archive SHA256; not inferred from this prepackage review.',
        'exit_code': 0,
    }
    write(ROOT / 'artifacts/tests/final_review.json', result)
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
