"""V3 links extend V2 checks with exact dataset, period and source snapshot bindings."""
from .encoding import Rejected, canonical, digest
from .expansion_schemas import ExpansionPolicy
from .merkle import snapshot
from .signatures import validate

def verify_links(receipt, sealed, audit, accepted, policy):
    from .v41_evidence import verify_links as common
    result = common(receipt, sealed, audit, accepted, policy)
    from .security_schemas import ExpansionPolicyV4
    from .publication_schemas import PublicationPolicy
    policy = validate(PublicationPolicy if receipt['schema_version'] == 5 else ExpansionPolicyV4 if receipt['schema_version'] == 4 else ExpansionPolicy, policy)
    if receipt['schema_version'] >= 4 and (receipt['trust_registry_digest'] != policy['trust_registry_digest'] or receipt['key_epoch'] != policy['key_epoch']):
        raise Rejected('RECEIPT_TRUST_BINDING_MISMATCH')
    if receipt['schema_version'] == 5 and any(receipt[key] != policy[key] for key in ('release_rules_digest', 'release_plan_id')):
        raise Rejected('RECEIPT_RELEASE_PLAN_MISMATCH')
    if receipt['dataset_digest'] != policy['dataset_digest'] or receipt['slot_id'] not in {slot['slot_id'] for slot in policy['selected_slots']}:
        raise Rejected('RECEIPT_DATASET_PERIOD_MISMATCH')
    bindings = {source['source_id']: source for source in policy['sources']}
    sources = receipt['source_snapshots']
    if [source['source_id'] for source in sources] != list(bindings) or any(record.get('source_id') not in bindings for record in sealed['records']):
        raise Rejected('RECEIPT_SOURCE_SET_MISMATCH')
    for source in sources:
        binding = bindings[source['source_id']]
        records = [record for record in sealed['records'] if record['source_id'] == source['source_id']]
        rebuilt = snapshot(records, policy['dataset_version'], receipt['slot_id'])
        if (source['count'] != len(records) or source['count'] > binding['node_count'] or source['root'] != rebuilt['merkle_root']
                or any(source[key] != binding[key] for key in ('partition_digest', 'certificate_sha256'))):
            raise Rejected('RECEIPT_SOURCE_SNAPSHOT_MISMATCH')
    result.update(source_bindings_verified=True, dataset_period_binding_verified=True, source_count=len(sources),
                  source_identity_scope='Exact CA-authenticated Source certificate fingerprints and GW-signed assertions; same-host processes')
    return result
