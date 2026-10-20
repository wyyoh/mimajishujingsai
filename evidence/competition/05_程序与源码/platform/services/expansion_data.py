"""Versioned load catalog. Customer values are read only by the trusted coordinator/Source."""
import math
import random
from datetime import datetime, timedelta, timezone

from .encoding import Rejected, digest
from .initialization import RUNTIME, ROOT
from .storage import read, write

PUBLIC_ID = 'UCI370-WEEK-20130603-V1'
SYNTHETIC_ID = 'SYN-WEEK-V42'

def catalogue():
    result = [{'dataset_id': SYNTHETIC_ID, 'name': '一周合成负荷', 'source': 'SYNTHETIC',
               'node_counts': [120, 300, 600, 900], 'days': 7, 'periods_per_day': 96,
               'interval_minutes': 15, 'reading_origin': '按类别日内曲线生成的合成读数',
               'grouping_origin': '区域与资源类别均为模拟标签', 'unit': 'W', 'date_start': '2026-10-12', 'timezone': 'UTC'}]
    path = ROOT / 'references/datasets/uci321/import.json'
    if path.exists() and (RUNTIME / 'datasets/uci321/week.json').exists():
        imported = read(path)
        result.insert(0, {'dataset_id': PUBLIC_ID, 'name': 'UCI 公开实际负荷', 'source': 'PUBLIC_OBSERVED_SIMULATED_GROUPS',
                         'node_counts': [120, 300, 370], 'days': 7, 'periods_per_day': 96,
                         'interval_minutes': 15, 'reading_origin': '公开客户实际负荷，kW转换为整数W',
                         'grouping_origin': '区域与资源类别为模拟分组，并非原始客户属性', 'unit': 'W', 'date_start': '2013-06-03', 'timezone': 'Europe/Lisbon', 'provenance': imported})
    return result

def synthetic(nodes):
    if nodes not in (120, 300, 600, 900):
        raise Rejected('DATASET_NODE_COUNT_INVALID')
    rng, records = random.Random(42016), []
    for index in range(nodes):
        region = 'A' if index < nodes // 2 else 'B'
        offset, half = index % (nodes // 2), nodes // 2
        kind = 'residential' if offset < int(half * .4) else 'commercial' if offset < int(half * .4) + int(half / 3) else 'charging'
        base = {'residential': 1800, 'commercial': 24000, 'charging': 9000}[kind]
        factor = rng.uniform(.65, 1.35)
        values = []
        for period in range(672):
            day, quarter = divmod(period, 96)
            hour = quarter / 4
            peak = lambda center, spread: math.exp(-((hour - center) / spread)**2 / 2)
            curve = (.35 + .8 * peak(7.5, 1.5) + 1.2 * peak(19, 2)) if kind == 'residential' else (.2 + 1.1 * peak(13, 4)) if kind == 'commercial' else (.15 + .6 * peak(12, 2) + 1.4 * peak(19, 2.5))
            weekend = .6 if day >= 5 and kind == 'commercial' else 1.1 if day >= 5 and kind == 'residential' else 1
            values.append(max(0, round(base * factor * curve * weekend * rng.uniform(.9, 1.1))))
        records.append({'node_id': f'SYN-{region}-{offset:04d}', 'region': region, 'resource_class': kind, 'values_W': values})
    begin = datetime(2026, 10, 12, tzinfo=timezone.utc)
    fmt = lambda value: value.isoformat(timespec='seconds').replace('+00:00', 'Z')
    result = {'dataset_id': SYNTHETIC_ID, 'source': 'SYNTHETIC', 'node_count': nodes, 'slot_count': 672, 'nodes': records,
              'unit': 'W', 'slots': [{'slot_id': f'period-{i:04d}', 'slot_start': fmt(begin + timedelta(minutes=15*i)),
                                     'slot_end': fmt(begin + timedelta(minutes=15*(i+1)))} for i in range(672)],
              'seed': 42016, 'reading_origin': 'synthetic daily shape, weekday/weekend and bounded noise',
              'grouping_origin': 'SIMULATED'}
    result['dataset_digest'] = digest(result)
    return result

def load(dataset_id, nodes):
    if dataset_id == SYNTHETIC_ID:
        path = RUNTIME / f'datasets/synthetic-{nodes}-v42.json'
        if not path.exists():
            write(path, synthetic(nodes), True)
        result = read(path)
    elif dataset_id == PUBLIC_ID and nodes in (120, 300, 370):
        path = RUNTIME / 'datasets/uci321/week.json'
        if not path.exists():
            raise Rejected('PUBLIC_DATA_NOT_IMPORTED')
        original = read(path)
        imported = read(ROOT / 'references/datasets/uci321/import.json')
        if (digest({key: value for key, value in original.items() if key != 'dataset_digest'}) != original['dataset_digest']
                or original['dataset_digest'] != imported['dataset_digest'] or original['raw_sha256'] != imported['raw_sha256']):
            raise Rejected('PUBLIC_DATA_IMPORT_DIGEST_MISMATCH')
        # Equal A/B subsets retain regional diversity without duplicating observed clients.
        selected = []
        half = nodes // 2
        for region in ('A', 'B'):
            available = [node for node in original['nodes'] if node['region'] == region]
            if nodes == 370:
                selected.extend(available)
            else:
                sizes = {'residential': int(half * .4), 'commercial': int(half / 3)}
                sizes['charging'] = half - sum(sizes.values())
                for kind, count in sizes.items():
                    selected.extend([node for node in available if node['resource_class'] == kind][:count])
        result = {**original, 'nodes': selected, 'node_count': nodes, 'parent_dataset_digest': original['dataset_digest']}
        result['dataset_digest'] = digest({key: value for key, value in result.items() if key != 'dataset_digest'})
    else:
        raise Rejected('DATASET_SELECTION_INVALID')
    if digest({key: value for key, value in result.items() if key != 'dataset_digest'}) != result['dataset_digest']:
        raise Rejected('DATASET_CONTENT_DIGEST_MISMATCH')
    return result

def select(dataset_id, nodes, day, periods):
    if type(day) is not int or not 0 <= day < 7 or not 1 <= len(periods) <= 4 or any(type(i) is not int or not 0 <= i < 96 for i in periods) or periods != sorted(set(periods)):
        raise Rejected('DATASET_PERIOD_SELECTION_INVALID')
    full = load(dataset_id, nodes)
    indices = [day * 96 + index for index in periods]
    result = {key: value for key, value in full.items() if key not in ('nodes', 'slots', 'slot_count', 'dataset_digest')}
    result.update(slot_count=len(indices), parent_dataset_digest=full['dataset_digest'], period_indices=indices,
                  slots=[{**full['slots'][index], 'slot_id': f'slot-{i}'} for i, index in enumerate(indices)],
                  nodes=[{key: value for key, value in node.items() if key not in ('original_column', 'values_W')} | {'values_W': [node['values_W'][index] for index in indices]} for node in full['nodes']])
    result['dataset_digest'] = digest(result)
    return result

def curve(dataset_id, nodes, day, region, resources):
    if type(day) is not int or not 0 <= day < 7:
        raise Rejected('DATASET_DAY_INVALID')
    full = load(dataset_id, nodes)
    selected = [node for node in full['nodes'] if node['region'] == region and node['resource_class'] in resources]
    return {'execution_mode': 'PREVIEW', 'scope': 'Trusted source-data preview for period selection; not a homomorphically computed or signed result',
            'dataset_id': dataset_id, 'dataset_digest': full['dataset_digest'], 'source': full['source'], 'day': day,
            'region': region, 'resources': resources, 'unit': 'W', 'group_node_count': len(selected),
            'points': [{'period': period, **full['slots'][day*96+period], 'sum_W': sum(node['values_W'][day*96+period] for node in selected)} for period in range(96)]}
