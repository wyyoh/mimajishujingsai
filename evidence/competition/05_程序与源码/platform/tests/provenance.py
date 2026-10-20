"""Explicit public run references for the current serial pytest item."""
current_runs = None
current_observations = None


def begin(run_ids, observations):
    global current_runs, current_observations
    current_runs = run_ids
    current_observations = observations


def end():
    global current_runs, current_observations
    current_runs = None
    current_observations = None


def record_run(value):
    if current_runs is not None:
        current_runs.add(value if isinstance(value, str) else value['run_id'])


def observe(name, value):
    if current_observations is not None:
        current_observations.append({'name': name, 'value': value})
