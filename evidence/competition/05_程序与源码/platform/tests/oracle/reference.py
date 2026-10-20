"""Independent experiment oracle. Never imports the PFDAM matcher."""


def expected(dataset, region, resources, slot, omitted=(), modified=()):
    # Deliberately operate on semantic source records, not gateway output.
    chosen = [
        n
        for n in dataset["nodes"]
        if n["region"] == region and n["resource_class"] in set(resources)
    ]
    valid = [n for n in chosen if n["node_id"] not in set(omitted) | set(modified)]
    return {
        "expected_node_ids": sorted(n["node_id"] for n in valid),
        "expected_sum_W": sum(n["values_W"][slot] for n in valid) if valid else None,
        "expected_target_count": len(chosen),
        "expected_accepted_count": len(valid),
    }


def compare(reference, accepted_report_ids, private_mapping, actual_value):
    actual = sorted(private_mapping[rid] for rid in accepted_report_ids)
    return {
        "set_match": actual == reference["expected_node_ids"],
        "value_match": actual_value == reference["expected_sum_W"],
        "expected_sum_W": reference["expected_sum_W"],
        "actual_sum_W": actual_value,
        "expected_count": reference["expected_accepted_count"],
        "actual_count": len(actual),
    }
