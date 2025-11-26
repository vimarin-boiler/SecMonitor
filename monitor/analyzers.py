def summarize_logons(security_events):
    logons_ok = [e for e in security_events if e.get("Id") == 4624]
    logons_fail = [e for e in security_events if e.get("Id") == 4625]

    return {
        "logons_ok_count": len(logons_ok),
        "logons_fail_count": len(logons_fail),
        "logons_fail_samples": logons_fail[:10],
    }

def evaluate_resources(resources, thresholds):
    cpu = resources.get("cpu", {}).get("CPUPercent", 0) or 0
    mem_free = resources.get("memory", {}).get("FreeGB", 0) or 0
    disks = resources.get("disk", []) or []

    cpu_status = "ok"
    if cpu >= thresholds.get("CpuCritical", 90):
        cpu_status = "critical"
    elif cpu >= thresholds.get("CpuWarning", 75):
        cpu_status = "warning"

    disk_warnings = []
    for d in disks:
        free = d.get("FreeGB", 0) or 0
        if free <= thresholds.get("DiskFreeGBWarning", 10):
            disk_warnings.append({
                "DeviceID": d.get("DeviceID"),
                "FreeGB": free
            })

    mem_status = "ok"
    if mem_free <= thresholds.get("RamFreeGBCritical", 1):
        mem_status = "critical"
    elif mem_free <= thresholds.get("RamFreeGBWarning", 2):
        mem_status = "warning"

    return {
        "cpu_status": cpu_status,
        "cpu_value": cpu,
        "mem_status": mem_status,
        "mem_free_gb": mem_free,
        "disk_warnings": disk_warnings,
    }


