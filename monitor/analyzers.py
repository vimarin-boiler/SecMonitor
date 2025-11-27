import json

def summarize_logons(security_events):
    logons_ok = [e for e in security_events if e.get("Id") == 4624]
    logons_fail = [e for e in security_events if e.get("Id") == 4625]

    return {
        "logons_ok_count": len(logons_ok),
        "logons_fail_count": len(logons_fail),
        "logons_fail_samples": logons_fail[:10],
    }
def normalize_field(value, default):
    if isinstance(value, str):
        try:
            return json.loads(value)
        except:
            return default
    return value

def evaluate_resources(resources, thresholds):
    cpu_info = resources.get("cpu", {})
    if not isinstance(cpu_info, dict):
        cpu_info = {}

    mem_info = resources.get("memory", {})
    if not isinstance(mem_info, dict):
        mem_info = {}

    disks = resources.get("disk", [])
    if not isinstance(disks, list):
        disks = []

    cpu = cpu_info.get("CPUPercent", 0)
    mem_free = mem_info.get("FreeGB", 0)

    cpu_status = "ok"
    if cpu >= thresholds.get("CpuCritical", 90):
        cpu_status = "critical"
    elif cpu >= thresholds.get("CpuWarning", 75):
        cpu_status = "warning"

    disk_warnings = []
    for d in disks:
        free = d.get("FreeGB", 0)
        if free <= thresholds.get("DiskFreeGBWarning", 10):
            disk_warnings.append({"DeviceID": d.get("DeviceID"), "FreeGB": free})

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


def summarize_connections(connections):
    """
    Pequeño resumen: cantidad total y por estado (Established, Listen, etc.).
    """
    total = len(connections or [])
    per_state = {}
    for c in connections or []:
        state = c.get("State", "Unknown")
        per_state[state] = per_state.get(state, 0) + 1

    return {
        "total": total,
        "by_state": per_state
    }


def summarize_critical_events(crit_summary):
    """
    Recibe el dict de get_critical_events_summary y solo normaliza la estructura.
    """
    total = 0
    per_log = {}
    for log, data in (crit_summary or {}).items():
        c = data.get("count", 0)
        total += c
        per_log[log] = c
    return {
        "total": total,
        "per_log": per_log
    }

