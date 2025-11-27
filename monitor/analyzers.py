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


TCP_STATE_MAP = {
    1: "Closed",
    2: "Listen",
    3: "SynSent",
    4: "SynReceived",
    5: "Established",
    6: "FinWait1",
    7: "FinWait2",
    8: "CloseWait",
    9: "Closing",
    10: "LastAck",
    11: "TimeWait",
    12: "DeleteTCB",
}

def summarize_connections(connections):
    """
    Pequeño resumen: cantidad total y por estado (Established, Listen, etc.).
    """
    total = len(connections or [])
    per_state = {}
    for c in connections or []:
        state = c.get("State", "Unknown")
        if isinstance(state, (int, float)):
            state = TCP_STATE_MAP.get(int(state), str(state))
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

def evaluate_log_growth(current_sizes: dict, previous_sizes: dict, thresholds: dict):
    """
    Compara tamaño de logs actual vs último estado.
    current_sizes: { path: sizeGB }
    previous_sizes: { path: sizeGB }
    """
    percent_warn = thresholds.get("LogGrowthPercentWarning", 50)
    gb_warn = thresholds.get("LogGrowthGBWarning", 1)

    results = []
    status_global = "ok"

    for path, curr in (current_sizes or {}).items():
        prev = (previous_sizes or {}).get(path)
        if curr is None or prev is None:
            results.append({
                "Path": path,
                "PrevGB": prev,
                "CurrGB": curr,
                "DiffGB": None,
                "DiffPercent": None,
                "Status": "unknown"
            })
            continue

        diff = curr - prev
        if prev > 0:
            diff_pct = (diff / prev) * 100
        else:
            diff_pct = None

        status = "ok"
        if diff > gb_warn or (diff_pct is not None and diff_pct > percent_warn):
            status = "warning"
            status_global = "warning"

        results.append({
            "Path": path,
            "PrevGB": round(prev, 3),
            "CurrGB": round(curr, 3),
            "DiffGB": round(diff, 3),
            "DiffPercent": round(diff_pct, 1) if diff_pct is not None else None,
            "Status": status
        })

    return {
        "global_status": status_global,
        "details": results
    }


def compute_risk_score(server: dict):
    """
    Se inventa un score simple de 0 a 100 y un nivel (OK / WARNING / CRITICAL).
    Se basa en:
      - CPU, RAM, discos
      - Logons fallidos
      - Actualizaciones pendientes
      - Eventos críticos
    """
    score = 0
    notes = []

    res_eval = server.get("resources_eval", {})
    cpu_status = res_eval.get("cpu_status")
    mem_status = res_eval.get("mem_status")
    disk_warnings = res_eval.get("disk_warnings", [])

    # CPU
    if cpu_status == "critical":
        score += 20
        notes.append("Uso de CPU crítico.")
    elif cpu_status == "warning":
        score += 10
        notes.append("Uso de CPU elevado.")

    # RAM
    if mem_status == "critical":
        score += 20
        notes.append("Memoria RAM muy baja.")
    elif mem_status == "warning":
        score += 10
        notes.append("Memoria RAM baja.")

    # Discos
    if disk_warnings:
        score += 15
        notes.append("Discos con poco espacio libre.")

    # Logons fallidos
    logons = server.get("logons", {})
    fails = logons.get("logons_fail_count", 0)
    if fails > 100:
        score += 25
        notes.append(f"Más de 100 logons fallidos ({fails}).")
    elif fails > 10:
        score += 10
        notes.append(f"Más de 10 logons fallidos ({fails}).")

    # Actualizaciones
    updates = server.get("updates", {})
    pend = updates.get("PendingSecurityCount")
    if pend is not None:
        if pend > 10:
            score += 20
            notes.append(f"Más de 10 actualizaciones de seguridad pendientes ({pend}).")
        elif pend > 0:
            score += 10
            notes.append(f"Tiene actualizaciones de seguridad pendientes ({pend}).")

    # Eventos críticos
    crit_sum = server.get("critical_events_summary", {})
    total_crit = crit_sum.get("total", 0)
    if total_crit > 50:
        score += 25
        notes.append(f"Más de 50 eventos críticos en las últimas 24h ({total_crit}).")
    elif total_crit > 10:
        score += 15
        notes.append(f"Más de 10 eventos críticos en las últimas 24h ({total_crit}).")

    # Crecimiento de logs
    log_growth = server.get("log_growth", {})
    if log_growth.get("global_status") == "warning":
        score += 10
        notes.append("Crecimiento inusual en logs o archivos de sistema.")

    # Binarios sin firma o con firma inválida
    unsigned = server.get("unsigned_binaries", [])
    if unsigned:
        count = len(unsigned)
        if count > 50:
            score += 25
            notes.append(f"Más de 50 binarios sin firma o con firma inválida ({count}).")
        elif count > 10:
            score += 15
            notes.append(f"Más de 10 binarios sin firma o con firma inválida ({count}).")
        else:
            score += 10
            notes.append(f"Se detectaron binarios sin firma o con firma inválida ({count}).")
            
    # Limitar score
    if score > 100:
        score = 100

    if score >= 70:
        level = "CRITICAL"
    elif score >= 40:
        level = "WARNING"
    else:
        level = "OK"

    return {
        "score": score,
        "level": level,
        "notes": notes
    }
