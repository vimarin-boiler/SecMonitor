from datetime import datetime

# Descripción en español de los estados de servicios Windows
SERVICE_STATUS_DESC = {
    "Running": "En ejecución",
    "Stopped": "Detenido",
    "StartPending": "Iniciando (pendiente)",
    "StopPending": "Deteniendo (pendiente)",
    "ContinuePending": "Reanudando (pendiente)",
    "PausePending": "Pausando (pendiente)",
    "Paused": "Pausado",

    # Map de valores numéricos del enum ServiceControllerStatus
    "0": "Detenido",
    "1": "Iniciando (pendiente)",
    "2": "Deteniéndose (pendiente)",
    "3": "En ejecución",
    "4": "Reanudando (pendiente)",
    "5": "Pausándose (pendiente)",
    "6": "Pausado",
}

# Descripción en español de los estados TCP
TCP_STATE_DESC = {
    "Closed": "Cerrada",
    "Listen": "Escuchando",
    "SynSent": "Esperando respuesta (SYN-SENT)",
    "SynReceived": "Recibiendo sincronización (SYN-RECEIVED)",
    "Established": "Conexión establecida",
    "FinWait1": "Finalización en curso (FIN-WAIT-1)",
    "FinWait2": "Finalización en curso (FIN-WAIT-2)",
    "CloseWait": "Esperando cierre remoto (CLOSE-WAIT)",
    "Closing": "Cerrando (CLOSING)",
    "LastAck": "Último ACK antes de cierre (LAST-ACK)",
    "TimeWait": "Esperando para liberar recursos (TIME-WAIT)",
    "DeleteTCB": "Eliminando bloque de control (DELETE-TCB)",
}


def build_html_report(servers_data):
    date_str = datetime.now().strftime("%Y-%m-%d %H:%M")
    html = f"""
    <html>
    <head>
      <meta charset="utf-8"/>
      <style>
        body {{ font-family: Arial, sans-serif; font-size: 12px; }}
        h1 {{ background-color: #003366; color: white; padding: 10px; }}
        h2 {{ color: #003366; border-bottom: 1px solid #ccc; margin-top: 30px; }}
        h3 {{ color: #003366; }}
        h4 {{ color: #003366; }}
        table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 6px; text-align: left; vertical-align: top; }}
        th {{ background-color: #f2f2f2; }}
        .ok {{ color: green; font-weight: bold; }}
        .warning {{ color: #e69138; font-weight: bold; }}
        .critical {{ color: red; font-weight: bold; }}
        .small {{ font-size: 10px; color: #666; }}
      </style>
    </head>
    <body>
      <h1>Reporte Diario de Seguridad y Recursos - {date_str}</h1>
      <p class="small">Generado automáticamente por el monitor de servidores Windows.</p>
    """

    # ==========================
    # Resumen ejecutivo global
    # ==========================
    html += "<h2>Resumen Ejecutivo Global</h2>"
    html += "<table><tr><th>Servidor</th><th>Nivel</th><th>Score</th><th>Comentarios</th></tr>"
    for s in servers_data:
        risk = s.get("risk", {})
        level = risk.get("level", "OK")
        score = risk.get("score", 0)
        notes = risk.get("notes", [])
        cls = "ok"
        if level == "WARNING":
            cls = "warning"
        elif level == "CRITICAL":
            cls = "critical"
        html += (
            f"<tr><td>{s['name']}</td>"
            f"<td class='{cls}'>{level}</td>"
            f"<td>{score}</td>"
            f"<td>{'; '.join(notes)}</td></tr>"
        )
    html += "</table>"

    # ==========================
    # Detalle por servidor
    # ==========================
    for s in servers_data:
        name = s["name"]
        html += f"<h2>Servidor: {name}</h2>"

        # ---- Resumen de recursos ----
        eval_res = s.get("resources_eval", {})
        cpu_class = eval_res.get("cpu_status", "ok")
        mem_class = eval_res.get("mem_status", "ok")

        html += "<h3>Resumen de Salud</h3>"
        html += "<table>"
        html += "<tr><th>Métrica</th><th>Valor</th><th>Estado</th></tr>"
        html += (
            f"<tr><td>CPU Uso (%)</td>"
            f"<td>{eval_res.get('cpu_value', 'N/A')}</td>"
            f"<td class='{cpu_class}'>{cpu_class.upper()}</td></tr>"
        )
        html += (
            f"<tr><td>RAM Libre (GB)</td>"
            f"<td>{eval_res.get('mem_free_gb', 'N/A')}</td>"
            f"<td class='{mem_class}'>{mem_class.upper()}</td></tr>"
        )
        html += "</table>"

        # ---- Discos ----
        res = s.get("resources", {})
        disk = res.get("disk", [])
        html += "<h3>Discos</h3>"
        html += "<table><tr><th>Disco</th><th>Tamaño (GB)</th><th>Libre (GB)</th><th>Alerta</th></tr>"
        warning_disks = {d["DeviceID"]: d["FreeGB"] for d in eval_res.get("disk_warnings", [])}
        for d in disk:
            dev = d.get("DeviceID")
            size = d.get("SizeGB")
            free = d.get("FreeGB")
            if dev in warning_disks:
                cls = "warning"
                alert = "Espacio bajo"
            else:
                cls = "ok"
                alert = ""
            html += f"<tr><td>{dev}</td><td>{size}</td><td>{free}</td><td class='{cls}'>{alert}</td></tr>"
        html += "</table>"

        # ---- Actualizaciones de seguridad ----
        upd = s.get("updates", {})
        html += "<h3>Actualizaciones de Seguridad</h3>"

        pending = upd.get("PendingCount", 0)
        pending_sec = upd.get("PendingSecurityCount", 0)

        cls = "ok" if pending == 0 and pending_sec == 0 else "warning"

        html += "<table>"
        html += f"<tr><th>Actualizaciones pendientes (totales)</th><td class='{cls}'>{pending}</td></tr>"
        html += f"<tr><th>Actualizaciones de seguridad pendientes</th><td class='{cls}'>{pending_sec}</td></tr>"
        html += "</table>"

        ptitles = upd.get("PendingTitles") or []

        # 👇 NORMALIZAMOS AQUÍ
        if isinstance(ptitles, str):
            # Un solo título en string → lo convertimos a lista con un solo elemento
            ptitles = [ptitles]
        elif isinstance(ptitles, dict):
            # Si por alguna razón vino como objeto, lo convertimos a string
            ptitles = [str(ptitles)]

        if ptitles:
            html += "<h4>Listado de actualizaciones pendientes</h4>"
            html += "<ul>"
            for t in ptitles:
                html += f"<li>{t}</li>"
            html += "</ul>"
        else:
            html += "<p class='small'>No se encontraron títulos de actualizaciones pendientes (0 o no disponible).</p>"

        # ---- Autenticaciones ----
        login_summary = s.get("logons", {})
        html += "<h3>Autenticaciones (últimas 24 horas)</h3>"
        html += "<table>"
        html += f"<tr><th>Logons correctos</th><td>{login_summary.get('logons_ok_count', 0)}</td></tr>"
        html += (
            "<tr><th>Logons fallidos</th>"
            f"<td><span class='warning'>{login_summary.get('logons_fail_count', 0)}</span></td></tr>"
        )
        html += "</table>"

        fail_samples = login_summary.get("logons_fail_samples", [])
        if fail_samples:
            html += "<h4>Ejemplos de logons fallidos</h4>"
            html += "<table><tr><th>Fecha/Hora</th><th>Proveedor</th><th>Mensaje</th></tr>"
            for e in fail_samples:
                time_created = e.get("TimeCreated")
                provider = e.get("ProviderName")
                msg = (e.get("Message") or "").replace("\r\n", " ")
                if len(msg) > 200:
                    msg = msg[:200] + "..."
                html += f"<tr><td>{time_created}</td><td>{provider}</td><td>{msg}</td></tr>"
            html += "</table>"

        # ---- Servicios críticos ----
        services = s.get("services", [])
        html += "<h3>Servicios Críticos</h3>"
        if services:
            html += "<table><tr><th>Nombre</th><th>DisplayName</th><th>Estado</th></tr>"
            for svc in services:
                raw_status = svc.get("Status")
                raw_str = str(raw_status) if raw_status is not None else "Unknown"

                # Buscamos descripción amigable: primero por la cadena tal cual,
                # y si no, por la versión string del número
                status_desc = SERVICE_STATUS_DESC.get(raw_str, raw_str)

                # Para el color, consideramos "Running" o 3 como OK
                is_running = (raw_str == "Running" or raw_str == "3")
                cls = "ok" if is_running else "critical"

                html += (
                    f"<tr><td>{svc.get('Name')}</td>"
                    f"<td>{svc.get('DisplayName')}</td>"
                    f"<td class='{cls}'>{status_desc}</td></tr>"
                )
            html += "</table>"
        else:
            html += (
                "<p class='small'>No se definieron servicios críticos "
                "o no se pudo obtener la información.</p>"
            )


        # ---- Conexiones activas ----
        conn_sum = s.get("connections_summary", {})
        html += "<h3>Conexiones Activas</h3>"
        html += "<table>"
        html += f"<tr><th>Total conexiones TCP</th><td>{conn_sum.get('total', 0)}</td></tr>"
        html += "</table>"

        by_state = conn_sum.get("by_state", {})
        if by_state:
            html += "<h4>Conexiones por estado</h4>"
            html += "<table><tr><th>Estado</th><th>Cantidad</th></tr>"
            for state, count in by_state.items():
                state_str = str(state)
                state_desc = TCP_STATE_DESC.get(state_str, state_str)
                # Mostramos "Descripción (EstadoOriginal)"
                html += f"<tr><td>{state_desc} ({state_str})</td><td>{count}</td></tr>"
            html += "</table>"

        # ---- Eventos críticos ----
        crit_summary = s.get("critical_events_summary", {})
        html += "<h3>Eventos Críticos (últimas 24 horas)</h3>"
        html += "<table><tr><th>Log</th><th>Cantidad de eventos Error/Critical</th></tr>"
        per_log = crit_summary.get("per_log", {})
        for log_name, count in per_log.items():
            cls = "ok" if count == 0 else "warning"
            html += f"<tr><td>{log_name}</td><td class='{cls}'>{count}</td></tr>"
        html += "</table>"

        # ---- Crecimiento de logs ----
        log_growth = s.get("log_growth", {})
        html += "<h3>Crecimiento de Logs / Archivos de Sistema</h3>"
        details = log_growth.get("details", [])
        if not details:
            html += "<p class='small'>No hay datos previos para comparar (primer día de ejecución o sin baseline).</p>"
        else:
            html += (
                "<table><tr><th>Ruta</th><th>Tamaño anterior (GB)</th>"
                "<th>Tamaño actual (GB)</th><th>Diferencia (GB)</th>"
                "<th>Diferencia (%)</th><th>Estado</th></tr>"
            )
            for item in details:
                cls = "ok"
                if item.get("Status") == "warning":
                    cls = "warning"
                html += (
                    f"<tr><td>{item.get('Path')}</td>"
                    f"<td>{item.get('PrevGB')}</td>"
                    f"<td>{item.get('CurrGB')}</td>"
                    f"<td>{item.get('DiffGB')}</td>"
                    f"<td>{item.get('DiffPercent')}</td>"
                    f"<td class='{cls}'>{item.get('Status')}</td></tr>"
                )
            html += "</table>"

        # ---- Binarios sin firma o firma inválida ----
        unsigned = s.get("unsigned_binaries", [])
        html += "<h3>Binarios sin firma o con firma digital inválida</h3>"
        if not unsigned:
            html += (
                "<p class='small'>No se detectaron binarios sin firma o con firma inválida "
                "en los servicios/procesos analizados.</p>"
            )
        else:
            html += f"<p>Se detectaron <b>{len(unsigned)}</b> binarios con problemas de firma digital.</p>"
            # Limitamos el detalle a los primeros 50 para no hacer el correo gigante
            html += (
                "<table>"
                "<tr><th>Tipo</th><th>Nombre</th><th>Ruta</th>"
                "<th>PID</th><th>Estado firma</th><th>Cert.Subject</th></tr>"
            )
            for item in unsigned[:50]:
                tipo = item.get("Type")
                nombre = item.get("Name")
                ruta = item.get("Path")
                pid = item.get("Pid", "")
                status = item.get("SignatureStatus")
                cert_subj = item.get("CertSubject") or ""
                if len(cert_subj) > 80:
                    cert_subj = cert_subj[:80] + "..."
                cls = "warning"
                status_str = str(status) if status is not None else "Unknown"
                if status_str.lower() in ("notsigned", "not signed"):
                    cls = "critical"
                html += (
                    f"<tr><td>{tipo}</td>"
                    f"<td>{nombre}</td>"
                    f"<td>{ruta}</td>"
                    f"<td>{pid}</td>"
                    f"<td class='{cls}'>{status_str}</td>"
                    f"<td>{cert_subj}</td></tr>"
                )
            html += "</table>"

    html += "</body></html>"
    return html