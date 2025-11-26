from datetime import datetime

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
        table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 6px; text-align: left; }}
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

    for s in servers_data:
        name = s["name"]
        html += f"<h2>Servidor: {name}</h2>"

        # Estado general de recursos
        eval_res = s.get("resources_eval", {})
        cpu_class = eval_res.get("cpu_status", "ok")
        mem_class = eval_res.get("mem_status", "ok")

        html += "<h3>Resumen de Salud</h3>"
        html += "<table>"
        html += "<tr><th>Métrica</th><th>Valor</th><th>Estado</th></tr>"
        html += f"<tr><td>CPU Uso (%)</td><td>{eval_res.get('cpu_value', 'N/A')}</td><td class='{cpu_class}'>{cpu_class.upper()}</td></tr>"
        html += f"<tr><td>RAM Libre (GB)</td><td>{eval_res.get('mem_free_gb', 'N/A')}</td><td class='{mem_class}'>{mem_class.upper()}</td></tr>"
        html += "</table>"

        # Discos
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

        # Autenticaciones
        login_summary = s.get("logons", {})
        html += "<h3>Autenticaciones (últimas 24 horas)</h3>"
        html += "<table>"
        html += f"<tr><th>Logons correctos</th><td>{login_summary.get('logons_ok_count', 0)}</td></tr>"
        html += f"<tr><th>Logons fallidos</th><td><span class='warning'>{login_summary.get('logons_fail_count', 0)}</span></td></tr>"
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

        # Servicios críticos
        services = s.get("services", [])
        html += "<h3>Servicios Críticos</h3>"
        if services:
            html += "<table><tr><th>Nombre</th><th>DisplayName</th><th>Estado</th></tr>"
            for svc in services:
                status = svc.get("Status")
                cls = "ok" if status == "Running" else "critical"
                html += f"<tr><td>{svc.get('Name')}</td><td>{svc.get('DisplayName')}</td><td class='{cls}'>{status}</td></tr>"
            html += "</table>"
        else:
            html += "<p class='small'>No se definieron servicios críticos o no se pudo obtener la información.</p>"

    html += "</body></html>"
    return html

