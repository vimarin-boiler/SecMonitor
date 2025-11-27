from monitor.config_loader import load_config
from monitor.state_store import load_state, save_state

from monitor.collectors import (
    create_session,
    get_system_resources,
    get_critical_services_status,
    get_recent_events,
    get_security_updates_status,
    get_active_connections,
    get_critical_events_summary,
    get_paths_size,
)
from monitor.analyzers import (
    summarize_logons,
    evaluate_resources,
    summarize_connections,
    summarize_critical_events,
    evaluate_log_growth,
    compute_risk_score,
)
from monitor.report_html import build_html_report
from monitor.mailer import send_html_email


def run_daily_monitor():
    config = load_config()
    smtp_conf = config["Smtp"]
    servers_conf = config["Servers"]
    thresholds = config.get("Thresholds", {})

    state = load_state(config)         # estado anterior
    new_state_servers = {}            # para guardar nuevo estado
    all_data = []

    for s in servers_conf:
        name = s["Name"]
        print(f"Monitoreando servidor: {name}")

        prev_server_state = state.get("servers", {}).get(name, {})
        prev_log_sizes = prev_server_state.get("log_sizes", {})

        try:
            session = create_session(
                host=s["Host"],
                username=s["Username"],
                password=s["Password"]
            )

            # Recursos
            resources = get_system_resources(session)
            res_eval = evaluate_resources(resources, thresholds)

            # Eventos de seguridad y logons
            events_sec = get_recent_events(session, "Security", 24, 300)
            logons = summarize_logons(events_sec)

            # Servicios críticos
            services = get_critical_services_status(session, s.get("CriticalServices", []))

            # Actualizaciones
            updates = get_security_updates_status(session)

            # Conexiones activas
            connections = get_active_connections(session, max_results=200)
            conn_summary = summarize_connections(connections)

            # Eventos críticos (System/Application/Security)
            crit_raw = get_critical_events_summary(session, hours=24, max_events_per_log=200)
            crit_summary = summarize_critical_events(crit_raw)

            # Tamaños de logs
            log_paths = s.get("LogPaths", [])
            current_log_sizes = get_paths_size(session, log_paths)
            log_growth = evaluate_log_growth(current_log_sizes, prev_log_sizes, thresholds)

            server_data = {
                "name": name,
                "resources": resources,
                "resources_eval": res_eval,
                "logons": logons,
                "services": services,
                "updates": updates,
                "connections_summary": conn_summary,
                "critical_events_raw": crit_raw,
                "critical_events_summary": crit_summary,
                "log_growth": log_growth,
            }

            # Resumen de riesgo
            risk = compute_risk_score(server_data)
            server_data["risk"] = risk

            all_data.append(server_data)

            # Actualizar estado para este servidor
            new_state_servers[name] = {
                "log_sizes": current_log_sizes
            }

        except Exception as ex:
            print(f"Error monitoreando {name}: {ex}")
            # En caso de error, generamos un registro mínimo pero igualmente visible
            server_data = {
                "name": name,
                "resources": {},
                "resources_eval": {"cpu_status": "critical", "mem_status": "critical", "disk_warnings": []},
                "logons": {"logons_ok_count": 0, "logons_fail_count": 0, "logons_fail_samples": []},
                "services": [],
                "updates": {"PendingCount": None, "PendingSecurityCount": None, "PendingTitles": [], "RecentInstalled": []},
                "connections_summary": {"total": 0, "by_state": {}},
                "critical_events_raw": {},
                "critical_events_summary": {"total": 0, "per_log": {}},
                "log_growth": {"global_status": "unknown", "details": []},
            }
            risk = compute_risk_score(server_data)
            server_data["risk"] = risk
            all_data.append(server_data)

            # mantenemos estado anterior si hubo error
            new_state_servers[name] = prev_server_state

    # Guardar nuevo estado
    new_state = {
        "servers": new_state_servers
    }
    save_state(config, new_state)

    # Construir reporte y enviar correo
    html = build_html_report(all_data)
    send_html_email(
        subject="Reporte Diario Seguridad & Recursos Servidores Windows",
        html_body=html,
        smtp_config=smtp_conf,
    )


if __name__ == "__main__":
    run_daily_monitor()



