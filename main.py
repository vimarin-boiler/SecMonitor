from monitor.config_loader import load_config
from monitor.collectors import (
    create_session,
    get_system_resources,
    get_critical_services_status,
    get_recent_events,
)
from monitor.analyzers import summarize_logons, evaluate_resources
from monitor.report_html import build_html_report
from monitor.mailer import send_html_email

def run_daily_monitor():
    print("Cargando configuración:")
    config = load_config()
    smtp_conf = config["Smtp"]
    servers_conf = config["Servers"]
    thresholds = config.get("Thresholds", {})

    all_data = []

    for s in servers_conf:
        name = s["Name"]
        print(f"Monitoreando servidor: {name}")
        try:
            session = create_session(
                host=s["Host"],
                username=s["Username"],
                password=s["Password"]
            )

            resources = get_system_resources(session)
            events_sec = get_recent_events(session, "Security", 24, 300)
            logons = summarize_logons(events_sec)
            services = get_critical_services_status(session, s.get("CriticalServices", []))
            res_eval = evaluate_resources(resources, thresholds)

            server_data = {
                "name": name,
                "resources": resources,
                "logons": logons,
                "services": services,
                "resources_eval": res_eval,
            }
            all_data.append(server_data)
        except Exception as ex:
            # Si un servidor falla, lo agregamos igual con error
            print(f"Error monitoreando {name}: {ex}")
            all_data.append({
                "name": name,
                "resources": {},
                "logons": {"logons_ok_count": 0, "logons_fail_count": 0, "logons_fail_samples": []},
                "services": [],
                "resources_eval": {"cpu_status": "critical", "mem_status": "critical", "disk_warnings": []},
            })

    html = build_html_report(all_data)

    send_html_email(
        subject="Reporte Diario Seguridad & Recursos Servidores Windows",
        html_body=html,
        smtp_config=smtp_conf,
    )

if __name__ == "__main__":
    run_daily_monitor()

