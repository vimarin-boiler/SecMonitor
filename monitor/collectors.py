import winrm
from monitor.analyzers import normalize_field
from datetime import datetime, timedelta
import json

def create_session(host: str, username: str, password: str) -> winrm.Session:
    # Para dev en Windows y prod en Linux, WinRM funciona igual si tienes conectividad y credenciales
    print (f"Creating WinRM session to {host} with user {username}")
    return winrm.Session(
        target=host,
        auth=(username, password),
        transport='ntlm'  # puedes cambiar a 'kerberos' si configuras SPN, etc.
    )

def _run_ps_json(session: winrm.Session, script: str):
    # print (f"Running PowerShell script:\n{script}")
    result = session.run_ps(script)
    if result.status_code != 0:
        # Podrías loggear result.std_err aquí
        return None
    out = result.std_out.decode('utf-8', errors='ignore').strip()
    if not out:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return None

def get_system_resources(session: winrm.Session):
    disk_script = r"""
    Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" |
    Select-Object DeviceID,
        @{Name="SizeGB";Expression={[math]::Round($_.Size/1GB,2)}},
        @{Name="FreeGB";Expression={[math]::Round($_.FreeSpace/1GB,2)}} |
    ConvertTo-Json
    """

    mem_script = r"""
    $os = Get-CimInstance Win32_OperatingSystem
    [PSCustomObject]@{
        TotalGB = [math]::Round($os.TotalVisibleMemorySize/1MB,2)
        FreeGB  = [math]::Round($os.FreePhysicalMemory/1MB,2)
    } | ConvertTo-Json
    """

    cpu_script = r"""
    $cpu = Get-Counter '\Processor(_Total)\% Processor Time' -SampleInterval 1 -MaxSamples 1
    $val = [math]::Round($cpu.CounterSamples.CookedValue,2)
    [PSCustomObject]@{ CPUPercent = $val } | ConvertTo-Json
    """

    print("Collecting system resources...")
    disk = _run_ps_json(session, disk_script) or []
    mem = _run_ps_json(session, mem_script) or {}
    cpu = _run_ps_json(session, cpu_script) or {}

    disk = normalize_field(disk, [])
    mem  = normalize_field(mem, {})
    cpu  = normalize_field(cpu, {})

    # Si ConvertTo-Json devuelve un solo objeto, asegurarse de lista
    if isinstance(disk, dict):
        disk = [disk]
        
    return {
        "disk": disk,
        "memory": mem,
        "cpu": cpu,
    }

def get_critical_services_status(session: winrm.Session, service_names):
    print("Collecting critical services status...")
    if not service_names:
        return []

    services_str = ",".join([f"'{s}'" for s in service_names])
    script = rf"""
    Get-Service | Where-Object {{ $_.Name -in @({services_str}) }} |
    Select-Object Name, DisplayName, Status | ConvertTo-Json
    """
    services = _run_ps_json(session, script)
    if services is None:
        return []
    # ConvertTo-Json devuelve objeto o lista, normalizamos a lista
    if isinstance(services, dict):
        services = [services]
    
     # Imprimir la variable 'services' (forma cruda y en JSON legible)
    print("services (raw):", services)
    try:
        print("services (json):", json.dumps(services, indent=2, ensure_ascii=False))
    except Exception as e:
        print("No se pudo serializar services a JSON:", e)
    
    return services

def get_recent_events(session: winrm.Session, log_name: str, hours: int = 24, max_events: int = 300):
    since = (datetime.utcnow() - timedelta(hours=hours)).strftime('%Y-%m-%dT%H:%M:%S')
    script = rf"""
    Get-WinEvent -LogName '{log_name}' -MaxEvents {max_events} |
    Where-Object {{ $_.TimeCreated -gt [datetime]'{since}' }} |
    Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message |
    ConvertTo-Json -Depth 3
    """
    events = _run_ps_json(session, script)
    if events is None:
        return []
    if isinstance(events, dict):
        events = [events]
    return events


# Ejemplo de uso
# events_security = get_recent_events(session, "Security", 24, 300)
# events_system   = get_recent_events(session, "System", 24, 200)
# events_app      = get_recent_events(session, "Application", 24, 200)


def get_security_updates_status(session: winrm.Session):
    """
    Intenta usar el módulo PSWindowsUpdate para obtener actualizaciones pendientes.
    Necesita que el módulo esté instalado en el servidor.
    Si no se puede, devuelve estructura básica.
    """
    script = r"""
    try {
        Import-Module PSWindowsUpdate -ErrorAction Stop | Out-Null

        $pending = Get-WindowsUpdate -MicrosoftUpdate -Criteria "IsInstalled=0 and Type='Software'" -ErrorAction SilentlyContinue
        $installed = Get-WUHistory | Select-Object -First 20

        $result = [PSCustomObject]@{
            PendingCount = ($pending | Measure-Object).Count
            PendingSecurityCount = ($pending | Where-Object { $_.Title -like '*Security*' } | Measure-Object).Count
            PendingTitles = ($pending | Select-Object -ExpandProperty Title)
            RecentInstalled = $installed | Select-Object Date, Title, Result
        }

        $result | ConvertTo-Json -Depth 4
    }
    catch {
        # Fallback muy simple: intentamos Get-HotFix para al menos mostrar algo
        $hotfixes = Get-HotFix | Select-Object -Last 20
        $result = [PSCustomObject]@{
            PendingCount = $null
            PendingSecurityCount = $null
            PendingTitles = @()
            RecentInstalled = $hotfixes | Select-Object InstalledOn, Description, HotFixID
        }
        $result | ConvertTo-Json -Depth 4
    }
    """

    data = _run_ps_json(session, script)
    if data is None:
        data = {
            "PendingCount": None,
            "PendingSecurityCount": None,
            "PendingTitles": [],
            "RecentInstalled": []
        }
    # normalizar arrays
    if isinstance(data.get("PendingTitles"), dict):
        data["PendingTitles"] = [data["PendingTitles"]]
    if isinstance(data.get("RecentInstalled"), dict):
        data["RecentInstalled"] = [data["RecentInstalled"]]
    return data


def get_active_connections(session: winrm.Session, max_results: int = 200):
    """
    Obtiene conexiones TCP activas.
    """
    script = rf"""
    try {{
        Get-NetTCPConnection |
        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess |
        Select-Object -First {max_results} |
        ConvertTo-Json -Depth 3
    }}
    catch {{
        # Para OS más antiguos sin Get-NetTCPConnection, usar netstat
        netstat -ano | Select-Object -First {max_results} | ForEach-Object {{
            $_
        }} | ConvertTo-Json -Depth 3
    }}
    """
    conns = _run_ps_json(session, script)
    if conns is None:
        return []
    if isinstance(conns, dict):
        conns = [conns]
    return conns


def get_critical_events_summary(session: winrm.Session, hours: int = 24, max_events_per_log: int = 100):
    """
    Resumen de eventos 'Error' y 'Critical' en System, Application y Security.
    """
    logs = ["System", "Application", "Security"]
    summary = {}
    since = (datetime.utcnow() - timedelta(hours=hours)).strftime('%Y-%m-%dT%H:%M:%S')

    for log in logs:
        script = rf"""
        Get-WinEvent -LogName '{log}' -MaxEvents {max_events_per_log} |
        Where-Object {{ $_.TimeCreated -gt [datetime]'{since}' -and ($_.LevelDisplayName -eq 'Error' -or $_.LevelDisplayName -eq 'Critical') }} |
        Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message |
        ConvertTo-Json -Depth 3
        """
        events = _run_ps_json(session, script)
        if events is None:
            events = []
        if isinstance(events, dict):
            events = [events]

        summary[log] = {
            "count": len(events),
            "samples": events[:10]  # primeros 10 para reporte
        }

    return summary
