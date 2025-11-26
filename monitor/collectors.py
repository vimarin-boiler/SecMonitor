import winrm
from datetime import datetime, timedelta
import json

def create_session(host: str, username: str, password: str) -> winrm.Session:
    # Para dev en Windows y prod en Linux, WinRM funciona igual si tienes conectividad y credenciales
    return winrm.Session(
        target=host,
        auth=(username, password),
        transport='ntlm'  # puedes cambiar a 'kerberos' si configuras SPN, etc.
    )

def _run_ps_json(session: winrm.Session, script: str):
    """Ejecuta PowerShell y devuelve JSON parseado o valor por defecto."""
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

    disk = _run_ps_json(session, disk_script) or []
    mem = _run_ps_json(session, mem_script) or {}
    cpu = _run_ps_json(session, cpu_script) or {}

    return {
        "disk": disk,
        "memory": mem,
        "cpu": cpu,
    }

def get_critical_services_status(session: winrm.Session, service_names):
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