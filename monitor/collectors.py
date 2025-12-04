import winrm
from monitor.analyzers import normalize_field
from datetime import datetime, timedelta
import json

import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="winrm")

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
    # print (f"PowerShell script executed with status code {result.status_code}")
    # print (f"StdOut: {result.std_out.decode('utf-8', errors='ignore')}")

    if result.status_code != 0:
        # print(f"PowerShell script failed with status {result.status_code}: {result.std_err.decode('utf-8', errors='ignore')}")
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
    $ErrorActionPreference="SilentlyContinue"
    $WarningPreference="SilentlyContinue"

    Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" |
    Select-Object DeviceID,
        @{Name="SizeGB";Expression={[math]::Round($_.Size/1GB,2)}},
        @{Name="FreeGB";Expression={[math]::Round($_.FreeSpace/1GB,2)}} |
    ConvertTo-Json
    """

    mem_script = r"""
    $ErrorActionPreference="SilentlyContinue"
    $WarningPreference="SilentlyContinue"

    $os = Get-CimInstance Win32_OperatingSystem
    [PSCustomObject]@{
        TotalGB = [math]::Round($os.TotalVisibleMemorySize/1MB,2)
        FreeGB  = [math]::Round($os.FreePhysicalMemory/1MB,2)
    } | ConvertTo-Json
    """

    cpu_script = r"""
    $ErrorActionPreference="SilentlyContinue"
    $WarningPreference="SilentlyContinue"

    $cpu = Get-WmiObject Win32_Processor | Measure-Object -Property LoadPercentage -Average
    $val = [math]::Round($cpu.Average, 2)

    [PSCustomObject]@{
        CPUPercent = $val
    } | ConvertTo-Json
    """

    print("    - Obteniendo uso de disco...")
    disk = _run_ps_json(session, disk_script) or []

    print("    - Obteniendo uso de memoria...")
    mem = _run_ps_json(session, mem_script) or {}

    print("    - Obteniendo uso de CPU...")
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
    if not service_names:
        return []

    services_str = ",".join([f"'{s}'" for s in service_names])
    script = rf"""
        Get-Service |
        Where-Object {{ $_.Name -in @({services_str}) }} |
        Select-Object Name, DisplayName,
            @{{
                Name = 'Status'
                Expression = {{ $_.Status.ToString() }}
            }} |
        ConvertTo-Json
    """
    services = _run_ps_json(session, script)
    if services is None:
        return []
    # ConvertTo-Json devuelve objeto o lista, normalizamos a lista
    if isinstance(services, dict):
        services = [services]
    
    # Imprimir la variable 'services' (forma cruda y en JSON legible)
    # print("services (raw):", services)
    # try:
    #    print("services (json):", json.dumps(services, indent=2, ensure_ascii=False))
    # except Exception as e:
    #    print("No se pudo serializar services a JSON:", e)
    
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
    Obtiene estado de actualizaciones de seguridad.
    Intenta usar PSWindowsUpdate; si no, hace un fallback a Get-HotFix.
    Siempre devuelve la misma estructura:
      {
        "PendingCount": int | 0,
        "PendingSecurityCount": int | 0,
        "PendingTitles": [str],
        "RecentInstalled": [ { "Date": ..., "Title": ..., "Result": ... } ]
      }
    """
    script = r"""
    $result = [PSCustomObject]@{
        PendingCount = 0
        PendingSecurityCount = 0
        PendingTitles = @()
        RecentInstalled = @()
    }

    try {
        Import-Module PSWindowsUpdate -ErrorAction Stop | Out-Null

        # Actualizaciones pendientes (no instaladas)
        $pending = Get-WindowsUpdate -MicrosoftUpdate -Criteria "IsInstalled=0 and Type='Software'" -ErrorAction SilentlyContinue

        if ($pending) {
            $result.PendingCount = ($pending | Measure-Object).Count
            $result.PendingSecurityCount = ($pending | Where-Object { $_.Title -like '*Security*' } | Measure-Object).Count
            $result.PendingTitles = $pending | Select-Object -ExpandProperty Title
        }

        # Historial reciente
        $hist = Get-WUHistory | Sort-Object Date -Descending | Select-Object -First 20
        if ($hist) {
            $result.RecentInstalled = $hist | Select-Object Date, Title, Result
        }
    }
    catch {
        # Fallback: usar Get-HotFix si PSWindowsUpdate no está disponible
        try {
            $hotfixes = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 20
            if ($hotfixes) {
                # No sabemos cuántas pendientes, así que lo dejamos en 0 y RecentInstalled se llena
                $result.RecentInstalled = @()
                foreach ($hf in $hotfixes) {
                    $result.RecentInstalled += [PSCustomObject]@{
                        Date = $hf.InstalledOn
                        Title = "$($hf.HotFixID) - $($hf.Description)"
                        Result = "Installed"
                    }
                }
            }
        } catch {
            # Si también falla, dejamos los valores por defecto
        }
    }

    $result | ConvertTo-Json -Depth 4
    """

    data = _run_ps_json(session, script)
    if data is None:
        data = {
            "PendingCount": 0,
            "PendingSecurityCount": 0,
            "PendingTitles": [],
            "RecentInstalled": []
        }

    # Normalización mínima
    if data.get("PendingCount") is None:
        data["PendingCount"] = 0
    if data.get("PendingSecurityCount") is None:
        data["PendingSecurityCount"] = 0

    pt = data.get("PendingTitles")
    if isinstance(pt, dict):
        data["PendingTitles"] = [pt]
    elif pt is None:
        data["PendingTitles"] = []

    ri = data.get("RecentInstalled")
    if isinstance(ri, dict):
        data["RecentInstalled"] = [ri]
    elif ri is None:
        data["RecentInstalled"] = []

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

def get_paths_size(session: winrm.Session, paths):
    """
    Devuelve tamaño total (GB) por ruta de log.
    """
    if not paths:
        return {}

    # Sanitizar rutas en PowerShell
    ps_paths = ",".join([f"'{p}'" for p in paths])

    script = rf"""
    $result = @()

    foreach ($path in @({ps_paths})) {{
        if (Test-Path $path) {{
            $bytes = (Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue |
                      Measure-Object -Property Length -Sum).Sum
            if (-not $bytes) {{ $bytes = 0 }}
            $sizeGB = [math]::Round($bytes/1GB, 3)
        }} else {{
            $sizeGB = $null
        }}
        $result += [PSCustomObject]@{{
            Path = $path
            SizeGB = $sizeGB
        }}
    }}

    $result | ConvertTo-Json -Depth 3
    """

    sizes = _run_ps_json(session, script)
    if sizes is None:
        return {}
    if isinstance(sizes, dict):
        sizes = [sizes]

    out = {}
    for item in sizes:
        p = item.get("Path")
        sz = item.get("SizeGB")
        out[p] = sz
    return out


def get_unsigned_or_invalid_binaries(session: winrm.Session, check_processes: bool = True, max_items: int = 200):
    """
    Busca binarios asociados a servicios y (opcionalmente) procesos,
    y devuelve aquellos sin firma digital o con firma inválida.

    IMPORTANTE: esto puede ser pesado en servidores muy cargados.
    Por eso se limita el número de ítems y la info que se devuelve.
    """
    script = rf"""
    $result = @()

    # 1) Servicios
    try {{
        $services = Get-WmiObject Win32_Service | Select-Object Name, DisplayName, PathName | Select-Object -First {max_items}
        foreach ($svc in $services) {{
            $path = $svc.PathName
            if (-not [string]::IsNullOrWhiteSpace($path)) {{
                # limpiar comillas y argumentos, nos quedamos con el exe
                $clean = $path.Split('"') | Where-Object {{ $_ -like '*.exe' -or $_ -like '*.dll' -or $_ -like '*.sys' }} | Select-Object -First 1
                if (-not $clean) {{
                    $clean = $path.Split(' ')[0]
                }}
                $clean = $clean.Trim()

                if (Test-Path $clean) {{
                    $sig = Get-AuthenticodeSignature -FilePath $clean -ErrorAction SilentlyContinue
                    $status = $sig.Status.ToString()
                    $subject = $sig.SignerCertificate.Subject
                    $issuer = $sig.SignerCertificate.Issuer

                    if ($status -ne 'Valid') {{
                        $result += [PSCustomObject]@{{
                            Type = 'Service'
                            Name = $svc.Name
                            DisplayName = $svc.DisplayName
                            Path = $clean
                            SignatureStatus = $status
                            CertSubject = $subject
                            CertIssuer = $issuer
                        }}
                    }}
                }}
            }}
        }}
    }} catch {{ }}

    # 2) Procesos
    if ({'true' if check_processes else 'false'}) {{
        try {{
            $procs = Get-Process | Select-Object Name, Id, Path | Where-Object {{ $_.Path }} | Select-Object -First {max_items}
            foreach ($p in $procs) {{
                $path = $p.Path
                if (Test-Path $path) {{
                    $sig = Get-AuthenticodeSignature -FilePath $path -ErrorAction SilentlyContinue
                    $status = $sig.Status.ToString()
                    $subject = $sig.SignerCertificate.Subject
                    $issuer = $sig.SignerCertificate.Issuer

                    if ($status -ne 'Valid') {{
                        $result += [PSCustomObject]@{{
                            Type = 'Process'
                            Name = $p.Name
                            DisplayName = $null
                            Path = $path
                            Pid = $p.Id
                            SignatureStatus = $status
                            CertSubject = $subject
                            CertIssuer = $issuer
                        }}
                    }}
                }}
            }}
        }} catch {{ }}
    }}

    $result | ConvertTo-Json -Depth 4
    """

    data = _run_ps_json(session, script)
    if data is None:
        return []

    if isinstance(data, dict):
        data = [data]

    return data