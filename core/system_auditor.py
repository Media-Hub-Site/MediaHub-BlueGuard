"""
core/system_auditor.py
──────────────────────
Auditor de postura de seguridad del dispositivo basado en controles prácticos de:
- CIS Controls v8 (Controles 4 y 12)
- NIST CSF 2.0 (Protect & Detect)
- ISO/IEC 27002 (A.8.8, A.8.20)
- OWASP Top 10 (A05 Security Misconfiguration)

Evalúa el estado real de Windows y ofrece explicaciones claras y scripts de mitigación opcionales.
"""

import winreg
import psutil


class SystemAuditor:
    @staticmethod
    def _check_firewall_enabled() -> bool:
        """Consulta en el registro de Windows si el Firewall está activo en los perfiles."""
        paths = [
            r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile",
            r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile",
        ]
        try:
            for p in paths:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, p) as key:
                    val, _ = winreg.QueryValueEx(key, "EnableFirewall")
                    if int(val) == 0:
                        return False
            return True
        except Exception:
            return True

    @staticmethod
    def _check_uac_enabled() -> bool:
        """Consulta si el Control de Cuentas de Usuario (UAC) está activo."""
        path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
                val, _ = winreg.QueryValueEx(key, "EnableLUA")
                return int(val) == 1
        except Exception:
            return True

    @staticmethod
    def _check_rdp_enabled() -> bool:
        """Verifica si Escritorio Remoto está habilitado en el registro o escuchando en 3389."""
        path = r"SYSTEM\CurrentControlSet\Control\Terminal Server"
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
                fDeny, _ = winreg.QueryValueEx(key, "fDenyTSConnections")
                if int(fDeny) == 0:
                    return True
        except Exception:
            pass
        return False

    @staticmethod
    def run_audit(connections: list[dict] | None = None) -> list[dict]:
        """
        Ejecuta una batería de controles de seguridad no invasivos y devuelve hallazgos
        explicados en lenguaje sencillo con su opción de mitigación.
        """
        if connections is None:
            from core.network_analyzer import NetworkAnalyzer
            connections = NetworkAnalyzer.scan_connections()

        listening_all_ports = {
            c["local_port"]: c
            for c in connections
            if c["status"] == "LISTEN" and c["local_ip"] in ("0.0.0.0", "::")
        }

        checks = []

        # 1. Estado del Cortafuegos (Windows Defender Firewall)
        fw_ok = SystemAuditor._check_firewall_enabled()
        checks.append({
            "id": "CIS-4.4-FIREWALL",
            "title": "Cortafuegos de Windows (Firewall) Activo",
            "standard": "CIS Control 4.4 / NIST PR.AC / ISO 27002 A.8.20",
            "status": "PASS" if fw_ok else "FAIL",
            "status_human": "Protegido" if fw_ok else "Desactivado (Riesgo Alto)",
            "risk": "LOW" if fw_ok else "HIGH",
            "human_explanation": (
                "El Firewall actúa como una puerta de seguridad que impide que extraños en tu Wi-Fi o Internet "
                "entren a tu computador sin permiso."
                if fw_ok else
                "¡Atención! Uno o más perfiles del Firewall de Windows están desactivados. Tu computador está expuesto a conexiones entrantes no autorizadas."
            ),
            "can_mitigate": not fw_ok,
            "mitigation_title": "Reactivar Windows Defender Firewall",
            "mitigation_explanation": (
                "Se activará nuevamente el Firewall nativo de Windows en todos los perfiles de red (Privado, Público y Dominio) "
                "para bloquear accesos entrantes no solicitados."
            ),
            "mitigation_cmd": "netsh advfirewall set allprofiles state on",
        })

        # 2. Control de Cuentas de Usuario (UAC)
        uac_ok = SystemAuditor._check_uac_enabled()
        checks.append({
            "id": "CIS-6.1-UAC",
            "title": "Confirmación de Permisos de Administrador (UAC)",
            "standard": "CIS Control 6 / NIST PR.AA / ISO 27002 A.8.2",
            "status": "PASS" if uac_ok else "FAIL",
            "status_human": "Activo y Seguro" if uac_ok else "Desactivado (Peligro)",
            "risk": "LOW" if uac_ok else "HIGH",
            "human_explanation": (
                "Windows te pide confirmación antes de que cualquier programa haga cambios profundos en el sistema."
                if uac_ok else
                "El control UAC está desactivado: cualquier programa o virus podría hacer cambios de Administrador sin avisarte."
            ),
            "can_mitigate": not uac_ok,
            "mitigation_title": "Habilitar protección UAC de Windows",
            "mitigation_explanation": (
                "Se activará el aviso de seguridad de Windows (EnableLUA=1) para que ningún software pueda modificar el sistema sin tu permiso."
            ),
            "mitigation_cmd": r'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f',
        })

        # 3. Escritorio Remoto (RDP Puerto 3389)
        rdp_open = (3389 in listening_all_ports) or SystemAuditor._check_rdp_enabled()
        checks.append({
            "id": "CIS-4.8-RDP",
            "title": "Acceso de Escritorio Remoto (Puerto 3389)",
            "standard": "CIS Control 4.8 / NIST PR.AC",
            "status": "WARN" if rdp_open else "PASS",
            "status_human": "Abierto / Habilitado" if rdp_open else "Cerrado (Seguro)",
            "risk": "HIGH" if rdp_open else "LOW",
            "human_explanation": (
                "El Escritorio Remoto permite controlar tu pantalla desde otro equipo. Si no lo usas activamente, dejarlo abierto es riesgoso."
                if rdp_open else
                "El puerto 3389 de Escritorio Remoto no está expuesto a conexiones externas."
            ),
            "can_mitigate": rdp_open,
            "mitigation_title": "Bloquear puerto 3389 (RDP) en el Firewall",
            "mitigation_explanation": (
                "Se creará una regla en el Firewall de Windows para bloquear conexiones entrantes al puerto 3389 (Escritorio Remoto), "
                "evitando que otros equipos intenten conectarse a tu pantalla."
            ),
            "mitigation_cmd": 'netsh advfirewall firewall add rule name="BlueGuard_Block_Port_3389_TCP" dir=in action=block protocol=TCP localport=3389',
        })

        # 4. Protocolos Inseguros sin Cifrado (Telnet 23 / FTP 21)
        insecure_open = [p for p in (21, 23) if p in listening_all_ports]
        has_insecure = len(insecure_open) > 0
        port_str = ", ".join(str(p) for p in insecure_open)
        checks.append({
            "id": "ISO-27002-CLEARTEXT",
            "title": "Servicios Antiguos Sin Cifrado (FTP 21 / Telnet 23)",
            "standard": "ISO 27002 A.8.20 / CIS Control 4.8",
            "status": "FAIL" if has_insecure else "PASS",
            "status_human": f"Expuesto ({port_str})" if has_insecure else "Sin exposición",
            "risk": "HIGH" if has_insecure else "LOW",
            "human_explanation": (
                f"Se detectaron puertos sin cifrado abiertos ({port_str}). Estos servicios envían contraseñas en texto claro."
                if has_insecure else
                "No tienes servidores antiguos sin cifrado (Telnet o FTP) abiertos en tu equipo."
            ),
            "can_mitigate": has_insecure,
            "mitigation_title": f"Bloquear puertos inseguros ({port_str or '21,23'})",
            "mitigation_explanation": (
                "Se agregará una regla en el Firewall para impedir conexiones entrantes hacia los puertos 21 (FTP) y 23 (Telnet)."
            ),
            "mitigation_cmd": 'netsh advfirewall firewall add rule name="BlueGuard_Block_Insecure_21_23" dir=in action=block protocol=TCP localport=21,23',
        })

        # 5. Servidores Web / Desarrollo Locales Abiertos a toda la Red (OWASP A05)
        dev_ports = [p for p in (80, 3000, 5000, 8000, 8080) if p in listening_all_ports]
        has_dev_exposed = len(dev_ports) > 0
        dev_str = ", ".join(str(p) for p in dev_ports)
        first_dev = dev_ports[0] if dev_ports else 8000
        checks.append({
            "id": "OWASP-A05-DEVPORTS",
            "title": "Servidores Web o de Prueba Expuestos en Red Wi-Fi (OWASP)",
            "standard": "OWASP A05 (Security Misconfiguration)",
            "status": "WARN" if has_dev_exposed else "PASS",
            "status_human": f"Abiertos en Wi-Fi ({dev_str})" if has_dev_exposed else "Aislados correctamente",
            "risk": "MEDIUM" if has_dev_exposed else "LOW",
            "human_explanation": (
                f"Tienes servidores locales escuchando en toda la red ({dev_str}). Otros dispositivos en tu misma Wi-Fi pueden acceder a ellos."
                if has_dev_exposed else
                "Tus aplicaciones locales no exponen paneles web abiertos hacia otros equipos de la red."
            ),
            "can_mitigate": has_dev_exposed,
            "mitigation_title": f"Proteger puerto web local ({first_dev}) frente a acceso externo",
            "mitigation_explanation": (
                f"Se bloqueará el acceso entrante desde otros equipos de la red al puerto {first_dev}, "
                "permitiendo que sigas usándolo normalmente dentro de tu propio PC (localhost)."
            ),
            "mitigation_cmd": f'netsh advfirewall firewall add rule name="BlueGuard_Block_Port_{first_dev}_TCP" dir=in action=block protocol=TCP localport={first_dev}',
        })

        return checks

    @staticmethod
    def calculate_security_score(audit_results: list[dict], connections: list[dict]) -> int:
        """Calcula una nota de salud de seguridad de 0 a 100 comprensible para el usuario."""
        score = 100
        for item in audit_results:
            if item["status"] == "FAIL":
                score -= 22
            elif item["status"] == "WARN":
                score -= 10

        high_conns = sum(1 for c in connections if c["risk"] == "HIGH")
        med_conns = sum(1 for c in connections if c["risk"] == "MEDIUM" and c["status"] == "LISTEN")

        score -= min(30, high_conns * 12)
        score -= min(15, med_conns * 3)
        return max(15, min(100, score))
