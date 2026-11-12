"""
core/network_analyzer.py
────────────────────────
Analizador de conexiones de red y puertos abiertos en tiempo real.
Traduce sockets técnicos (IP, Puerto, Estado, PID) a información comprensible
para el usuario común, evaluando riesgos según ISO 27002, NIST CSF, CIS Controls y OWASP.
"""

import socket
import psutil
from core.standards import (
    PORT_KNOWLEDGE_BASE,
    SUSPICIOUS_PORTS,
    PROTECTED_SYSTEM_PROCESSES,
)


class NetworkAnalyzer:
    @staticmethod
    def is_private_or_loopback(ip: str) -> bool:
        if not ip:
            return True
        if ip in ("127.0.0.1", "::1", "0.0.0.0", "::", "*"):
            return True
        if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("169.254."):
            return True
        if ip.startswith("172."):
            parts = ip.split(".")
            if len(parts) > 1 and parts[1].isdigit():
                second = int(parts[1])
                if 16 <= second <= 31:
                    return True
        return False

    @staticmethod
    def scan_connections() -> list[dict]:
        """
        Obtiene todas las conexiones y puertos activos del dispositivo y los traduce
        a registros claros y explicados para el usuario común.
        """
        results = []
        try:
            conns = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            conns = []
        except Exception:
            conns = []

        # Cache rápido de procesos por PID
        proc_cache = {}

        seen_keys = set()
        for c in conns:
            laddr_ip = c.laddr.ip if c.laddr else ""
            laddr_port = c.laddr.port if c.laddr else 0
            raddr_ip = c.raddr.ip if c.raddr else ""
            raddr_port = c.raddr.port if c.raddr else 0
            status = c.status if c.status else "UDP"
            pid = c.pid or 0

            proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"

            # Evitar duplicados exactos
            dedup_key = (proto, laddr_ip, laddr_port, raddr_ip, raddr_port, status, pid)
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            # Resolver nombre de proceso
            if pid not in proc_cache:
                proc_name = "Sistema / Desconocido"
                exe_path = ""
                if pid > 0:
                    try:
                        p = psutil.Process(pid)
                        proc_name = p.name()
                        exe_path = p.exe()
                    except Exception:
                        proc_name = f"Proceso (PID {pid})"
                elif pid == 0:
                    proc_name = "System Idle"
                proc_cache[pid] = (proc_name, exe_path)

            proc_name, exe_path = proc_cache[pid]
            is_protected = proc_name.lower() in PROTECTED_SYSTEM_PROCESSES or pid in (0, 4)

            # Evaluar riesgo y explicación humana
            analysis = NetworkAnalyzer._evaluate_connection(
                proto=proto,
                laddr_ip=laddr_ip,
                laddr_port=laddr_port,
                raddr_ip=raddr_ip,
                raddr_port=raddr_port,
                status=status,
                proc_name=proc_name,
                is_protected=is_protected,
            )

            results.append({
                "proto": proto,
                "local_ip": laddr_ip,
                "local_port": laddr_port,
                "remote_ip": raddr_ip if raddr_ip else "—",
                "remote_port": raddr_port if raddr_port else 0,
                "remote_display": f"{raddr_ip}:{raddr_port}" if raddr_ip else "Sin conexión externa",
                "status": status,
                "status_human": analysis["status_human"],
                "pid": pid,
                "process_name": proc_name,
                "exe_path": exe_path,
                "is_protected": is_protected,
                "risk": analysis["risk"],          # HIGH, MEDIUM, LOW
                "risk_label": analysis["risk_label"],
                "service_name": analysis["service_name"],
                "human_explanation": analysis["human_explanation"],
                "standard_ref": analysis["standard_ref"],
                "recommendation": analysis["recommendation"],
            })

        # Ordenar: primero HIGH, luego MEDIUM, luego LOW, y por puerto local
        risk_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        results.sort(key=lambda x: (risk_order.get(x["risk"], 3), x["local_port"]))
        return results

    @staticmethod
    def _evaluate_connection(
        proto: str,
        laddr_ip: str,
        laddr_port: int,
        raddr_ip: str,
        raddr_port: int,
        status: str,
        proc_name: str,
        is_protected: bool,
    ) -> dict:
        # Traducción del estado técnico
        status_map = {
            "LISTEN": "Puerto Abierto (Escuchando)",
            "ESTABLISHED": "Conexión Activa",
            "TIME_WAIT": "Cerrando Conexión",
            "CLOSE_WAIT": "Esperando Cierre",
            "SYN_SENT": "Intentando Conectar",
            "UDP": "Canal UDP Activo",
        }
        status_human = status_map.get(status, status)

        # Consultar base de conocimiento por puerto local o remoto
        kb = PORT_KNOWLEDGE_BASE.get(laddr_port) or PORT_KNOWLEDGE_BASE.get(raddr_port)
        service_name = kb["service"] if kb else f"Puerto {laddr_port}"
        standard_ref = kb["standard"] if kb else "NIST DE.CM / CIS Control 12"

        is_Loopback = laddr_ip in ("127.0.0.1", "::1")
        is_AllInterfaces = laddr_ip in ("0.0.0.0", "::")
        is_ExternalRemote = bool(raddr_ip) and not NetworkAnalyzer.is_private_or_loopback(raddr_ip)

        # 1. ¿Es un puerto altamente sospechoso (ej. 4444, 1337, 31337, 6667)?
        if laddr_port in SUSPICIOUS_PORTS or raddr_port in SUSPICIOUS_PORTS:
            risk = "HIGH"
            risk_label = "Riesgo Alto"
            human_explanation = (
                f"¡Alerta! El programa '{proc_name}' está usando el puerto {laddr_port or raddr_port}, "
                "frecuentemente empleado por conexiones no autorizadas o herramientas de acceso remoto."
            )
            recommendation = (
                f"Si no reconoces '{proc_name}', bloquea inmediatamente este puerto en el Firewall y cierra la conexión."
            )
            return {
                "status_human": status_human,
                "risk": risk,
                "risk_label": risk_label,
                "service_name": service_name,
                "human_explanation": human_explanation,
                "standard_ref": "NIST DE.CM / ISO 27002 A.8.16",
                "recommendation": recommendation,
            }

        # 2. Caso LISTEN (Puerto abierto esperando conexiones entrantes)
        if status == "LISTEN":
            if is_Loopback:
                risk = "LOW"
                risk_label = "Seguro (Interno)"
                human_explanation = (
                    f"'{proc_name}' abrió el puerto {laddr_port} ({service_name}) solo para comunicación interna "
                    "dentro de tu propio computador (127.0.0.1). Nadie desde afuera puede entrar por aquí."
                )
                recommendation = "No requiere acción. Es un canal interno seguro de tu equipo."
            elif is_AllInterfaces:
                if kb and kb["risk"] == "HIGH":
                    risk = "HIGH"
                    risk_label = "Exposición Alta"
                    human_explanation = (
                        f"El puerto sensible {laddr_port} ({service_name}) está abierto a toda la red por '{proc_name}'. "
                        f"{kb['human_desc']}"
                    )
                    recommendation = kb["recommendation"]
                else:
                    risk = "MEDIUM"
                    risk_label = "Abierto en Red"
                    base_desc = kb["human_desc"] if kb else "Este puerto acepta conexiones desde otros dispositivos en tu red Wi-Fi o LAN."
                    human_explanation = (
                        f"'{proc_name}' mantiene el puerto {laddr_port} ({service_name}) abierto hacia la red ({laddr_ip}). {base_desc}"
                    )
                    recommendation = (
                        kb["recommendation"]
                        if kb
                        else f"Si no necesitas que otros equipos se conecten a '{proc_name}', puedes bloquear el puerto {laddr_port} en el Firewall."
                    )
            else:
                risk = "MEDIUM" if (kb and kb["risk"] != "LOW") else "LOW"
                risk_label = "Atención" if risk == "MEDIUM" else "Normal"
                human_explanation = (
                    f"'{proc_name}' está escuchando en {laddr_ip}:{laddr_port} ({service_name})."
                )
                recommendation = kb["recommendation"] if kb else "Verifica si utilizas esta aplicación en tu red local."

        # 3. Caso ESTABLISHED (Conexión activa con otro servidor o dispositivo)
        elif status == "ESTABLISHED":
            if is_ExternalRemote and raddr_port not in (80, 443, 53, 123):
                risk = "HIGH" if (raddr_port in SUSPICIOUS_PORTS or (kb and kb["risk"] == "HIGH")) else "MEDIUM"
                risk_label = "Riesgo Alto" if risk == "HIGH" else "Conexión Externa Inusual"
                human_explanation = (
                    f"'{proc_name}' está conectado activamente hacia la IP externa {raddr_ip} por un puerto no web ({raddr_port}). "
                    "Si no es un juego, llamada o descarga que tú iniciaste, conviene revisarlo."
                )
                recommendation = (
                    f"Si no reconoces esta actividad de '{proc_name}', puedes bloquear el puerto {laddr_port} o cortar la conexión."
                )
            elif is_ExternalRemote and raddr_port in (80, 443):
                risk = "LOW"
                risk_label = "Tráfico Web Normal"
                human_explanation = (
                    f"'{proc_name}' está conectado por Internet seguro ({service_name}) con el servidor {raddr_ip}:{raddr_port}."
                )
                recommendation = "Conexión estándar de Internet. Solo mitiga si no reconoces la aplicación."
            else:
                risk = "LOW"
                risk_label = "Conexión Local"
                human_explanation = (
                    f"Comunicación local activa de '{proc_name}' entre el puerto {laddr_port} y {raddr_ip}:{raddr_port}."
                )
                recommendation = "Actividad local normal del sistema o aplicación."

        # 4. Otros estados (UDP, TIME_WAIT, CLOSE_WAIT)
        else:
            if kb and kb["risk"] == "HIGH" and not is_Loopback:
                risk = "MEDIUM"
                risk_label = "Atención"
                human_explanation = f"Canal {proto} en puerto {laddr_port} ({service_name}) usado por '{proc_name}'. {kb['human_desc']}"
                recommendation = kb["recommendation"]
            else:
                risk = "LOW"
                risk_label = "Normal"
                human_explanation = (
                    f"Actividad {status_human.lower()} de '{proc_name}' en el puerto {laddr_port} ({proto})."
                )
                recommendation = "No requiere intervención a menos que desconozcas el programa."

        return {
            "status_human": status_human,
            "risk": risk,
            "risk_label": risk_label,
            "service_name": service_name,
            "human_explanation": human_explanation,
            "standard_ref": standard_ref,
            "recommendation": recommendation,
        }
