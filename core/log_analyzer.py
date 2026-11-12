"""
core/log_analyzer.py
────────────────────
Analizador y traductor de eventos del sistema Windows (Visor de Eventos)
a explicaciones sencillas para el usuario común bajo criterios CIS Control 8 e ISO 27002 A.8.15.
"""

import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime
from core.standards import WINDOWS_EVENT_TRANSLATIONS


class LogAnalyzer:
    @staticmethod
    def fetch_recent_events(max_events: int = 25) -> list[dict]:
        """
        Consulta los últimos eventos relevantes de Windows (System y Application/Security)
        y los traduce a lenguaje comprensible sin bloquear la interfaz.
        """
        events = []
        channels = ["System", "Application", "Security"]

        creation_flags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0

        for channel in channels:
            try:
                cmd = [
                    "wevtutil",
                    "qe",
                    channel,
                    f"/c:{max_events // 2}",
                    "/rd:true",
                    "/f:xml",
                ]
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=3,
                    creationflags=creation_flags,
                    encoding="utf-8",
                    errors="ignore",
                )
                if proc.returncode == 0 and proc.stdout.strip():
                    xml_wrapped = f"<Events>{proc.stdout}</Events>"
                    root = ET.fromstring(xml_wrapped)
                    for ev in root:
                        parsed = LogAnalyzer._parse_event_xml(ev, channel)
                        if parsed:
                            events.append(parsed)
            except Exception:
                continue

        # Si por permisos no se obtuvieron suficientes eventos, ordenar los encontrados
        events.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        return events[:max_events]

    @staticmethod
    def _parse_event_xml(ev_elem, channel: str) -> dict | None:
        ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
        sys_elem = ev_elem.find("e:System", ns)
        if sys_elem is None:
            return None

        ev_id_elem = sys_elem.find("e:EventID", ns)
        ev_id = int(ev_id_elem.text) if (ev_id_elem is not None and ev_id_elem.text and ev_id_elem.text.isdigit()) else 0

        provider_elem = sys_elem.find("e:Provider", ns)
        provider = provider_elem.attrib.get("Name", channel) if provider_elem is not None else channel

        time_elem = sys_elem.find("e:TimeCreated", ns)
        raw_time = time_elem.attrib.get("SystemTime", "") if time_elem is not None else ""
        clean_time = raw_time[:19].replace("T", " ") if raw_time else datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        level_elem = sys_elem.find("e:Level", ns)
        win_level = int(level_elem.text) if (level_elem is not None and level_elem.text and level_elem.text.isdigit()) else 4

        # Traducción humana desde nuestro catálogo o inferencia por nivel de severidad de Windows
        kb = WINDOWS_EVENT_TRANSLATIONS.get(ev_id)
        if kb:
            title = kb["title"]
            level = kb["level"]
            explanation = kb["explanation"]
            standard = kb["standard"]
        else:
            if win_level in (1, 2):
                level = "HIGH"
                title = f"Error del Sistema o Aplicación (ID {ev_id})"
                explanation = (
                    f"El componente '{provider}' reportó un fallo importante (Evento {ev_id}). "
                    "Si ocurre repetidamente, puede indicar un servicio inestable o bloqueado."
                )
                standard = "ISO 27002 A.8.15 ( Monitoreo de Eventos )"
            elif win_level == 3:
                level = "MEDIUM"
                title = f"Advertencia del Sistema (ID {ev_id})"
                explanation = (
                    f"El servicio '{provider}' registró una advertencia preventiva (Evento {ev_id}). "
                    "Normalmente Windows lo resuelve automáticamente."
                )
                standard = "CIS Control 8.2"
            else:
                level = "INFO"
                title = f"Actividad Normal Registrada (ID {ev_id})"
                explanation = f"Operación rutinaria del componente '{provider}' en el canal {channel}."
                standard = "NIST DE.CM"

        level_labels = {
            "HIGH": "Importante / Alerta",
            "MEDIUM": "Advertencia",
            "LOW": "Aviso Menor",
            "INFO": "Informativo",
        }

        return {
            "timestamp": clean_time,
            "channel": channel,
            "event_id": ev_id,
            "provider": provider,
            "title": title,
            "level": level,
            "level_label": level_labels.get(level, "Informativo"),
            "human_explanation": explanation,
            "standard": standard,
        }
