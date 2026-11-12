"""
core/mitigator.py
─────────────────
Motor de mitigación asistida con consentimiento explícito del usuario (Human-in-the-Loop).
Cumple con criterios éticos y de seguridad:
1. Explica en lenguaje humano qué se hará antes de ejecutar cualquier acción.
2. Muestra el comando auditable exacto.
3. Protege procesos críticos de Windows (whitelist) para nunca dañar la estabilidad del equipo.
4. Permite revertir reglas de Firewall creadas por BlueGuard en cualquier momento.
"""

import ctypes
import json
import os
import subprocess
import psutil
from core.standards import PROTECTED_SYSTEM_PROCESSES


class Mitigator:
    @staticmethod
    def get_rules_history_file() -> str:
        home = os.environ.get("USERPROFILE") or os.path.expanduser("~")
        folder = os.path.join(home, ".mediahub", "blueguard")
        os.makedirs(folder, exist_ok=True)
        return os.path.join(folder, "applied_rules.json")

    @staticmethod
    def load_applied_rules() -> list[dict]:
        path = Mitigator.get_rules_history_file()
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return []
        return []

    @staticmethod
    def save_applied_rule(rule_name: str, port: int, proto: str, description: str):
        rules = Mitigator.load_applied_rules()
        rules = [r for r in rules if r.get("rule_name") != rule_name]
        rules.append({
            "rule_name": rule_name,
            "port": port,
            "proto": proto,
            "description": description,
        })
        path = Mitigator.get_rules_history_file()
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(rules, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

    @staticmethod
    def remove_saved_rule(rule_name: str):
        rules = Mitigator.load_applied_rules()
        rules = [r for r in rules if r.get("rule_name") != rule_name]
        path = Mitigator.get_rules_history_file()
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(rules, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

    @staticmethod
    def build_connection_mitigation_plan(conn: dict) -> dict:
        """
        Construye el plan explicativo y técnico para mitigar un puerto abierto o una conexión sospechosa.
        """
        port = conn["local_port"]
        proto = conn["proto"]
        proc_name = conn["process_name"]
        pid = conn["pid"]
        remote_ip = conn["remote_ip"]
        is_protected = conn["is_protected"]

        rule_in = f"BlueGuard_Block_Port_{port}_{proto}_IN"
        rule_out = f"BlueGuard_Block_Port_{port}_{proto}_OUT"

        cmd_parts = [
            f'netsh advfirewall firewall add rule name="{rule_in}" dir=in action=block protocol={proto} localport={port}',
            f'netsh advfirewall firewall add rule name="{rule_out}" dir=out action=block protocol={proto} localport={port}',
        ]

        if is_protected:
            process_note = (
                f"Nota de Seguridad: '{proc_name}' es un componente protegido de Windows, por lo que BlueGuard "
                f"NO cerrará el proceso para no afectar tu sistema; únicamente bloqueará el puerto {port} ({proto}) en el Firewall."
            )
            can_kill_proc = False
        else:
            process_note = (
                f"Además de bloquear el puerto {port} ({proto}) en el Firewall, puedes optar por cerrar "
                f"el programa '{proc_name}' (PID {pid}) para cortar la conexión activa de raíz."
            )
            can_kill_proc = pid > 4

        target_desc = f"hacia {remote_ip}" if remote_ip and remote_ip != "—" else f"en el puerto local {port}"

        return {
            "title": f"¿Deseas bloquear el puerto {port} ({proto}) y cortar la conexión?",
            "finding_summary": (
                f"Programa detectado: {proc_name} (PID {pid})\n"
                f"Actividad: {conn['status_human']} {target_desc}\n"
                f"Criterio: {conn['standard_ref']}"
            ),
            "what_it_does": (
                f"Esto ejecutará un script de seguridad en tu equipo para bloquear el puerto {port} ({proto}) "
                f"en Windows Defender Firewall (entrante y saliente) y cortar cualquier comunicación no deseada.\n\n"
                f"{process_note}"
            ),
            "script_preview": " && ".join(cmd_parts),
            "commands": cmd_parts,
            "rule_names": [(rule_in, port, proto, f"Bloqueo entrante puerto {port} ({proc_name})"),
                           (rule_out, port, proto, f"Bloqueo saliente puerto {port} ({proc_name})")],
            "can_kill_process": can_kill_proc,
            "pid": pid,
            "process_name": proc_name,
            "port": port,
            "proto": proto,
        }

    @staticmethod
    def execute_commands_with_consent(commands: list[str], kill_pid: int | None = None) -> tuple[bool, str]:
        """
        Ejecuta los comandos aprobados por el usuario.
        Primero intenta ejecución directa; si requiere permisos de Administrador,
        solicita elevación oficial de Windows (UAC) con el permiso explícito del usuario.
        """
        # 1. Si el usuario solicitó terminar el proceso no crítico asociado
        proc_msg = ""
        if kill_pid and kill_pid > 4:
            try:
                p = psutil.Process(kill_pid)
                pname = p.name().lower()
                if pname not in PROTECTED_SYSTEM_PROCESSES:
                    p.terminate()
                    proc_msg = f"Se cerró el proceso (PID {kill_pid}) exitosamente.\n"
            except Exception as e:
                proc_msg = f"Aviso al cerrar el proceso PID {kill_pid}: {e}\n"

        if not commands:
            return True, proc_msg or "Acción completada."

        combined_cmd = " & ".join(commands)
        creation_flags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0

        # Intentar primero en el contexto actual
        try:
            res = subprocess.run(
                combined_cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=8,
                creationflags=creation_flags,
            )
            if res.returncode == 0:
                return True, f"{proc_msg}Las reglas de protección se aplicaron correctamente en tu máquina."
        except Exception:
            pass

        # Si requiere elevación de Administrador (UAC), invocar ShellExecuteW("runas")
        try:
            ret = ctypes.windll.shell32.ShellExecuteW(
                None,
                "runas",
                "cmd.exe",
                f'/c {combined_cmd}',
                None,
                0,  # SW_HIDE
            )
            if int(ret) > 32:
                return True, (
                    f"{proc_msg}Se ejecutó el script con permisos de Administrador (UAC) y la mitigación fue aplicada."
                )
            else:
                return False, (
                    "No se concedieron permisos de Administrador en la ventana de Windows (UAC), "
                    "por lo que no se realizó ningún cambio en tu equipo."
                )
        except Exception as e:
            return False, f"No se pudo completar el comando de mitigación:\n{e}"

    @staticmethod
    def revert_firewall_rule(rule_name: str) -> tuple[bool, str]:
        """Elimina una regla de Firewall creada previamente por BlueGuard."""
        cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
        ok, msg = Mitigator.execute_commands_with_consent([cmd])
        if ok:
            Mitigator.remove_saved_rule(rule_name)
            return True, f"Se eliminó la regla '{rule_name}' y el puerto volvió a su estado original."
        return False, msg
