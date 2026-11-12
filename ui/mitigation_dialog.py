"""
ui/mitigation_dialog.py
───────────────────────
Diálogo ético de consentimiento informado (Human-in-the-Loop) para mitigación en BlueGuard.
Explica de forma transparente qué se detectó, qué estándar aplica (ISO 27000, NIST, CIS, OWASP),
qué script exacto se ejecutará en la máquina y otorga libre albedrío al usuario mediante
los botones explícitos 'Aceptar' y 'Denegar' (o copiar el comando para ejecutarlo manualmente).
"""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QPlainTextEdit, QCheckBox, QFrame, QApplication, QMessageBox
)
from PyQt6.QtCore import Qt


class MitigationDialog(QDialog):
    def __init__(
        self,
        title: str,
        finding_summary: str,
        what_it_does: str,
        script_preview: str,
        can_kill_process: bool = False,
        process_name: str = "",
        pid: int = 0,
        parent=None,
    ):
        super().__init__(parent)
        self.setWindowTitle("Confirmación de Seguridad — BlueGuard")
        self.setMinimumWidth(580)
        self.script_preview = script_preview
        self.should_kill_process = False

        self._init_ui(title, finding_summary, what_it_does, script_preview, can_kill_process, process_name, pid)

    def _init_ui(self, title, finding_summary, what_it_does, script_preview, can_kill_process, process_name, pid):
        self.setStyleSheet("""
            QDialog {
                background-color: #0F172A;
                color: #F8FAFC;
            }
            QLabel {
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 22, 24, 22)
        layout.setSpacing(14)

        # Título de la pregunta de consentimiento
        lbl_title = QLabel(title)
        lbl_title.setWordWrap(True)
        lbl_title.setStyleSheet("font-size: 13.5pt; font-weight: 800; color: #38BDF8;")
        layout.addWidget(lbl_title)

        # Tarjeta 1: Detalle del Hallazgo
        card_finding = QFrame()
        card_finding.setStyleSheet("""
            QFrame {
                background-color: #1E293B;
                border: 1px solid #334155;
                border-radius: 10px;
                padding: 10px;
            }
        """)
        cf_layout = QVBoxLayout(card_finding)
        cf_layout.setContentsMargins(10, 8, 10, 8)
        cf_layout.setSpacing(4)

        lbl_f_hdr = QLabel("Diagnóstico Analizado:")
        lbl_f_hdr.setStyleSheet("color: #94A3B8; font-weight: 700; font-size: 9pt;")
        lbl_f_body = QLabel(finding_summary)
        lbl_f_body.setWordWrap(True)
        lbl_f_body.setStyleSheet("color: #F1F5F9; font-size: 9.5pt;")

        cf_layout.addWidget(lbl_f_hdr)
        cf_layout.addWidget(lbl_f_body)
        layout.addWidget(card_finding)

        # Tarjeta 2: Explicación de la Herramienta antes de su uso
        card_explain = QFrame()
        card_explain.setStyleSheet("""
            QFrame {
                background-color: rgba(37, 99, 235, 0.12);
                border: 1px solid #2563EB;
                border-radius: 10px;
                padding: 10px;
            }
        """)
        ce_layout = QVBoxLayout(card_explain)
        ce_layout.setContentsMargins(10, 8, 10, 8)
        ce_layout.setSpacing(6)

        lbl_e_hdr = QLabel("¿Qué hará exactamente esta herramienta en tu dispositivo?")
        lbl_e_hdr.setStyleSheet("color: #60A5FA; font-weight: 700; font-size: 9.5pt;")
        lbl_e_body = QLabel(what_it_does)
        lbl_e_body.setWordWrap(True)
        lbl_e_body.setStyleSheet("color: #E2E8F0; font-size: 9.5pt;")

        ce_layout.addWidget(lbl_e_hdr)
        ce_layout.addWidget(lbl_e_body)
        layout.addWidget(card_explain)

        # Opción adicional para terminar proceso si no es crítico del sistema
        self.chk_kill = None
        if can_kill_process:
            self.chk_kill = QCheckBox(f"Cerrar también la aplicación '{process_name}' (PID {pid}) para cortar la conexión inmediatamente")
            self.chk_kill.setChecked(False)
            self.chk_kill.setStyleSheet("""
                QCheckBox {
                    color: #FBBF24;
                    font-weight: 600;
                    font-size: 9.5pt;
                    spacing: 8px;
                }
            """)
            layout.addWidget(self.chk_kill)

        # Vista transparente del Script que se ejecutará
        script_header_row = QHBoxLayout()
        lbl_script = QLabel("Script auditable que se ejecutará (requerirá permiso de Administrador):")
        lbl_script.setStyleSheet("color: #94A3B8; font-size: 8.5pt; font-weight: 600;")
        script_header_row.addWidget(lbl_script)
        script_header_row.addStretch()

        btn_copy = QPushButton("Copiar script (Hacerlo yo mismo)")
        btn_copy.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_copy.setFixedHeight(26)
        btn_copy.setStyleSheet("""
            QPushButton {
                background-color: #1E293B;
                color: #38BDF8;
                border: 1px solid #334155;
                border-radius: 5px;
                padding: 0 10px;
                font-size: 8pt;
                font-weight: 600;
            }
            QPushButton:hover { background-color: #334155; color: #FFFFFF; }
        """)
        btn_copy.clicked.connect(self._copy_script)
        script_header_row.addWidget(btn_copy)
        layout.addLayout(script_header_row)

        txt_cmd = QPlainTextEdit()
        txt_cmd.setPlainText(script_preview)
        txt_cmd.setReadOnly(True)
        txt_cmd.setFixedHeight(64)
        txt_cmd.setStyleSheet("""
            QPlainTextEdit {
                background-color: #090D16;
                color: #38BDF8;
                border: 1px solid #1E293B;
                border-radius: 8px;
                padding: 8px;
                font-family: Consolas, monospace;
                font-size: 9pt;
            }
        """)
        layout.addWidget(txt_cmd)

        # Nota de libre albedrío
        lbl_free_will = QLabel(
            "Tienes total elección: puedes pulsar 'Aceptar' para que BlueGuard aplique la protección por ti, "
            "o pulsar 'Denegar' si prefieres no hacer cambios o resolverlo manualmente."
        )
        lbl_free_will.setWordWrap(True)
        lbl_free_will.setStyleSheet("color: #94A3B8; font-size: 8.5pt; font-style: italic;")
        layout.addWidget(lbl_free_will)

        # Botonera inferior: Denegar vs Aceptar
        btn_row = QHBoxLayout()
        btn_row.setSpacing(12)
        btn_row.addStretch()

        self.btn_deny = QPushButton("Denegar")
        self.btn_deny.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_deny.setFixedHeight(40)
        self.btn_deny.setStyleSheet("""
            QPushButton {
                background-color: #334155;
                color: #F8FAFC;
                font-weight: 700;
                font-size: 10pt;
                padding: 0 24px;
                border-radius: 8px;
                border: 1px solid #475569;
            }
            QPushButton:hover { background-color: #475569; }
        """)
        self.btn_deny.clicked.connect(self.reject)

        self.btn_accept = QPushButton("Aceptar")
        self.btn_accept.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_accept.setFixedHeight(40)
        self.btn_accept.setStyleSheet("""
            QPushButton {
                background-color: #10B981;
                color: #FFFFFF;
                font-weight: 700;
                font-size: 10pt;
                padding: 0 28px;
                border-radius: 8px;
                border: none;
            }
            QPushButton:hover { background-color: #059669; }
        """)
        self.btn_accept.clicked.connect(self._on_accept)

        btn_row.addWidget(self.btn_deny)
        btn_row.addWidget(self.btn_accept)
        layout.addLayout(btn_row)

    def _copy_script(self):
        clipboard = QApplication.clipboard()
        if clipboard:
            clipboard.setText(self.script_preview)
            QMessageBox.information(
                self,
                "Comando Copiado",
                "El comando fue copiado al portapapeles. Puedes ejecutarlo tú mismo en una consola con permisos de Administrador si así lo prefieres.",
            )

    def _on_accept(self):
        if self.chk_kill and self.chk_kill.isChecked():
            self.should_kill_process = True
        self.accept()
