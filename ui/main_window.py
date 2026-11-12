"""
ui/main_window.py
─────────────────
Ventana Principal de BlueGuard — Centro de Ciberseguridad Defensiva (Blue Team)
para el Usuario Común.
Traduce datos complejos de red, puertos, configuración y logs de Windows en información
legible en tiempo real bajo criterios ISO/IEC 27000, NIST CSF 2.0, CIS Controls v8 y OWASP.
"""

import os
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTabWidget, QFrame, QGridLayout, QTableWidget, QTableWidgetItem,
    QHeaderView, QLineEdit, QComboBox, QMessageBox, QScrollArea, QAbstractItemView
)
from PyQt6.QtGui import QIcon, QColor, QBrush, QFont
from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal

from core.standards import SECURITY_STANDARDS_INFO
from core.network_analyzer import NetworkAnalyzer
from core.system_auditor import SystemAuditor
from core.log_analyzer import LogAnalyzer
from core.mitigator import Mitigator
from ui.mitigation_dialog import MitigationDialog


class LogLoaderThread(QThread):
    """Carga y traduce los eventos de Windows en segundo plano para mantener la UI fluida."""
    logs_ready = pyqtSignal(list)

    def run(self):
        events = LogAnalyzer.fetch_recent_events(max_events=24)
        self.logs_ready.emit(events)


class BlueGuardWindow(QMainWindow):
    def __init__(self, lang: str = "es"):
        super().__init__()
        self.lang = lang
        self.setWindowTitle("BlueGuard — Asistente de Ciberseguridad y Defensa en Tiempo Real")
        self.resize(1160, 760)
        self.setMinimumSize(1020, 680)

        self.connections_data: list[dict] = []
        self.audit_data: list[dict] = []
        self.logs_data: list[dict] = []
        self.realtime_enabled = True

        self._setup_icon()
        self.init_ui()
        self._apply_theme()

        # Timer de monitoreo en tiempo real (cada 5 segundos)
        self.monitor_timer = QTimer(self)
        self.monitor_timer.setInterval(5000)
        self.monitor_timer.timeout.connect(self._refresh_realtime_data)
        self.monitor_timer.start()

        # Primer escaneo inmediato
        self._refresh_realtime_data()
        self._load_logs_async()

    def _setup_icon(self):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        icon_path = os.path.join(base_dir, "assets", "hub", "Media-Hub.ico")
        if os.path.isfile(icon_path):
            self.setWindowIcon(QIcon(icon_path))

    def init_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root_layout = QVBoxLayout(central)
        root_layout.setContentsMargins(26, 20, 26, 20)
        root_layout.setSpacing(14)

        # ── 1. Header Bento ───────────────────────────────────────────────────
        header_layout = QHBoxLayout()
        title_box = QVBoxLayout()
        title_box.setSpacing(2)

        title_lbl = QLabel("BlueGuard")
        title_lbl.setStyleSheet("font-size: 21pt; font-weight: 800; color: #FFFFFF;")
        subtitle_lbl = QLabel(
            "Análisis defensivo Blue Team en tiempo real traducido a lenguaje claro (ISO 27000 • NIST • CIS • OWASP)"
        )
        subtitle_lbl.setStyleSheet("font-size: 9.5pt; color: #94A3B8;")

        title_box.addWidget(title_lbl)
        title_box.addWidget(subtitle_lbl)
        header_layout.addLayout(title_box)
        header_layout.addStretch()

        # Insignia de Puntaje de Salud
        self.lbl_score_badge = QLabel("Salud del Equipo: -- / 100")
        self.lbl_score_badge.setStyleSheet("""
            background-color: rgba(16, 185, 129, 0.15);
            color: #34D399;
            border: 1px solid #10B981;
            border-radius: 8px;
            padding: 6px 14px;
            font-weight: 800;
            font-size: 10pt;
        """)
        header_layout.addWidget(self.lbl_score_badge)

        # Botón Monitoreo en Tiempo Real (Toggle)
        self.btn_realtime = QPushButton("Tiempo Real: Activo")
        self.btn_realtime.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_realtime.setFixedHeight(36)
        self.btn_realtime.clicked.connect(self._toggle_realtime)
        self._style_realtime_btn()
        header_layout.addWidget(self.btn_realtime)

        # Botón Analizar Ahora
        self.btn_scan = QPushButton("Analizar Ahora")
        self.btn_scan.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_scan.setFixedHeight(36)
        self.btn_scan.setStyleSheet("""
            QPushButton {
                background-color: #2563EB;
                color: #FFFFFF;
                font-weight: 700;
                font-size: 9.5pt;
                padding: 0 18px;
                border-radius: 8px;
                border: none;
            }
            QPushButton:hover { background-color: #1D4ED8; }
        """)
        self.btn_scan.clicked.connect(self._manual_scan)
        header_layout.addWidget(self.btn_scan)

        root_layout.addLayout(header_layout)

        # ── 2. Pestañas Principales ───────────────────────────────────────────
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #1E293B;
                background-color: #0F172A;
                border-radius: 12px;
                padding: 12px;
            }
            QTabBar::tab {
                background-color: #1E293B;
                color: #94A3B8;
                padding: 10px 20px;
                margin-right: 4px;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                font-weight: 600;
                font-size: 9.5pt;
            }
            QTabBar::tab:selected {
                background-color: #2563EB;
                color: #FFFFFF;
            }
        """)

        self.tab_dashboard = QWidget()
        self.tab_network = QWidget()
        self.tab_audit = QWidget()
        self.tab_logs = QWidget()

        self._init_dashboard_tab()
        self._init_network_tab()
        self._init_audit_tab()
        self._init_logs_tab()

        self.tabs.addTab(self.tab_dashboard, "Estado General y Estándares")
        self.tabs.addTab(self.tab_network, "Monitor de Red y Puertos")
        self.tabs.addTab(self.tab_audit, "Auditoría del Dispositivo (CIS / NIST)")
        self.tabs.addTab(self.tab_logs, "Traductor de Logs y Reglas")

        root_layout.addWidget(self.tabs, 1)

    # ─────────────────────────────────────────────────────────────────────────
    #  Tab 1: Dashboard & Guía de Estándares
    # ─────────────────────────────────────────────────────────────────────────

    def _init_dashboard_tab(self):
        layout = QVBoxLayout(self.tab_dashboard)
        layout.setSpacing(14)

        # Fila de 4 tarjetas de métricas en vivo
        metrics_grid = QGridLayout()
        metrics_grid.setSpacing(12)

        self.card_metric_score = self._create_metric_card("Nivel de Protección", "-- / 100", "Evaluación global NIST / CIS", "#38BDF8")
        self.card_metric_conns = self._create_metric_card("Conexiones y Canales", "0", "Canales de red activos en tu PC", "#A78BFA")
        self.card_metric_listen = self._create_metric_card("Puertos en Escucha", "0", "Puertos abiertos esperando datos", "#FBBF24")
        self.card_metric_alerts = self._create_metric_card("Atención / Riesgos", "0", "Puntos que puedes revisar o mitigar", "#F87171")

        metrics_grid.addWidget(self.card_metric_score[0], 0, 0)
        metrics_grid.addWidget(self.card_metric_conns[0], 0, 1)
        metrics_grid.addWidget(self.card_metric_listen[0], 0, 2)
        metrics_grid.addWidget(self.card_metric_alerts[0], 0, 3)

        layout.addLayout(metrics_grid)

        # Banner de filosofía de uso ético y libre elección
        philosophy_card = QFrame()
        philosophy_card.setStyleSheet("""
            QFrame {
                background-color: #131C31;
                border: 1px solid #1E3A8A;
                border-radius: 10px;
                padding: 10px;
            }
        """)
        p_layout = QVBoxLayout(philosophy_card)
        p_layout.setSpacing(4)
        lbl_p_title = QLabel("¿Cómo te protege BlueGuard sin invadir tu computador?")
        lbl_p_title.setStyleSheet("color: #60A5FA; font-weight: 700; font-size: 10.5pt;")
        lbl_p_desc = QLabel(
            "1. Analiza tu red, puertos y configuraciones en tiempo real sin modificar nada por su cuenta.\n"
            "2. Traduce términos técnicos complejos a explicaciones claras para que sepas exactamente qué ocurre.\n"
            "3. Cuando pulsas 'Mitigar', te explica qué hará el script y te da libre elección ('Aceptar' o 'Denegar') antes de ejecutar cualquier cambio."
        )
        lbl_p_desc.setWordWrap(True)
        lbl_p_desc.setStyleSheet("color: #E2E8F0; font-size: 9.5pt;")
        p_layout.addWidget(lbl_p_title)
        p_layout.addWidget(lbl_p_desc)
        layout.addWidget(philosophy_card)

        # Sección de Estándares Internacionales explicados en sencillo
        lbl_std = QLabel("Estándares Internacionales Aplicados en este Diagnóstico:")
        lbl_std.setStyleSheet("color: #F8FAFC; font-weight: 700; font-size: 10.5pt;")
        layout.addWidget(lbl_std)

        std_grid = QGridLayout()
        std_grid.setSpacing(10)
        for i, std in enumerate(SECURITY_STANDARDS_INFO):
            frame = QFrame()
            frame.setStyleSheet("""
                QFrame {
                    background-color: #1E293B;
                    border: 1px solid #334155;
                    border-radius: 10px;
                    padding: 10px;
                }
            """)
            fl = QVBoxLayout(frame)
            fl.setSpacing(4)

            top_r = QHBoxLayout()
            t_lbl = QLabel(std["title"])
            t_lbl.setStyleSheet("color: #38BDF8; font-weight: 700; font-size: 9.5pt;")
            b_lbl = QLabel(std["badge"])
            b_lbl.setStyleSheet("""
                background-color: #0F172A;
                color: #94A3B8;
                border: 1px solid #334155;
                border-radius: 5px;
                padding: 2px 8px;
                font-size: 8pt;
                font-weight: 600;
            """)
            top_r.addWidget(t_lbl)
            top_r.addStretch()
            top_r.addWidget(b_lbl)

            s_lbl = QLabel(std["summary"])
            s_lbl.setWordWrap(True)
            s_lbl.setStyleSheet("color: #CBD5E1; font-size: 9pt;")

            fl.addLayout(top_r)
            fl.addWidget(s_lbl)
            std_grid.addWidget(frame, i // 2, i % 2)

        layout.addLayout(std_grid)
        layout.addStretch()

    def _create_metric_card(self, title: str, value: str, subtitle: str, accent_color: str):
        frame = QFrame()
        frame.setStyleSheet("""
            QFrame {
                background-color: #1E293B;
                border: 1px solid #334155;
                border-radius: 10px;
                padding: 10px;
            }
        """)
        vl = QVBoxLayout(frame)
        vl.setSpacing(2)

        lbl_t = QLabel(title)
        lbl_t.setStyleSheet("color: #94A3B8; font-size: 9pt; font-weight: 600;")

        lbl_v = QLabel(value)
        lbl_v.setStyleSheet(f"color: {accent_color}; font-size: 18pt; font-weight: 800;")

        lbl_s = QLabel(subtitle)
        lbl_s.setStyleSheet("color: #64748B; font-size: 8pt;")

        vl.addWidget(lbl_t)
        vl.addWidget(lbl_v)
        vl.addWidget(lbl_s)
        return frame, lbl_v

    # ─────────────────────────────────────────────────────────────────────────
    #  Tab 2: Monitor de Red y Puertos en Tiempo Real
    # ─────────────────────────────────────────────────────────────────────────

    def _init_network_tab(self):
        layout = QVBoxLayout(self.tab_network)
        layout.setSpacing(10)

        # Barra de filtro y búsqueda
        filter_row = QHBoxLayout()
        filter_row.setSpacing(10)

        lbl_f = QLabel("Filtrar conexiones:")
        lbl_f.setStyleSheet("color: #CBD5E1; font-weight: 600;")
        self.txt_net_search = QLineEdit()
        self.txt_net_search.setPlaceholderText("Buscar por programa, puerto, dirección IP o explicación...")
        self.txt_net_search.textChanged.connect(self._populate_network_table)

        lbl_r = QLabel("Nivel de atención:")
        lbl_r.setStyleSheet("color: #CBD5E1; font-weight: 600;")
        self.combo_net_filter = QComboBox()
        self.combo_net_filter.addItems([
            "Mostrar Todo",
            "Solo Riesgo Alto y Atención (Puertos Expuestos)",
            "Solo Puertos Abiertos (Escuchando)",
            "Solo Conexiones Externas Activas",
        ])
        self.combo_net_filter.currentIndexChanged.connect(self._populate_network_table)

        filter_row.addWidget(lbl_f)
        filter_row.addWidget(self.txt_net_search, 1)
        filter_row.addWidget(lbl_r)
        filter_row.addWidget(self.combo_net_filter)
        layout.addLayout(filter_row)

        # Tabla de conexiones traducidas
        self.table_net = QTableWidget(0, 7)
        self.table_net.setHorizontalHeaderLabels([
            "Aplicación",
            "Puerto Local",
            "Destino Remoto",
            "Estado",
            "Evaluación",
            "Explicación en Lenguaje Claro",
            "Acción",
        ])
        self._configure_table(
            self.table_net,
            default_widths=[180, 250, 170, 160, 140, 460, 110],
            fixed_last_col=110,
        )

        layout.addWidget(self.table_net, 1)

    # ─────────────────────────────────────────────────────────────────────────
    #  Tab 3: Auditoría del Dispositivo (CIS / NIST / ISO / OWASP)
    # ─────────────────────────────────────────────────────────────────────────

    def _init_audit_tab(self):
        layout = QVBoxLayout(self.tab_audit)
        layout.setSpacing(10)

        lbl_intro = QLabel(
            "Revisión automática de seguridad basada en CIS Controls v8, NIST CSF, ISO/IEC 27002 y OWASP. "
            "Si algún control presenta riesgo, puedes pulsar 'Mitigar' para ver la explicación y decidir si aplicarlo."
        )
        lbl_intro.setWordWrap(True)
        lbl_intro.setStyleSheet("color: #94A3B8; font-size: 9.5pt;")
        layout.addWidget(lbl_intro)

        self.audit_scroll = QScrollArea()
        self.audit_scroll.setWidgetResizable(True)
        self.audit_scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.audit_container = QWidget()
        self.audit_container_layout = QVBoxLayout(self.audit_container)
        self.audit_container_layout.setSpacing(10)
        self.audit_container_layout.setContentsMargins(0, 0, 6, 0)
        self.audit_scroll.setWidget(self.audit_container)

        layout.addWidget(self.audit_scroll, 1)

    # ─────────────────────────────────────────────────────────────────────────
    #  Tab 4: Traductor de Logs de Windows y Reglas Aplicadas
    # ─────────────────────────────────────────────────────────────────────────

    def _init_logs_tab(self):
        layout = QVBoxLayout(self.tab_logs)
        layout.setSpacing(10)

        # Cabecera de Logs
        top_log_row = QHBoxLayout()
        lbl_l = QLabel("Eventos Recientes del Sistema Traducidos para el Usuario:")
        lbl_l.setStyleSheet("color: #F8FAFC; font-weight: 700; font-size: 10pt;")
        top_log_row.addWidget(lbl_l)
        top_log_row.addStretch()

        self.btn_refresh_logs = QPushButton("Actualizar Eventos")
        self.btn_refresh_logs.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_refresh_logs.setFixedHeight(30)
        self.btn_refresh_logs.setStyleSheet("""
            QPushButton {
                background-color: #1E293B;
                color: #38BDF8;
                border: 1px solid #334155;
                border-radius: 6px;
                padding: 0 12px;
                font-weight: 600;
                font-size: 8.5pt;
            }
            QPushButton:hover { background-color: #334155; color: #FFFFFF; }
        """)
        self.btn_refresh_logs.clicked.connect(self._load_logs_async)
        top_log_row.addWidget(self.btn_refresh_logs)
        layout.addLayout(top_log_row)

        self.table_logs = QTableWidget(0, 5)
        self.table_logs.setHorizontalHeaderLabels([
            "Fecha y Hora",
            "Canal / ID",
            "Nivel",
            "Resumen del Evento",
            "Traducción y Significado para tu Equipo",
        ])
        self._configure_table(
            self.table_logs,
            default_widths=[145, 190, 110, 240, 520],
            fixed_last_col=None,
        )
        layout.addWidget(self.table_logs, 3)

        # Sección inferior: Reglas creadas por BlueGuard con botón Revertir
        lbl_rules = QLabel("Puertos Bloqueados con BlueGuard (Puedes revertirlos cuando quieras):")
        lbl_rules.setStyleSheet("color: #F8FAFC; font-weight: 700; font-size: 10pt;")
        layout.addWidget(lbl_rules)

        self.table_rules = QTableWidget(0, 4)
        self.table_rules.setHorizontalHeaderLabels([
            "Nombre de Regla Firewall",
            "Puerto / Protocolo",
            "Descripción",
            "Restaurar",
        ])
        self.table_rules.setMaximumHeight(150)
        self._configure_table(
            self.table_rules,
            default_widths=[220, 150, 440, 130],
            fixed_last_col=130,
        )

        layout.addWidget(self.table_rules, 1)

    def _configure_table(
        self,
        table: QTableWidget,
        default_widths: list[int],
        fixed_last_col: int | None = None,
    ):
        """Configura tablas con scroll horizontal fluido y columnas redimensionables."""
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        table.setWordWrap(False)
        table.setTextElideMode(Qt.TextElideMode.ElideNone)
        table.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        table.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        table.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)

        hdr = table.horizontalHeader()
        hdr.setStretchLastSection(False)
        hdr.setMinimumSectionSize(70)
        last_idx = len(default_widths) - 1
        for idx, width in enumerate(default_widths):
            if fixed_last_col is not None and idx == last_idx:
                hdr.setSectionResizeMode(idx, QHeaderView.ResizeMode.Fixed)
                table.setColumnWidth(idx, fixed_last_col)
            else:
                hdr.setSectionResizeMode(idx, QHeaderView.ResizeMode.Interactive)
                table.setColumnWidth(idx, width)

    def _autosize_table_once(
        self,
        table: QTableWidget,
        flag_attr: str,
        fixed_last_col: int | None = None,
    ):
        """Ajusta columnas al contenido la primera vez que llegan filas, preservando ajustes manuales luego."""
        if getattr(self, flag_attr, False) or table.rowCount() == 0:
            return
        setattr(self, flag_attr, True)
        table.resizeColumnsToContents()
        col_count = table.columnCount()
        last_idx = col_count - 1
        for idx in range(col_count):
            if fixed_last_col is not None and idx == last_idx:
                table.setColumnWidth(idx, fixed_last_col)
            else:
                table.setColumnWidth(idx, table.columnWidth(idx) + 18)

    # ─────────────────────────────────────────────────────────────────────────
    #  Lógica de Actualización y Escaneo en Tiempo Real
    # ─────────────────────────────────────────────────────────────────────────

    def _style_realtime_btn(self):
        if self.realtime_enabled:
            self.btn_realtime.setText("Tiempo Real: Activo")
            self.btn_realtime.setStyleSheet("""
                QPushButton {
                    background-color: rgba(16, 185, 129, 0.15);
                    color: #10B981;
                    border: 1px solid #10B981;
                    border-radius: 8px;
                    padding: 0 14px;
                    font-weight: 700;
                    font-size: 9pt;
                }
            """)
        else:
            self.btn_realtime.setText("Tiempo Real: Pausado")
            self.btn_realtime.setStyleSheet("""
                QPushButton {
                    background-color: #1E293B;
                    color: #94A3B8;
                    border: 1px solid #334155;
                    border-radius: 8px;
                    padding: 0 14px;
                    font-weight: 600;
                    font-size: 9pt;
                }
            """)

    def _toggle_realtime(self):
        self.realtime_enabled = not self.realtime_enabled
        if self.realtime_enabled:
            self.monitor_timer.start()
            self._refresh_realtime_data()
        else:
            self.monitor_timer.stop()
        self._style_realtime_btn()

    def _manual_scan(self):
        self._refresh_realtime_data()
        self._load_logs_async()

    def _refresh_realtime_data(self):
        self.connections_data = NetworkAnalyzer.scan_connections()
        self.audit_data = SystemAuditor.run_audit(self.connections_data)
        score = SystemAuditor.calculate_security_score(self.audit_data, self.connections_data)

        # Actualizar métricas del Dashboard
        total_conns = len(self.connections_data)
        listen_count = sum(1 for c in self.connections_data if c["status"] == "LISTEN")
        alerts_count = (
            sum(1 for c in self.connections_data if c["risk"] in ("HIGH", "MEDIUM"))
            + sum(1 for a in self.audit_data if a["status"] != "PASS")
        )

        self.card_metric_score[1].setText(f"{score} / 100")
        self.card_metric_conns[1].setText(str(total_conns))
        self.card_metric_listen[1].setText(str(listen_count))
        self.card_metric_alerts[1].setText(str(alerts_count))

        self.lbl_score_badge.setText(f"Salud del Equipo: {score} / 100")
        if score >= 80:
            self.lbl_score_badge.setStyleSheet("""
                background-color: rgba(16, 185, 129, 0.15);
                color: #34D399;
                border: 1px solid #10B981;
                border-radius: 8px;
                padding: 6px 14px;
                font-weight: 800;
                font-size: 10pt;
            """)
        elif score >= 55:
            self.lbl_score_badge.setStyleSheet("""
                background-color: rgba(245, 158, 11, 0.15);
                color: #FBBF24;
                border: 1px solid #F59E0B;
                border-radius: 8px;
                padding: 6px 14px;
                font-weight: 800;
                font-size: 10pt;
            """)
        else:
            self.lbl_score_badge.setStyleSheet("""
                background-color: rgba(239, 68, 68, 0.15);
                color: #F87171;
                border: 1px solid #EF4444;
                border-radius: 8px;
                padding: 6px 14px;
                font-weight: 800;
                font-size: 10pt;
            """)

        self._populate_network_table()
        self._populate_audit_cards()
        self._populate_rules_table()

    def _populate_network_table(self):
        query = self.txt_net_search.text().strip().lower()
        mode = self.combo_net_filter.currentIndex()

        filtered = []
        for c in self.connections_data:
            if mode == 1 and c["risk"] not in ("HIGH", "MEDIUM"):
                continue
            elif mode == 2 and c["status"] != "LISTEN":
                continue
            elif mode == 3 and (c["status"] != "ESTABLISHED" or c["remote_ip"] in ("—", "127.0.0.1", "::1")):
                continue

            if query:
                haystack = (
                    f"{c['process_name']} {c['local_port']} {c['remote_display']} "
                    f"{c['service_name']} {c['human_explanation']}"
                ).lower()
                if query not in haystack:
                    continue

            filtered.append(c)

        self.table_net.setRowCount(len(filtered))

        for row, c in enumerate(filtered):
            self.table_net.setRowHeight(row, 48)

            app_item = QTableWidgetItem(f"{c['process_name']} (PID {c['pid']})")
            port_item = QTableWidgetItem(f"{c['local_port']} / {c['proto']} ({c['service_name']})")
            rem_item = QTableWidgetItem(c["remote_display"])
            st_item = QTableWidgetItem(c["status_human"])
            risk_item = QTableWidgetItem(c["risk_label"])
            exp_item = QTableWidgetItem(c["human_explanation"])
            exp_item.setToolTip(f"{c['human_explanation']}\n\nCriterio: {c['standard_ref']}\nRecomendación: {c['recommendation']}")

            if c["risk"] == "HIGH":
                risk_color = QColor("#F87171")
            elif c["risk"] == "MEDIUM":
                risk_color = QColor("#FBBF24")
            else:
                risk_color = QColor("#34D399")

            risk_item.setForeground(QBrush(risk_color))
            f = risk_item.font()
            f.setBold(True)
            risk_item.setFont(f)

            self.table_net.setItem(row, 0, app_item)
            self.table_net.setItem(row, 1, port_item)
            self.table_net.setItem(row, 2, rem_item)
            self.table_net.setItem(row, 3, st_item)
            self.table_net.setItem(row, 4, risk_item)
            self.table_net.setItem(row, 5, exp_item)

            # Botón de Mitigar en cada fila
            btn_mitigate = QPushButton("Mitigar")
            btn_mitigate.setCursor(Qt.CursorShape.PointingHandCursor)
            btn_mitigate.setFixedHeight(30)
            if c["risk"] == "HIGH":
                btn_style = "background-color: #DC2626; color: #FFFFFF; font-weight: 700; border-radius: 6px; padding: 0 12px;"
            elif c["risk"] == "MEDIUM":
                btn_style = "background-color: #D97706; color: #FFFFFF; font-weight: 700; border-radius: 6px; padding: 0 12px;"
            else:
                btn_style = "background-color: #334155; color: #E2E8F0; font-weight: 600; border-radius: 6px; padding: 0 12px;"
            btn_mitigate.setStyleSheet(f"QPushButton {{ {btn_style} }}")
            btn_mitigate.clicked.connect(lambda checked, conn=c: self._on_mitigate_connection(conn))

            cell_widget = QWidget()
            cl = QHBoxLayout(cell_widget)
            cl.setContentsMargins(6, 4, 6, 4)
            cl.addWidget(btn_mitigate)
            self.table_net.setCellWidget(row, 6, cell_widget)

        self._autosize_table_once(self.table_net, "_net_cols_sized", fixed_last_col=110)

    def _populate_audit_cards(self):
        # Limpiar contenedor previo
        while self.audit_container_layout.count():
            item = self.audit_container_layout.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()

        for item in self.audit_data:
            card = QFrame()
            border_col = "#10B981" if item["status"] == "PASS" else ("#F59E0B" if item["status"] == "WARN" else "#EF4444")
            card.setStyleSheet(f"""
                QFrame {{
                    background-color: #1E293B;
                    border: 1px solid {border_col};
                    border-radius: 10px;
                    padding: 12px;
                }}
            """)
            row_l = QHBoxLayout(card)
            row_l.setSpacing(14)

            text_col = QVBoxLayout()
            text_col.setSpacing(4)

            top_h = QHBoxLayout()
            lbl_t = QLabel(item["title"])
            lbl_t.setStyleSheet("color: #FFFFFF; font-weight: 700; font-size: 10.5pt; border: none;")
            lbl_std = QLabel(item["standard"])
            lbl_std.setStyleSheet("color: #38BDF8; font-size: 8.5pt; font-weight: 600; border: none;")
            top_h.addWidget(lbl_t)
            top_h.addSpacing(10)
            top_h.addWidget(lbl_std)
            top_h.addStretch()

            lbl_exp = QLabel(item["human_explanation"])
            lbl_exp.setWordWrap(True)
            lbl_exp.setStyleSheet("color: #CBD5E1; font-size: 9.5pt; border: none;")

            text_col.addLayout(top_h)
            text_col.addWidget(lbl_exp)
            row_l.addLayout(text_col, 1)

            status_lbl = QLabel(item["status_human"])
            status_lbl.setStyleSheet(f"color: {border_col}; font-weight: 800; font-size: 9.5pt; border: none;")
            row_l.addWidget(status_lbl)

            if item.get("can_mitigate"):
                btn_m = QPushButton("Mitigar")
                btn_m.setCursor(Qt.CursorShape.PointingHandCursor)
                btn_m.setFixedHeight(34)
                btn_m.setStyleSheet("""
                    QPushButton {
                        background-color: #2563EB;
                        color: #FFFFFF;
                        font-weight: 700;
                        padding: 0 18px;
                        border-radius: 7px;
                        border: none;
                    }
                    QPushButton:hover { background-color: #1D4ED8; }
                """)
                btn_m.clicked.connect(lambda checked, a_item=item: self._on_mitigate_audit(a_item))
                row_l.addWidget(btn_m)

            self.audit_container_layout.addWidget(card)

        self.audit_container_layout.addStretch()

    def _load_logs_async(self):
        self.btn_refresh_logs.setEnabled(False)
        self.btn_refresh_logs.setText("Analizando Eventos...")
        self.log_thread = LogLoaderThread(self)
        self.log_thread.logs_ready.connect(self._on_logs_loaded)
        self.log_thread.start()

    def _on_logs_loaded(self, events: list[dict]):
        self.btn_refresh_logs.setEnabled(True)
        self.btn_refresh_logs.setText("Actualizar Eventos")
        self.logs_data = events
        self.table_logs.setRowCount(len(events))

        for row, ev in enumerate(events):
            self.table_logs.setRowHeight(row, 42)
            t_item = QTableWidgetItem(ev["timestamp"])
            c_item = QTableWidgetItem(f"{ev['channel']} (ID {ev['event_id']})")
            l_item = QTableWidgetItem(ev["level_label"])
            ti_item = QTableWidgetItem(ev["title"])
            ex_item = QTableWidgetItem(f"{ev['human_explanation']} [{ev['standard']}]")

            if ev["level"] == "HIGH":
                l_item.setForeground(QBrush(QColor("#F87171")))
            elif ev["level"] == "MEDIUM":
                l_item.setForeground(QBrush(QColor("#FBBF24")))
            else:
                l_item.setForeground(QBrush(QColor("#38BDF8")))

            self.table_logs.setItem(row, 0, t_item)
            self.table_logs.setItem(row, 1, c_item)
            self.table_logs.setItem(row, 2, l_item)
            self.table_logs.setItem(row, 3, ti_item)
            self.table_logs.setItem(row, 4, ex_item)

        self._autosize_table_once(self.table_logs, "_logs_cols_sized", fixed_last_col=None)

    def _populate_rules_table(self):
        rules = Mitigator.load_applied_rules()
        self.table_rules.setRowCount(len(rules))
        for row, r in enumerate(rules):
            self.table_rules.setRowHeight(row, 38)
            self.table_rules.setItem(row, 0, QTableWidgetItem(r.get("rule_name", "")))
            self.table_rules.setItem(row, 1, QTableWidgetItem(f"{r.get('port')} / {r.get('proto')}"))
            self.table_rules.setItem(row, 2, QTableWidgetItem(r.get("description", "")))

            btn_rev = QPushButton("Desbloquear")
            btn_rev.setCursor(Qt.CursorShape.PointingHandCursor)
            btn_rev.setFixedHeight(28)
            btn_rev.setStyleSheet("""
                QPushButton {
                    background-color: #334155;
                    color: #F8FAFC;
                    border-radius: 5px;
                    font-weight: 600;
                    padding: 0 10px;
                }
                QPushButton:hover { background-color: #475569; }
            """)
            rname = r.get("rule_name", "")
            btn_rev.clicked.connect(lambda checked, rn=rname: self._on_revert_rule(rn))

            w = QWidget()
            wl = QHBoxLayout(w)
            wl.setContentsMargins(6, 2, 6, 2)
            wl.addWidget(btn_rev)
            self.table_rules.setCellWidget(row, 3, w)

        self._autosize_table_once(self.table_rules, "_rules_cols_sized", fixed_last_col=130)

    # ─────────────────────────────────────────────────────────────────────────
    #  Acciones de Mitigación con Consentimiento Informado (Aceptar / Denegar)
    # ─────────────────────────────────────────────────────────────────────────

    def _on_mitigate_connection(self, conn: dict):
        plan = Mitigator.build_connection_mitigation_plan(conn)
        dlg = MitigationDialog(
            title=plan["title"],
            finding_summary=plan["finding_summary"],
            what_it_does=plan["what_it_does"],
            script_preview=plan["script_preview"],
            can_kill_process=plan["can_kill_process"],
            process_name=plan["process_name"],
            pid=plan["pid"],
            parent=self,
        )
        if dlg.exec() == MitigationDialog.DialogCode.Accepted:
            kill_pid = plan["pid"] if dlg.should_kill_process else None
            ok, msg = Mitigator.execute_commands_with_consent(plan["commands"], kill_pid=kill_pid)
            if ok:
                for rname, port, proto, desc in plan["rule_names"]:
                    Mitigator.save_applied_rule(rname, port, proto, desc)
                QMessageBox.information(self, "Mitigación Aplicada — BlueGuard", msg)
                self._refresh_realtime_data()
            else:
                QMessageBox.warning(self, "Mitigación Cancelada o Incompleta", msg)

    def _on_mitigate_audit(self, audit_item: dict):
        dlg = MitigationDialog(
            title=f"¿Deseas aplicar la corrección: {audit_item['mitigation_title']}?",
            finding_summary=f"Control: {audit_item['title']}\nCriterio: {audit_item['standard']}\nDiagnóstico: {audit_item['human_explanation']}",
            what_it_does=audit_item["mitigation_explanation"],
            script_preview=audit_item["mitigation_cmd"],
            can_kill_process=False,
            parent=self,
        )
        if dlg.exec() == MitigationDialog.DialogCode.Accepted:
            ok, msg = Mitigator.execute_commands_with_consent([audit_item["mitigation_cmd"]])
            if ok:
                QMessageBox.information(self, "Protección Aplicada — BlueGuard", msg)
                self._refresh_realtime_data()
            else:
                QMessageBox.warning(self, "Aviso", msg)

    def _on_revert_rule(self, rule_name: str):
        ok, msg = Mitigator.revert_firewall_rule(rule_name)
        if ok:
            QMessageBox.information(self, "Regla Revertida", msg)
            self._refresh_realtime_data()
        else:
            QMessageBox.warning(self, "Aviso", msg)

    def closeEvent(self, event):
        if hasattr(self, "monitor_timer") and self.monitor_timer.isActive():
            self.monitor_timer.stop()
        if hasattr(self, "log_thread") and self.log_thread is not None and self.log_thread.isRunning():
            self.log_thread.wait(3000)
        super().closeEvent(event)

    def _apply_theme(self):
        self.setStyleSheet("""
            QMainWindow {
                background-color: #0B0F19;
            }
            QLabel {
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            }
            QLineEdit, QComboBox {
                background-color: #1E293B;
                color: #F8FAFC;
                border: 1px solid #334155;
                border-radius: 6px;
                padding: 6px 10px;
                font-size: 9.5pt;
            }
            QTableWidget {
                background-color: #0B0F19;
                alternate-background-color: #111827;
                color: #E2E8F0;
                border: 1px solid #1E293B;
                border-radius: 8px;
                gridline-color: #1E293B;
                font-size: 9pt;
            }
            QHeaderView::section {
                background-color: #1E293B;
                color: #94A3B8;
                font-weight: 700;
                font-size: 9pt;
                padding: 8px;
                border: none;
                border-bottom: 1px solid #334155;
            }
            QScrollBar:horizontal {
                background: #0B0F19;
                height: 10px;
                margin: 0px;
                border-radius: 5px;
            }
            QScrollBar::handle:horizontal {
                background: #334155;
                min-width: 32px;
                border-radius: 5px;
            }
            QScrollBar::handle:horizontal:hover {
                background: #475569;
            }
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
                width: 0px;
            }
            QScrollBar:vertical {
                background: #0B0F19;
                width: 10px;
                margin: 0px;
                border-radius: 5px;
            }
            QScrollBar::handle:vertical {
                background: #334155;
                min-height: 32px;
                border-radius: 5px;
            }
            QScrollBar::handle:vertical:hover {
                background: #475569;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
        """)
