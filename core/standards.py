"""
core/standards.py
─────────────────
Base de conocimiento de estándares internacionales de ciberseguridad (ISO/IEC 27000,
NIST CSF 2.0, CIS Controls v8 y OWASP) adaptada en lenguaje sencillo para el usuario común.
Incluye diccionarios de puertos, procesos protegidos del sistema y eventos de Windows.
"""

# Procesos críticos del sistema operativo Windows que NUNCA deben cerrarse forzosamente
PROTECTED_SYSTEM_PROCESSES = {
    "system",
    "idle",
    "registry",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "winlogon.exe",
    "explorer.exe",
    "dwm.exe",
    "fontdrvhost.exe",
    "spoolsv.exe",
    "MsMpEng.exe".lower(),
    "securityhealthservice.exe",
}

# Explicación pedagógica de los estándares para el usuario común
SECURITY_STANDARDS_INFO = [
    {
        "id": "ISO/IEC 27001 & 27002",
        "title": "ISO/IEC 27000 (Seguridad de la Información)",
        "badge": "Controles A.8.20 / A.8.16",
        "summary": (
            "Familia de normas internacionales que definen cómo proteger la información. "
            "En tu PC, el control A.8.20 recomienda vigilar las conexiones de red y mantener "
            "abiertos únicamente los servicios que realmente utilizas."
        ),
    },
    {
        "id": "NIST CSF 2.0",
        "title": "NIST Cybersecurity Framework (Identificar, Proteger, Detectar, Responder)",
        "badge": "Marco Defensivo Blue Team",
        "summary": (
            "Creado por el Instituto Nacional de Estándares y Tecnología (EE. UU.). "
            "Organiza la defensa en pasos simples: saber qué tienes conectado (Identificar), "
            "activar cortafuegos (Proteger), descubrir conexiones raras (Detectar) y actuar con tu permiso (Responder)."
        ),
    },
    {
        "id": "CIS Controls v8",
        "title": "CIS Controls v8 (Configuración Segura del Equipo)",
        "badge": "Controles 4 y 12",
        "summary": (
            "Guía práctica de acciones concretas para blindar tu computador. "
            "Recomienda activar el Firewall en todas las redes, desactivar protocolos antiguos (como Telnet o SMBv1) "
            "y cerrar puertos de administración remota si no los necesitas."
        ),
    },
    {
        "id": "OWASP",
        "title": "OWASP (Seguridad en Aplicaciones y Servicios Expuestos)",
        "badge": "A05: Configuración Incorrecta",
        "summary": (
            "Estándar enfocado en aplicaciones y servidores locales. "
            "Advierte sobre el peligro de dejar servidores de prueba, bases de datos o paneles web locales "
            "(como puertos 80, 3000, 5000, 8000, 8080) abiertos a toda la red sin contraseña."
        ),
    },
]

# Catálogo de puertos conocidos traducidos a lenguaje humano
PORT_KNOWLEDGE_BASE = {
    20: {
        "service": "FTP Datos",
        "risk": "HIGH",
        "human_desc": "Transferencia de archivos antigua sin cifrado. Cualquier dato enviado puede leerse en la red.",
        "standard": "CIS Control 4.8 / ISO 27002 A.8.20",
        "recommendation": "Cerrar este puerto salvo que uses un servidor FTP local temporal y controlado.",
    },
    21: {
        "service": "FTP Control",
        "risk": "HIGH",
        "human_desc": "Puerto de servidor FTP. Envía usuarios y contraseñas en texto plano sin protección.",
        "standard": "CIS Control 4.8 / NIST PR.DS",
        "recommendation": "Bloquear el puerto 21 en el Firewall para evitar accesos no autorizados a tus carpetas.",
    },
    22: {
        "service": "SSH (Consola Remota)",
        "risk": "MEDIUM",
        "human_desc": "Permite controlar el equipo por consola remota o transferir archivos cifrados.",
        "standard": "CIS Control 4.4 / NIST PR.AC",
        "recommendation": "Si no te conectas remotamente a tu PC por SSH, es más seguro bloquear su acceso externo.",
    },
    23: {
        "service": "Telnet (Remoto Inseguro)",
        "risk": "HIGH",
        "human_desc": "Control remoto obsoleto y sin cifrado. Muy buscado por ataques automáticos y malware.",
        "standard": "CIS Control 4.8 / ISO 27002 A.8.20",
        "recommendation": "Se recomienda encarecidamente bloquear el puerto 23 de inmediato.",
    },
    53: {
        "service": "DNS (Resolución de Nombres)",
        "risk": "LOW",
        "human_desc": "Traduce nombres de páginas web (como google.com) a direcciones IP.",
        "standard": "NIST DE.CM",
        "recommendation": "Normal en conexiones salientes. Si está en escucha hacia toda la red, verifica qué app lo abrió.",
    },
    80: {
        "service": "HTTP (Servidor Web sin cifrar)",
        "risk": "MEDIUM",
        "human_desc": "Tráfico web estándar o un servidor web local corriendo en tu máquina.",
        "standard": "OWASP A02 & A05",
        "recommendation": "Normal al navegar, pero si tu PC tiene el puerto 80 abierto en escucha (LISTEN), otros en tu Wi-Fi podrían verlo.",
    },
    135: {
        "service": "Windows RPC (Llamadas Remotas)",
        "risk": "MEDIUM",
        "human_desc": "Servicio interno de Windows para comunicación entre componentes del sistema.",
        "standard": "CIS Control 12.2 / ISO 27002 A.8.20",
        "recommendation": "Es un servicio propio de Windows, pero no debe quedar expuesto en redes Wi-Fi públicas.",
    },
    139: {
        "service": "NetBIOS (Carpetas Compartidas)",
        "risk": "MEDIUM",
        "human_desc": "Servicio antiguo de Windows para compartir archivos e impresoras en red local.",
        "standard": "CIS Control 4.8",
        "recommendation": "Si estás en una red pública o no compartes carpetas, conviene filtrarlo en el Firewall.",
    },
    443: {
        "service": "HTTPS (Web Segura Cifrada)",
        "risk": "LOW",
        "human_desc": "Conexión segura y cifrada hacia sitios web y servicios en la nube.",
        "standard": "ISO 27002 A.8.24",
        "recommendation": "Tráfico habitual y seguro de navegadores y aplicaciones legítimas.",
    },
    445: {
        "service": "SMB (Compartición de Archivos Windows)",
        "risk": "HIGH",
        "human_desc": "Usado para compartir discos en red, pero históricamente explotado por ransomware (como WannaCry) si está expuesto.",
        "standard": "CIS Control 4.4 / NIST PR.AC",
        "recommendation": "Asegúrate de que el Firewall bloquee el puerto 445 frente a conexiones entrantes no confiables.",
    },
    1433: {
        "service": "Microsoft SQL Server",
        "risk": "MEDIUM",
        "human_desc": "Base de datos SQL Server abierta. Si está en 0.0.0.0, otros equipos podrían intentar adivinar su clave.",
        "standard": "OWASP A05 / CIS Control 4.4",
        "recommendation": "Limitar solo a uso interno (127.0.0.1) o bloquear entradas externas en el Firewall.",
    },
    3306: {
        "service": "MySQL / MariaDB",
        "risk": "MEDIUM",
        "human_desc": "Motor de base de datos abierto en tu equipo.",
        "standard": "OWASP A05 / CIS Control 4.4",
        "recommendation": "Si lo usas para estudiar o programar, evita que acepte conexiones fuera de tu propio PC.",
    },
    3389: {
        "service": "RDP (Escritorio Remoto de Windows)",
        "risk": "HIGH",
        "human_desc": "Permite ver y controlar la pantalla completa de tu computador a distancia.",
        "standard": "CIS Control 4.4 / NIST PR.AC / ISO 27002 A.8.20",
        "recommendation": "Si no estás usando Escritorio Remoto ahora mismo, bloquéalo para impedir intentos de intrusión.",
    },
    4444: {
        "service": "Puerto Sospechoso (Común en Backdoors)",
        "risk": "HIGH",
        "human_desc": "Puerto frecuentemente utilizado por herramientas de control remoto no autorizado o pruebas de intrusión.",
        "standard": "NIST DE.CM / ISO 27002 A.8.16",
        "recommendation": "¡Atención! Revisa qué aplicación abrió este puerto y bloquéalo si no lo reconoces.",
    },
    5432: {
        "service": "PostgreSQL",
        "risk": "MEDIUM",
        "human_desc": "Motor de base de datos PostgreSQL en ejecución.",
        "standard": "OWASP A05",
        "recommendation": "Restringir acceso externo si solo programas localmente.",
    },
    5900: {
        "service": "VNC (Pantalla Remota)",
        "risk": "HIGH",
        "human_desc": "Permite ver y controlar tu escritorio remotamente mediante VNC.",
        "standard": "CIS Control 4.4 / NIST PR.AC",
        "recommendation": "Bloquear el acceso externo si no necesitas asistencia remota activa.",
    },
    6667: {
        "service": "IRC / Canal de Comando",
        "risk": "HIGH",
        "human_desc": "Canal de chat antiguo que a veces es utilizado por programas maliciosos para recibir órdenes.",
        "standard": "NIST DE.CM",
        "recommendation": "Bloquear inmediatamente si no utilizas un cliente IRC.",
    },
    8000: {
        "service": "Servidor Web de Desarrollo",
        "risk": "MEDIUM",
        "human_desc": "Usado por proyectos locales (Python, Node, etc.). Si escucha en 0.0.0.0, es visible en tu red Wi-Fi.",
        "standard": "OWASP A05 (Security Misconfiguration)",
        "recommendation": "Bloquear acceso entrante externo si solo estás probando una app en tu propio PC.",
    },
    8080: {
        "service": "HTTP Alternativo / Proxy / Dev",
        "risk": "MEDIUM",
        "human_desc": "Servidor web local o servicio proxy activo en el puerto 8080.",
        "standard": "OWASP A05",
        "recommendation": "Verificar a qué programa pertenece y bloquear entradas externas si no deseas compartirlo en red.",
    },
}

# Puertos adicionales comúnmente asociados a troyanos/backdoors o minería
SUSPICIOUS_PORTS = {1337, 31337, 4444, 4445, 5554, 6666, 6667, 12345, 27374, 3333, 14444}

# Traducción de eventos de Windows a lenguaje sencillo
WINDOWS_EVENT_TRANSLATIONS = {
    4624: {
        "title": "Inicio de sesión correcto",
        "level": "INFO",
        "explanation": "Alguien o un servicio del sistema inició sesión correctamente en este equipo.",
        "standard": "ISO 27002 A.8.15 / NIST DE.CM",
    },
    4625: {
        "title": "Intento fallido de inicio de sesión",
        "level": "HIGH",
        "explanation": "Se ingresó una contraseña incorrecta al intentar entrar a tu equipo (posible intento de adivinar tu clave).",
        "standard": "CIS Control 8 / NIST DE.AE",
    },
    4672: {
        "title": "Permisos de Administrador asignados",
        "level": "INFO",
        "explanation": "Una sesión recibió privilegios especiales de Administrador.",
        "standard": "CIS Control 6 (Gestión de Privilegios)",
    },
    1102: {
        "title": "Historial de seguridad borrado",
        "level": "HIGH",
        "explanation": "¡Alerta! Se limpió el registro de auditoría de seguridad. A veces el malware hace esto para ocultar su rastro.",
        "standard": "CIS Control 8 / ISO 27002 A.8.15",
    },
    7045: {
        "title": "Nuevo servicio instalado en el sistema",
        "level": "MEDIUM",
        "explanation": "Se registró un nuevo servicio de fondo en Windows. Verifica que corresponda a un programa que tú instalaste.",
        "standard": "NIST DE.CM / CIS Control 2",
    },
    7036: {
        "title": "Cambio de estado en un servicio de Windows",
        "level": "INFO",
        "explanation": "Un servicio interno de Windows pasó a estado iniciado o detenido normalmente.",
        "standard": "ISO 27002 A.8.15",
    },
    6005: {
        "title": "Encendido del registro de eventos (Inicio del PC)",
        "level": "INFO",
        "explanation": "El sistema operativo arrancó e inició la vigilancia de eventos correctamente.",
        "standard": "CIS Control 8",
    },
    6006: {
        "title": "Apagado limpio del sistema",
        "level": "INFO",
        "explanation": "El equipo se apagó o reinició de forma normal.",
        "standard": "CIS Control 8",
    },
    6008: {
        "title": "Apagado inesperado del sistema",
        "level": "MEDIUM",
        "explanation": "El computador se apagó de golpe anteriormente (corte de energía, bloqueo o reinicio forzado).",
        "standard": "ISO 27002 A.8.14 (Disponibilidad)",
    },
    10016: {
        "title": "Aviso de permisos internos DCOM",
        "level": "LOW",
        "explanation": "Una aplicación pidió acceso a un componente interno de Windows sin permiso elevado (común e inofensivo en Windows).",
        "standard": "CIS Control 4",
    },
}
