# Orquestador de Ciberseguridad para Outlook (TFG)

Este proyecto es un complemento (Add-in) para Microsoft Outlook diseñado para detectar amenazas en tiempo real. Utiliza un enfoque multicapa (Ensemble) combinando Inteligencia de Amenazas (OSINT), análisis estático de malware y Procesamiento de Lenguaje Natural (PLN) mediante un LLM ejecutado en local.

## Arquitectura de Detección (Filtro Multicapa)

La herramienta evalúa cada correo electrónico pasando por tres fases críticas:

1. **Capa OSINT (Reputación de Red):** - Extrae el dominio/IP del remitente y realiza consultas DNS inversas a **Spamhaus DBL**, **SpamCop** y **PSBL**. Detecta envíos desde servidores catalogados como emisores de Spam.
2. **Capa de Análisis de Malware:**
   - Extrae los archivos adjuntos (en Base64) y consulta la API de **VirusTotal** para evaluarlos contra más de 70 motores antivirus simultáneos.
3. **Capa Semántica (LLM Local Fine-Tuned):**
   - Utiliza un modelo **Llama-3 cuantizado (GGUF)**, entrenado específicamente (Fine-Tuning con método LoRA) para este TFG usando un dataset equilibrado de Phishing.
   - Detecta tácticas de Ingeniería Social, sentido de urgencia ("Call to Action") y peticiones de datos sensibles. Se ejecuta de manera **100% offline y privada** para proteger el contenido corporativo.

---

## Guía de Instalación y Despliegue

### 1. Clonar el repositorio
```bash
git clone <https://github.com/MrOmarxD/TFG>
cd <nombre_de_la_carpeta>