import os
import base64
import requests
import logging

logger = logging.getLogger(__name__)

def analizar_archivo_vt(nombre_archivo: str, contenido_base64: str) -> dict:
    """
    Envía un archivo decodificado a la API de VirusTotal para su análisis.
    """
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key or api_key == "tu_clave_aqui_mas_adelante":
        logger.error("No se ha configurado la API Key de VirusTotal en el .env")
        return {"error": "API Key no configurada"}

    logger.info(f"Enviando '{nombre_archivo}' a VirusTotal...")

    # 1. Decodificamos el archivo que viene de Outlook (Base64 -> Bytes reales)
    try:
        archivo_bytes = base64.b64decode(contenido_base64)
    except Exception as e:
        logger.error(f"Error decodificando el adjunto: {e}")
        return {"error": "Archivo corrupto o mal codificado"}

    # 2. Preparamos la petición a la API v3 de VirusTotal
    url = "https://www.virustotal.com/api/v3/files"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    # Simulamos un formulario subiendo el archivo
    files = { "file": (nombre_archivo, archivo_bytes) }

    try:
        # Hacemos la petición POST a VirusTotal
        response = requests.post(url, headers=headers, files=files)
        
        if response.status_code == 200:
            data = response.json()
            # VT nos devuelve un ID de análisis. Con este ID podríamos consultar
            # el reporte detallado, pero para la PoC, devolveremos el enlace directo.
            id_analisis = data.get("data", {}).get("id", "")
            
            logger.info("Archivo recibido correctamente por VirusTotal.")
            return {
                "analizado": True,
                "mensaje": f"Archivo '{nombre_archivo}' subido a VirusTotal.",
                "id_analisis": id_analisis
            }
        else:
            logger.error(f"Error de VirusTotal HTTP {response.status_code}: {response.text}")
            return {"error": f"Fallo al contactar con VirusTotal (HTTP {response.status_code})"}

    except Exception as e:
        logger.error(f"Excepción al conectar con VirusTotal: {e}")
        return {"error": str(e)}