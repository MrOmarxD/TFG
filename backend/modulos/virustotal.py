import os
import requests
import base64
import logging

logger = logging.getLogger(__name__)

def analizar_archivo_vt(nombre_archivo: str, contenido_base64: str) -> dict:
    """ Sube un archivo a VirusTotal y obtiene el análisis (Tu código original) """
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return {"error": True, "mensaje": "API Key de VirusTotal no configurada."}

    headers = {"x-apikey": api_key}
    
    try:
        # 1. Subir archivo
        files = {"file": (nombre_archivo, base64.b64decode(contenido_base64))}
        upload_res = requests.post("https://www.virustotal.com/api/v3/files", headers=headers, files=files)
        
        if upload_res.status_code != 200:
            return {"error": True, "mensaje": f"Error subiendo a VT: {upload_res.status_code}"}
            
        analysis_id = upload_res.json()["data"]["id"]
        
        # 2. Obtener resultado
        report_res = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers)
        if report_res.status_code == 200:
            stats = report_res.json()["data"]["attributes"]["stats"]
            maliciosos = stats.get("malicious", 0) + stats.get("suspicious", 0)
            total = sum(stats.values())
            
            return {
                "analizado": True,
                "es_peligroso": maliciosos > 0,
                "maliciosos": maliciosos,
                "total_motores": total,
                "mensaje": "Análisis completado."
            }
        return {"error": True, "mensaje": "No se pudo recuperar el informe."}
    except Exception as e:
        logger.error(f"Error VT: {e}")
        return {"error": True, "mensaje": str(e)}

def analizar_url_vt(url: str) -> dict:
    """ Transforma la URL a Base64 y consulta su reputación en VirusTotal """
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return {"error": True, "mensaje": "API Key de VirusTotal no configurada."}

    # VirusTotal v3 requiere que la URL esté en formato base64url sin el relleno '='
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    
    headers = {"x-apikey": api_key}
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    
    try:
        response = requests.get(endpoint, headers=headers)
        if response.status_code == 200:
            stats = response.json()["data"]["attributes"]["last_analysis_stats"]
            maliciosos = stats.get("malicious", 0) + stats.get("suspicious", 0)
            total = sum(stats.values())
            
            return {
                "url": url,
                "analizado": True,
                "es_peligroso": maliciosos > 0,
                "maliciosos": maliciosos,
                "total_motores": total,
                "mensaje": "OK"
            }
        elif response.status_code == 404:
            # Significa que VT nunca ha visto esta URL antes
            return {"url": url, "analizado": False, "es_peligroso": False, "mensaje": "URL desconocida en VT."}
        elif response.status_code == 429:
             return {"url": url, "error": True, "mensaje": "Límite de API excedido."}
        else:
            return {"url": url, "error": True, "mensaje": f"Error HTTP {response.status_code}"}
    except Exception as e:
        logger.error(f"Error analizando URL en VT: {e}")
        return {"url": url, "error": True, "mensaje": str(e)}