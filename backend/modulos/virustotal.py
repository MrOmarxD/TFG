import os
import requests
import base64
import hashlib
import logging
import time

logger = logging.getLogger(__name__)

def analizar_archivo_vt(nombre_archivo: str, contenido_base64: str) -> dict:
    """ Sube un archivo a VirusTotal calculando su Hash primero (Lógica original segura) """
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return {"error": True, "mensaje": "API Key de VirusTotal no configurada."}

    try:
        # 1. Decodificamos el archivo en MEMORIA
        archivo_bytes = base64.b64decode(contenido_base64)
        
        # 2. Calculamos el Hash SHA-256 (La "huella dactilar" matemática)
        sha256_hash = hashlib.sha256(archivo_bytes).hexdigest()
        logger.info(f"🔍 Hash del archivo '{nombre_archivo}': {sha256_hash}")

        headers = {
            "accept": "application/json",
            "x-apikey": api_key
        }

        # 3. Preguntamos a VirusTotal si YA CONOCE este Hash
        url_hash = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
        logger.info("Consultando reporte del archivo en VirusTotal...")
        res_hash = requests.get(url_hash, headers=headers)

        if res_hash.status_code == 200:
            # Si lo conoce, Extraemos las estadísticas exactas
            stats = res_hash.json()["data"]["attributes"]["last_analysis_stats"]
            maliciosos = stats.get("malicious", 0) + stats.get("suspicious", 0)
            total_motores = sum(stats.values())
            
            es_peligroso = maliciosos > 0
            logger.info(f"Reporte VT: {maliciosos}/{total_motores} motores lo detectan como malware.")
            
            return {
                "analizado": True,
                "es_peligroso": es_peligroso,
                "maliciosos": maliciosos,
                "total_motores": total_motores,
                "mensaje": f"{maliciosos} de {total_motores} antivirus detectan amenaza."
            }

        elif res_hash.status_code == 404:
            # 4. No lo conoce. Lo subimos a la cola de análisis directamente desde la memoria RAM
            logger.info("Archivo desconocido para VT. Procediendo a subirlo...")
            url_upload = "https://www.virustotal.com/api/v3/files"
            files = { "file": (nombre_archivo, archivo_bytes) }
            res_upload = requests.post(url_upload, headers=headers, files=files)

            if res_upload.status_code == 200:
                # Opcional: Podríamos esperar y pedir el análisis, pero para la PoC decir que está pendiente es válido
                return {
                    "analizado": False,
                    "es_peligroso": False, 
                    "mensaje": "Archivo nuevo. Subido a VirusTotal (Pendiente de análisis)."
                }
            else:
                return {"error": True, "mensaje": f"Fallo al subir: {res_upload.status_code}"}
        else:
            return {"error": True, "mensaje": f"Error API VT: {res_hash.status_code}"}

    except Exception as e:
        logger.error(f"Error analizando archivo en VT: {e}")
        return {"error": True, "mensaje": str(e)}

def analizar_url_vt(url: str) -> dict:
    """ Envía una URL a VirusTotal usando el formato correcto x-www-form-urlencoded """
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return {"error": True, "mensaje": "API Key de VirusTotal no configurada."}

    headers = {
        "x-apikey": api_key,
        "Content-Type": "application/x-www-form-urlencoded"
    }
    
    try:
        # 1. Enviar la URL a escanear
        payload = {"url": url}
        scan_res = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=payload)
        
        if scan_res.status_code == 200:
            analysis_id = scan_res.json()["data"]["id"]
            
            # Esperamos 3 segundos a que VT procese el enlace
            time.sleep(3)
            
            # 2. Consultar el ID del análisis
            headers_get = {"x-apikey": api_key}
            report_res = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers_get)
            
            if report_res.status_code == 200:
                stats = report_res.json()["data"]["attributes"]["stats"]
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
            return {"url": url, "error": True, "mensaje": "No se pudo recuperar el informe de la URL."}
            
        elif scan_res.status_code == 429:
             return {"url": url, "error": True, "mensaje": "Límite de API excedido."}
        else:
            return {"url": url, "error": True, "mensaje": f"Error HTTP {scan_res.status_code} al enviar URL"}
            
    except Exception as e:
        logger.error(f"Error analizando URL en VT: {e}")
        return {"url": url, "error": True, "mensaje": str(e)}