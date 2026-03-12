import os
import base64
import requests
import hashlib
import logging

logger = logging.getLogger(__name__)

def analizar_archivo_vt(nombre_archivo: str, contenido_base64: str) -> dict:
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key or api_key == "tu_clave_aqui_mas_adelante":
        return {"error": "API Key no configurada", "es_peligroso": False}

    try:
        # 1. Decodificamos el archivo
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
            data = res_hash.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            
            maliciosos = stats.get("malicious", 0)
            sospechosos = stats.get("suspicious", 0)
            inofensivos = stats.get("undetected", 0) + stats.get("harmless", 0)
            total_motores = maliciosos + sospechosos + inofensivos
            
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
            # 4. No lo conoce. Lo subimos a la cola de análisis
            logger.info("Archivo desconocido para VT. Procediendo a subirlo...")
            url_upload = "https://www.virustotal.com/api/v3/files"
            files = { "file": (nombre_archivo, archivo_bytes) }
            res_upload = requests.post(url_upload, headers=headers, files=files)

            if res_upload.status_code == 200:
                return {
                    "analizado": False,
                    "es_peligroso": False, # Aún no lo sabemos
                    "mensaje": "Archivo nuevo. Subido a VirusTotal (Pendiente de análisis)."
                }
            else:
                return {"error": f"Fallo al subir: {res_upload.status_code}", "es_peligroso": False}
        else:
            return {"error": f"Error API VT: {res_hash.status_code}", "es_peligroso": False}

    except Exception as e:
        logger.error(f"Excepción en VT: {e}")
        return {"error": str(e), "es_peligroso": False}