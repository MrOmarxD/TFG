import dns.resolver
import re
import logging

logger = logging.getLogger(__name__)

def analizar_spf_y_cabeceras(remitente: str, cabeceras: str) -> dict:
    """
    Analiza el dominio del remitente consultando su registro TXT (SPF) en DNS,
    y extrae el resultado de validación de las cabeceras del correo.
    """
    resultado = {
        "tiene_spf": False,
        "registro_spf": "No encontrado",
        "estado_cabecera": "desconocido", # pass, fail, softfail, neutral
        "es_peligroso": False,
        "detalles": ""
    }
    
    if not remitente or "@" not in remitente:
        resultado["detalles"] = "Remitente inválido."
        return resultado

    dominio = remitente.split("@")[1].strip()

    # 1. CONSULTA DNS: Buscar el registro TXT (v=spf1)
    try:
        respuestas = dns.resolver.resolve(dominio, 'TXT')
        for rdata in respuestas:
            texto_txt = rdata.to_text().strip('"')
            # Buscamos la firma estándar del SPF
            if texto_txt.startswith("v=spf1"):
                resultado["tiene_spf"] = True
                resultado["registro_spf"] = texto_txt
                break
    except Exception as e:
        logger.warning(f"No se pudo resolver el TXT de {dominio}: {e}")
        resultado["detalles"] = "Error al consultar los registros DNS del dominio."

    # 2. ANÁLISIS DE CABECERAS: Buscar el veredicto del servidor
    if cabeceras:
        # Buscamos la línea Authentication-Results que contiene "spf=..."
        match_spf = re.search(r'spf=(pass|fail|softfail|neutral|none)', cabeceras, re.IGNORECASE)
        
        if match_spf:
            estado = match_spf.group(1).lower()
            resultado["estado_cabecera"] = estado
            
            if estado == "pass":
                resultado["detalles"] = "El remitente está autorizado por el SPF del dominio."
            elif estado in ["fail", "softfail"]:
                resultado["es_peligroso"] = True
                resultado["detalles"] = f"ALERTA DE SPOOFING: El SPF falló ({estado}). La IP de origen no está autorizada."
            else:
                resultado["detalles"] = f"El SPF no es concluyente ({estado})."
        else:
            resultado["detalles"] = "No se encontró el estado del SPF en las cabeceras."
    else:
        resultado["detalles"] = "No se proporcionaron cabeceras para analizar."

    # Si el dominio ni siquiera tiene SPF configurado, es sospechoso
    if not resultado["tiene_spf"]:
        resultado["detalles"] = "El dominio no tiene políticas de seguridad SPF (Riesgo alto de suplantación)."

    logger.info(f"Análisis SPF para {dominio}: Configurado={resultado['tiene_spf']}, Cabecera={resultado['estado_cabecera']}")
    
    return resultado