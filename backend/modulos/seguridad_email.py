import dns.resolver
import ipaddress
import re
import logging

logger = logging.getLogger(__name__)

def obtener_registro_spf(dominio: str) -> str:
    """Busca el registro TXT de SPF en DNS."""
    try:
        respuestas = dns.resolver.resolve(dominio, 'TXT')
        for rdata in respuestas:
            texto = rdata.to_text().strip('"')
            if texto.startswith("v=spf1"):
                return texto
    except Exception as e:
        pass
    return None

def extraer_ip_origen(cabeceras: str) -> str:
    """Usa Expresiones Regulares para buscar la IP original del remitente en las cabeceras."""
    if not cabeceras:
        return None
    # Buscamos campos típicos donde Microsoft/Google dejan la IP: client-ip=1.2.3.4
    match = re.search(r'client-ip=([0-9\.]+)', cabeceras, re.IGNORECASE)
    if match:
        return match.group(1)
    return None

def validar_ip_en_spf(ip_origen: str, dominio: str, saltos_maximos=10, saltos_actuales=0) -> bool:
    """Motor recursivo de validación matemática CIDR para SPF (RFC 7208)."""
    if saltos_actuales >= saltos_maximos:
        return False

    registro = obtener_registro_spf(dominio)
    if not registro:
        return False

    mecanismos = registro.split()[1:]
    try:
        ip_obj = ipaddress.ip_address(ip_origen)
    except ValueError:
        return False

    for mec in mecanismos:
        if mec.startswith("ip4:"):
            rango_ip = mec.split("ip4:")[1]
            if "/" not in rango_ip:
                rango_ip += "/32"
            try:
                red = ipaddress.ip_network(rango_ip, strict=False)
                if ip_obj in red:
                    return True
            except ValueError:
                pass
        elif mec.startswith("include:"):
            nuevo_dominio = mec.split("include:")[1]
            if validar_ip_en_spf(ip_origen, nuevo_dominio, saltos_maximos, saltos_actuales + 1):
                return True
        elif mec == "a":
            try:
                ips_a = dns.resolver.resolve(dominio, 'A')
                for rdata in ips_a:
                    if rdata.to_text() == ip_origen:
                        return True
            except:
                pass
    return False

def analizar_spf_y_cabeceras(remitente: str, cabeceras: str) -> dict:
    """Orquestador híbrido: Valida matemáticamente y usa el veredicto de cabecera como respaldo."""
    resultado = {
        "tiene_spf": False,
        "registro_spf": "No encontrado",
        "estado_cabecera": "desconocido",
        "es_peligroso": False,
        "detalles": ""
    }
    
    if not remitente or "@" not in remitente:
        resultado["detalles"] = "Remitente inválido."
        return resultado

    dominio = remitente.split("@")[1].strip()
    registro_spf = obtener_registro_spf(dominio)
    
    if registro_spf:
        resultado["tiene_spf"] = True
        resultado["registro_spf"] = registro_spf

    # 1. Intentamos la validación matemática
    ip_origen = extraer_ip_origen(cabeceras)
    validacion_matematica = None
    
    if ip_origen and registro_spf:
        logger.info(f"Iniciando validación matemática SPF para IP: {ip_origen}")
        validacion_matematica = validar_ip_en_spf(ip_origen, dominio)

    # 2. Leemos la cabecera como respaldo
    match_spf = re.search(r'spf=(pass|fail|softfail|neutral|none)', cabeceras, re.IGNORECASE)
    estado_header = match_spf.group(1).lower() if match_spf else None

    # 3. El veredicto del juez
    if validacion_matematica is True:
        resultado["estado_cabecera"] = "pass"
        resultado["detalles"] = f"Validación Matemática (CIDR): PASS. La IP {ip_origen} pertenece al servidor autorizado."
    elif validacion_matematica is False and estado_header not in ["pass"]:
        # Solo marcamos fail matemático si la cabecera tampoco dice lo contrario (evita falsos positivos con IPs internas complejas)
        resultado["es_peligroso"] = True
        resultado["estado_cabecera"] = "fail"
        resultado["detalles"] = f"SPOOFING: La IP {ip_origen} no superó la validación recursiva del SPF."
    else:
        # Fallback a la cabecera
        if estado_header:
            resultado["estado_cabecera"] = estado_header
            if estado_header == "pass":
                resultado["detalles"] = "El remitente está autorizado por el servidor de correo."
            elif estado_header in ["fail", "softfail"]:
                resultado["es_peligroso"] = True
                resultado["detalles"] = f"ALERTA DE SPOOFING: El SPF falló según las cabeceras ({estado_header})."
            else:
                resultado["detalles"] = f"El SPF no es concluyente ({estado_header})."
        else:
            resultado["detalles"] = "No se encontraron datos suficientes en la cabecera para validar la IP."

    if not resultado["tiene_spf"]:
        resultado["detalles"] = "El dominio no tiene políticas SPF. Alto riesgo de suplantación."

    return resultado