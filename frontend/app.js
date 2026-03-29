const BACKEND_URL = "https://overintense-cleo-unwaved.ngrok-free.dev/api/v1/analizar";

Office.onReady((info) => {
    if (info.host === Office.HostType.Outlook) {
        document.getElementById("btn-analizar").addEventListener("click", orquestarAnalisis);
    }
});

async function orquestarAnalisis() {
    const btn = document.getElementById("btn-analizar");
    const consola = document.getElementById("consola");
    
    btn.disabled = true;
    btn.innerHTML = '<div class="spinner"></div> Analizando...';
    consola.style.display = "block";
    consola.innerHTML = "<i>1. Leyendo correo y extrayendo cabeceras...</i>";

    try {
        const texto = await obtenerTextoAsync();
        const remitente = Office.context.mailbox.item.from.emailAddress;
        
        // OBTENER CABECERAS PARA EL SPF
        const cabeceras = await obtenerCabecerasAsync();

        // LÓGICA DE ADJUNTOS
        const adjuntosOutlook = Office.context.mailbox.item.attachments;
        const tieneAdjuntos = adjuntosOutlook.length > 0;
        let listaAdjuntosParaPython = [];

        if (tieneAdjuntos) {
            consola.innerHTML += `<br><i>2. Extrayendo ${adjuntosOutlook.length} archivo(s) adjunto(s)...</i>`;
            const primerAdjunto = adjuntosOutlook[0];
            const contenidoBase64 = await obtenerAdjuntoBase64Async(primerAdjunto.id);
            
            listaAdjuntosParaPython.push({
                nombre: primerAdjunto.name,
                contenido_base64: contenidoBase64
            });
        } else {
            consola.innerHTML += `<br><i>2. Sin archivos adjuntos para extraer...</i>`;
        }

        consola.innerHTML += "<br><i>3. Consultando Inteligencia (OSINT, SPF, VT, IA)...</i>";

        // PETICIÓN AL BACKEND
        const respuesta = await fetch(BACKEND_URL, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ 
                texto: texto,
                remitente: remitente,
                tiene_adjuntos: tieneAdjuntos,
                adjuntos: listaAdjuntosParaPython,
                cabeceras: cabeceras // Enviamos las cabeceras al servidor
            })
        });

        if (!respuesta.ok) throw new Error(`Error HTTP: ${respuesta.status}`);
        const data = await respuesta.json();
        const resultados = data.resultados;

        // LÓGICA DE COLORES DEL VEREDICTO
        let colorVeredicto = "#107C10"; // Verde por defecto (SEGURO)
        if (resultados.veredicto.includes("PHISHING") || resultados.veredicto === "MALWARE") {
            colorVeredicto = "#D83B01"; // Rojo
        } else if (resultados.veredicto === "SPAM") {
            colorVeredicto = "#FFB900"; // Naranja/Amarillo
        }
        consola.style.borderLeftColor = colorVeredicto;

        // 1. BLOQUE VISUAL OSINT
        const osint = resultados.osint;
        const getIcon = (isListed) => isListed ? "🔴" : "🟢";
        const getColor = (isListed) => isListed ? "#D83B01" : "#107C10";
        
        let htmlOSINT = `
            <div style="margin-top: 15px; margin-bottom: 10px; padding: 10px; background: #fff; border: 1px solid #ddd; border-radius: 4px;">
                <b style="font-size: 11px; color: #555;">📍 CAPA 1: OSINT (REPUTACIÓN RED)</b><br>
                <span style="color: ${getColor(osint.spamhaus)};">${getIcon(osint.spamhaus)} Spamhaus DBL</span><br>
                <span style="color: ${getColor(osint.spamcop)};">${getIcon(osint.spamcop)} SpamCop</span><br>
                <span style="color: ${getColor(osint.psbl)};">${getIcon(osint.psbl)} PSBL</span>
            </div>
        `;

        // 1.5. BLOQUE VISUAL AUTENTICACIÓN (SPF, DKIM, DMARC)
        let htmlAuth = "";
        if (resultados.spf) {
            const auth = resultados.spf;
            
            // Función para dar color y semáforo según el estado
            const getAuthStyle = (estado) => {
                if (estado === "pass" || estado === "bestguesspass") return { color: "#107C10", icon: "🟢" };
                if (estado === "fail" || estado === "permerror") return { color: "#D83B01", icon: "🔴" };
                return { color: "#FFB900", icon: "⚠️" }; // neutral, none, softfail
            };

            const spfStyle = getAuthStyle(auth.estado_spf);
            const dkimStyle = getAuthStyle(auth.estado_dkim);
            const dmarcStyle = getAuthStyle(auth.estado_dmarc);
            
            htmlAuth = `
                <div style="margin-bottom: 10px; padding: 10px; background: #fff; border: 1px solid #ddd; border-radius: 4px;">
                    <b style="font-size: 11px; color: #555;">🔐 CAPA 1.5: AUTENTICACIÓN (ANTI-SPOOFING)</b><br>
                    <table style="width: 100%; font-size: 12px; margin-top: 5px;">
                        <tr>
                            <td><b>SPF:</b></td>
                            <td style="color: ${spfStyle.color};">${spfStyle.icon} ${auth.estado_spf.toUpperCase()}</td>
                        </tr>
                        <tr>
                            <td><b>DKIM:</b></td>
                            <td style="color: ${dkimStyle.color};">${dkimStyle.icon} ${auth.estado_dkim.toUpperCase()}</td>
                        </tr>
                        <tr>
                            <td><b>DMARC:</b></td>
                            <td style="color: ${dmarcStyle.color};">${dmarcStyle.icon} ${auth.estado_dmarc.toUpperCase()}</td>
                        </tr>
                    </table>
                    <hr style="border:0; border-top:1px solid #eee; margin: 5px 0;">
                    <i style="font-size: 11px; color: #666;">${auth.detalles}</i>
                </div>
            `;
        }

        // 2. BLOQUE VISUAL VIRUSTOTAL (ARCHIVOS Y URLs)
       let htmlVT = `
            <div style="margin-bottom: 10px; padding: 10px; background: #fff; border: 1px solid #ddd; border-radius: 4px;">
                <b style="font-size: 11px; color: #555;">🦠 CAPA 2: VIRUSTOTAL (MALWARE Y URLs)</b><br>
                Sin adjuntos ni enlaces para analizar.
            </div>`;
            
        const vtData = resultados.virustotal;
        let vtDetails = "";
        let hasVtData = false;

        // Mostrar resultados de Archivos
        if (vtData.archivos && vtData.archivos.length > 0) {
            hasVtData = true;
            let vt = vtData.archivos[0]; 
            if (vt.error) {
                vtDetails += `<b>Adjunto:</b> ⚠️ Error de conexión.<br>`;
            } else if (vt.analizado) {
                let colorVT = vt.es_peligroso ? "#D83B01" : "#107C10";
                let icono = vt.es_peligroso ? "🔴" : "🟢";
                vtDetails += `<b>Adjunto:</b> <span style="color:${colorVT}; font-weight:bold;">${icono} ${vt.maliciosos}/${vt.total_motores} motores alertan malware</span><br>`;
            } else {
                vtDetails += `<b>Adjunto:</b> ⏳ ${vt.mensaje}<br>`;
            }
        }

        // Mostrar resultados de URLs
        if (vtData.urls && vtData.urls.length > 0) {
            hasVtData = true;
            vtData.urls.forEach(urlRes => {
                // Acortar la URL visualmente para que no rompa el diseño del Add-in
                let urlCortada = urlRes.url.length > 35 ? urlRes.url.substring(0, 35) + '...' : urlRes.url;
                if (urlRes.error) {
                    vtDetails += `<b style="color: #666;">Enlace:</b> ⚠️ Error al escanear (${urlCortada})<br>`;
                } else if (urlRes.analizado) {
                    let colorVT = urlRes.es_peligroso ? "#D83B01" : "#107C10";
                    let icono = urlRes.es_peligroso ? "🔴" : "🟢";
                    vtDetails += `<b style="color: #666;">Enlace:</b> <span style="color:${colorVT}; font-weight:bold;">${icono} ${urlRes.maliciosos}/${urlRes.total_motores} motores (${urlCortada})</span><br>`;
                } else {
                    vtDetails += `<b style="color: #666;">Enlace:</b> ⚪ URL no reportada antes (${urlCortada})<br>`;
                }
            });
        }

        if (hasVtData) {
            htmlVT = `
                <div style="margin-bottom: 10px; padding: 10px; background: #fff; border: 1px solid #ddd; border-radius: 4px;">
                    <b style="font-size: 11px; color: #555;">🦠 CAPA 2: VIRUSTOTAL (MALWARE Y ENLACES)</b><br>
                    ${vtDetails}
                </div>`;
        }

        // 3. BLOQUE VISUAL INTELIGENCIA ARTIFICIAL
        let htmlIA = `
            <div style="margin-bottom: 10px; padding: 10px; background: #fff; border: 1px solid #ddd; border-radius: 4px;">
                <b style="font-size: 11px; color: #555;">🧠 CAPA 3: ANÁLISIS SEMÁNTICO (IA LOCAL)</b><br>
                Error al procesar el texto.
            </div>`;

        const ia = resultados.ia;
        if (ia && !ia.error) {
            const getIaIcon = (flag) => flag ? "🔴 Sí" : "🟢 No";
            htmlIA = `
                <div style="margin-bottom: 10px; padding: 10px; background: #fff; border: 1px solid #ddd; border-radius: 4px;">
                    <b style="font-size: 11px; color: #555;">🧠 CAPA 3: ANÁLISIS SEMÁNTICO (LLAMA-3)</b><br>
                    <b>Urgencia detectada:</b> ${getIaIcon(ia.urgencia)}<br>
                    <b>Petición sensible:</b> ${getIaIcon(ia.peticion_sensible)}<br>
                    <hr style="border:0; border-top:1px solid #eee; margin: 5px 0;">
                    <b>Intención:</b> <span style="font-size: 12px;">${ia.intencion_detectada || 'N/A'}</span><br>
                    <b>Justificación:</b> <i style="font-size: 12px; color: #666;">"${ia.justificacion || 'Sin justificación'}"</i>
                </div>
            `;
        } else if (ia && ia.error) {
            htmlIA = `
                <div style="margin-bottom: 10px; padding: 10px; background: #fff; border: 1px solid #ddd; border-radius: 4px;">
                    <b style="font-size: 11px; color: #555;">🧠 CAPA 3: ANÁLISIS SEMÁNTICO</b><br>
                    <span style="color:#D83B01;">⚠️ ${ia.error}</span>
                </div>`;
        }

        // CONSTRUIR PANTALLA FINAL
        consola.innerHTML = `
            <div style="text-align: center; margin-bottom: 15px;">
                <span style="font-size: 18px; font-weight:bold; color:${colorVeredicto};">${resultados.veredicto}</span><br>
                <span style="font-size: 12px; color: #666;">Confianza: ${(resultados.confianza * 100).toFixed(0)}%</span>
            </div>
            <div style="font-size: 12px; margin-bottom: 15px; text-align: justify;">
                <b>Detalle:</b> ${resultados.detalles}
            </div>
            ${htmlOSINT}
            ${htmlAuth}
            ${htmlVT}
            ${htmlIA}
        `;

    } catch (error) {
        console.error(error);
        consola.style.borderLeftColor = "#D83B01";
        consola.innerHTML = `<b>Error Crítico:</b> <small>${error.message}</small><br><br><i>Asegúrate de que ngrok está actualizado y el backend de Python está encendido.</i>`;
    } finally {
        btn.disabled = false;
        btn.innerHTML = "Analizar Correo";
    }
}

// HELPER PARA EXTRAER CABECERAS DE OUTLOOK
function obtenerCabecerasAsync() {
    return new Promise((resolve) => {
        if (Office.context.mailbox.item.getAllInternetHeadersAsync) {
            Office.context.mailbox.item.getAllInternetHeadersAsync((result) => {
                if (result.status === Office.AsyncResultStatus.Succeeded) {
                    resolve(result.value);
                } else {
                    resolve(""); 
                }
            });
        } else {
            resolve(""); 
        }
    });
}

// Helpers originales
function obtenerTextoAsync() {
    return new Promise((resolve, reject) => {
        Office.context.mailbox.item.body.getAsync(Office.CoercionType.Text, (result) => {
            if (result.status === Office.AsyncResultStatus.Failed) reject(new Error(result.error.message));
            else resolve(result.value);
        });
    });
}

function obtenerAdjuntoBase64Async(attachmentId) {
    return new Promise((resolve, reject) => {
        Office.context.mailbox.item.getAttachmentContentAsync(attachmentId, (result) => {
            if (result.status === Office.AsyncResultStatus.Failed) {
                reject(new Error(result.error.message));
            } else {
                resolve(result.value.content);
            }
        });
    });
}