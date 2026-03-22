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

        // 1.5. BLOQUE VISUAL SPF
        let htmlSPF = "";
        if (resultados.spf) {
            const spf = resultados.spf;
            let colorSpf = spf.es_peligroso ? "#D83B01" : (spf.estado_cabecera === "pass" ? "#107C10" : "#FFB900");
            let iconoSpf = spf.es_peligroso ? "🔴" : (spf.estado_cabecera === "pass" ? "🟢" : "⚠️");
            
            htmlSPF = `
                <div style="margin-bottom: 10px; padding: 10px; background: #fff; border: 1px solid #ddd; border-radius: 4px;">
                    <b style="font-size: 11px; color: #555;">🔐 CAPA 1.5: AUTENTICACIÓN (SPF)</b><br>
                    <b>Estado:</b> <span style="color: ${colorSpf};">${iconoSpf} ${spf.estado_cabecera.toUpperCase()}</span><br>
                    <i style="font-size: 11px; color: #666;">${spf.detalles}</i>
                </div>
            `;
        }

        // 2. BLOQUE VISUAL VIRUSTOTAL
        let htmlVT = `
            <div style="margin-bottom: 10px; padding: 10px; background: #fff; border: 1px solid #ddd; border-radius: 4px;">
                <b style="font-size: 11px; color: #555;">🦠 CAPA 2: VIRUSTOTAL (MALWARE)</b><br>
                Sin adjuntos para analizar.
            </div>`;
            
        if (resultados.virustotal && resultados.virustotal.length > 0) {
            let vt = resultados.virustotal[0]; 
            if (vt.error) {
                htmlVT = `<div style="margin-bottom: 10px; padding: 10px; background: #fff; border: 1px solid #ddd; border-radius: 4px;"><b style="font-size: 11px; color: #555;">🦠 CAPA 2: VIRUSTOTAL</b><br>⚠️ Error de conexión.</div>`;
            } else if (vt.analizado) {
                let colorVT = vt.es_peligroso ? "#D83B01" : "#107C10";
                let icono = vt.es_peligroso ? "🔴" : "🟢";
                htmlVT = `
                    <div style="margin-bottom: 10px; padding: 10px; background: #fff; border: 1px solid #ddd; border-radius: 4px;">
                        <b style="font-size: 11px; color: #555;">🦠 CAPA 2: VIRUSTOTAL (MALWARE)</b><br>
                        <span style="color:${colorVT}; font-weight:bold;">${icono} ${vt.maliciosos} / ${vt.total_motores} motores detectaron malware</span>
                    </div>`;
            } else {
                htmlVT = `<div style="margin-bottom: 10px; padding: 10px; background: #fff; border: 1px solid #ddd; border-radius: 4px;"><b style="font-size: 11px; color: #555;">🦠 CAPA 2: VIRUSTOTAL</b><br>⏳ ${vt.mensaje}</div>`;
            }
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
            ${htmlSPF}
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