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
    consola.style.borderLeftColor = "#ccc"; // Color neutro al empezar

    // CREAMOS EL "ESQUELETO" VISUAL (Las cajas en estado de espera)
    consola.innerHTML = `
        <div id="veredicto-box" style="text-align: center; margin-bottom: 15px;">
            <span style="font-size: 16px; font-weight:bold; color: #555;">⏳ Analizando en tiempo real...</span><br>
            <span style="font-size: 12px; color: #888;">Por favor, no cierre el panel.</span>
        </div>
        <div id="box-osint" style="margin-bottom: 10px; padding: 10px; background: #fafafa; border: 1px dashed #ccc; border-radius: 4px; color: #888; font-size: 12px;">
            ⏳ <b>Capa 1:</b> Consultando reputación del remitente (OSINT)...
        </div>
        <div id="box-auth" style="margin-bottom: 10px; padding: 10px; background: #fafafa; border: 1px dashed #ccc; border-radius: 4px; color: #888; font-size: 12px;">
            ⏳ <b>Capa 1.5:</b> A la espera de OSINT para validar SPF/DKIM/DMARC...
        </div>
        <div id="box-vt" style="margin-bottom: 10px; padding: 10px; background: #fafafa; border: 1px dashed #ccc; border-radius: 4px; color: #888; font-size: 12px;">
            ⏳ <b>Capa 2:</b> A la espera de la Autenticación para escanear Malware...
        </div>
        <div id="box-ia" style="margin-bottom: 10px; padding: 10px; background: #fafafa; border: 1px dashed #ccc; border-radius: 4px; color: #888; font-size: 12px;">
            ⏳ <b>Capa 3:</b> A la espera para iniciar Análisis Semántico (Llama-3)...
        </div>
    `;

    try {
        const texto = await obtenerTextoAsync();
        const remitente = Office.context.mailbox.item.from.emailAddress;
        const cabeceras = await obtenerCabecerasAsync();

        const adjuntosOutlook = Office.context.mailbox.item.attachments;
        const tieneAdjuntos = adjuntosOutlook.length > 0;
        let listaAdjuntosParaPython = [];

        if (tieneAdjuntos) {
            const primerAdjunto = adjuntosOutlook[0];
            const contenidoBase64 = await obtenerAdjuntoBase64Async(primerAdjunto.id);
            listaAdjuntosParaPython.push({ nombre: primerAdjunto.name, contenido_base64: contenidoBase64 });
        }

        // INICIAMOS LA PETICIÓN POR STREAMING
        const respuesta = await fetch(BACKEND_URL, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ 
                texto: texto, remitente: remitente, tiene_adjuntos: tieneAdjuntos,
                adjuntos: listaAdjuntosParaPython, cabeceras: cabeceras 
            })
        });

        if (!respuesta.ok) throw new Error(`Error HTTP: ${respuesta.status}`);
        
        // LEER EL FLUJO DE DATOS (STREAM) EN TIEMPO REAL
        const reader = respuesta.body.getReader();
        const decoder = new TextDecoder("utf-8");
        let buffer = "";

        while (true) {
            const { value, done } = await reader.read();
            if (done) break;
            
            // Decodificamos el trozo de texto que acaba de llegar
            buffer += decoder.decode(value, { stream: true });
            
            // Separamos por saltos de línea (por si llegan 2 JSONs juntos muy rápido)
            let partes = buffer.split("\n");
            buffer = partes.pop(); // Guardamos el trozo incompleto para la siguiente vuelta
            
            for (let parte of partes) {
                if (parte.trim() !== "") {
                    const chunk = JSON.parse(parte);
                    pintarCapaEnVivo(chunk.capa, chunk.datos); // Actualizamos la cajita correspondiente
                }
            }
        }

    } catch (error) {
        console.error(error);
        document.getElementById("consola").style.borderLeftColor = "#D83B01";
        document.getElementById("veredicto-box").innerHTML = `<b>Error Crítico:</b> <small>${error.message}</small>`;
    } finally {
        btn.disabled = false;
        btn.innerHTML = "Analizar Correo";
    }
}

// FUNCIÓN PARA PINTAR LAS CAJAS DINÁMICAMENTE
function pintarCapaEnVivo(capa, datos) {
    if (capa === "osint") {
        document.getElementById("box-auth").innerHTML = "⏳ <b>Capa 1.5:</b> Verificando criptografía y SPF...";
        document.getElementById("box-osint").outerHTML = `
            <div style="margin-bottom: 10px; padding: 10px; background: #fff; border: 1px solid #ddd; border-radius: 4px; box-shadow: 0 2px 4px rgba(0,0,0,0.05);">
                <b style="font-size: 11px; color: #555;">📍 CAPA 1: OSINT (REPUTACIÓN RED)</b><br>
                <span style="color: ${datos.spamhaus ? '#D83B01' : '#107C10'};">${datos.spamhaus ? '🔴' : '🟢'} Spamhaus DBL</span><br>
                <span style="color: ${datos.spamcop ? '#D83B01' : '#107C10'};">${datos.spamcop ? '🔴' : '🟢'} SpamCop</span><br>
                <span style="color: ${datos.psbl ? '#D83B01' : '#107C10'};">${datos.psbl ? '🔴' : '🟢'} PSBL</span>
            </div>`;
    } 
    else if (capa === "auth") {
        document.getElementById("box-vt").innerHTML = "⏳ <b>Capa 2:</b> Subiendo adjuntos y URLs a VirusTotal...";
        const spfStyle = (datos.estado_spf === "pass") ? "🟢" : (datos.estado_spf === "fail" ? "🔴" : "⚠️");
        const dkimStyle = (datos.estado_dkim === "pass") ? "🟢" : (datos.estado_dkim === "fail" ? "🔴" : "⚠️");
        const dmarcStyle = (datos.estado_dmarc === "pass") ? "🟢" : (datos.estado_dmarc === "fail" ? "🔴" : "⚠️");
        
        document.getElementById("box-auth").outerHTML = `
            <div style="margin-bottom: 10px; padding: 10px; background: #fff; border: 1px solid #ddd; border-radius: 4px; box-shadow: 0 2px 4px rgba(0,0,0,0.05);">
                <b style="font-size: 11px; color: #555;">🔐 CAPA 1.5: AUTENTICACIÓN (ANTI-SPOOFING)</b><br>
                <b>SPF:</b> ${spfStyle} ${datos.estado_spf.toUpperCase()} | 
                <b>DKIM:</b> ${dkimStyle} ${datos.estado_dkim.toUpperCase()} | 
                <b>DMARC:</b> ${dmarcStyle} ${datos.estado_dmarc.toUpperCase()}<br>
                <i style="font-size: 11px; color: #666;">${datos.detalles}</i>
            </div>`;
    }
    else if (capa === "vt") {
        document.getElementById("box-ia").innerHTML = "⏳ <b>Capa 3:</b> Despertando a Llama-3. Analizando la semántica del texto... (Esto tomará unos segundos)";
        let vtDetails = "";
        let hasData = false;
        
        if (datos.archivos && datos.archivos.length > 0) {
            hasData = true;
            let vt = datos.archivos[0];
            vtDetails += `<b>Adjunto:</b> ${vt.error ? '⚠️ Error' : (vt.analizado ? (vt.es_peligroso ? `🔴 <span style="color:#D83B01;font-weight:bold">${vt.maliciosos}/${vt.total_motores}</span>` : `🟢 Limpio`) : `⏳ Pendiente`)}<br>`;
        }
        if (datos.urls && datos.urls.length > 0) {
            hasData = true;
            datos.urls.forEach(u => {
                let uCortada = u.url.length > 40 ? u.url.substring(0, 40) + '...' : u.url;
                vtDetails += `<div style="word-break:break-all; margin-top:4px;"><b>Enlace:</b> ${u.error ? '⚠️ Error' : (u.analizado ? (u.es_peligroso ? `🔴 <span style="color:#D83B01;font-weight:bold">${u.maliciosos}/${u.total_motores}</span>` : `🟢 Limpio`) : `⚪ Desconocido`)}<br><small style="color:#888;">${uCortada}</small></div>`;
            });
        }
        
        document.getElementById("box-vt").outerHTML = `
            <div style="margin-bottom: 10px; padding: 10px; background: #fff; border: 1px solid #ddd; border-radius: 4px; box-shadow: 0 2px 4px rgba(0,0,0,0.05);">
                <b style="font-size: 11px; color: #555;">🦠 CAPA 2: VIRUSTOTAL (MALWARE)</b><br>
                ${hasData ? vtDetails : "Sin adjuntos ni enlaces sospechosos."}
            </div>`;
    }
    else if (capa === "ia") {
        const getIaIcon = (flag) => flag ? "🔴 Sí" : "🟢 No";
        document.getElementById("box-ia").outerHTML = `
            <div style="margin-bottom: 10px; padding: 10px; background: #fff; border: 1px solid #ddd; border-radius: 4px; box-shadow: 0 2px 4px rgba(0,0,0,0.05);">
                <b style="font-size: 11px; color: #555;">🧠 CAPA 3: ANÁLISIS SEMÁNTICO (LLAMA-3)</b><br>
                ${datos.error ? `<span style="color:#D83B01;">⚠️ ${datos.error}</span>` : `
                <b>Urgencia:</b> ${getIaIcon(datos.urgencia)} | 
                <b>Datos Sensibles:</b> ${getIaIcon(datos.peticion_sensible)}<br>
                <hr style="border:0; border-top:1px solid #eee; margin: 5px 0;">
                <i style="font-size: 11px; color: #666;">"${datos.justificacion || 'N/A'}"</i>`}
            </div>`;
    }
    else if (capa === "veredicto") {
        let colorV = "#107C10"; 
        if (datos.veredicto.includes("PHISHING") || datos.veredicto === "MALWARE") colorV = "#D83B01";
        else if (datos.veredicto === "SPAM") colorV = "#FFB900";
        
        document.getElementById("consola").style.borderLeftColor = colorV;
        document.getElementById("veredicto-box").innerHTML = `
            <span style="font-size: 20px; font-weight:bold; color:${colorV};">${datos.veredicto}</span><br>
            <span style="font-size: 12px; color: #666;">Confianza: ${(datos.confianza * 100).toFixed(0)}%</span>
            <div style="font-size: 12px; margin-top: 5px; text-align: justify; padding: 5px; background: ${colorV}15; border-radius: 4px;">
                <b>Detalle:</b> ${datos.detalles}
            </div>`;
    }
    else if (capa === "error") {
        document.getElementById("veredicto-box").innerHTML = `<b>Error Interno:</b> <small>${datos}</small>`;
    }
}

// Helpers originales
function obtenerCabecerasAsync() {
    return new Promise((resolve) => {
        if (Office.context.mailbox.item.getAllInternetHeadersAsync) {
            Office.context.mailbox.item.getAllInternetHeadersAsync((result) => resolve(result.status === Office.AsyncResultStatus.Succeeded ? result.value : ""));
        } else resolve(""); 
    });
}
function obtenerTextoAsync() {
    return new Promise((resolve, reject) => {
        Office.context.mailbox.item.body.getAsync(Office.CoercionType.Text, (result) => result.status === Office.AsyncResultStatus.Failed ? reject(new Error(result.error.message)) : resolve(result.value));
    });
}
function obtenerAdjuntoBase64Async(attachmentId) {
    return new Promise((resolve, reject) => {
        Office.context.mailbox.item.getAttachmentContentAsync(attachmentId, (result) => result.status === Office.AsyncResultStatus.Failed ? reject(new Error(result.error.message)) : resolve(result.value.content));
    });
}