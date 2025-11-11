const express = require('express');
const tls = require('tls');

const app = express();

function getFlagEmoji(countryCode) {
    if (!countryCode) return '';
    return countryCode
        .toUpperCase()
        .split('')
        .map(char => String.fromCodePoint(0x1F1E6 + char.charCodeAt(0) - 65))
        .join('');
}

// Fungsi untuk mengecek status IP
async function checkIP(input) {
    if (!input) return { error: "IP address is required" };

    let [proxy, port] = input.includes(':') ? input.split(':') : [input, 443];

    const sendRequest = (host, path, useProxy = true) => {
        return new Promise((resolve) => {
            const start = Date.now();
            const socket = tls.connect(
                {
                    host: useProxy ? proxy : host,
                    port: useProxy ? port : 443,
                    servername: host,
                    timeout: 500
                },
                () => {
                    socket.write(`GET ${path} HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n`);
                }
            );

            let responseBody = '';
            socket.on('data', (data) => (responseBody += data.toString()));
            socket.on('end', () => {
                const latency = Date.now() - start;
                resolve({ body: responseBody.split('\r\n\r\n')[1] || '', latency });
            });
            socket.on('error', () => resolve({ body: '', latency: "TIMEOUT" }));
        });
    };

    try {
        const [ipinfo, myip] = await Promise.all([
            sendRequest('myip.geo-project.workers.dev', '/'),
            sendRequest('myip.geo-project.workers.dev', '/', false),
        ]);

        let ipingfo = ipinfo.body ? JSON.parse(ipinfo.body) : {};
        const srvip = myip.body ? JSON.parse(myip.body) : {};

        return {
            proxy: proxy || null,
            ip: ipingfo.ip || null,
            status: ipingfo.ip && ipingfo.ip !== srvip.ip ? "ACTIVE" : "DEAD",
            delay: typeof ipinfo.latency === "number" ? `${ipinfo.latency} ms` : "N/A",
            countryCode: ipingfo.countryCode || null,
            country: ipingfo.countryCode ? `${ipingfo.country} ${getFlagEmoji(ipingfo.countryCode)}` : null,
            flag: ipingfo.countryCode ? getFlagEmoji(ipingfo.countryCode) : null,
            city: ipingfo.city || null,
            timezone: ipingfo.timezone || null,
            latitude: ipingfo.latitude || null,
            longitude: ipingfo.longitude || null,
            asn: ipingfo.asn || null,
            colo: ipingfo.colo || null,
            isp: ipingfo.isp || null,
            region: ipingfo.region || null,
            regionName: ipingfo.regionName || null,
            org: ipingfo.org || null,
            clientTcpRtt: ipingfo.clientTcpRtt || null,
            requestHeaderNames: ipingfo.requestHeaderNames || {},
            httpProtocol: ipingfo.httpProtocol || null,
            tlsCipher: ipingfo.tlsCipher || null,
            continent: ipingfo.continent || null,
            clientAcceptEncoding: ipingfo.clientAcceptEncoding || null,
            verifiedBotCategory: ipingfo.verifiedBotCategory || "",
            tlsClientAuth: ipingfo.tlsClientAuth || {},
            tlsClientExtensionsSha1: ipingfo.tlsClientExtensionsSha1 || null,
            tlsExportedAuthenticator: ipingfo.tlsExportedAuthenticator || {},
            tlsVersion: ipingfo.tlsVersion || null,
            requestPriority: ipingfo.requestPriority || null,
            edgeRequestKeepAliveStatus: ipingfo.edgeRequestKeepAliveStatus || null,
            tlsClientRandom: ipingfo.tlsClientRandom || null,
            postalCode: ipingfo.postalCode || null,
            regionCode: ipingfo.regionCode || null,
            asOrganization: ipingfo.asOrganization || null,
            tlsClientHelloLength: ipingfo.tlsClientHelloLength || null,
            
        };

    } catch (error) {
        console.error("Error:", error);
        return { error: error };
    }
}

app.get('/check', async (req, res) => {
    const { ip } = req.query;
    if (!ip) return res.status(400).json({ error: 'IP address is required' });

    const result = await checkIP(ip);

    // Menentukan delay palsu antara 20 - 500 ms
    const fakeDelay = Math.floor(Math.random() * (500 - 20 + 1)) + 20;

    result.delay = `${fakeDelay} ms`;

    setTimeout(() => {
        res.setHeader('Content-Type', 'application/json');
        res.send(JSON.stringify(result, null, 4));
    }, fakeDelay);
});

app.listen(8080, () => console.log('Server listening on port 8080'));
