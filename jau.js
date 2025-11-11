const fetch = require('node-fetch');
const TelegramBot = require('node-telegram-bot-api');
const crypto = require('crypto');
const fs = require("fs");
const path = require("path");

const TOKEN = "7913953826:AAEiEzOnYRCGf3fMaQM_XmBNzke5G4ga3uE";
const API_URL = "https://geovpn.vercel.app/check?ip=";
const DEFAULT_HOST = "joss.gpj1.dpdns.org";
const QR_API_URL = "https://api.qrserver.com/v1/create-qr-code/";
const AUTHORIZED_IDS = [1467883032]; // ID Admin
const GROUP_ID = -1002042632790; // ID Grup
const GROUP_LINK = "https://t.me/auto_sc"; // Link Grup
const DISCUSSION_TOPIC_ID = 2; // ID topik Diskusi

const bot = new TelegramBot(TOKEN, { polling: true });
const ALLOWED_GROUP_ID = -1002042632790;
const ALLOWED_THREAD_ID = 1876;

const WILDCARD_MAP = {
  ava: "ava.game.naver.com",
  df: "df.game.naver.com",
  quiz: "quiz.vidio.com",
  "quiz_img.e": "img.email1.vidio.com",
  "quiz_img.em": "img.email2.vidio.com",
  "quiz_img.ema": "img.email3.vidio.com",
  quiz_int: "quiz.int.vidio.com",
  graph: "graph.instagram.com",
  investors: "investors.spotify.com",
  cache: "cache.netflix.com",
  creative: "creativeservices.netflix.com",
  support: "support.zoom.us",
  zaintest: "zaintest.vuclip.com",
  live: "live.iflix.com",
  ruangguru: "io.ruangguru.com",
  data: "data.mt",
  udemy: "www.udemy.com",
  beta: "beta.zoom.us",
  blog: "blog.webex.com",
  bakrie: "bakrie.ac.id",
  investor: "investor.fb.com",
  ads: "ads.ruangguru.com",
  mssdk24: "mssdk24-normal-useast2a.tiktokv.com",
  api: "api.midtrans.com"
};

const WILDCARD_OPTIONS = Object.entries(WILDCARD_MAP).map(([value, text]) => ({ text, value }));

let tempData = {};

async function fetchIPData(ip, port) {
  try {
    const response = await fetch(`${API_URL}${encodeURIComponent(ip)}:${encodeURIComponent(port)}`);
    if (!response.ok) throw new Error("Gagal mengambil data dari API.");
    return await response.json();
  } catch (error) {
    console.error("Error fetching IP data:", error);
    return null;
  }
}

function createProtocolInlineKeyboard(ip, port) {
  return {
    inline_keyboard: [
      [
        { text: "⚡ VLESS", callback_data: `PROTOCOL|VLESS|${ip}|${port}` },
        { text: "⚡ TROJAN", callback_data: `PROTOCOL|TROJAN|${ip}|${port}` },
      ],
      [
        { text: "⚡ SHADOWSOCKS", callback_data: `PROTOCOL|SHADOWSOCKS|${ip}|${port}` }
      ]
    ],
  };
}

function createInitialWildcardInlineKeyboard(ip, port, protocol) {
  return {
    inline_keyboard: [
      [
        { text: "🚫 NO WILDCARD", callback_data: `NOWILDCARD|${protocol}|${ip}|${port}` },
        { text: "🔅 WILDCARD", callback_data: `SHOW_WILDCARD|${protocol}|${ip}|${port}` }
      ],
      [
        { text: "🔙 Kembali", callback_data: `BACK|${ip}|${port}` }
      ]
    ]
  };
}

function createWildcardOptionsInlineKeyboard(ip, port, protocol) {
  const buttons = WILDCARD_OPTIONS.map((option, index) => [
    { text: `🔅 ${index + 1}. ${option.text}`, callback_data: `WILDCARD|${protocol}|${ip}|${port}|${option.value}` },
  ]);
  
  buttons.push([{ text: "🔙 Kembali", callback_data: `BACK|${ip}|${port}` }]);

  return { inline_keyboard: buttons };
}

function generateConfig(config, protocol, wildcardKey = null) {
  if (!config || !config.ip || !config.port || !config.isp) {
    return "❌ Data tidak valid!";
  }

  function generateUUID() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
      var r = Math.random() * 16 | 0,
          v = c === 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  }

  const toBase64 = (str) => {
    const encoder = new TextEncoder();
    const data = encoder.encode(str);
    return btoa(String.fromCharCode(...new Uint8Array(data.buffer)));
  };

  const host = wildcardKey ? `${WILDCARD_MAP[wildcardKey]}.${DEFAULT_HOST}` : DEFAULT_HOST;
  const sni = host;
  const ispEncoded = encodeURIComponent(config.isp);
  const uuid = generateUUID();
  const path = encodeURIComponent(`/Free-VPN-CF-Geo-Project/${config.ip}=${config.port}`);

  let qrUrl = "";

  if (protocol === "VLESS") {
    const configString1 = `vless://${uuid}@${host}:443?encryption=none&security=tls&sni=${sni}&fp=randomized&type=ws&host=${host}&path=${path}#${ispEncoded}`;
    const configString2 = `vless://${uuid}@${host}:80?path=${path}&security=none&encryption=none&host=${host}&fp=randomized&type=ws&sni=${host}#${ispEncoded}`;

    qrUrl = `https://api.qrserver.com/v1/create-qr-code/?data=${encodeURIComponent(configString1)}&size=200x200`;

    return `
\`\`\`VLESS-TLS
${configString1}
\`\`\`\`\`\`VLESS-NTLS
${configString2}
\`\`\`
               👉 [QR Code URL](${qrUrl})
               
           🌍 [View Google Maps](https://www.google.com/maps?q=${config.latitude},${config.longitude})
           
    👨‍💻 Modded By : [GEO PROJECT](https://t.me/sampiiiiu)
  `;
  }

  if (protocol === "TROJAN") {
    const configString1 = `trojan://${uuid}@${host}:443?security=tls&sni=${sni}&fp=randomized&type=ws&host=${host}&path=${path}#${ispEncoded}`;
    const configString2 = `trojan://${uuid}@${host}:80?path=${path}&security=none&encryption=none&host=${host}&fp=randomized&type=ws&sni=${host}#${ispEncoded}`;

    qrUrl = `https://api.qrserver.com/v1/create-qr-code/?data=${encodeURIComponent(configString1)}&size=200x200`;

    return `
\`\`\`TROJAN-TLS
${configString1}
\`\`\`\`\`\`TROJAN-NTLS
${configString2}
\`\`\`
               👉 [QR Code URL](${qrUrl})
               
           🌍 [View Google Maps](https://www.google.com/maps?q=${config.latitude},${config.longitude})
           
    👨‍💻 Modded By : [GEO PROJECT](https://t.me/sampiiiiu)
  `;
  }

  if (protocol === "SHADOWSOCKS") {
    const configString1 = `ss://${toBase64(`none:${uuid}`)}@${host}:443?encryption=none&type=ws&host=${host}&path=${path}&security=tls&sni=${sni}#${ispEncoded}`;
    const configString2 = `ss://${toBase64(`none:${uuid}`)}@${host}:80?encryption=none&type=ws&host=${host}&path=${path}&security=none&sni=${sni}#${ispEncoded}`;

    qrUrl = `https://api.qrserver.com/v1/create-qr-code/?data=${encodeURIComponent(configString1)}&size=200x200`;

    return `
\`\`\`SHADOWSOCKS-TLS
${configString1}
\`\`\`\`\`\`SHADOWSOCKS-NTLS
${configString2}
\`\`\`
               👉 [QR Code URL](${qrUrl})
               
           🌍 [View Google Maps](https://www.google.com/maps?q=${config.latitude},${config.longitude})
           
    👨‍💻 Modded By : [GEO PROJECT](https://t.me/sampiiiiu)
  `;
  }

  return "❌ Unknown protocol!";
}

bot.on("message", async (msg) => {
  const chatId = msg.chat.id;
  const text = msg.text?.trim();
  const messageThreadId = msg.message_thread_id;

  // Pastikan pesan berasal dari grup yang diizinkan dan thread yang sesuai
  if (chatId !== ALLOWED_GROUP_ID || messageThreadId !== ALLOWED_THREAD_ID) {
    return;
  }

  const ipPortRegex = /^(\d{1,3}\.){3}\d{1,3}(:\d{1,5})?$/;
  if (!ipPortRegex.test(text)) {
    return;
  }
  
  const [ip, port = "443"] = text.split(":");

  if (!ip || isNaN(port) || port <= 0 || port > 65535) {
    bot.sendMessage(chatId, "⚠️ Port tidak valid. Pastikan nilainya antara 1-65535.", { 
      parse_mode: "Markdown",
      message_thread_id: msg.message_thread_id 
    });
    return;
  }

  try {
    const loadingMessage = await bot.sendMessage(chatId, "⏳", {
      message_thread_id: msg.message_thread_id 
    });

    const data = await fetchIPData(ip, port);
    if (!data) {
      bot.editMessageText("⚠️ Tidak dapat mengambil data IP.", {
        chat_id: chatId,
        message_id: loadingMessage.message_id,
        parse_mode: "Markdown",
        message_thread_id: msg.message_thread_id 
      });
      return;
    }

    tempData = { ip, port, isp: data.isp, latitude: data.latitude, longitude: data.longitude };
    const status = data.status === "ACTIVE" ? "✅ ACTIVE" : "❌ DEAD";

    if (data.status === "ACTIVE") {
      bot.editMessageText(`IP PORT : \`${data.ip}:${data.port}\`
\`\`\`INFORMATION
 ISP     : ${data.isp}
 COUNTRY : ${data.country}
 DELAY   : ${data.delay}
 STATUS  : ${status}
\`\`\`
`, { chat_id: chatId, message_id: loadingMessage.message_id, parse_mode: "Markdown", reply_markup: createProtocolInlineKeyboard(ip, port) });
    } else {
      bot.editMessageText("IP ❌ DEAD", { chat_id: chatId, message_id: loadingMessage.message_id, parse_mode: "Markdown" });
    }

    if (data.latitude && data.longitude) {
      console.log(`Latitude: ${data.latitude}, Longitude: ${data.longitude}`);
    }

  } catch (error) {
    bot.editMessageText("❌ Terjadi kesalahan saat mengambil data. Coba lagi nanti.", { chat_id: chatId, message_id: loadingMessage.message_id, parse_mode: "Markdown" });
    console.error("Error fetching IP data:", error);
  }
});

bot.on("callback_query", async (callbackQuery) => {
  const { message, data, id } = callbackQuery;
  const chatId = message.chat.id;
  const messageId = message.message_id;

  const [action, type, ip, port, wildcardKey] = data.split("|");

  if (action === "PROTOCOL") {
    bot.editMessageText("*Pilih Wildcard atau No Wildcard:*", {
      chat_id: chatId,
      message_id: messageId,
      parse_mode: "Markdown",
      message_thread_id: message.message_thread_id, 
      reply_markup: createInitialWildcardInlineKeyboard(ip, port, type),
    });

    return bot.answerCallbackQuery(id);
  }

  if (action === "SHOW_WILDCARD") {
    bot.editMessageText("*Pilih salah satu wildcard:*", {
      chat_id: chatId,
      message_id: messageId,
      parse_mode: "Markdown",
      message_thread_id: message.message_thread_id,
      reply_markup: createWildcardOptionsInlineKeyboard(ip, port, type),
    });

    return bot.answerCallbackQuery(id);
  }

  if (action === "WILDCARD" || action === "NOWILDCARD") {
    const apiData = tempData;

    if (apiData && apiData.ip && apiData.port && apiData.isp) {
      const responseText = action === "NOWILDCARD"
        ? generateConfig(apiData, type) 
        : generateConfig(apiData, type, wildcardKey);

      bot.editMessageText(responseText, {
        chat_id: chatId,
        message_id: messageId,
        parse_mode: "Markdown",
        message_thread_id: message.message_thread_id,
        reply_markup: {
          inline_keyboard: [
            [{ text: "🔙 Kembali", callback_data: `BACK|${ip}|${port}` }]
          ]
        }
      });

      return bot.answerCallbackQuery(id);
    } else {
      return bot.answerCallbackQuery(id, { text: "❌ Data tidak valid!", show_alert: true });
    }
  }

  if (action === "BACK") {
    bot.editMessageText("⚙️ Pilih salah satu protokol", {
      chat_id: chatId,
      message_id: messageId,
      parse_mode: "Markdown",
      message_thread_id: message.message_thread_id,
      reply_markup: createProtocolInlineKeyboard(ip, port),
    });

    return bot.answerCallbackQuery(id);
  }
});

bot.onText(/findproxy/, async (msg) => {
    const chatId = msg.chat.id;
    const messageThreadId = msg.message_thread_id; // Pastikan pesan dikirim di thread yang benar jika dalam grup

    const message = `
══════════════════
🏷️ *TUTORIAL CARI PROXY* 🏷️
══════════════════
📌 **FOFA (fofa.info)**  
🔗 Situs: [en.fofa.info](https://en.fofa.info)  
🔍 Kueri pencarian:  
\`\`\`query
server=="cloudflare" && is_domain=false && banner="Content-Length: 155" && protocol="http" && org!="CLOUDFLARENET" && country="ID" && asn!="59134"
\`\`\`
💡 **Catatan:**  
- Ubah \`asn="63949"\` untuk ISP tertentu  
- Ubah \`country="ID"\` ke kode negara lain  
- Tambahkan filter port: \`&& port="443"\`

══════════════════
📌 **HUNTER.HOW**  
🔗 Situs: [hunter.how](https://hunter.how)  
🔍 Kueri pencarian:  
\`\`\`query
as.org!="Cloudflare London, LLC"&&product.name="CloudFlare"&&header.status_code=="400"&&protocol=="http"&&header.content_length=="655"&&ip.country=="ID"
\`\`\`
💡 **Catatan:**  
- Tambah \`&&as.number="59134"\` untuk filter ASN  
- Tambah \`&&ip.port="443"\` untuk fokus ke port 443  
- Ubah negara dengan \`ip.country="SG"\`  

══════════════════
📌 **SHODAN.IO**  
🔗 Situs: [shodan.io](https://shodan.io)  
🔍 Kueri pencarian:  
\`\`\`query
product:"Cloudflare" country:"ID"
\`\`\`
💡 **Catatan:**  
- Filter port: \`port:443\`  
- Filter provider: \`org:"Akamai"\`  

══════════════════
📌 **ZOOMEYE.HK**  
🔗 Situs: [zoomeye.hk](https://zoomeye.hk)  
🔍 Kueri pencarian:  
\`\`\`query
+app:"Cloudflare" +service:"http" +title:"400 The plain HTTP request was sent to HTTPS port" +country:"Singapore"
\`\`\`
💡 **Catatan:**  
- Tambah \`+asn:59134\` untuk filter ASN  
- Spesifikkan port dengan \`+port:"443"\`  
- Ubah negara dengan \`+country:"Indonesia"\`  

══════════════════
📌 **BINARYEDGE.IO**  
🔗 Situs: [app.binaryedge.io](https://app.binaryedge.io)  
🔍 Kueri pencarian:  
\`\`\`query
country:ID title:"400 The plain HTTP request was sent to HTTPS port" product:nginx protocol:"tcp" name:http banner:"Server: cloudflare" banner:"CF-RAY: -" NOT asn:209242
\`\`\`
💡 **Catatan:**  
- Hapus \`NOT\` untuk mencari ASN tertentu (\`asn:59134\`)  
- Tambah filter port dengan \`port:443\`  
- Filter provider: \`as_name:Digitalocean\`  

══════════════════
📌 **CENSYS.IO**  
🔗 Situs: [search.censys.io](https://search.censys.io)  
🔍 Kueri pencarian dasar:  
\`\`\`query
not autonomous_system.name: "CLOUDFLARE*" and services: (software.product: "CloudFlare Load Balancer" and http.response.html_title: "400 The plain HTTP request was sent to HTTPS port") and location.country: "Indonesia"
\`\`\`
💡 **Catatan:**  
- Tambahkan filter port dengan \`and services.port=443\`  
- Filter provider: \`autonomous_system.name: "nama_provider"\`  

══════════════════
🔎 Untuk mengecek status proxy, kirim hasil pencarian langsung ke bot ini.  

👨‍💻 *Modded By:* [Geo Project](https://t.me/sampiiiiu)
`;

    try {
        await bot.sendMessage(chatId, message, { 
            parse_mode: "Markdown",
            disable_web_page_preview: true,
            ...(messageThreadId && { message_thread_id: messageThreadId }) // Pastikan ini hanya digunakan jika dalam grup
        });
    } catch (error) {
        console.error("Gagal mengirim pesan:", error);
    }
});

bot.onText(/\/listpointing/, async (msg) => {
    const chatId = msg.chat.id;

    const message = `
*🏷️ LIST WILDCARD 🏷️*
══════════════════

  • \`ava.game.naver.com.${DEFAULT_HOST}\`
  • \`df.game.naver.com.${DEFAULT_HOST}\`
  • \`quiz.vidio.com.${DEFAULT_HOST}\`
  • \`quiz.int.vidio.com.${DEFAULT_HOST}\`
  • \`graph.instagram.com.${DEFAULT_HOST}\`
  • \`investors.spotify.com.${DEFAULT_HOST}\`
  • \`cache.netflix.com.${DEFAULT_HOST}\`
  • \`creativeservices.netflix.com.${DEFAULT_HOST}\`
  • \`support.zoom.us.${DEFAULT_HOST}\`
  • \`zaintest.vuclip.com.${DEFAULT_HOST}\`
  • \`live.iflix.com.${DEFAULT_HOST}\`
  • \`io.ruangguru.com.${DEFAULT_HOST}\`
  • \`data.mt.${DEFAULT_HOST}\`
  • \`www.udemy.com.${DEFAULT_HOST}\`
  • \`beta.zoom.us.${DEFAULT_HOST}\`
  • \`investor.fb.com.${DEFAULT_HOST}\`
  • \`bakrie.ac.id.${DEFAULT_HOST}\`

👨‍💻 Modded By : [Geo Project](https://t.me/sampiiiiu)
`;

    await bot.sendMessage(chatId, message, { 
      parse_mode: "Markdown",
      message_thread_id: msg.message_thread_id // Memastikan ini ada dalam opsi
    });
});

bot.onText(/\/start/, async (msg) => {
  const chatId = msg.chat.id;
  const userId = msg.from.id;

  try {
    // Periksa apakah user adalah admin atau sudah bergabung di grup
    const isAdmin = AUTHORIZED_IDS.includes(userId);
    const member = await bot.getChatMember(GROUP_ID, userId);
    const isMember = ["member", "administrator", "creator"].includes(member.status);

    if (!isAdmin && !isMember) {
      bot.sendMessage(
        chatId,
        `❌ Anda tidak memiliki izin untuk menggunakan bot ini.\n\n🚀 Untuk mendapatkan akses, silakan bergabung ke grup berikut:\n👉 [Masuk Grup](${GROUP_LINK})`,
        { parse_mode: "Markdown", disable_web_page_preview: true }
      );
      return;
    }

    // Ambil jumlah anggota grup
    const memberCount = await bot.getChatMemberCount(GROUP_ID);

    // Pesan Welcome dengan jumlah anggota grup
    const welcomeMessage = `
━━━━━━━━━━━━━━━━━        
≡          𝗪𝗘𝗟𝗖𝗢𝗠𝗘             ≡
━━━━━━━━━━━━━━━━━
» *Name:* ${msg.from.first_name}  
» *Username:* @${msg.from.username || "Tidak Ada"}  
» *User ID:* ${userId}  
━━━━━━━━━━━━━━━━━
👤 *Informasi Member :*
👥 *Member Group :* ${memberCount} Orang
━━━━━━━━━━━━━━━━━

🔍 *Cara Penggunaan:*
1. Masukkan alamat IP dan port yang ingin Anda cek.
2. Jika tidak memasukkan port, maka default adalah *443*.
3. Tunggu beberapa detik untuk hasilnya

💡KETIK /menu UNTUK MELIHAT COMMAND

💡 *Format IP yang Diterima:*
• \`176.97.78.80\`
• \`176.97.78.80:2053\`

⚠️ *Catatan:*
- Jika status *DEAD*, maka akun *VLESS*, *SS*, dan *TROJAN* tidak akan dibuat.

👨‍💻 Modded By : [Geo Project](https://t.me/sampiiiiu)

🌐 [WEB VPN TUNNEL](https://joss.gpj1.dpdns.org)
📺 [CHANNEL VPS & Script VPS](https://t.me/testikuy_mang)
👥 [Phreaker GROUP](${GROUP_LINK})
`;

    bot.sendMessage(chatId, welcomeMessage, { 
      parse_mode: "Markdown", 
      disable_web_page_preview: true, 
      message_thread_id: msg.message_thread_id
    });

  } catch (error) {
    console.error("Error checking group membership:", error);
    bot.sendMessage(chatId, "⚠️ Terjadi kesalahan saat memverifikasi akses Anda.");
  }
});

bot.onText(/menu/, async (msg) => {
    const chatId = msg.chat.id;
    const messageThreadId = msg.message_thread_id; // ID thread dari pesan yang diterima

    // Periksa apakah pesan berasal dari grup yang benar dan thread yang benar
    if (chatId === ALLOWED_GROUP_ID && messageThreadId === ALLOWED_THREAD_ID) {
        const message = `
══════════════════
≡      MENU UTAMA BOT      ≡
══════════════════
Pilih command sesuai kebutuhan !
══════════════════
/start → mulai bot !
/randomcc → Config random sesuai tombol Flag CC
/cekpaket → Cek paket xl ! 
/listpointing → Daftar bug wildcard ! 
/traffic → Melihat data pemakaian CF! 
/randomconfig → Config random mix protocol! 
/geo → Generate config auto-rotate! 
/sublink → Buat subscription link kustom!
/converttoclash → Convert V2Ray ke format Clash! 
/tsel → Daftar paket Telkomsel injectable! 
/randomip → Mencari IP Active Random
/getrandom → Mencari IP Active sesuai input CC
══════════════════
SUPPORT
/donate → Bantu admin 😘 !
══════════════════

👨‍💻 Modded By : [Geo Project](https://t.me/sampiiiiu)
`;

        await bot.sendMessage(chatId, message, { 
            parse_mode: "Markdown",
            message_thread_id: messageThreadId // Memastikan ini ada dalam opsi
        });
    } else {
        // Kirim pesan bahwa bot hanya dapat diakses di thread yang dimaksud
        await bot.sendMessage(chatId, "hanya di group om maaf 🙏🙏🙏");
    }
});

bot.onText(/\/donate/, async (msg) => {
    const chatId = msg.chat.id;
    const messageThreadId = msg.message_thread_id; // Ambil ID thread pesan
    const imageUrl = "https://github.com/jaka1m/project/raw/main/BAYAR.jpg"; // Ganti dengan URL gambar QRIS yang benar

    try {
        await bot.sendPhoto(chatId, imageUrl, {
            caption: `
🎁 *Dukung Pengembangan Bot!* 🎁

Bantu kami terus berkembang dengan scan QRIS di atas!

Terima kasih atas dukungannya! 🙏
            `,
            parse_mode: "Markdown",
            message_thread_id: messageThreadId // Pastikan pesan tetap dalam thread yang sama
        });
    } catch (error) {
        console.error("Error mengirim gambar:", error);
        await bot.sendMessage(chatId, "⚠️ Gagal mengirim gambar donasi. Silakan coba lagi nanti.", { 
            message_thread_id: messageThreadId
        });
    }
});

const CLOUDFLARE_API_TOKEN = "D-_YPTZQ8auMOE1p_OXYM1zEVBFVcxc7Ch9YLeMi";
const CLOUDFLARE_ZONE_ID = "929ebaf98fe21fc3f53bee2a53900ebe";

// Fungsi untuk mendapatkan tanggal 10 hari terakhir
const getTenDaysAgoDate = () => {
    const date = new Date();
    date.setDate(date.getDate() - 10); // 10 hari ke belakang
    return date.toISOString().split("T")[0]; // Format YYYY-MM-DD
};

bot.onText(/\/traffic/, async (msg) => {
    const chatId = msg.chat.id;
    const messageThreadId = msg.message_thread_id; // Ambil ID thread pesan
    const tenDaysAgo = getTenDaysAgoDate(); // Ambil tanggal 10 hari terakhir

    // Periksa apakah pesan berasal dari grup dan thread yang sesuai
    if (chatId === ALLOWED_GROUP_ID && messageThreadId === ALLOWED_THREAD_ID) {
        try {
            const response = await fetch("https://api.cloudflare.com/client/v4/graphql", {
                method: "POST",
                headers: {
                    "Authorization": `Bearer ${CLOUDFLARE_API_TOKEN}`,
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    query: `query {
                        viewer {
                            zones(filter: { zoneTag: "${CLOUDFLARE_ZONE_ID}" }) {
                                httpRequests1dGroups(
                                    limit: 10, 
                                    orderBy: [date_DESC],
                                    filter: { date_geq: "${tenDaysAgo}" }
                                ) {
                                    sum {
                                        bytes
                                        requests
                                    }
                                    dimensions {
                                        date
                                    }
                                }
                            }
                        }
                    }`
                })
            });

            const result = await response.json();
            console.log(result); // Debugging

            if (!result.data || !result.data.viewer || !result.data.viewer.zones.length) {
                throw new Error("⚠️ Gagal mengambil data pemakaian.");
            }

            let usageText = "*📊 Data Pemakaian 10 Hari Terakhir:*\n\n";
            result.data.viewer.zones[0].httpRequests1dGroups.forEach(day => {
                const tanggal = day.dimensions.date;
                const totalData = (day.sum.bytes / (1024 ** 4)).toFixed(2); // Konversi ke TB
                const totalRequests = day.sum.requests.toLocaleString();

                usageText += `📅 *Tanggal:* ${tanggal}\n📦 *Total Data:* ${totalData} TB\n📊 *Total Requests:* ${totalRequests}\n\n`;
            });

            await bot.sendMessage(chatId, usageText, { 
                parse_mode: "Markdown",
                message_thread_id: messageThreadId // Pastikan menggunakan ID thread yang benar
            });

        } catch (error) {
            console.error(error); // Debugging error
            await bot.sendMessage(chatId, `⚠️ Gagal mengambil data pemakaian.\n\n_Error:_ ${error.message}`, { parse_mode: "Markdown" });
        }
    } else {
        // Jika perintah tidak berasal dari grup dan thread yang dimaksud
        await bot.sendMessage(chatId, "Perintah ini hanya bisa diakses di Grup.");
    }
});


if (/^\/config(@\w+)?$/.test(text)) {
    const targetMessageId = menuMessageIds.get(chatId) || messageId;
    const threadId = msg.message_thread_id; // Menjaga thread tetap konsisten

    await bot.sendMessage(chatId, `
🌟 ROTATE CONFIGURATION 🌟
Rotate config adalah config yang akan berganti proxy secara acak setiap menitnya.

Masukan format berikut untuk memproses bot menghasilkan rotate config:

\`rotate + query\`

Country yang tersedia:
id, sg, my, us, ca, in, gb, ir, ae, fi, tr, md, tw, ch, se, nl, es, ru, ro, pl, al, nz, mx, it, de, fr, am, cy, dk, br, kr, vn, th, hk, cn, jp.

Contoh:
\`rotate id\`
\`rotate sg\`
\`rotate my\`
`, { parse_mode: 'Markdown', message_thread_id: threadId });
});

// Menangani perintah rotate
bot.on('message', async (msg) => {
    const chatId = msg.chat.id;
    const threadId = msg.message_thread_id;
    const text = msg.text;

    if (!text.startsWith('rotate')) return;

    const args = text.split(' ');
    if (args.length < 2) {
        return await bot.sendMessage(chatId, `⚠️ *Format salah! Gunakan contoh berikut:*\n\`rotate id\``, { parse_mode: 'Markdown', message_thread_id: threadId });
    }

    const countryCode = args[1].toLowerCase();
    const validCountries = ['id', 'sg', 'my', 'us', 'ca', 'in', 'gb', 'ir', 'ae', 'fi', 'tr', 'md', 'tw', 'ch', 'se', 'nl', 'es', 'ru', 'ro', 'pl', 'al', 'nz', 'mx', 'it', 'de', 'fr', 'am', 'cy', 'dk', 'br', 'kr', 'vn', 'th', 'hk', 'cn', 'jp'];

    if (!validCountries.includes(countryCode)) {
        return await bot.sendMessage(chatId, `⚠️ *Kode negara tidak valid! Gunakan kode yang tersedia.*`, { parse_mode: 'Markdown', message_thread_id: threadId });
    }

    try {
        const response = await fetch('https://raw.githubusercontent.com/paoandest/botak/refs/heads/main/cek/proxyList.txt');
        const ipText = await response.text();
        const ipList = ipText.split('\n').map(line => line.trim()).filter(line => line !== '');

        if (ipList.length === 0) {
            return await bot.sendMessage(chatId, `⚠️ *Daftar IP kosong atau tidak ditemukan.*`, { parse_mode: 'Markdown', message_thread_id: threadId });
        }

        // Memfilter hanya IP yang sesuai dengan negara yang dipilih
        const filteredIpList = ipList.map(line => line.split(',')).filter(parts => parts.length >= 4 && parts[2].toLowerCase() === countryCode);

        if (filteredIpList.length === 0) {
            return await bot.sendMessage(chatId, `⚠️ *Tidak ada IP yang tersedia untuk negara ${countryCode.toUpperCase()}*`, { parse_mode: 'Markdown', message_thread_id: threadId });
        }

        // Memilih IP secara acak dari daftar yang sudah difilter
        const [ip, port, country, provider] = filteredIpList[Math.floor(Math.random() * filteredIpList.length)];

        const statusResponse = await fetch(`https://geovpn.vercel.app/check?ip=${encodeURIComponent(ip)}:${encodeURIComponent(port)}`);
        const ipData = await statusResponse.json();

        if (ipData.status !== "ACTIVE") {
            return await bot.sendMessage(chatId, `⚠️ *IP ${ip}:${port} tidak aktif atau tidak valid.*`, { parse_mode: 'Markdown', message_thread_id: threadId });
        }

        function getFlagEmoji(code) {
            return code
                .toUpperCase()
                .split('')
                .map(char => String.fromCodePoint(0x1F1E6 + char.charCodeAt(0) - 65))
                .join('');
        }

        const flag = getFlagEmoji(countryCode);
        const status = ipData.status === "ACTIVE" ? "✅ ACTIVE" : "❌ DEAD";
        const host = 'joss.dus.biz.id';
        const path = `/Free-VPN-CF-Geo-Project/${countryCode.toUpperCase()}`;

        function generateUUID() {
            return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
                var r = Math.random() * 16 | 0,
                    v = c === 'x' ? r : (r & 0x3 | 0x8);
                return v.toString(16);
            });
        }

        const toBase64 = (str) => Buffer.from(str).toString('base64');

        const configText = `
\`\`\`INFORMATION
IP      : ${ip}
PORT    : ${port}
ISP     : ${provider}
COUNTRY : ${countryCode.toUpperCase()} ${flag}
STATUS  : ${status}
\`\`\`
🌟 *ROTATE VLESS ${countryCode.toUpperCase()} ${flag} TLS* 🌟
\`\`\`
vless://${generateUUID()}@${host}:443?encryption=none&security=tls&sni=${host}&fp=randomized&type=ws&host=${host}&path=${path}#ROTATE%20VLESS%20${countryCode.toUpperCase()}%20${flag}%20TLS
\`\`\`
🌟 *ROTATE VLESS ${countryCode.toUpperCase()} ${flag} NTLS* 🌟
\`\`\`
vless://${generateUUID()}@${host}:80?path=${path}&security=none&encryption=none&host=${host}&fp=randomized&type=ws&sni=${host}#ROTATE%20VLESS%20${countryCode.toUpperCase()}%20${flag}%20NTLS
\`\`\`
🌟 *ROTATE TROJAN ${countryCode.toUpperCase()} ${flag} TLS* 🌟
\`\`\`
trojan://${generateUUID()}@${host}:443?encryption=none&security=tls&sni=${host}&fp=randomized&type=ws&host=${host}&path=${path}#ROTATE%20TROJAN%20${countryCode.toUpperCase()}%20${flag}%20TLS
\`\`\`
🌟 *ROTATE SS ${countryCode.toUpperCase()} ${flag} TLS* 🌟
\`\`\`
ss://${toBase64(`none:${generateUUID()}`)}@${host}:443?encryption=none&type=ws&host=${host}&path=${path}&security=tls&sni=${host}#ROTATE%20SHADOWSOCKS%20${countryCode.toUpperCase()}%20${flag}%20TLS
\`\`\`
🌟 *ROTATE SS ${countryCode.toUpperCase()} ${flag} NTLS* 🌟
\`\`\`
ss://${toBase64(`none:${generateUUID()}`)}@${host}:80?encryption=none&type=ws&host=${host}&path=${path}&security=none&sni=${host}#ROTATE%20SHADOWSOCKS%20${countryCode.toUpperCase()}%20${flag}%20NTLS
\`\`\`
👨‍💻 Developer By : [GEO PROJECT](https://t.me/sampiiiiu)
`;

        await bot.sendMessage(chatId, configText, { parse_mode: 'Markdown', message_thread_id: threadId });
    } catch (error) {
        console.error('Error:', error);
        await bot.sendMessage(chatId, `⚠️ *Terjadi kesalahan: ${error.message}*`, { parse_mode: 'Markdown', message_thread_id: threadId });
    }
});

const atob = (str) => Buffer.from(str, "base64").toString("utf-8");

bot.onText(/\/convertoclash/, async (msg) => {
    const chatId = msg.chat.id;
    const threadId = msg.message_thread_id; // Mengambil ID thread jika ada

    await bot.sendMessage(chatId, 
`📌 *Konversi ke Clash Config* 📌
Masukkan konfigurasi (maksimal 5) dengan awalan:

- \`vless://\`
- \`vmess://\`
- \`trojan://\`

Pisahkan setiap konfigurasi dengan baris baru.`, 
    { parse_mode: 'Markdown', message_thread_id: threadId });
});

bot.on("message", async (msg) => {
    const chatId = msg.chat.id;
    const threadId = msg.message_thread_id; // Ambil thread ID jika ada

    if (!msg.text) return;

    const text = msg.text.trim();
    if (text.includes("vless://") || text.includes("vmess://") || text.includes("trojan://")) {
        const configs = text.split("\n").filter(line =>
            line.startsWith("vless://") || line.startsWith("vmess://") || line.startsWith("trojan://")
        );

        if (configs.length > 5) {
            await bot.sendMessage(chatId, "❌ Maksimal hanya bisa mengonversi 5 konfigurasi dalam satu kali permintaan.", {
                message_thread_id: threadId
            });
            return;
        }

        let yamlConfigs = [];
        let invalidConfigs = [];

        for (const config of configs) {
            try {
                let type, server, port, uuid, name, tls, network, path, host;

                if (config.startsWith("vmess://")) {
                    // Dekode Base64 untuk VMESS
                    const decoded = JSON.parse(atob(config.replace("vmess://", "")));

                    type = "vmess";
                    server = decoded.add;
                    port = parseInt(decoded.port) || 443;
                    uuid = decoded.id;
                    name = decoded.ps || "Unknown";
                    tls = decoded.tls === "tls";
                    network = decoded.net;
                    path = decoded.path || "/";
                    host = decoded.host || server;
                } else {
                    // Proses VLESS & TROJAN
                    const url = new URL(config);
                    type = url.protocol.replace(":", "");
                    uuid = url.username || ""; // UUID hanya untuk VLESS & TROJAN
                    server = url.hostname; // Domain tanpa port
                    port = parseInt(url.port) || 443; // Pastikan hanya angka
                    const params = Object.fromEntries(new URLSearchParams(url.search));
                    name = decodeURIComponent(url.hash.replace("#", "")) || "Unknown";
                    tls = true;
                    network = params.type || "ws";
                    path = params.path || "/";
                    host = params.host || server;
                }

                let yamlConfig = `
- name: ${name}
  server: ${server}
  port: ${port}
  type: ${type}
  uuid: ${uuid}
  cipher: auto
  tls: ${tls}
  udp: true
  skip-cert-verify: true
  network: ${network}
  servername: ${host}
  ws-opts:
    path: ${path}
    headers:
      Host: ${host}
`;

                yamlConfigs.push(yamlConfig);
            } catch (error) {
                console.error("Error parsing config:", config, error);
                invalidConfigs.push(config);
            }
        }

        if (yamlConfigs.length > 0) {
            const yamlOutput = `Konversi ke format Clash (YAML) berhasil! 🎉\n\n\`\`\`yaml\n${yamlConfigs.join("\n")}\n\`\`\``;
            await bot.sendMessage(chatId, yamlOutput, { 
                parse_mode: "Markdown",
                message_thread_id: threadId
            });
        }

        if (invalidConfigs.length > 0) {
            await bot.sendMessage(chatId, `❌ Terjadi kesalahan saat memproses beberapa konfigurasi:\n\`${invalidConfigs.join("\n")}\``, { 
                parse_mode: "Markdown",
                message_thread_id: threadId
            });
        }
    }
});

bot.on("message", async (msg) => {
    const chatId = msg.chat.id;
    const threadId = msg.message_thread_id; // Pastikan threadId diambil jika ada

    if (!msg.text) return;

    const text = msg.text.trim();
    if (text.includes("vless://") || text.includes("vmess://") || text.includes("trojan://")) {
        const configs = text.split("\n").filter(line =>
            line.startsWith("vless://") || line.startsWith("vmess://") || line.startsWith("trojan://")
        );

        if (configs.length > 5) {
            await bot.sendMessage(chatId, "❌ Maksimal hanya bisa mengonversi 5 konfigurasi dalam satu kali permintaan.", {
                message_thread_id: threadId
            });
            return;
        }

        let yamlProxies = [];
        let proxyNames = [];
        let invalidConfigs = [];

        configs.forEach((config, index) => {
            try {
                let type, server, port, uuid, name, tls, network, path, host;

                if (config.startsWith("vmess://")) {
                    const decoded = JSON.parse(atob(config.replace("vmess://", "")));

                    type = "vmess";
                    server = decoded.add;
                    port = decoded.port;
                    uuid = decoded.id;
                    name = decoded.ps || "Unknown";
                    tls = decoded.tls === "tls";
                    network = decoded.net;
                    path = decoded.path || "/";
                    host = decoded.host || server;
                } else {
                    const url = new URL(config);
                    type = url.protocol.replace(":", "");
                    server = url.hostname;
                    uuid = url.username || url.host.split("@")[0];
                    const params = Object.fromEntries(new URLSearchParams(url.search));
                    name = decodeURIComponent(url.hash.replace("#", "")) || "Unknown";
                    tls = true;
                    network = "ws";
                    path = params.path || "/";
                    host = params.host || server;
                    port = url.port || "443";
                }

                // Tambahkan nomor urutan agar unik
                const uniqueName = `${name} ${index + 1}`;
                proxyNames.push(`    - ${uniqueName}`);

                let yamlProxy = `
  - name: ${uniqueName}
    server: ${server}
    port: ${port}
    type: ${type}
    uuid: ${uuid}
    cipher: auto
    tls: ${tls}
    udp: true
    skip-cert-verify: true
    network: ${network}
    servername: ${host}
    ws-opts:
      path: ${path}
      headers:
        Host: ${host}
`;

                yamlProxies.push(yamlProxy);
            } catch (error) {
                console.error("Error parsing config:", config, error);
                invalidConfigs.push(config);
            }
        });

        if (yamlProxies.length > 0) {
            const yamlContent = `
port: 7890
socks-port: 7891
redir-port: 7892
mixed-port: 7893
tproxy-port: 7895
mode: rule
log-level: silent
allow-lan: true
external-controller: 0.0.0.0:9090
secret: ""
bind-address: "*"
unified-delay: true
profile:
  store-selected: true

dns:
  enable: true
  ipv6: false
  enhanced-mode: redir-host
  listen: 0.0.0.0:7874
  nameserver:
    - "https://8.8.8.8/dns-query"
    - "https://8.8.4.4/dns-query"
  fallback:
    - "https://1.1.1.1/dns-query"
    - 8.8.8.8
    - 1.1.1.1
  default-nameserver:
    - 8.8.8.8
    - 1.1.1.1

rules:
  - AND,((NETWORK,UDP),(DST-PORT,123)),DIRECT
  - AND,((NETWORK,UDP),(OR,((DST-PORT,443),(GEOSITE,youtube)))),REJECT
  - GEOIP,PRIVATE,DIRECT,no-resolve
  - MATCH,Tunnel

proxy-groups:
 - name: Tunnel
   type: select
   proxies:
    - Url Test
    - Selector
   url: 'https://cp.cloudflare.com/generate_204'
   interval: 300
 - name: Url Test
   type: url-test
   url: 'https://cp.cloudflare.com/generate_204'
   interval: 300
   proxies:
${proxyNames.join("\n")}
 - name: Selector
   type: select
   url: 'https://cp.cloudflare.com/generate_204'
   interval: 300
   proxies:
${proxyNames.join("\n")}

proxies:
${yamlProxies.join("\n")}
`;

            // Tentukan path file untuk menyimpan
            const filePath = path.join(__dirname, "clash-config.yaml");

            // Simpan file YAML
            fs.writeFileSync(filePath, yamlContent);

            // Kirim file YAML ke pengguna
            await bot.sendDocument(chatId, filePath, {
                message_thread_id: threadId
            }, {
                caption: "✅ Konfigurasi berhasil dikonversi. Silakan download file YAML."
            });
        }

        if (invalidConfigs.length > 0) {
            await bot.sendMessage(chatId, `❌ Terjadi kesalahan saat memproses beberapa konfigurasi:\n\`${invalidConfigs.join("\n")}\``, {
                parse_mode: "Markdown",
                message_thread_id: threadId
            });
        }
    }
});

const fileExtensions = {
    clash: "yaml",
    singbox: "bpf",
    surfboard: "conf",
    nekobox: "json",
    husi: "json",
    v2ray: "txt",
    v2rayng: "txt"
};

const userSessions = {};

// Handle perintah /sublink
bot.onText(/\/sublink/, async (msg) => {
    const chatId = msg.chat.id;
    const threadId = msg.message_thread_id;

    if (chatId !== ALLOWED_GROUP_ID || threadId !== ALLOWED_THREAD_ID) return;

    const keyboard = {
    inline_keyboard: [
        [{ text: "V2ray", callback_data: "v2ray" }, { text: "V2rayng", callback_data: "v2rayng" }],
        [{ text: "Clash", callback_data: "clash" }, { text: "Surfboard", callback_data: "surfboard" }],
        [{ text: "Singbox", callback_data: "singbox" }, { text: "Nekobox", callback_data: "nekobox" }],
        [{ text: "Husi", callback_data: "husi" }]
    ]
};

bot.sendMessage(chatId, "📌 *Pilih aplikasi:*", {
    parse_mode: "Markdown",
    reply_markup: keyboard,
    message_thread_id: threadId
});

    userSessions[chatId] = { step: "choose_app", threadId };
});

// Handle tombol interaktif
bot.on("callback_query", async (query) => {
    const chatId = query.message.chat.id;
    const threadId = userSessions[chatId]?.threadId;
    const data = query.data;

    if (!userSessions[chatId]) return;

    const session = userSessions[chatId];

    if (session.step === "choose_app") {
        session.aplikasi = data;

        const keyboard = {
    inline_keyboard: [
        [{ text: "VLESS", callback_data: "vless" }, { text: "Trojan", callback_data: "trojan" }],
        [{ text: "Shadowsocks", callback_data: "shadowsocks" }]
    ]
};

bot.sendMessage(chatId, "📌 *Pilih TypeConfig:*", {
    parse_mode: "Markdown",
    reply_markup: keyboard,
    message_thread_id: threadId
});

        session.step = "choose_typeconfig";

    } else if (session.step === "choose_typeconfig") {
        session.typeconfig = data;

        await bot.editMessageText("📌 *Masukkan Bug (contoh: quiz.int.vidio.com)*", {
            chat_id: chatId,
            message_id: query.message.message_id,
            parse_mode: "Markdown"
        });

        session.step = "choose_bug";

    } else if (session.step === "choose_wildcard") {
        session.wildcard = data;

        const keyboard = {
            inline_keyboard: [
                [{ text: "True", callback_data: "true" }, { text: "False", callback_data: "false" }]
            ]
        };

        await bot.editMessageText("📌 *Pilih TLS:*", {
            chat_id: chatId,
            message_id: query.message.message_id,
            parse_mode: "Markdown",
            reply_markup: keyboard
        });

        session.step = "choose_tls";

    } else if (session.step === "choose_tls") {
        session.tls = data;

        await bot.editMessageText("📌 *Masukkan kode negara (contoh: id, sg, us, random):*", {
            chat_id: chatId,
            message_id: query.message.message_id,
            parse_mode: "Markdown"
        });

        session.step = "choose_country";
    }
});

// Handle input teks untuk Bug, Country, dan Limit
bot.on("message", async (msg) => {
    const chatId = msg.chat.id;
    const threadId = msg.message_thread_id;
    const text = msg.text;

    if (chatId !== ALLOWED_GROUP_ID || threadId !== ALLOWED_THREAD_ID) return;
    if (!userSessions[chatId]) return;

    const session = userSessions[chatId];

    if (session.step === "choose_bug") {
        session.bug = text;

        const keyboard = {
            inline_keyboard: [
                [{ text: "True", callback_data: "true" }, { text: "False", callback_data: "false" }]
            ]
        };

        await bot.sendMessage(chatId, "📌 *Pilih Wildcard:*", {
            parse_mode: "Markdown",
            reply_markup: keyboard,
            message_thread_id: threadId
        });

        session.step = "choose_wildcard";

    } else if (session.step === "choose_country") {
        session.country = text.toLowerCase();

        await bot.sendMessage(chatId, "📌 *Masukkan limit konfigurasi (angka):*", {
            parse_mode: "Markdown",
            message_thread_id: threadId
        });

        session.step = "choose_limit";

    } else if (session.step === "choose_limit") {
        if (isNaN(text) || parseInt(text) <= 0) {
            return bot.sendMessage(chatId, "❌ Limit harus berupa angka positif!", { message_thread_id: threadId });
        }

        session.limit = text;

        const fileExt = fileExtensions[session.aplikasi];
        const filePath = `./${session.aplikasi}.${fileExt}`;

        const url = `https://joss.gpj1.dpdns.org/vpn/${session.aplikasi}?type=${session.typeconfig}&bug=${session.bug}&tls=${session.tls}&wildcard=${session.wildcard}&limit=${session.limit}&country=${session.country}`;

        const response = await fetch(url);
        if (!response.ok) {
            return bot.sendMessage(chatId, "❌ Gagal mengunduh file konfigurasi.", { message_thread_id: threadId });
        }

        const fileStream = fs.createWriteStream(filePath);
        await new Promise((resolve, reject) => {
            response.body.pipe(fileStream);
            response.body.on("error", reject);
            fileStream.on("finish", resolve);
        });

        await bot.sendDocument(chatId, filePath, {
            caption: `✅ Berikut file konfigurasi untuk *${session.aplikasi}*.`,
            message_thread_id: threadId
        });

        delete userSessions[chatId];
    }
});


bot.onText(/\/cekkuota/, async (msg) => {
    const chatId = msg.chat.id;
    const messageThreadId = msg.message_thread_id; // Ambil ID thread pesan

    // Pastikan hanya berjalan di grup dan thread yang diizinkan
    if (chatId !== ALLOWED_GROUP_ID || messageThreadId !== ALLOWED_THREAD_ID) {
        return;
    }

    // Meminta pengguna untuk memasukkan nomor
    await bot.sendMessage(chatId, "📌 Silakan masukkan nomor yang ingin dicek :", {
        message_thread_id: messageThreadId
    });

    // Mendengarkan input nomor berikutnya dari pengguna
    bot.once("message", async (response) => {
        const userChatId = response.chat.id;
        const userThreadId = response.message_thread_id;

        // Pastikan respon berasal dari grup dan thread yang benar
        if (userChatId !== ALLOWED_GROUP_ID || userThreadId !== ALLOWED_THREAD_ID) {
            return;
        }

        const inputText = response.text.trim();
        const numbers = inputText.split(/[\s.\n]+/).filter(num => num.match(/^0\d+$/));

        if (numbers.length === 0) {
            return bot.sendMessage(userChatId, " ", {
                message_thread_id: userThreadId
            });
        }

        // Mengirim pesan loading
        const loadingMessage = await bot.sendMessage(userChatId, `⏳ Sedang memproses ${numbers.length} nomor, harap tunggu...`, {
            message_thread_id: userThreadId
        });

        let hasilAkhir = "";
        for (const number of numbers) {
            const hasilCek = await cekkuota(number); // Pastikan fungsi cekkuota tersedia
            hasilAkhir += `\n${hasilCek}`;
        }

        try {
            // Mengedit pesan loading dengan hasil
            await bot.editMessageText(hasilAkhir, {
                chat_id: userChatId,
                message_id: loadingMessage.message_id,
                parse_mode: "Markdown",
                message_thread_id: userThreadId
            });
        } catch (error) {
            // Jika gagal edit, kirim pesan baru
            await bot.sendMessage(userChatId, hasilAkhir, {
                parse_mode: "Markdown",
                message_thread_id: userThreadId
            });
        }
    });
});

// Function untuk mengecek kuota
async function cekkuota(number) {
    try {
        const url = `https://api.khfy-store.com:8443/cek_kuota?msisdn=${number}`;
        const headers = {
            'User-Agent': 'Mozilla/5.0',
            'Accept': 'application/json'
        };

        const response = await fetch(url, { headers });
        const data = await response.json();

        if (!data.data?.data_sp) {
            return `❌ Gagal mendapatkan data untuk *${number}*.`;
        }

        const dataSp = data.data.data_sp;
        let infoPelanggan = `
📌 *Info Pelanggan:*
🔢 *Nomor:* ${number}
⌛️ *Umur Kartu:* ${dataSp.active_card?.value || '-'}
📶 *Status Simcard:* ${dataSp.status_4g?.value || '-'}
📋 *Status Dukcapil:* ${dataSp.dukcapil?.value || '-'}
⏳ *Masa Aktif:* ${dataSp.active_period?.value || '-'}
        `;

        let infoPaket = `\n📌 *Info Paket Aktif:*\n`;

        if (dataSp.quotas?.success) {
            for (const paket of dataSp.quotas.value) {
                infoPaket += `
⚡️ *Nama Paket:* ${paket.name}
📅 *Expired:* ${paket.date_end}
-----------------------------`;

                for (const detail of paket.detail_quota || []) {
                    infoPaket += `
🎁 *Benefit:* ${detail.name}
💡 *Quota:* ${detail.total_text}
⏳ *Sisa Quota:* ${detail.remaining_text}`;
                }
                infoPaket += `\n`;
            }
        } else {
            infoPaket += `\nTidak ada paket aktif.`;
        }

        return infoPelanggan + infoPaket;
    } catch (error) {
        console.error('Error:', error);
        return `❌ *Terjadi kesalahan saat memeriksa nomor ${number}.*`;
    }
}


let ipList = [];
const IP_SOURCE_URL = 'https://raw.githubusercontent.com/jaka2m/botak/refs/heads/main/cek/proxyList.txt';
const HOSTKU = 'gpj1.dpdns.org';
const SUBDOMAIN = 'joss';
const APIKU = 'https://geovpn.vercel.app/check?ip=';

// Function to fetch and update the IP list
async function fetchIPList() {
    try {
        const response = await fetch(IP_SOURCE_URL);
        if (!response.ok) throw new Error('Failed to fetch IP list');
        
        const ipText = await response.text();
        ipList = ipText.split('\n').filter(line => line.trim() !== '');
        console.log('✅ IP List updated successfully.');
    } catch (error) {
        console.error('❌ Error fetching IP list:', error);
    }
}
fetchIPList();

// Function to convert country code to flag emoji
function getFlagEmoji(code) {
    return code.toUpperCase().split('')
        .map(char => String.fromCodePoint(0x1F1E6 + char.charCodeAt(0) - 65))
        .join('');
}

// Function to generate UUID
function generateUUID() {
    return crypto.randomUUID();
}

// Function to convert text to Base64
function toBase64(str) {
    return Buffer.from(str).toString('base64');
}

bot.onText(/\/randomcc/, async (msg) => {
    const chatId = msg.chat.id;
    const messageThreadId = msg.message_thread_id; // Ambil ID thread pesan

    // Pastikan hanya berjalan di grup dan thread yang diizinkan
    if (chatId !== ALLOWED_GROUP_ID || messageThreadId !== ALLOWED_THREAD_ID) {
        return;
    }

    try {
        const response = await fetch('https://raw.githubusercontent.com/jaka2m/botak/refs/heads/main/cek/proxyList.txt');
        const ipText = await response.text();
        const ipList = ipText.split('\n').filter(line => line.trim() !== '');

        if (ipList.length === 0) {
            return bot.sendMessage(chatId, `⚠️ *Daftar IP kosong atau tidak ditemukan. Coba lagi nanti.*`, {
                message_thread_id: messageThreadId,
                parse_mode: 'Markdown'
            });
        }

        // Ambil daftar kode negara unik dari daftar IP
        const countryCodes = [...new Set(ipList.map(line => line.split(',')[2]))];

        // Buat tombol inline per 4 negara dalam satu baris
        const buttons = [];
        for (let i = 0; i < countryCodes.length; i += 4) {
            buttons.push(
                countryCodes.slice(i, i + 4).map(code => ({
                    text: getFlagEmoji(code) + ` ${code}`,
                    callback_data: `select_${code}`
                }))
            );
        }

        // Kirim pesan dengan tombol inline
        bot.sendMessage(chatId, '🌍 *Pilih negara:*', {
            reply_markup: { inline_keyboard: buttons },
            parse_mode: 'Markdown',
            message_thread_id: messageThreadId
        });

    } catch (error) {
        console.error('Error fetching IP list:', error);
        bot.sendMessage(chatId, `⚠️ *Terjadi kesalahan saat mengambil daftar IP: ${error.message}*`, {
            message_thread_id: messageThreadId,
            parse_mode: 'Markdown'
        });
    }
});

bot.on('callback_query', async (callbackQuery) => {
    const chatId = callbackQuery.message.chat.id;
    const data = callbackQuery.data;

    if (data.startsWith('select_')) {
        const countryCode = data.split('_')[1];
        const filteredIPs = ipList.filter(line => line.split(',')[2] === countryCode);

        if (filteredIPs.length === 0) {
            return bot.sendMessage(chatId, `⚠️ *Tidak ada IP tersedia untuk negara ${countryCode}.*`, {
                message_thread_id: callbackQuery.message.message_thread_id
            });
        }

        const randomProxy = filteredIPs[Math.floor(Math.random() * filteredIPs.length)];
        const [ip, port, country, provider] = randomProxy.split(',');

        try {
            const statusResponse = await fetch(`${APIKU}${ip}:${port}`);
            const ipData = await statusResponse.json();
            const status = ipData.status === "ACTIVE" ? "✅ ACTIVE" : "❌ DEAD";

            const buttons = [
                [
                    { text: '⚡VLESS', callback_data: `config_vless_${ip}_${port}_${countryCode}_${provider}` },
                    { text: '⚡TROJAN', callback_data: `config_trojan_${ip}_${port}_${countryCode}_${provider}` }
                ],
                [
                    { text: '⚡SHADOWSOCKS', callback_data: `config_ss_${ip}_${port}_${countryCode}_${provider}` }
                ]
            ];

            let messageText = `✅ *Info IP untuk ${getFlagEmoji(countryCode)} ${countryCode} :*\n` +
            `\`\`\`INFORMATION
IP      : ${ip}
PORT    : ${port}
ISP     : ${provider}
COUNTRY : ${ipData.country}
STATUS  : ${status}
\`\`\``;

            if (ipData.latitude && ipData.longitude) {
                messageText += `\n👉 🌍 [View Google Maps](https://www.google.com/maps?q=${ipData.latitude},${ipData.longitude})`;
            }

            // Kirim pesan langsung dengan informasi tanpa loading
            bot.sendMessage(chatId, messageText, {
                parse_mode: 'Markdown',
                message_thread_id: callbackQuery.message.message_thread_id,
                reply_markup: { inline_keyboard: buttons }
            });

        } catch (error) {
            console.error('❌ Error fetching IP status:', error);
            bot.sendMessage(chatId, `⚠️ *Terjadi kesalahan saat memverifikasi IP ${ip}:${port}.*`, {
                parse_mode: "Markdown",
                message_thread_id: callbackQuery.message.message_thread_id
            });
        }
    }
});

// Handle protocol selection (VLESS, TROJAN, SHADOWSOCKS)
bot.on('callback_query', async (callbackQuery) => {
    const chatId = callbackQuery.message.chat.id;
    const data = callbackQuery.data;

    if (data.startsWith('config_')) {
        const [_, type, ip, port, countryCode, provider] = data.split('_');

        const uuid = generateUUID();
        const path = encodeURIComponent(`/Free-VPN-CF-Geo-Project/${ip}=${port}`);
        const prov = encodeURIComponent(`${provider} ${getFlagEmoji(countryCode)}`);
        let configText = '';

        if (type === 'vless') {
            configText = `\`\`\`VLESS-TLS
vless://${uuid}@${SUBDOMAIN}.${HOSTKU}:443?encryption=none&security=tls&sni=${SUBDOMAIN}.${HOSTKU}&fp=randomized&type=ws&host=${SUBDOMAIN}.${HOSTKU}&path=${path}#${prov}
\`\`\`\n\`\`\`VLESS-NTLS
vless://${uuid}@${SUBDOMAIN}.${HOSTKU}:80?path=${path}&security=none&encryption=none&host=${SUBDOMAIN}.${HOSTKU}&fp=randomized&type=ws&sni=${SUBDOMAIN}.${HOSTKU}#${prov}
\`\`\``;
        } else if (type === 'trojan') {
            configText = `\`\`\`TROJAN-TLS
trojan://${uuid}@${SUBDOMAIN}.${HOSTKU}:443?encryption=none&security=tls&sni=${SUBDOMAIN}.${HOSTKU}&fp=randomized&type=ws&host=${SUBDOMAIN}.${HOSTKU}&path=${path}#${prov}
\`\`\`\n\`\`\`TROJAN-NTLS
trojan://${uuid}@${SUBDOMAIN}.${HOSTKU}:80?path=${path}&security=none&encryption=none&host=${SUBDOMAIN}.${HOSTKU}&fp=randomized&type=ws&sni=${SUBDOMAIN}.${HOSTKU}#${prov}
\`\`\``;
        } else if (type === 'ss') {
            configText = `\`\`\`SHADOWSOCKS-TLS
ss://${toBase64(`none:${uuid}`)}@${SUBDOMAIN}.${HOSTKU}:443?encryption=none&type=ws&host=${SUBDOMAIN}.${HOSTKU}&path=${path}&security=tls&sni=${SUBDOMAIN}.${HOSTKU}#${prov}
\`\`\`\n\`\`\`SHADOWSOCKS-NTLS
ss://${toBase64(`none:${uuid}`)}@${SUBDOMAIN}.${HOSTKU}:80?encryption=none&type=ws&host=${SUBDOMAIN}.${HOSTKU}&path=${path}&security=none&sni=${SUBDOMAIN}.${HOSTKU}#${prov}
\`\`\``;
        }

        bot.sendMessage(
            chatId,
`✅ *Konfigurasi ${type.toUpperCase()} untuk ${getFlagEmoji(countryCode)} ${countryCode} :*\n` +
`\`\`\`INFORMATION
IP      : ${ip}
PORT    : ${port}
ISP     : ${provider}
COUNTRY : ${countryCode} ${getFlagEmoji(countryCode)}
STATUS  : ✅ ACTIVE
\`\`\`` +
`${configText}
👨‍💻 Modded By: [GEO PROJECT](https://t.me/sampiiiiu)`,
            {
                parse_mode: 'Markdown',
                message_thread_id: callbackQuery.message.message_thread_id
            }
        );
    }
});


const ALLOW_THREAD_ID = 1876;

// Fungsi untuk mendapatkan emoji bendera dari kode negara
function getFlagEmoji(countryCode) {
    const codePoints = [...countryCode].map(c => 0x1F1E6 - 65 + c.charCodeAt());
    return String.fromCodePoint(...codePoints);
}

// Perintah /randomcc
bot.onText(/\/randomip/, async (msg) => {
    const chatId = msg.chat.id;
    const messageThreadId = msg.message_thread_id;

    if (chatId !== ALLOWED_GROUP_ID || messageThreadId !== ALLOW_THREAD_ID) {
        return;
    }

    try {
        const response = await fetch('https://raw.githubusercontent.com/jaka2m/botak/refs/heads/main/cek/proxyList.txt');
        const ipText = await response.text();
        ipList = ipText.split('\n').filter(line => line.trim() !== '');

        if (ipList.length === 0) {
            return bot.sendMessage(chatId, `⚠️ *Daftar IP kosong atau tidak ditemukan. Coba lagi nanti.*`, {
                message_thread_id: messageThreadId,
                parse_mode: 'Markdown'
            });
        }

        // Ambil daftar kode negara unik
        const countryCodes = [...new Set(ipList.map(line => line.split(',')[2]))];

        // Buat tombol inline per 4 negara dalam satu baris
        const buttons = [];
        for (let i = 0; i < countryCodes.length; i += 4) {
            buttons.push(
                countryCodes.slice(i, i + 4).map(code => ({
                    text: getFlagEmoji(code) + ` ${code}`,
                    callback_data: `select_${code}`
                }))
            );
        }

        // Kirim pesan dengan tombol negara
        bot.sendMessage(chatId, '🌍 *Pilih negara:*', {
            reply_markup: { inline_keyboard: buttons },
            parse_mode: 'Markdown',
            message_thread_id: messageThreadId
        });

    } catch (error) {
        console.error('Error fetching IP list:', error);
        bot.sendMessage(chatId, `⚠️ *Terjadi kesalahan saat mengambil daftar IP: ${error.message}*`, {
            message_thread_id: messageThreadId,
            parse_mode: 'Markdown'
        });
    }
});

// Handle klik tombol negara
bot.on('callback_query', async (callbackQuery) => {
    const chatId = callbackQuery.message.chat.id;
    const messageThreadId = callbackQuery.message.message_thread_id;
    const data = callbackQuery.data;

    if (data.startsWith('select_')) {
        const countryCode = data.split('_')[1];
        const filteredIPs = ipList.filter(line => line.split(',')[2] === countryCode);

        if (filteredIPs.length === 0) {
            return bot.sendMessage(chatId, `⚠️ *Tidak ada IP tersedia untuk negara ${countryCode}.*`, {
                message_thread_id: messageThreadId
            });
        }

        // Buat file daftar proxy
        const fileName = `proxy_${countryCode}.txt`;
        const filePath = `/tmp/${fileName}`;
        fs.writeFileSync(filePath, filteredIPs.join('\n'));

        // Kirim file proxy langsung
        bot.sendDocument(chatId, filePath, {
            caption: `📥 *Daftar proxy untuk ${getFlagEmoji(countryCode)} ${countryCode}*`,
            message_thread_id: messageThreadId,
            parse_mode: 'Markdown'
        }).then(() => {
            // Hapus file setelah dikirim
            fs.unlink(filePath, (err) => {
                if (err) console.error(`Gagal menghapus file: ${err}`);
            });
        }).catch((err) => {
            console.error(`Gagal mengirim file: ${err}`);
        });
    }
});

bot.onText(/\/randomconfig/, async (msg) => {
  const chatId = msg.chat.id;
  const messageThreadId = msg.message_thread_id; // Ambil ID thread pesan

  if (chatId === ALLOWED_GROUP_ID && messageThreadId === ALLOWED_THREAD_ID) {
    try {
      const response = await fetch('https://raw.githubusercontent.com/jaka2m/botak/refs/heads/main/cek/proxyList.txt');
      const ipText = await response.text();
      const ipList = ipText.split('\n').filter(line => line.trim() !== '');

      if (ipList.length === 0) {
        return bot.sendMessage(chatId, `⚠️ *Daftar IP kosong atau tidak ditemukan.*`, {
          parse_mode: "Markdown",
          message_thread_id: messageThreadId // Gunakan messageThreadId yang benar
        });
      }

      function generateUUID() {
        return crypto.randomUUID();
      }

      function getFlagEmoji(countryCode) {
        if (!countryCode) return '🏳'; // Jika kode negara tidak ditemukan, gunakan bendera putih
        return countryCode
          .toUpperCase()
          .split('')
          .map(char => String.fromCodePoint(0x1F1E6 + char.charCodeAt(0) - 65))
          .join('');
      }

      const randomProxy = ipList[Math.floor(Math.random() * ipList.length)];
      const [ip, port, country, provider] = randomProxy.split(',');

      if (!ip || !port || !country || !provider) {
        return bot.sendMessage(chatId, `⚠️ *Data IP tidak lengkap.*`, {
          parse_mode: "Markdown",
          message_thread_id: messageThreadId
        });
      }

      const countryFlag = getFlagEmoji(country);
      const loadingMessage = await bot.sendMessage(chatId, `🔍 Search IP ✅ ACTIVE For Vless Trojan SS : ${country.toUpperCase()} ${countryFlag}`, {
        message_thread_id: messageThreadId
      });

      const statusResponse = await fetch(`https://geovpn.vercel.app/check?ip=${encodeURIComponent(ip)}:${encodeURIComponent(port)}`);
      const ipData = await statusResponse.json();

      if (ipData.status !== "ACTIVE") {
        return bot.editMessageText(`⚠️ *IP ${ip}:${port} tidak aktif atau tidak valid.*`, {
          chat_id: chatId,
          message_id: loadingMessage.message_id,
          parse_mode: "Markdown",
          message_thread_id: messageThreadId
        });
      }

      const status = ipData.status === "ACTIVE" ? "✅ ACTIVE" : "❌ DEAD";
      const HOSTKU = 'joss.gpj1.dpdns.org';
      const path = encodeURIComponent(`/Free-VPN-CF-Geo-Project/${ip}=${port}`);
      const toBase64 = (str) => Buffer.from(str).toString('base64');

      const ipInfo = `IP PORT : \`${ip}:${port}\``;
      const infoMessage = `
\`\`\`INFORMATION
IP      : ${ipInfo}
PORT    : ${port}
ISP     : ${provider}
COUNTRY : ${country} ${countryFlag}
STATUS  : ${status}
\`\`\`
`;

      const configText = `\`\`\`VLESS-TLS
vless://${generateUUID()}@${HOSTKU}:443?encryption=none&security=tls&sni=${HOSTKU}&fp=randomized&type=ws&host=${HOSTKU}&path=${path}#${provider}%20${country}
\`\`\`\`\`\`VLESS-NTLS
vless://${generateUUID()}@${HOSTKU}:80?path=${path}&security=none&encryption=none&host=${HOSTKU}&fp=randomized&type=ws&sni=${HOSTKU}#${provider}%20${country}
\`\`\`\`\`\`TROJAN-TLS
trojan://${generateUUID()}@${HOSTKU}:443?encryption=none&security=tls&sni=${HOSTKU}&fp=randomized&type=ws&host=${HOSTKU}&path=${path}#${provider}%20${country}
\`\`\`\`\`\`TROJAN-NTLS
trojan://${generateUUID()}@${HOSTKU}:80?path=${path}&security=none&encryption=none&host=${HOSTKU}&fp=randomized&type=ws&sni=${HOSTKU}#${provider}%20${country}
\`\`\`\`\`\`SHADOWSOCKS-TLS
ss://${toBase64(`none:${generateUUID()}`)}@${HOSTKU}:443?encryption=none&type=ws&host=${HOSTKU}&path=${path}&security=tls&sni=${HOSTKU}#${provider}%20${country}
\`\`\`\`\`\`SHADOWSOCKS-NTLS
ss://${toBase64(`none:${generateUUID()}`)}@${HOSTKU}:80?encryption=none&type=ws&host=${HOSTKU}&path=${path}&security=none&sni=${HOSTKU}#${provider}%20${country}
\`\`\`
👨‍💻 Modded By : [GEO PROJECT](https://t.me/sampiiiiu)
`;

      await bot.editMessageText(ipInfo + '\n' + configText, {
        chat_id: chatId,
        message_id: loadingMessage.message_id,
        parse_mode: "Markdown",
        message_thread_id: messageThreadId
      });

    } catch (error) {
      console.error('Error fetching or processing IP list:', error);
      await bot.editMessageText(`⚠️ *Terjadi kesalahan saat mengambil data IP: ${error.message}*`, {
        chat_id: chatId,
        message_id: loadingMessage.message_id,
        parse_mode: "Markdown",
        message_thread_id: messageThreadId
      });
    }
  } else {
    await bot.sendMessage(chatId, "❌ Perintah ini hanya bisa diakses di Grup.", {
      message_thread_id: messageThreadId
    });
  }
});
