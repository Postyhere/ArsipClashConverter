package com.posty.clashconverter

import android.content.ClipData
import android.content.ClipboardManager
import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.MediaStore
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import java.net.URLDecoder
import java.util.Base64

class MainActivity : AppCompatActivity() {

    private lateinit var inputLinks: EditText
    private lateinit var txtResult: TextView
    private lateinit var btnConvert: Button
    private lateinit var btnClear: Button
    private lateinit var btnCopy: Button
    private lateinit var btnShare: Button
    private lateinit var btnSave: Button

    private val HEADER = """
redir-port: 9797
tproxy-port: 9898
mode: global
allow-lan: true
bind-address: '*'
log-level: silent
unified-delay: true
geodata-mode: true
geodata-loader: memconservative
ipv6: false
external-controller: 0.0.0.0:9090
secret: ''
external-ui: /data/adb/box/clash/dashboard
global-client-fingerprint: chrome
find-process-mode: strict
keep-alive-interval: 15
geo-auto-update: false
geo-update-interval: 24
tcp-concurrent: true

tun:
  enable: false
  mtu: 9000
  device: clash
  stack: mixed
  dns-hijack:
    - any:53
    - tcp://any:53
  auto-route: true
  strict-route: false
  auto-redirect: true
  auto-detect-interface: true

profile:
  store-selected: true
  store-fake-ip: false

geox-url:
  geoip: https://github.com/MetaCubeX/meta-rules-dat/raw/release/geoip-lite.dat
  mmdb: https://github.com/MetaCubeX/meta-rules-dat/raw/release/country-lite.mmdb
  geosite: https://github.com/MetaCubeX/meta-rules-dat/raw/release/geosite.dat

sniffer:
  enable: true
  force-dns-mapping: false
  parse-pure-ip: false
  override-destination: false
  sniff:
    QUIC:
      ports: [443]
    TLS:
      ports: [443, 8443]
    HTTP:
      ports: [80, 8080-8880]
      override-destination: true
  sniffing: [tls, http]
  port-whitelist: [80, 443]

dns:
  cache-algorithm: arc
  enable: true
  prefer-h3: false
  ipv6: false
  ipv6-timeout: 300
  default-nameserver:
    - 8.8.8.8
    - 1.1.1.1
  listen: 0.0.0.0:1053
  use-hosts: true
  enhanced-mode: redir-host
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter:
    - '*.lan'
    - '*.ntp.*'
  nameserver:
    - 1.1.1.1#🆃🆆🅾🅿🅴🅽
    - 8.8.8.8#🆃🆆🅾🅿🅴🅽
  proxy-server-nameserver:
    - 112.215.203.246

proxies:
""".trimIndent()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        inputLinks = findViewById(R.id.inputLinks)
        txtResult  = findViewById(R.id.txtResult)
        btnConvert = findViewById(R.id.btnConvert)
        btnClear   = findViewById(R.id.btnClear)
        btnCopy    = findViewById(R.id.btnCopy)
        btnShare   = findViewById(R.id.btnShare)
        btnSave    = findViewById(R.id.btnSave)

        btnConvert.setOnClickListener { doConvert() }
        btnClear.setOnClickListener   { inputLinks.setText(""); txtResult.text = "" }
        btnCopy.setOnClickListener    { copyToClipboard(txtResult.text.toString()) }
        btnShare.setOnClickListener   { shareText(txtResult.text.toString()) }
        btnSave.setOnClickListener    { saveToDownloads(txtResult.text.toString()) }
    }

    private fun doConvert() {
        val links = extractLinks(inputLinks.text.toString())
        if (links.isEmpty()) {
            Toast.makeText(this, "Tempel link vmess/vless/trojan dulu", Toast.LENGTH_SHORT).show()
            return
        }

        val proxiesYaml = StringBuilder()
        val names = mutableListOf<String>()
        var idx = 1

        for (raw in links) {
            when {
                raw.startsWith("vmess://", true) -> {
                    val v = parseVmess(raw)
                    if (v != null) {
                        val name = (v["ps"] as? String)?.takeIf { it.isNotBlank() } ?: "VMess$idx"
                        names += name
                        proxiesYaml.append(vmessToYaml(name, v))
                        idx++
                    }
                }
                raw.startsWith("vless://", true) -> {
                    val v = parseVless(raw)
                    if (v != null) {
                        names += v.name
                        proxiesYaml.append(vlessToYaml(v))
                        idx++
                    }
                }
                raw.startsWith("trojan://", true) -> {
                    val v = parseTrojan(raw)
                    if (v != null) {
                        names += v.name
                        proxiesYaml.append(trojanToYaml(v))
                        idx++
                    }
                }
            }
        }

        if (names.isEmpty()) {
            Toast.makeText(this, "Link tidak valid", Toast.LENGTH_SHORT).show()
            return
        }

        val groupsYaml = buildGroupsYaml(names)
        val rulesYaml  = "rules:\n  - MATCH,🆃🆆🅾🅿🅴🅽\n"
        val finalYaml = buildString {
    append(HEADER.trimEnd())      // buang spasi akhir kalau ada
    append('\n')                  // pastikan newline setelah "proxies:"
    append(proxiesYaml.toString().trimStart())
    append('\n')
    append('\n')
    append(groupsYaml.trimEnd())
    append('\n')
    append(rulesYaml)
}
txtResult.text = finalYaml
    }

    // ===== Helpers =====
    private fun extractLinks(text: String): List<String> {
        val regex = Regex("(vmess://[A-Za-z0-9+/_=-]+|vless://\\S+|trojan://\\S+)", RegexOption.IGNORE_CASE)
        return regex.findAll(text).map { it.value.trim() }.distinct().toList()
    }

    private fun b64(s: String): String {
        var x = s.replace('-', '+').replace('_', '/')
        val pad = x.length % 4
        if (pad != 0) x = x.padEnd(x.length + (4 - pad), '=')
        return String(Base64.getDecoder().decode(x))
    }

    // ===== VMESS =====
    private fun parseVmess(link: String): Map<String, Any?>? {
        return try {
            val payload = link.removePrefix("vmess://")
            val json = b64(payload)
            fun j(key: String): String? {
                val r = Regex("\"$key\"\\s*:\\s*\"([^\"]*)\"")
                return r.find(json)?.groupValues?.getOrNull(1)
            }
            val add = j("add") ?: return null
            val port = j("port") ?: return null
            val id = j("id") ?: return null
            mapOf(
                "ps" to j("ps"),
                "add" to add,
                "port" to port,
                "id" to id,
                "aid" to (j("aid") ?: "0"),
                "net" to (j("net") ?: "ws"),
                "path" to (j("path") ?: "/"),
                "host" to j("host"),
                "sni"  to j("sni"),
                "tls"  to j("tls")
            )
        } catch (_: Exception) {
            null
        }
    }

    private fun vmessToYaml(name: String, v: Map<String, Any?>): String {
        val server = v["add"] as String
        val port = (v["port"] as String).toInt()
        val uuid = v["id"] as String
        val alterId = (v["aid"] as String).toIntOrNull() ?: 0
        val net = (v["net"] as? String ?: "ws").lowercase()
        val path = (v["path"] as? String ?: "/")
        val host = (v["host"] as? String)
        val sni  = (v["sni"]  as? String) ?: host
        val tls = ((v["tls"] as? String)?.lowercase() == "tls")

        return buildString {
            append("- name: ").append(name).append('\n')
            append("  type: vmess\n")
            append("  server: ").append(server).append('\n')
            append("  port: ").append(port).append('\n')
            append("  uuid: ").append(uuid).append('\n')
            append("  alterId: ").append(alterId).append('\n')
            append("  cipher: auto\n")
            append("  tls: ").append(if (tls) "true" else "false").append('\n')
            append("  skip-cert-verify: true\n")
            append("  servername: ").append(sni ?: server).append('\n')
            append("  network: ").append(net).append('\n')
            append("  udp: true\n")
            if (net == "ws") {
                append("  ws-opts:\n")
                append("    path: ").append(path).append('\n')
                append("    headers:\n")
                append("      Host: ").append(host ?: sni ?: server).append('\n')
            }
        }
    }

    // ===== VLESS =====
    data class Vless(
        val name: String, val server: String, val port: Int, val uuid: String,
        val tls: Boolean, val sni: String?, val network: String, val path: String?, val host: String?
    )

    private fun parseVless(link: String): Vless? {
        return try {
            val u = Uri.parse(link)
            val name = (u.fragment ?: "").let { URLDecoder.decode(it, "UTF-8") }
                .ifBlank { "VLESS ${u.host}:${u.port.takeIf { it != -1 } ?: 443}" }
            val type = (u.getQueryParameter("type") ?: u.getQueryParameter("network") ?: "tcp").lowercase()
            val security = (u.getQueryParameter("security") ?: "").lowercase()
            val tls = security == "tls" || security == "reality" || security == "xtls"
            val sni = u.getQueryParameter("sni") ?: u.getQueryParameter("host") ?: u.host
            val path = u.getQueryParameter("path") ?: "/"
            val host = u.getQueryParameter("host") ?: sni ?: u.host
            Vless(
                name = name,
                server = u.host ?: return null,
                port = (if (u.port != -1) u.port else 443),
                uuid = u.userInfo ?: return null,
                tls = tls,
                sni = sni,
                network = type,
                path = if (type == "ws") path else null,
                host = if (type == "ws") host else null
            )
        } catch (_: Exception) {
            null
        }
    }

    private fun vlessToYaml(v: Vless): String {
        return buildString {
            append("- name: ").append(v.name).append('\n')
            append("  type: vless\n")
            append("  server: ").append(v.server).append('\n')
            append("  port: ").append(v.port).append('\n')
            append("  uuid: ").append(v.uuid).append('\n')
            append("  udp: true\n")
            append("  tls: ").append(if (v.tls) "true" else "false").append('\n')
            append("  skip-cert-verify: true\n")
            if (v.tls && !v.sni.isNullOrBlank()) append("  servername: ").append(v.sni).append('\n')
            append("  network: ").append(v.network).append('\n')
            if (v.network == "ws" && v.path != null && v.host != null) {
                append("  ws-opts:\n")
                append("    path: ").append(v.path).append('\n')
                append("    headers:\n")
                append("      Host: ").append(v.host).append('\n')
            }
        }
    }

    // ===== TROJAN =====
    data class Trojan(
        val name: String, val server: String, val port: Int, val password: String,
        val sni: String?, val network: String, val path: String?, val host: String?
    )

    private fun parseTrojan(link: String): Trojan? {
        return try {
            val u = Uri.parse(link)
            val name = (u.fragment ?: "").let { URLDecoder.decode(it, "UTF-8") }
                .ifBlank { "TROJAN ${u.host}:${u.port.takeIf { it != -1 } ?: 443}" }
            val type = (u.getQueryParameter("type") ?: u.getQueryParameter("network") ?: "tcp").lowercase()
            val sni = u.getQueryParameter("sni") ?: u.getQueryParameter("host") ?: u.host
            val path = u.getQueryParameter("path") ?: "/"
            val host = u.getQueryParameter("host") ?: sni ?: u.host
            Trojan(
                name = name,
                server = u.host ?: return null,
                port = (if (u.port != -1) u.port else 443),
                password = u.userInfo ?: return null,
                sni = sni,
                network = type,
                path = if (type == "ws") path else null,
                host = if (type == "ws") host else null
            )
        } catch (_: Exception) {
            null
        }
    }

    private fun trojanToYaml(v: Trojan): String {
        return buildString {
            append("- name: ").append(v.name).append('\n')
            append("  type: trojan\n")
            append("  server: ").append(v.server).append('\n')
            append("  port: ").append(v.port).append('\n')
            append("  password: ").append(v.password).append('\n')
            append("  udp: true\n")
            append("  sni: ").append(v.sni ?: v.server).append('\n')
            append("  skip-cert-verify: true\n")
            append("  network: ").append(v.network).append('\n')
            if (v.network == "ws" && v.path != null && v.host != null) {
                append("  ws-opts:\n")
                append("    path: ").append(v.path).append('\n')
                append("    headers:\n")
                append("      Host: ").append(v.host).append('\n')
            }
        }
    }

    // ===== GROUP & RULES (tanpa DIRECT) =====
    private fun buildGroupsYaml(names: List<String>): String {
        return buildString {
            append("proxy-groups:\n")
            append("  - name: 🆃🆆🅾🅿🅴🅽\n")
            append("    type: select\n")
            append("    proxies:\n")
            for (n in names) append("     - ").append(n).append('\n') // 5 spasi agar mirip contoh
        }
    }

    private fun copyToClipboard(text: String) {
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText("clash.yaml", text))
        Toast.makeText(this, "Disalin ke clipboard", Toast.LENGTH_SHORT).show()
    }

    private fun shareText(text: String) {
        val it = Intent(Intent.ACTION_SEND)
        it.type = "text/plain"
        it.putExtra(Intent.EXTRA_TEXT, text)
        startActivity(Intent.createChooser(it, "Bagikan YAML"))
    }

    private fun saveToDownloads(text: String) {
        try {
            val name = "clash.yaml"
            val values = ContentValues().apply {
                put(MediaStore.Downloads.DISPLAY_NAME, name)
                put(MediaStore.Downloads.MIME_TYPE, "text/yaml")
            }
            val uri = contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
            if (uri != null) {
                contentResolver.openOutputStream(uri)?.use { it.write(text.toByteArray(Charsets.UTF_8)) }
                Toast.makeText(this, "Tersimpan di Download/$name", Toast.LENGTH_SHORT).show()
            } else {
                Toast.makeText(this, "Gagal menyimpan", Toast.LENGTH_SHORT).show()
            }
        } catch (e: Exception) {
            Toast.makeText(this, "Error simpan: ${e.message}", Toast.LENGTH_SHORT).show()
        }
    }
}