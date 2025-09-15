package com.posty.clashconverter

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.util.Base64
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import org.json.JSONObject
import org.yaml.snakeyaml.DumperOptions
import org.yaml.snakeyaml.Yaml
import java.io.OutputStreamWriter

class MainActivity : AppCompatActivity() {

    private lateinit var inputLinks: EditText
    private lateinit var outputYaml: EditText

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        inputLinks = findViewById(R.id.inputLinks)
        outputYaml = findViewById(R.id.outputYaml)

        findViewById<Button>(R.id.btnConvert).setOnClickListener { doConvert() }
        findViewById<Button>(R.id.btnClear).setOnClickListener { doClear() }
        findViewById<Button>(R.id.btnSave).setOnClickListener { doSave() }
        findViewById<Button>(R.id.btnShare).setOnClickListener { doShare() }
    }

    private fun doClear() {
        inputLinks.setText("")
        outputYaml.setText("")
    }

    private fun doConvert() {
        val links = inputLinks.text.toString()
            .split("\n")
            .map { it.trim() }
            .filter { it.isNotEmpty() }

        if (links.isEmpty()) {
            Toast.makeText(this, "Masukkan link VMess/VLESS/Trojan!", Toast.LENGTH_SHORT).show()
            return
        }

        val yamlText = buildClashConfig(links)
        outputYaml.setText(yamlText)
    }

    // ==================== YAML Builder ====================
    private fun buildClashConfig(links: List<String>): String {
        val options = DumperOptions().apply {
            defaultFlowStyle = DumperOptions.FlowStyle.BLOCK
            defaultScalarStyle = DumperOptions.ScalarStyle.PLAIN
            isPrettyFlow = true
            indent = 2
        }
        val yaml = Yaml(options)

        val baseConfig = mutableMapOf<String, Any>(
            "redir-port" to 9797,
            "tproxy-port" to 9898,
            "mode" to "global",
            "allow-lan" to true,
            "bind-address" to "*",
            "log-level" to "silent",
            "unified-delay" to true,
            "geodata-mode" to true,
            "geodata-loader" to "memconservative",
            "ipv6" to false,
            "external-controller" to "0.0.0.0:9090",
            "secret" to "",
            "external-ui" to "/data/adb/box/clash/dashboard",
            "global-client-fingerprint" to "chrome",
            "find-process-mode" to "strict",
            "keep-alive-interval" to 15,
            "geo-auto-update" to false,
            "geo-update-interval" to 24,
            "tcp-concurrent" to true,
            "tun" to mapOf(
                "exclude-package" to emptyList<String>(),
                "enable" to false,
                "mtu" to 9000,
                "device" to "clash",
                "stack" to "mixed",
                "dns-hijack" to listOf("any:53", "tcp://any:53"),
                "auto-route" to true,
                "strict-route" to false,
                "auto-redirect" to true,
                "auto-detect-interface" to true
            ),
            "profile" to mapOf(
                "store-selected" to true,
                "store-fake-ip" to false
            ),
            "dns" to mapOf(
                "cache-algorithm" to "arc",
                "enable" to true,
                "prefer-h3" to false,
                "ipv6" to false,
                "default-nameserver" to listOf("8.8.8.8", "1.1.1.1"),
                "listen" to "0.0.0.0:1053",
                "use-hosts" to true,
                "enhanced-mode" to "redir-host",
                "fake-ip-range" to "198.18.0.1/16",
                "fake-ip-filter" to listOf("*.lan", "*.ntp.*"),
                "nameserver" to listOf("1.1.1.1", "8.8.8.8"),
                "proxy-server-nameserver" to listOf("112.215.203.246")
            ),
            "proxies" to mutableListOf<Map<String, Any>>(),
            "proxy-groups" to listOf(
                mutableMapOf(
                    "name" to "🆃🆆🅾🅿🅴🅽",
                    "type" to "select",
                    "proxies" to mutableListOf("DIRECT")
                )
            ),
            "rules" to listOf("MATCH,🆃🆆🅾🅿🅴🅽")
        )

        val proxyList = baseConfig["proxies"] as MutableList<Map<String, Any>>
        val groupList = (baseConfig["proxy-groups"] as List<MutableMap<String, Any>>)[0]["proxies"] as MutableList<String>

        links.forEach { link ->
            val proxy: Map<String, Any>? = when {
                link.startsWith("vmess://") -> parseVmessLink(link)
                link.startsWith("vless://") -> parseVlessLink(link)
                link.startsWith("trojan://") -> parseTrojanLink(link)
                else -> null
            }
            if (proxy != null) {
                proxyList.add(proxy)
                // Amanin supaya tidak crash kalau name kosong
                val safeName = (proxy["name"] as? String)?.ifBlank { "Proxy-${groupList.size + 1}" }
                    ?: "Proxy-${groupList.size + 1}"
                groupList.add(safeName)
            }
        }

        return yaml.dump(baseConfig)
    }

    // ==================== VMESS Parser ====================
    private fun parseVmessLink(link: String): Map<String, Any>? {
        return try {
            val payload = link.removePrefix("vmess://")
            val decoded = String(Base64.decode(payload, Base64.NO_WRAP))
            val obj = JSONObject(decoded)

            val add = obj.optString("add")
            val port = obj.optInt("port", 0)
            val id   = obj.optString("id")
            if (add.isBlank() || port <= 0 || id.isBlank()) return null

            val name = obj.optString("ps").ifBlank { "VMess $add" }
            val net  = obj.optString("net", "tcp").lowercase()
            val tls  = obj.optString("tls").equals("tls", ignoreCase = true) ||
                       obj.optString("security").equals("tls", ignoreCase = true)
            val sni  = obj.optString("sni").ifBlank { obj.optString("host").ifBlank { add } }
            val path = obj.optString("path", "/")
            val hostHdr = obj.optString("host").ifBlank { sni }

            val map = mutableMapOf<String, Any>(
                "name" to name,
                "type" to "vmess",
                "server" to add,
                "port" to port,
                "uuid" to id,
                "alterId" to obj.optInt("aid", 0),
                "cipher" to "auto",
                "tls" to tls,
                "skip-cert-verify" to true,
                "udp" to true
            )
            if (net == "ws") {
                map["network"] = "ws"
                map["ws-opts"] = mapOf(
                    "path" to path,
                    "headers" to mapOf("Host" to hostHdr)
                )
            }
            if (tls) map["servername"] = sni
            map
        } catch (_: Exception) {
            null
        }
    }

    // ==================== VLESS Parser ====================
    private fun parseVlessLink(link: String): Map<String, Any>? {
        return try {
            val uri = Uri.parse(link)

            val host = uri.host ?: return null
            val port = if (uri.port > 0) uri.port else 443
            val uuid = uri.userInfo ?: ""
            val name = (uri.fragment ?: "").ifBlank { "VLESS $host" }

            val network = (uri.getQueryParameter("type") ?: uri.getQueryParameter("network") ?: "tcp").lowercase()
            val security = (uri.getQueryParameter("security") ?: "").lowercase()
            val tls = security == "tls" || security == "reality" || security == "xtls"
            val sni = (uri.getQueryParameter("sni") ?: uri.getQueryParameter("host") ?: host)
            val path = uri.getQueryParameter("path") ?: "/"
            val hostHdr = (uri.getQueryParameter("host") ?: sni)

            val map = mutableMapOf<String, Any>(
                "name" to name,
                "type" to "vless",
                "server" to host,
                "port" to port,
                "uuid" to uuid,
                "udp" to true,
                "tls" to tls,
                "skip-cert-verify" to true
            )
            if (tls) map["servername"] = sni
            if (network == "ws") {
                map["network"] = "ws"
                map["ws-opts"] = mapOf(
                    "path" to path,
                    "headers" to mapOf("Host" to hostHdr)
                )
            }
            map
        } catch (_: Exception) {
            null
        }
    }

    // ==================== TROJAN Parser ====================
    private fun parseTrojanLink(link: String): Map<String, Any>? {
        return try {
            val uri = Uri.parse(link)

            val host = uri.host ?: return null
            val port = if (uri.port > 0) uri.port else 443
            val passwd = uri.userInfo ?: ""
            val name = (uri.fragment ?: "").ifBlank { "Trojan $host" }

            val network = (uri.getQueryParameter("type") ?: uri.getQueryParameter("network") ?: "tcp").lowercase()
            val sni = (uri.getQueryParameter("sni") ?: uri.getQueryParameter("host") ?: host)
            val path = uri.getQueryParameter("path") ?: "/"
            val hostHdr = (uri.getQueryParameter("host") ?: sni)

            val map = mutableMapOf<String, Any>(
                "name" to name,
                "type" to "trojan",
                "server" to host,
                "port" to port,
                "password" to passwd,
                "udp" to true,
                "sni" to sni,
                "skip-cert-verify" to true
            )
            if (network == "ws") {
                map["network"] = "ws"
                map["ws-opts"] = mapOf(
                    "path" to path,
                    "headers" to mapOf("Host" to hostHdr)
                )
            }
            map
        } catch (_: Exception) {
            null
        }
    }

    // ==================== SAVE & SHARE ====================
    private fun doSave() {
        val content = outputYaml.text.toString()
        if (content.isEmpty()) {
            Toast.makeText(this, "Tidak ada YAML untuk disimpan", Toast.LENGTH_SHORT).show()
            return
        }

        val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "text/yaml"
            putExtra(Intent.EXTRA_TITLE, "clash.yaml")
        }
        startActivityForResult(intent, 1001)
    }

    private fun doShare() {
        val content = outputYaml.text.toString()
        if (content.isEmpty()) {
            Toast.makeText(this, "Tidak ada YAML untuk dishare", Toast.LENGTH_SHORT).show()
            return
        }

        val shareIntent = Intent().apply {
            action = Intent.ACTION_SEND
            putExtra(Intent.EXTRA_TEXT, content)
            type = "text/plain"
        }
        startActivity(Intent.createChooser(shareIntent, "Bagikan file YAML"))
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == 1001 && resultCode == Activity.RESULT_OK) {
            data?.data?.also { uri ->
                saveToUri(uri, outputYaml.text.toString())
            }
        }
    }

    private fun saveToUri(uri: Uri, content: String) {
        try {
            contentResolver.openOutputStream(uri)?.use { out ->
                OutputStreamWriter(out).use { writer ->
                    writer.write(content)
                }
            }
            Toast.makeText(this, "Berhasil disimpan", Toast.LENGTH_SHORT).show()
        } catch (e: Exception) {
            Toast.makeText(this, "Gagal simpan: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }
}