package ru.darkprince.krot

import android.Manifest
import android.app.*
import android.content.Intent
import android.graphics.Color
import android.os.*
import android.text.InputType
import android.view.*
import android.widget.*
import java.util.Locale

class MainActivity : Activity() {
    private val handler = Handler(Looper.getMainLooper())
    private lateinit var state: TextView; private lateinit var metrics: TextView; private lateinit var logs: TextView
    private lateinit var toggle: Button; private lateinit var settings: Button
    private var previousTunnel: Tunnel? = null
    private var lastTime = System.nanoTime(); private var lastTx = 0L; private var lastRx = 0L; private var lastQueries = 0L
    private val tick = object : Runnable { override fun run() { refresh(); handler.postDelayed(this, 1000) } }
    private fun dp(n: Int) = (n * resources.displayMetrics.density).toInt()
    private fun label(text: String, size: Float = 16f): TextView = TextView(this).apply { this.text = text; textSize = size; setTextColor(Color.parseColor("#D9E5DC")); setPadding(0, dp(6), 0, dp(6)) }
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(24), dp(16), dp(24), dp(16)); setBackgroundColor(Color.parseColor("#101713")) }
        root.setOnApplyWindowInsetsListener { view, insets ->
            view.setPadding(dp(24) + insets.systemWindowInsetLeft, dp(16) + insets.systemWindowInsetTop, dp(24) + insets.systemWindowInsetRight, dp(16) + insets.systemWindowInsetBottom); insets
        }
        root.addView(label("КРОТ", 34f)); root.addView(label("Интернет через DNS", 14f))
        state = label("Остановлен", 23f); root.addView(state)
        metrics = label("RTT —   •   QPS —\n↑ 0 кБ/с   ↓ 0 кБ/с   •   потоков 0"); root.addView(metrics)
        toggle = Button(this).apply { text = "Запустить"; setOnClickListener {
            if (Live.running) startService(Intent(this@MainActivity, TunnelService::class.java).setAction("STOP"))
            else {
                try {
                    Config.load(this@MainActivity).validate()
                    if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED) requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
                    startForegroundService(Intent(this@MainActivity, TunnelService::class.java))
                } catch (e: Exception) { Toast.makeText(this@MainActivity, e.message, Toast.LENGTH_LONG).show(); editSettings() }
            }
        } }; root.addView(toggle, LinearLayout.LayoutParams(-1, dp(62)))
        settings = Button(this).apply { text = "Настройки"; setOnClickListener { editSettings() } }; root.addView(settings)
        root.addView(Button(this).apply { text = "Экспорт журнала"; setOnClickListener { startActivityForResult(Intent(Intent.ACTION_CREATE_DOCUMENT).apply { type = "text/plain"; addCategory(Intent.CATEGORY_OPENABLE); putExtra(Intent.EXTRA_TITLE, "krot-log.txt") }, 2) } })
        root.addView(label("Журнал · последние 200 строк", 14f))
        logs = label("", 12f).apply { typeface = android.graphics.Typeface.MONOSPACE; setTextIsSelectable(true) }
        root.addView(ScrollView(this).apply { addView(logs) }, LinearLayout.LayoutParams(-1, 0, 1f))
        setContentView(root)
    }
    override fun onResume() { super.onResume(); handler.post(tick) }
    override fun onPause() { handler.removeCallbacks(tick); super.onPause() }
    private fun refresh() {
        state.text = when { Live.connected -> "Подключён"; Live.running -> "Подключение…"; else -> "Остановлен" }
        state.setTextColor(Color.parseColor(if (Live.connected) "#9BDD7C" else "#D9E5DC"))
        toggle.text = if (Live.running) "Остановить" else "Запустить"; settings.isEnabled = !Live.running
        val tunnel = Live.tunnel
        if (previousTunnel !== tunnel) { previousTunnel = tunnel; lastTx = 0; lastRx = 0; lastQueries = 0; lastTime = System.nanoTime() }
        val now = System.nanoTime(); val seconds = ((now - lastTime) / 1e9).coerceAtLeast(0.1)
        val tx = tunnel?.tx?.get() ?: 0; val rx = tunnel?.rx?.get() ?: 0; val q = tunnel?.queries?.get() ?: 0
        metrics.text = String.format(Locale.ROOT, "RTT %.0f мс  •  QPS %.1f  •  в полёте %d\n↑ %.1f кБ/с  ↓ %.1f кБ/с  •  потоков %d", tunnel?.rtt ?: 0.0, (q - lastQueries) / seconds, tunnel?.inFlight?.get() ?: 0, (tx - lastTx) / seconds / 1024, (rx - lastRx) / seconds / 1024, tunnel?.active?.get() ?: 0)
        lastTime = now; lastTx = tx; lastRx = rx; lastQueries = q
        logs.text = Live.logs()
    }
    private fun editSettings() {
        if (Live.running) return
        val cfg = Config.load(this)
        val box = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(20), dp(8), dp(20), dp(8)) }
        fun edit(title: String, value: String, number: Boolean = false, password: Boolean = false): EditText {
            box.addView(label(title, 13f))
            return EditText(this).apply {
                setSingleLine(true); setText(value)
                inputType = when { number -> InputType.TYPE_CLASS_NUMBER; password -> InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD; else -> InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI }
                box.addView(this)
            }
        }
        val domain = edit("Делегированная зона", cfg.domain)
        val password = edit("Пароль", cfg.password, password = true)
        val dns = edit("Nameserver IP · пусто = системный DNS", cfg.nameserver)
        box.addView(label("Тип DNS-записи", 13f))
        val types = listOf(16, 10, 1)
        val type = Spinner(this).apply { adapter = ArrayAdapter(this@MainActivity, android.R.layout.simple_spinner_dropdown_item, listOf("TXT · рекомендуется", "NULL · экспериментально", "A · медленно")); setSelection(types.indexOf(cfg.recordType).coerceAtLeast(0)) }; box.addView(type)
        val pipeline = edit("Конвейер · 8–32", cfg.pipeline.toString(), true)
        val size = edit("Максимум ответа · 100–1100 байт (адаптивно)", cfg.maxResponse.toString(), true)
        val port = edit("Порт SOCKS · 1024–65535", cfg.socksPort.toString(), true)
        val lan = CheckBox(this).apply { text = "Принимать SOCKS-соединения из LAN"; isChecked = cfg.lan }; box.addView(lan)
        box.addView(label("LAN открывает прокси без пароля для устройств вашей сети. Включайте только в доверенной сети.", 12f))
        val dialog = AlertDialog.Builder(this).setTitle("Настройки Крота").setView(ScrollView(this).apply { addView(box) }).setNegativeButton("Отмена", null).setPositiveButton("Сохранить", null).create()
        dialog.setOnShowListener { dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
            try {
                Config(domain.text.toString().trim().lowercase(Locale.ROOT).trimEnd('.'), password.text.toString(), dns.text.toString().trim(), types[type.selectedItemPosition], pipeline.text.toString().toInt(), size.text.toString().toInt(), port.text.toString().toInt(), lan.isChecked).save(this)
                dialog.dismiss()
            } catch (e: Exception) { Toast.makeText(this, e.message ?: "Проверьте настройки", Toast.LENGTH_LONG).show() }
        } }
        dialog.show()
    }
    @Deprecated("Platform result API")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == 2 && resultCode == RESULT_OK) data?.data?.let { uri ->
            try { contentResolver.openOutputStream(uri)?.use { it.write(Live.logs().toByteArray()) } }
            catch (e: Exception) { Toast.makeText(this, e.message, Toast.LENGTH_LONG).show() }
        }
    }
}
