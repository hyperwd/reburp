package com.reburp.routes

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.requests.HttpRequest
import com.reburp.*
import io.ktor.http.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import java.awt.Component
import java.awt.Container
import java.awt.Frame
import java.awt.image.BufferedImage
import java.io.ByteArrayOutputStream
import java.util.Base64
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import javax.imageio.ImageIO
import javax.swing.AbstractButton
import javax.swing.JTabbedPane
import javax.swing.SwingUtilities
import javax.swing.text.JTextComponent

// Iteratively finds the first component matching type T and predicate (BFS)
private inline fun <reified T : Component> findComponent(root: Component, crossinline predicate: (T) -> Boolean): T? {
    val queue = ArrayDeque<Component>()
    queue.add(root)
    while (queue.isNotEmpty()) {
        val current = queue.removeFirst()
        if (current is T && predicate(current)) return current
        if (current is Container) current.components.forEach { queue.add(it) }
    }
    return null
}

// Locates the inner JTabbedPane inside the Repeater tool panel
private fun findRepeaterTabsPane(api: MontoyaApi): JTabbedPane? {
    val frame = api.userInterface().swingUtils().suiteFrame()
    // Find the top-level suite JTabbedPane (has a "Repeater" tab)
    val suiteTabs = findComponent<JTabbedPane>(frame) { tp ->
        (0 until tp.tabCount).any { tp.getTitleAt(it).equals("Repeater", ignoreCase = true) }
    } ?: return null
    val repeaterIdx = (0 until suiteTabs.tabCount)
        .firstOrNull { suiteTabs.getTitleAt(it).equals("Repeater", ignoreCase = true) } ?: return null
    val repeaterPanel = suiteTabs.getComponentAt(repeaterIdx) ?: return null
    // The first JTabbedPane inside the Repeater panel holds the individual request tabs
    return findComponent<JTabbedPane>(repeaterPanel) { true }
}

// [Montoya API] - api.repeater() and api.intruder()
fun Routing.repeaterIntruderRoutes(api: MontoyaApi) {

    // ── Repeater ──────────────────────────────────────────────────────────────

    /**
     * Sends a request to the Burp Repeater tab.
     * The request appears immediately in the Repeater UI - you still need to click Send in Burp.
     */
    post("/api/repeater/send") {
        val req = runCatching { call.receive<SendToRepeaterRequest>() }.getOrElse {
            return@post call.respond(HttpStatusCode.BadRequest, ErrorResponse(it.message ?: "Invalid request body"))
        }
        val httpReq = runCatching {
            val norm = normalizeRequest(req.raw_request)
            HttpRequest.httpRequest(serviceFromRawRequest(norm), norm)
        }.getOrElse {
            return@post call.respond(
                HttpStatusCode.BadRequest,
                ErrorResponse("Failed to parse raw_request: ${it.message}. Ensure the request includes a valid HTTP first line and a Host header.")
            )
        }
        runCatching {
            if (req.tab_name != null) api.repeater().sendToRepeater(httpReq, req.tab_name)
            else api.repeater().sendToRepeater(httpReq)
        }.onFailure {
            return@post call.respond(
                HttpStatusCode.InternalServerError,
                ErrorResponse("sendToRepeater failed: ${it.message}")
            )
        }
        call.respond(MessageResponse("Request sent to Repeater${req.tab_name?.let { " (tab: '$it')" } ?: ""}. Open the Repeater tab in Burp to review and send."))
    }

    /**
     * One call: show Repeater, append a tab, Send that tab, wait until its response
     * editor is non-empty, then capture the suite frame. Does not clear other tabs.
     * Failure is a structured error and never includes a PNG.
     */
    post("/api/repeater/proof") {
        val req = runCatching { call.receive<RepeaterProofRequest>() }.getOrElse {
            return@post call.respond(HttpStatusCode.BadRequest, RepeaterProofError("bad_request", it.message))
        }
        if (req.raw_request.isBlank()) {
            return@post call.respond(HttpStatusCode.BadRequest, RepeaterProofError("bad_request"))
        }
        val tabName = req.tab_name?.trim()?.takeIf { it.isNotEmpty() }
            ?: "proof-${System.currentTimeMillis() % 1_000_000}"
        val timeout = (req.timeout_ms ?: 20_000L).coerceIn(1_000L, 120_000L)
        val httpReq = runCatching {
            val norm = normalizeRequest(req.raw_request)
            HttpRequest.httpRequest(serviceFromRawRequest(norm), norm)
        }.getOrElse {
            return@post call.respond(HttpStatusCode.BadRequest, RepeaterProofError("bad_request", it.message))
        }
        val result = runCatching { runRepeaterProof(api, httpReq, tabName, req.expect, timeout) }
        result.onSuccess {
            call.respond(
                RepeaterProofResponse(
                    tab_name = it.tabName,
                    response = it.response,
                    elapsed_ms = it.elapsedMs,
                    png_base64 = Base64.getEncoder().encodeToString(it.png),
                )
            )
        }.onFailure { e ->
            val fail = e as? ProofFail
            val status = fail?.status ?: HttpStatusCode.InternalServerError
            val code = fail?.error ?: "repeater_unavailable"
            if (!call.response.isCommitted) {
                call.respond(status, RepeaterProofError(code, fail?.responseText))
            }
        }
    }

    /**
     * Closes all tabs in Burp Repeater by traversing the Swing component tree.
     * The last tab (the "+" placeholder) is preserved so Repeater remains functional.
     */
    delete("/api/repeater/tabs") {
        var removed = 0
        var errorMsg: String? = null
        val latch = CountDownLatch(1)
        SwingUtilities.invokeLater {
            try {
                val pane = findRepeaterTabsPane(api)
                if (pane == null) {
                    errorMsg = "Could not locate Repeater tabs pane - make sure the Repeater tab has been opened in Burp at least once"
                } else {
                    // Keep the last tab (the '+' button); remove all others from front
                    while (pane.tabCount > 1) {
                        pane.removeTabAt(0)
                        removed++
                    }
                }
            } catch (e: Exception) {
                errorMsg = e.message
            } finally {
                latch.countDown()
            }
        }
        latch.await(5, TimeUnit.SECONDS)
        if (errorMsg != null) {
            call.respond(HttpStatusCode.InternalServerError, ErrorResponse(errorMsg!!))
        } else {
            call.respond(MessageResponse("Cleared $removed Repeater tab(s)"))
        }
    }

    // ── Intruder ──────────────────────────────────────────────────────────────

    /**
     * Sends a request to the Burp Intruder tab.
     * Mark injection points with § symbols in raw_request (e.g. "username=§admin§").
     * After sending, configure the attack type and payload sets in the Burp Intruder UI.
     */
    post("/api/intruder/send") {
        val req = runCatching { call.receive<SendToIntruderRequest>() }.getOrElse {
            return@post call.respond(HttpStatusCode.BadRequest, ErrorResponse(it.message ?: "Invalid request body"))
        }
        val httpReq = runCatching {
            val norm = normalizeRequest(req.raw_request)
            HttpRequest.httpRequest(serviceFromRawRequest(norm), norm)
        }.getOrElse {
            return@post call.respond(
                HttpStatusCode.BadRequest,
                ErrorResponse("Failed to parse raw_request: ${it.message}. Ensure the request includes a valid HTTP first line and a Host header.")
            )
        }
        runCatching {
            if (req.tab_name != null) api.intruder().sendToIntruder(httpReq, req.tab_name)
            else api.intruder().sendToIntruder(httpReq)
        }.onFailure {
            return@post call.respond(
                HttpStatusCode.InternalServerError,
                ErrorResponse("sendToIntruder failed: ${it.message}")
            )
        }
        call.respond(MessageResponse("Request sent to Intruder${req.tab_name?.let { " (tab: '$it')" } ?: ""}. Configure attack type and payloads in the Burp Intruder UI, then start the attack."))
    }
}

private class ProofShot(val tabName: String, val response: String, val elapsedMs: Long, val png: ByteArray)

private class ProofFail(
    val error: String,
    val status: HttpStatusCode,
    val responseText: String? = null,
) : RuntimeException(error)

private fun runRepeaterProof(
    api: MontoyaApi,
    httpReq: HttpRequest,
    tabName: String,
    expect: String?,
    timeoutMs: Long,
): ProofShot {
    val beforeCount = onEdt {
        val frame = suiteFrame(api) ?: throw ProofFail("repeater_unavailable", HttpStatusCode.Conflict)
        showRepeater(frame)
        val indexes = tabIndexes(api, tabName) ?: throw ProofFail("repeater_unavailable", HttpStatusCode.Conflict)
        indexes.size
    }
    runCatching { api.repeater().sendToRepeater(httpReq, tabName) }.getOrElse {
        throw ProofFail("repeater_unavailable", HttpStatusCode.Conflict, it.message)
    }
    val appeared = System.currentTimeMillis() + 5_000
    var ready = false
    while (System.currentTimeMillis() < appeared) {
        val n = onEdt { tabIndexes(api, tabName)?.size ?: 0 }
        if (n > beforeCount) {
            ready = true
            break
        }
        Thread.sleep(100)
    }
    if (!ready) throw ProofFail("repeater_unavailable", HttpStatusCode.Conflict)
    val clickedAt = onEdt {
        val pane = findRepeaterTabsPane(api) ?: throw ProofFail("repeater_unavailable", HttpStatusCode.Conflict)
        val idx = tabIndexes(api, tabName)?.lastOrNull()
            ?: throw ProofFail("repeater_unavailable", HttpStatusCode.Conflict)
        pane.selectedIndex = idx
        val scope = (repeaterToolPanel(api) as? java.awt.Container) ?: pane
        val btn = findSendControl(scope)
            ?: throw ProofFail("send_control_missing", HttpStatusCode.InternalServerError)
        val before = editorTexts(scope).toSet()
        val t0 = System.nanoTime()
        activateSend(btn, scope)
        t0 to before
    }
    val (t0, before) = clickedAt
    val deadline = System.currentTimeMillis() + timeoutMs
    var response: String? = null
    while (System.currentTimeMillis() < deadline) {
        val hit = onEdt {
            val scope = repeaterToolPanel(api) ?: return@onEdt null
            editorTexts(scope).firstOrNull { text ->
                text.trimStart().startsWith("HTTP/") && text !in before
            }
        }
        if (hit != null) {
            response = hit
            break
        }
        Thread.sleep(100)
    }
    val elapsed = (System.nanoTime() - t0) / 1_000_000
    val body = response ?: throw ProofFail("send_timeout", HttpStatusCode.GatewayTimeout)
    if (!expect.isNullOrEmpty() && !body.contains(expect)) {
        throw ProofFail("expect_mismatch", HttpStatusCode.Conflict, body)
    }
    val png = runCatching { captureSuiteFrame(api) }.getOrElse {
        throw ProofFail("capture_failed", HttpStatusCode.InternalServerError, body)
    }
    return ProofShot(tabName, body, elapsed, png)
}

private fun showRepeater(frame: Frame) {
    frame.extendedState = frame.extendedState or Frame.MAXIMIZED_BOTH
    frame.toFront()
    val suiteTabs = findComponent<JTabbedPane>(frame) { tp ->
        (0 until tp.tabCount).any { tp.getTitleAt(it).equals("Repeater", ignoreCase = true) }
    } ?: return
    val idx = (0 until suiteTabs.tabCount).first { suiteTabs.getTitleAt(it).equals("Repeater", ignoreCase = true) }
    suiteTabs.selectedIndex = idx
}

private fun repeaterToolPanel(api: MontoyaApi): Component? {
    val frame = suiteFrame(api) ?: return null
    val suiteTabs = findComponent<JTabbedPane>(frame) { tp ->
        (0 until tp.tabCount).any { tp.getTitleAt(it).equals("Repeater", ignoreCase = true) }
    } ?: return null
    val idx = (0 until suiteTabs.tabCount).firstOrNull { suiteTabs.getTitleAt(it).equals("Repeater", ignoreCase = true) }
        ?: return null
    return suiteTabs.getComponentAt(idx)
}

private fun tabIndexes(api: MontoyaApi, tabName: String): List<Int>? {
    val pane = findRepeaterTabsPane(api) ?: return null
    return (0 until pane.tabCount).filter { pane.getTitleAt(it) == tabName }
}

private fun isSendLabel(text: String?): Boolean {
    val t = text?.trim().orEmpty()
    return t.equals("Send", ignoreCase = true)
}

// Burp's Send control is a custom widget (not a JButton). Its accessible name is "Send".
// AbstractButton gets doClick; anything else is clicked in-process on the component that
// actually owns the mouse listener (still not screen coordinates).
private fun findSendControl(root: Component): Component? {
    val hits = walkTree(root).filter { c ->
        val names = listOfNotNull(
            (c as? AbstractButton)?.text,
            (c as? javax.swing.JLabel)?.text,
            (c as? javax.swing.JComponent)?.toolTipText,
            c.accessibleContext?.accessibleName,
        )
        names.any { isSendLabel(it) }
    }.toList()
    return hits.firstOrNull { isSendLabel(it.accessibleContext?.accessibleName) }
        ?: hits.firstOrNull { it is AbstractButton }
        ?: hits.firstOrNull()
}

private fun activateSend(control: Component, scope: java.awt.Container) {
    if (control is AbstractButton) {
        control.doClick()
        return
    }
    val p = java.awt.Point((control.width / 2).coerceAtLeast(1), (control.height / 2).coerceAtLeast(1))
    val (target, pt) = retargetForClick(control, p, scope)
    clickAt(target, pt.x, pt.y, "left", 1)
}

private fun editorTexts(root: Component): List<String> =
    walkTree(root).mapNotNull { c ->
        if (c !is JTextComponent) return@mapNotNull null
        val n = c.document.length
        if (n < 8) return@mapNotNull null
        runCatching { c.document.getText(0, n) }.getOrNull()
    }.toList()

private fun captureSuiteFrame(api: MontoyaApi): ByteArray {
    // Render the suite frame off-screen. java.awt.Robot reads the compositor's screen
    // buffer, which is black on this machine even when the window is showing, so a
    // Robot capture cannot be the evidence. printAll is the frame's own pixels.
    val img = onEdt {
        val frame = suiteFrame(api) ?: throw ProofFail("capture_failed", HttpStatusCode.InternalServerError)
        frame.extendedState = frame.extendedState or Frame.MAXIMIZED_BOTH
        frame.toFront()
        val w = frame.width
        val h = frame.height
        if (w < 200 || h < 200) throw ProofFail("capture_failed", HttpStatusCode.InternalServerError)
        val image = BufferedImage(w, h, BufferedImage.TYPE_INT_RGB)
        val g = image.createGraphics()
        frame.printAll(g)
        g.dispose()
        image
    }
    val out = ByteArrayOutputStream()
    if (!ImageIO.write(img, "png", out) || out.size() < 1024) {
        throw ProofFail("capture_failed", HttpStatusCode.InternalServerError)
    }
    return out.toByteArray()
}
