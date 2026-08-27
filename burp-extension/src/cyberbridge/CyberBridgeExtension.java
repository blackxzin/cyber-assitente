package cyberbridge;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

import cyberbridge.MiniHttpServer.Request;
import cyberbridge.MiniHttpServer.Response;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Cyber Bridge: exposes a small local HTTP API so the cybersecurity-ai
 * backend (a separate Python process) can read Burp's proxy history and
 * send requests through Burp — without needing the Pro-only native REST
 * API / Agentic AI features, which the Community edition doesn't have.
 *
 * Built on a hand-rolled HTTP server (MiniHttpServer, java.base only):
 * Burp's extension classloader does not expose com.sun.net.httpserver
 * (jdk.httpserver module) to extensions.
 *
 * Everything is gated by a random token written to a discovery file on
 * startup (~/.cyber-ai-burp-bridge.json); the caller-side confirmation gate
 * (safety.py / ConfirmationStore) still lives entirely in the Python app —
 * this extension is a dumb transport, not a policy layer.
 */
public class CyberBridgeExtension implements BurpExtension {

    private static final Path DISCOVERY_FILE =
            Path.of(System.getProperty("user.home"), ".cyber-ai-burp-bridge.json");
    private static final int MAX_HISTORY_LIMIT = 200;

    private MontoyaApi api;
    private MiniHttpServer server;
    private String token;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Cyber Bridge");
        this.token = UUID.randomUUID().toString();

        try {
            server = new MiniHttpServer(0);
        } catch (IOException e) {
            api.logging().logToError("Cyber Bridge: failed to bind local server", e);
            return;
        }
        server.start(this::route);

        int port = server.port();
        writeDiscoveryFile(port);
        api.logging().logToOutput("Cyber Bridge listening on 127.0.0.1:" + port
                + " (discovery file: " + DISCOVERY_FILE + ")");

        api.extension().registerUnloadingHandler(() -> {
            server.stop();
            try {
                Files.deleteIfExists(DISCOVERY_FILE);
            } catch (IOException ignored) {
                // best-effort cleanup
            }
        });
    }

    private void writeDiscoveryFile(int port) {
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("port", (double) port);
        doc.put("token", token);
        try {
            Files.writeString(DISCOVERY_FILE, MiniJson.write(doc), StandardCharsets.UTF_8);
        } catch (IOException e) {
            api.logging().logToError("Cyber Bridge: failed to write discovery file", e);
        }
    }

    // --- routing ------------------------------------------------------

    private Response route(Request request) {
        if (request.path().equals("/health")) {
            return json(200, Map.of("status", "ok"));
        }
        String presented = request.header("x-cyber-token");
        if (presented == null || !constantTimeEquals(presented, token)) {
            return json(403, Map.of("error", "invalid or missing X-Cyber-Token"));
        }
        return switch (request.path()) {
            case "/proxy/history" -> handleProxyHistory(request);
            case "/http/send" -> handleHttpSend(request);
            default -> json(404, Map.of("error", "not found"));
        };
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a.length() != b.length()) return false;
        int diff = 0;
        for (int i = 0; i < a.length(); i++) diff |= a.charAt(i) ^ b.charAt(i);
        return diff == 0;
    }

    // --- handlers -------------------------------------------------------

    private Response handleProxyHistory(Request request) {
        if (!"GET".equalsIgnoreCase(request.method())) {
            return json(405, Map.of("error", "GET only"));
        }
        int limit = parseLimitParam(request.query().get("limit"));
        List<ProxyHttpRequestResponse> history = api.proxy().history();
        List<Object> items = new ArrayList<>();
        int start = Math.max(0, history.size() - limit);
        for (ProxyHttpRequestResponse item : history.subList(start, history.size())) {
            HttpRequest finalRequest = item.finalRequest();
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("id", (double) item.id());
            row.put("method", finalRequest.method());
            row.put("url", finalRequest.url());
            row.put("host", finalRequest.httpService().host());
            row.put("port", (double) finalRequest.httpService().port());
            row.put("statusCode", item.hasResponse() ? (double) item.response().statusCode() : null);
            row.put("mimeType", item.mimeType() != null ? item.mimeType().toString() : null);
            row.put("time", item.time() != null ? item.time().format(DateTimeFormatter.ISO_INSTANT) : null);
            items.add(row);
        }
        return json(200, Map.of("history", items));
    }

    private Response handleHttpSend(Request request) {
        if (!"POST".equalsIgnoreCase(request.method())) {
            return json(405, Map.of("error", "POST only"));
        }
        Map<String, Object> req;
        try {
            req = MiniJson.parseObject(new String(request.body(), StandardCharsets.UTF_8));
        } catch (IllegalArgumentException e) {
            return json(400, Map.of("error", "malformed JSON body: " + e.getMessage()));
        }

        Object urlObj = req.get("url");
        if (!(urlObj instanceof String url) || url.isBlank()) {
            return json(400, Map.of("error", "'url' is required"));
        }
        String method = req.get("method") instanceof String m && !m.isBlank() ? m : "GET";
        String body = req.get("body") instanceof String b ? b : null;

        HttpRequest httpRequest;
        try {
            httpRequest = HttpRequest.httpRequestFromUrl(url).withMethod(method);
        } catch (RuntimeException e) {
            return json(400, Map.of("error", "invalid url: " + e.getMessage()));
        }
        if (body != null) {
            httpRequest = httpRequest.withBody(body);
        }
        if (req.get("headers") instanceof Map<?, ?> headers) {
            for (Map.Entry<?, ?> entry : headers.entrySet()) {
                httpRequest = httpRequest.withAddedHeader(String.valueOf(entry.getKey()), String.valueOf(entry.getValue()));
            }
        }

        HttpRequestResponse result;
        try {
            result = api.http().sendRequest(httpRequest);
        } catch (RuntimeException e) {
            return json(502, Map.of("error", "request failed: " + e.getMessage()));
        }

        HttpResponse response = result.response();
        if (response == null) {
            return json(502, Map.of("error", "no response (timeout or connection refused)"));
        }
        Map<String, Object> headersOut = response.headers().stream()
                .collect(Collectors.toMap(
                        h -> h.name(),
                        h -> (Object) h.value(),
                        (a, b) -> a + ", " + b,
                        LinkedHashMap::new));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("statusCode", (double) response.statusCode());
        out.put("headers", headersOut);
        out.put("body", response.bodyToString());
        return json(200, out);
    }

    // --- helpers ----------------------------------------------------------

    private static int parseLimitParam(String raw) {
        if (raw == null) return 50;
        try {
            return Math.min(MAX_HISTORY_LIMIT, Math.max(1, Integer.parseInt(raw)));
        } catch (NumberFormatException e) {
            return 50;
        }
    }

    private static Response json(int status, Object body) {
        return Response.of(status, "application/json", MiniJson.write(body).getBytes(StandardCharsets.UTF_8));
    }
}
