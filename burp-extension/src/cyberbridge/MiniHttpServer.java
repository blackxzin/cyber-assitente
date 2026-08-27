package cyberbridge;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Minimal single-request-per-connection HTTP/1.1 server built on plain
 * java.net sockets. Burp's extension classloader only exposes java.base to
 * extensions (jdk.httpserver — com.sun.net.httpserver — is not visible),
 * so we can't use the JDK's built-in HttpServer here.
 */
final class MiniHttpServer {

    interface Handler {
        Response handle(Request request) throws Exception;
    }

    record Request(String method, String path, Map<String, String> query,
                    Map<String, String> headers, byte[] body) {
        String header(String name) {
            return headers.get(name.toLowerCase());
        }
    }

    record Response(int status, String contentType, byte[] body) {
        static Response of(int status, String contentType, byte[] body) {
            return new Response(status, contentType, body);
        }
    }

    private static final int MAX_REQUEST_LINE = 8192;
    private static final int MAX_HEADERS = 8192;
    private static final int MAX_BODY = 1_000_000;

    private final ServerSocket serverSocket;
    private final ExecutorService pool = Executors.newCachedThreadPool();
    private volatile boolean running = true;

    MiniHttpServer(int port) throws IOException {
        serverSocket = new ServerSocket(port, 50, InetAddress.getByName("127.0.0.1"));
    }

    int port() {
        return serverSocket.getLocalPort();
    }

    void start(Handler handler) {
        Thread acceptThread = new Thread(() -> acceptLoop(handler), "cyber-bridge-accept");
        acceptThread.setDaemon(true);
        acceptThread.start();
    }

    void stop() {
        running = false;
        try {
            serverSocket.close();
        } catch (IOException ignored) {
            // shutting down
        }
        pool.shutdownNow();
    }

    private void acceptLoop(Handler handler) {
        while (running) {
            Socket socket;
            try {
                socket = serverSocket.accept();
            } catch (IOException e) {
                if (running) {
                    // transient accept error — keep serving
                    continue;
                }
                return;
            }
            pool.submit(() -> serveOne(socket, handler));
        }
    }

    private void serveOne(Socket socket, Handler handler) {
        try (socket; InputStream rawIn = socket.getInputStream();
             OutputStream out = socket.getOutputStream()) {
            BufferedInputStream in = new BufferedInputStream(rawIn);
            Request request;
            try {
                request = readRequest(in);
            } catch (IOException | IllegalArgumentException e) {
                writeResponse(out, 400, "text/plain", ("bad request: " + e.getMessage())
                        .getBytes(StandardCharsets.UTF_8));
                return;
            }
            Response response;
            try {
                response = handler.handle(request);
            } catch (Exception e) {
                String msg = "internal error: " + e;
                writeResponse(out, 500, "text/plain", msg.getBytes(StandardCharsets.UTF_8));
                return;
            }
            writeResponse(out, response.status(), response.contentType(), response.body());
        } catch (IOException ignored) {
            // client disconnected mid-response — nothing to do
        }
    }

    private Request readRequest(BufferedInputStream in) throws IOException {
        String requestLine = readLine(in, MAX_REQUEST_LINE);
        String[] parts = requestLine.split(" ", 3);
        if (parts.length < 2) {
            throw new IllegalArgumentException("malformed request line");
        }
        String method = parts[0];
        String rawPath = parts[1];
        String path = rawPath;
        Map<String, String> query = new LinkedHashMap<>();
        int qIdx = rawPath.indexOf('?');
        if (qIdx >= 0) {
            path = rawPath.substring(0, qIdx);
            for (String pair : rawPath.substring(qIdx + 1).split("&")) {
                if (pair.isEmpty()) continue;
                String[] kv = pair.split("=", 2);
                query.put(kv[0], kv.length > 1 ? kv[1] : "");
            }
        }

        Map<String, String> headers = new LinkedHashMap<>();
        int headerBytes = 0;
        String line;
        while (!(line = readLine(in, MAX_HEADERS)).isEmpty()) {
            headerBytes += line.length();
            if (headerBytes > MAX_HEADERS) throw new IllegalArgumentException("headers too large");
            int idx = line.indexOf(':');
            if (idx < 0) continue;
            headers.put(line.substring(0, idx).trim().toLowerCase(), line.substring(idx + 1).trim());
        }

        byte[] body = new byte[0];
        String lenHeader = headers.get("content-length");
        if (lenHeader != null) {
            int len = Math.min(MAX_BODY, Integer.parseInt(lenHeader.trim()));
            body = in.readNBytes(len);
        }
        return new Request(method, path, query, headers, body);
    }

    private static String readLine(InputStream in, int max) throws IOException {
        StringBuilder sb = new StringBuilder();
        int c;
        int count = 0;
        while ((c = in.read()) != -1) {
            count++;
            if (count > max) throw new IllegalArgumentException("line too long");
            if (c == '\n') {
                if (sb.length() > 0 && sb.charAt(sb.length() - 1) == '\r') {
                    sb.setLength(sb.length() - 1);
                }
                return sb.toString();
            }
            sb.append((char) c);
        }
        if (sb.isEmpty()) throw new IOException("connection closed");
        return sb.toString();
    }

    private static void writeResponse(OutputStream out, int status, String contentType, byte[] body)
            throws IOException {
        String reason = switch (status) {
            case 200 -> "OK";
            case 400 -> "Bad Request";
            case 403 -> "Forbidden";
            case 404 -> "Not Found";
            case 405 -> "Method Not Allowed";
            case 502 -> "Bad Gateway";
            default -> "Error";
        };
        StringBuilder head = new StringBuilder();
        head.append("HTTP/1.1 ").append(status).append(' ').append(reason).append("\r\n");
        head.append("Content-Type: ").append(contentType).append("\r\n");
        head.append("Content-Length: ").append(body.length).append("\r\n");
        head.append("Connection: close\r\n");
        head.append("\r\n");
        out.write(head.toString().getBytes(StandardCharsets.US_ASCII));
        out.write(body);
        out.flush();
    }
}
