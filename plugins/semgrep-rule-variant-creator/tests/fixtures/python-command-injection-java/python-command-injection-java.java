package com.example.ops;

import java.io.IOException;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Diagnostics endpoints that shell out to host tooling.
 *
 * Java port of the Python `python-command-injection` taint rule:
 *   source    request.args.get(...)  -> HttpServletRequest.getParameter/getHeader/getQueryString,
 *                                       and Spring @RequestParam handler arguments
 *   sink      os.system(...)         -> Runtime.getRuntime().exec(...), new ProcessBuilder(...).start()
 *   sanitizer shlex.quote(...)       -> no JDK equivalent; allowlist validation, or passing
 *                                       the value as a discrete argv element
 */
@WebServlet("/admin/diagnostics")
public class HostDiagnosticsServlet extends HttpServlet {

    private static final Pattern SAFE_HOSTNAME = Pattern.compile("[a-zA-Z0-9_.-]+");

    private static final List<String> ALLOWED_UNITS = List.of("nginx", "postgresql", "redis");

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String host = request.getParameter("host");

        // Whole-command surface: exec(String) does not spawn a shell, but the tainted value
        // still selects the target and can inject extra argv tokens on whitespace.
        // ruleid: python-command-injection-java
        Process ping = Runtime.getRuntime().exec("ping -c 1 " + host);
        ping.getInputStream().transferTo(response.getOutputStream());

        String logQuery = request.getParameter("q");
        String shellCommand = "grep -F " + logQuery + " /var/log/app.log";

        // Explicit `sh -c` wrapping reproduces the Python severity exactly: `;`, `|` and
        // backticks in the parameter are interpreted by the shell.
        // ruleid: python-command-injection-java
        Process grep = new ProcessBuilder("/bin/sh", "-c", shellCommand).start();
        grep.getInputStream().transferTo(response.getOutputStream());
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String tenant = request.getHeader("X-Tenant-Id");

        // ruleid: python-command-injection-java
        Runtime.getRuntime().exec(new String[] {"bash", "-c", "/opt/app/bin/rotate.sh " + tenant});

        String rawQuery = request.getQueryString();

        // ruleid: python-command-injection-java
        new ProcessBuilder("/bin/sh", "-c", "/opt/app/bin/replay.sh " + rawQuery).start();

        response.setStatus(HttpServletResponse.SC_ACCEPTED);
    }

    void allowlistValidated(HttpServletRequest request) throws IOException {
        String host = request.getParameter("host");
        if (!SAFE_HOSTNAME.matcher(host).matches()) {
            throw new IllegalArgumentException("host must match [a-zA-Z0-9_.-]+, got: " + host);
        }

        // Allowlist validation is the closest Java analogue to shlex.quote: no shell
        // metacharacter survives the regex, so concatenation is no longer reachable taint.
        // ok: python-command-injection-java
        Runtime.getRuntime().exec("ping -c 1 " + host);
    }

    void discreteArgvElement(HttpServletRequest request) throws IOException {
        String author = request.getParameter("author");

        // The Java idiom for doing this correctly: no shell, no concatenation. The tainted
        // value is one argv element, so it is passed to git as a single literal argument
        // regardless of what it contains.
        // ok: python-command-injection-java
        new ProcessBuilder("/usr/bin/git", "log", "--author", author).start();
    }

    void switchDispatch(HttpServletRequest request) throws IOException {
        String requested = request.getParameter("unit");
        if (!ALLOWED_UNITS.contains(requested.toLowerCase(Locale.ROOT))) {
            throw new IllegalArgumentException("unknown unit: " + requested);
        }
        String unit = requested.toLowerCase(Locale.ROOT);

        // ok: python-command-injection-java
        new ProcessBuilder("/usr/bin/systemctl", "is-active", unit).start();
    }

    void noUserInput() throws IOException {
        // ok: python-command-injection-java
        Runtime.getRuntime().exec("/bin/sh -c 'df -h /var/lib/app'");
    }
}

@RestController
class BackupController {

    private static final Pattern SAFE_SNAPSHOT_ID = Pattern.compile("[a-zA-Z0-9_.-]+");

    @GetMapping("/backups/restore")
    String restore(@RequestParam("snapshot") String snapshot) throws IOException {
        // ruleid: python-command-injection-java
        Process restore = new ProcessBuilder("/bin/sh", "-c", "restic restore " + snapshot).start();
        return "started pid=" + restore.pid();
    }

    @GetMapping("/backups/verify")
    String verify(@RequestParam("snapshot") String snapshot) throws IOException {
        if (!SAFE_SNAPSHOT_ID.matcher(snapshot).matches()) {
            throw new IllegalArgumentException("snapshot id must be [a-zA-Z0-9_.-]+");
        }
        List<String> argv = List.of("/usr/bin/restic", "check", "--snapshot", snapshot);

        // ok: python-command-injection-java
        Process verify = new ProcessBuilder(argv).start();
        return "verifying pid=" + verify.pid();
    }
}
