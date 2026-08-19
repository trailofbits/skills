// Command diagtool is a small HTTP service that runs diagnostic commands.
// It exercises the Go port of the python-command-injection rule: request data
// reaching a shell-wrapped process launch, and the safe argv-style forms.
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/alessio/shellescape"
	"github.com/gin-gonic/gin"
	"github.com/go-chi/chi/v5"
	"github.com/gorilla/mux"
)

// ---------------------------------------------------------------------------
// Vulnerable: request data reaches a shell, so metacharacters are code.
// ---------------------------------------------------------------------------

// pingHandler serves GET /ping?host=example.com.
func pingHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	script := fmt.Sprintf("ping -c 1 %s", host)
	// ruleid: python-command-injection-go
	out, err := exec.Command("sh", "-c", script).CombinedOutput()
	if err != nil {
		http.Error(w, "ping failed", http.StatusBadGateway)
		return
	}
	w.Write(out)
}

// archiveHandler serves POST /archive with a "path" form field.
func archiveHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	target := r.PostFormValue("path")

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	line := "tar czf /var/backups/out.tgz " + target
	// ruleid: python-command-injection-go
	if err := exec.CommandContext(ctx, "bash", "-c", line).Run(); err != nil {
		http.Error(w, "archive failed", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

// versionHandler is registered on a gorilla/mux router as /tools/{tool}/version.
// The taint lands in the program-name position rather than in a shell string.
func versionHandler(w http.ResponseWriter, r *http.Request) {
	tool := mux.Vars(r)["tool"]
	// ruleid: python-command-injection-go
	out, err := exec.Command(tool, "--version").Output()
	if err != nil {
		http.Error(w, "unknown tool", http.StatusNotFound)
		return
	}
	fmt.Fprintf(w, "%s", out)
}

// restoreHandler replaces the current process with an operator-supplied binary.
func restoreHandler(w http.ResponseWriter, r *http.Request) {
	bin := r.Header.Get("X-Restore-Binary")
	// ruleid: python-command-injection-go
	if err := syscall.Exec(bin, []string{bin, "--restore"}, os.Environ()); err != nil {
		http.Error(w, "exec failed", http.StatusInternalServerError)
	}
}

// gitLogHandler is a chi handler mounted at /repos/{repo}/log, running under
// the Windows agent build.
func gitLogHandler(w http.ResponseWriter, r *http.Request) {
	repo := chi.URLParam(r, "repo")
	// ruleid: python-command-injection-go
	out, err := exec.Command("cmd", "/C", "git -C "+repo+" log -1").Output()
	if err != nil {
		http.Error(w, "log failed", http.StatusInternalServerError)
		return
	}
	w.Write(out)
}

// ---------------------------------------------------------------------------
// Safe forms.
// ---------------------------------------------------------------------------

// listHandler is the idiomatic Go fix: no shell at all. os/exec passes argv
// directly to execve, so dir is data and can never be parsed as a command.
func listHandler(w http.ResponseWriter, r *http.Request) {
	dir := r.URL.Query().Get("dir")
	// ok: python-command-injection-go
	out, err := exec.Command("ls", "-l", "--", dir).Output()
	if err != nil {
		http.Error(w, "list failed", http.StatusInternalServerError)
		return
	}
	w.Write(out)
}

// diskUsageHandler needs a shell for the pipeline, so it escapes the argument.
func diskUsageHandler(w http.ResponseWriter, r *http.Request) {
	path := r.FormValue("path")
	line := "du -sh " + shellescape.Quote(path) + " | tail -1"
	// ok: python-command-injection-go
	out, err := exec.Command("sh", "-c", line).Output()
	if err != nil {
		http.Error(w, "du failed", http.StatusInternalServerError)
		return
	}
	w.Write(out)
}

// serviceStatusHandler maps the request parameter through an allow-list, so the
// string that reaches the shell is one of a fixed set of literals.
func serviceStatusHandler(w http.ResponseWriter, r *http.Request) {
	var unit string
	switch r.URL.Query().Get("service") {
	case "web":
		unit = "nginx"
	case "db":
		unit = "postgresql"
	case "queue":
		unit = "redis"
	default:
		http.Error(w, "unknown service", http.StatusBadRequest)
		return
	}
	// ok: python-command-injection-go
	out, err := exec.Command("sh", "-c", "systemctl status "+unit+" | head -5").Output()
	if err != nil {
		http.Error(w, "status failed", http.StatusInternalServerError)
		return
	}
	w.Write(out)
}

// rotateLogs runs on a timer with a configured path; nothing here is request data.
func rotateLogs(ctx context.Context, logDir string) error {
	// ok: python-command-injection-go
	return exec.CommandContext(ctx, "sh", "-c", "logrotate -f "+logDir+"/logrotate.conf").Run()
}

// ginAuthorHandler passes the query parameter as its own argv element.
func ginAuthorHandler(c *gin.Context) {
	author := c.Query("author")
	// ok: python-command-injection-go
	out, err := exec.Command("git", "log", "--author", author, "-5").Output()
	if err != nil {
		c.String(http.StatusInternalServerError, "log failed")
		return
	}
	c.String(http.StatusOK, string(out))
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/ping", pingHandler).Methods(http.MethodGet)
	r.HandleFunc("/archive", archiveHandler).Methods(http.MethodPost)
	r.HandleFunc("/tools/{tool}/version", versionHandler).Methods(http.MethodGet)
	r.HandleFunc("/restore", restoreHandler).Methods(http.MethodPost)
	r.HandleFunc("/list", listHandler).Methods(http.MethodGet)
	r.HandleFunc("/du", diskUsageHandler).Methods(http.MethodGet)
	r.HandleFunc("/status", serviceStatusHandler).Methods(http.MethodGet)

	srv := &http.Server{
		Addr:              ":8080",
		Handler:           r,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}
