// execute-rt.cc — corpus replay runtime for coverage builds.
//
// Link this instead of a fuzzing engine, together with a libFuzzer-style harness that defines
// LLVMFuzzerTestOneInput, and build with -fprofile-instr-generate -fcoverage-mapping (or the
// gcov flags). It replays every regular file in one or more directories (recursively).
//
//   ./fuzz_exec CORPUS_DIR [CORPUS_DIR...]              replay in-process (fastest)
//   ./fuzz_exec --isolate [--crash-log FILE] CORPUS_DIR...
//       fork once per input so a crashing input cannot take the coverage data of the other
//       inputs with it. Run with LLVM_PROFILE_FILE containing %m so the children's counters merge
//       into one profile (the wrapper script sets that). Crashes are reported on stderr and, with --crash-log,
//       appended to FILE as "<path>\t<signal or exit>" lines. The exit status is the number of
//       crashing inputs (capped at 125), so a run with crashes is visible to the caller, and the
//       coverage of a crashing input is NOT recorded: its child died before writing a profile.
//
// Paths with spaces are fine; zero-byte files are replayed with size 0; unreadable entries are
// reported and skipped. Exit 2 means a usage or directory error.
#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <string>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

namespace {

struct Options {
  bool isolate = false;
  const char *crash_log = nullptr;
  std::vector<std::string> dirs;
};

bool read_file(const std::string &path, std::vector<uint8_t> &out) {
  FILE *file = fopen(path.c_str(), "rb");
  if (file == nullptr) {
    return false;
  }
  out.clear();
  uint8_t chunk[65536];
  size_t got;
  while ((got = fread(chunk, 1, sizeof chunk, file)) > 0) {
    out.insert(out.end(), chunk, chunk + got);
  }
  bool ok = ferror(file) == 0;
  fclose(file);
  return ok;
}

void collect(const std::string &dir, std::vector<std::string> &files) {
  DIR *handle = opendir(dir.c_str());
  if (handle == nullptr) {
    fprintf(stderr, "execute-rt: cannot open directory %s: %s\n", dir.c_str(), strerror(errno));
    exit(2);
  }
  struct dirent *entry;
  std::vector<std::string> subdirs;
  while ((entry = readdir(handle)) != nullptr) {
    if (entry->d_name[0] == '.') {
      continue;
    }
    std::string path = dir + "/" + entry->d_name;
    struct stat st;
    if (stat(path.c_str(), &st) != 0) {
      fprintf(stderr, "execute-rt: skipping unreadable entry %s\n", path.c_str());
      continue;
    }
    if (S_ISDIR(st.st_mode)) {
      subdirs.push_back(path);
    } else if (S_ISREG(st.st_mode)) {
      files.push_back(path);
    }
  }
  closedir(handle);
  for (const std::string &sub : subdirs) {
    collect(sub, files);
  }
}

void run_one(const std::string &path) {
  std::vector<uint8_t> data;
  if (!read_file(path, data)) {
    fprintf(stderr, "execute-rt: cannot read %s: %s\n", path.c_str(), strerror(errno));
    return;
  }
  LLVMFuzzerTestOneInput(data.empty() ? nullptr : data.data(), data.size());
}

FILE *open_crash_log(const char *path) {
  FILE *log = fopen(path, "a");
  if (log == nullptr) {
    fprintf(stderr, "execute-rt: cannot open crash log %s: %s\n", path, strerror(errno));
  }
  return log;
}

// crash_log is opened lazily on the first crash so a clean run leaves no empty file behind.
int run_isolated(const std::string &path, const char *crash_log_path, FILE **crash_log) {
  fflush(stdout);
  fflush(stderr);
  pid_t pid = fork();
  if (pid < 0) {
    fprintf(stderr, "execute-rt: fork failed for %s: %s\n", path.c_str(), strerror(errno));
    return 0;
  }
  if (pid == 0) {
    run_one(path);
    exit(0);  // a normal exit runs the profile runtime's atexit writer; _exit would drop the data
  }
  int status = 0;
  if (waitpid(pid, &status, 0) < 0) {
    fprintf(stderr, "execute-rt: waitpid failed for %s\n", path.c_str());
    return 0;
  }
  if (WIFSIGNALED(status)) {
    int sig = WTERMSIG(status);
    fprintf(stderr, "execute-rt: CRASH %s (signal %d %s); its coverage is not recorded\n",
            path.c_str(), sig, strsignal(sig));
    if (crash_log_path != nullptr && *crash_log == nullptr) {
      *crash_log = open_crash_log(crash_log_path);
    }
    if (*crash_log != nullptr) {
      fprintf(*crash_log, "%s\tsignal %d %s\n", path.c_str(), sig, strsignal(sig));
      fflush(*crash_log);
    }
    return 1;
  }
  if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
    int code = WEXITSTATUS(status);
    fprintf(stderr, "execute-rt: CRASH %s (exit %d); its coverage is not recorded\n", path.c_str(),
            code);
    if (crash_log_path != nullptr && *crash_log == nullptr) {
      *crash_log = open_crash_log(crash_log_path);
    }
    if (*crash_log != nullptr) {
      fprintf(*crash_log, "%s\texit %d\n", path.c_str(), code);
      fflush(*crash_log);
    }
    return 1;
  }
  return 0;
}

void usage(const char *argv0) {
  fprintf(stderr, "usage: %s [--isolate] [--crash-log FILE] CORPUS_DIR [CORPUS_DIR...]\n", argv0);
  exit(2);
}

}  // namespace

int main(int argc, char **argv) {
  Options opts;
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--isolate") == 0) {
      opts.isolate = true;
    } else if (strcmp(argv[i], "--crash-log") == 0 && i + 1 < argc) {
      opts.crash_log = argv[++i];
    } else if (argv[i][0] == '-' && argv[i][1] == '-' && argv[i][2] != '\0') {
      usage(argv[0]);
    } else {
      opts.dirs.push_back(argv[i]);
    }
  }
  if (opts.dirs.empty()) {
    usage(argv[0]);
  }
  std::vector<std::string> files;
  for (const std::string &dir : opts.dirs) {
    collect(dir, files);
  }
  if (files.empty()) {
    fprintf(stderr, "execute-rt: no input files found; nothing was executed\n");
    return 3;
  }
  FILE *crash_log = nullptr;
  int crashes = 0;
  for (const std::string &path : files) {
    if (opts.isolate) {
      crashes += run_isolated(path, opts.crash_log, &crash_log);
    } else {
      run_one(path);
    }
  }
  if (crash_log != nullptr) {
    fclose(crash_log);
  }
  fprintf(stderr, "execute-rt: replayed %zu input(s)%s\n", files.size(),
          opts.isolate ? (crashes ? ", with crashes" : ", no crashes") : "");
  if (crashes > 0) {
    fprintf(stderr, "execute-rt: %d crashing input(s); see the crash log\n", crashes);
    return crashes > 125 ? 125 : crashes;
  }
  return 0;
}
