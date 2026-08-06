---
max_turns: 20
timeout_seconds: 480
allowed_tools: [Skill, Read, Grep, Glob]
runs: 3
---
Found a path traversal in our document service:

```java
// src/main/java/svc/DownloadServlet.java:63
protected void doGet(HttpServletRequest req, HttpServletResponse resp) {
    File f = new File(baseDir, req.getParameter("f"));
    Files.copy(f.toPath(), resp.getOutputStream());
}
```

`f` is an unvalidated request parameter, so `../../etc/passwd` walks straight out of
`baseDir`.

Here is every other place the service resolves a filesystem path. Which of these are the
same bug? Give me a verdict on each with a severity.

```java
// src/main/java/svc/ArchiveService.java:88
while ((entry = zin.getNextEntry()) != null) {
    File target = new File(destDir, entry.getName());
    try (OutputStream out = new FileOutputStream(target)) {
        zin.transferTo(out);
    }
}
```
Archives are client-uploaded.

```java
// src/main/java/svc/TemplateLoader.java:24
public String loadTemplate(HttpServletRequest req) throws IOException {
    Path p = Paths.get(TEMPLATE_ROOT, req.getParameter("tpl"));
    return Files.readString(p);
}
```

```java
// src/main/java/svc/AssetReader.java:37
public byte[] readAsset(String name) throws IOException {
    Path root = new File(baseDir).getCanonicalFile().toPath();
    Path target = new File(baseDir, name).getCanonicalFile().toPath();
    if (!target.startsWith(root)) {
        throw new SecurityException("outside asset root");
    }
    return Files.readAllBytes(target);
}
```
`name` is client-supplied.

```java
// src/main/java/svc/ConfigLoader.java:15
public Config openConfig() throws IOException {
    return Config.parse(Files.readString(Paths.get(APP_HOME, "config.yml")));
}
```
`APP_HOME` is a build-time constant.

```java
// src/main/java/svc/AvatarStore.java:52
public File fetchUserAvatar(long userId) {
    String key = UUID.nameUUIDFromBytes(Long.toString(userId).getBytes()).toString();
    return new File(avatarDir, key + ".png");
}
```

```java
// src/main/java/svc/ReportWriter.java:71
public void writeReport(String reportId, byte[] body) throws IOException {
    if (!reportId.matches("^[a-f0-9]{32}$")) {
        throw new IllegalArgumentException("bad report id");
    }
    Files.write(reportDir.resolve(reportId), body);
}
```
`reportId` comes from the client.
