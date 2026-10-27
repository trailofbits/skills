# Checker Framework: Existing Java Tainting Configurations

Recognize a project's configured Tainting Checker and keep its existing trust
policy. It is a qualifier-based static checker, so its findings are native type
errors rather than source-to-sink path reports. Prefer Joern for a new Java setup
unless this checker is already working in the project.

The native annotations bind particular Java values:

```java
import org.checkerframework.checker.tainting.qual.PolyTainted;
import org.checkerframework.checker.tainting.qual.Tainted;
import org.checkerframework.checker.tainting.qual.Untainted;

class Boundary {
    static @Tainted String requestValue() {
        return System.getenv("REQUEST_VALUE");
    }

    static @PolyTainted String relay(@PolyTainted String value) {
        return value;
    }

    static void executeCommand(@Untainted String command) {}

    static void positive() {
        executeCommand(relay(requestValue())); // native argument type error
    }

    static void negative() {
        executeCommand("literal");
    }
}
```

This example declares a shell-sink policy. An arbitrary return from an entrypoint
does not become `@Tainted` because it is reachable. Library declarations can be
modeled in native `.astub` files; use the existing project's annotation processor,
classpath, and stub options rather than rewriting its build.

With the Checker Framework's `javac` wrapper on `PATH`, run a fixture without
executing it:

```bash
javac -version
javac -processor org.checkerframework.checker.tainting.TaintingChecker Boundary.java
```

For external stubs, the native processor option is `-Astubs=boundary.astub`.
Retain compiler diagnostics, processor version, actual compiled sources, and build
failures. A missing processor or dependency error is not a taint finding. The
helper reads native `javac` diagnostic blocks containing `@Tainted` and
`@Untainted`, combining captured stdout/stderr for this backend. Preserve the raw
compiler log; a silent exit-zero compilation has unknown measured coverage and
is limited rather than proof that every project source was analyzed.

`@Untainted` represents the configured trust lattice, not independent HTML, SQL,
and shell kinds. The helper rejects generated sanitizer models for this backend;
do not annotate an HTML encoder's return `@Untainted` and thereby erase SQL taint.
Document an existing universal trust policy as a limitation. Do not introduce
casts or suppressions to force an unsafe argument through the checker.

The positive must produce the expected argument error and the literal case must
compile without it. Require an additional `@PolyTainted` propagation case if
claiming that contract; test side effects separately because polymorphic return
qualifiers do not establish how mutable arguments are updated.

Sources: [Tainting Checker](https://checkerframework.org/manual/manual-Tainting-Checker.html),
[running a checker](https://checkerframework.org/manual/manual-Using-checker.html),
[stub files](https://checkerframework.org/manual/manual-Annotating-libraries.html#stub).
