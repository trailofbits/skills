# Seatbelt Sandboxer

Generate a MacOS Seatbelt configuration that sandboxes the target with the minimum set of permissions necessary for it to operate normally.

**Author:** Spencer Michaels

## When to Use

Use this skill when you need a targeted way to isolate a process on MacOS without using containers. This can be helpful for applications that are themselves trusted, but might execute potentially-untrusted third-party code as part of normal operation (such as Javascript bundlers), or that are at a high risk of supply chain attacks. Running such an application in a restricted sandbox helps reduce the "blast radius" if it is exploited.

This skill should NOT be used to run an untrusted process, since it requires running the target process to profile it in order to determine what permissions are actually needed.

## What It Does

This skill provides a systematic four-step process for sandbox profiling:
1. **Profile a target application** - Identify the actual set of permissions required for the application to run normally.
2. **Generate a minimal Seatbelt profile** - Start from a default-deny profile.
3. **Iteratively expand permissions as needed** - Test the application empirically to identify what calls fail with the minimal profile, and add the needed permissions until the application runs normally.
4. **Create helper scripts if needed** - If the application has multiple subcommands that perform highly different functions (such as "serve" and "build" tasks), create separate Seatbelt configurations for each, and create a helper script to switch configurations based on how the target application is invoked.


## Installation

```
	/plugin install trailofbits/skills/plugins/seatbelt-sandboxer
```
