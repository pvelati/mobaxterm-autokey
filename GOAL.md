# Project Goal

## Project Status

This repository is intentionally kept public as an **archival and historical project**.

The original author no longer uses MobaXterm or Windows and does not intend to actively maintain this project. The repository is preserved so that the source code, release artifacts, and reverse-engineering work remain available to anyone interested in studying the implementation or creating a fork.

This should **not** be interpreted as an indication of active development, ongoing compatibility, or user support.

## Original Purpose

MobaXterm AutoKey is a small Go utility originally created to automate the generation of a `Custom.mxtpro` file for MobaXterm.

The project was developed as a practical reverse-engineering experiment around MobaXterm's license-file format and Windows executable version information.

The original implementation was intentionally kept small and self-contained:

* Go implementation
* No external Go dependencies
* Windows-specific executable/version handling
* Automatic detection of a MobaXterm executable in the working directory
* Extraction of the executable's version information
* Generation of the resulting license archive

The `1.0.0` release represents the final maintained state of the original project.

## Current Goal

The goal of this repository is now **preservation rather than active development**.

In particular, the repository should:

1. Preserve the original source code and historical implementation.
2. Keep the documentation accurate about the project's maintenance status.
3. Make it clear which behavior belongs to the original implementation and which behavior would need independent validation by a fork.
4. Remain useful as a starting point for future forks or independent research.
5. Avoid creating the expectation that the original author will maintain compatibility with future MobaXterm releases.

## Maintenance Policy

There is no active development roadmap for this repository.

The original author does not plan to:

* provide regular updates;
* maintain compatibility with future MobaXterm releases;
* investigate new versions;
* provide ongoing troubleshooting or user support;
* maintain a feature backlog;
* guarantee that the existing binary continues to work with current or future versions of MobaXterm.

Issues and pull requests may therefore remain unanswered or unattended.

## Forking

Forks are welcome.

Anyone continuing this work should treat the current repository as a **historical baseline**, not as an authoritative implementation for newer software versions.

A fork should maintain its own:

* compatibility information;
* testing strategy;
* release history;
* documentation;
* security and legal review;
* maintenance policy.

Fork maintainers should clearly distinguish their own changes from the original implementation.

## Known Historical Limitations

The original implementation was intentionally minimal and contains assumptions that may not remain valid over time.

Among other things, the current code:

* targets Windows APIs directly;
* expects MobaXterm executables to be available in the current working directory;
* selects the first matching `MobaXterm*.exe` file it finds;
* extracts only the major/minor executable version used by the original implementation;
* writes a fixed output filename, `Custom.mxtpro`;
* contains several values that were fixed for the original use case rather than exposed as general configuration.

These limitations are part of the historical implementation and should not be interpreted as a specification for future versions.

## Reproducibility

The repository should preserve the original source and release artifacts without unnecessary rewrites.

When making archival changes, prefer documentation improvements, provenance information, and reproducibility notes over modifications to the historical implementation.

The objective is to make it possible for someone studying or forking the project to understand:

* what the original program did;
* what assumptions it made;
* which parts are Windows-specific;
* what the original release represented;
* which aspects require independent validation today.

## Legal and Licensing Notice

This repository contains source code released under the license included in the repository.

The existence of this project does not grant any additional rights to MobaXterm or its proprietary software, trademarks, licenses, or intellectual property.

Users and fork maintainers are responsible for determining whether their use of the software is permitted under the applicable MobaXterm license terms and applicable law.

The repository is preserved for historical, research, and software-development purposes and should not be interpreted as legal advice.

## Definition of Done

For the original project, the goal is already complete.

The repository is considered successfully archived when:

* the historical source remains available;
* the final release remains identifiable;
* documentation accurately states that the project is no longer maintained;
* no unsupported compatibility claims are made;
* future contributors can understand the historical scope and limitations;
* forks can be created without depending on the original author for continued maintenance.

## Final Note

This project is intentionally **finished, not abandoned accidentally**.

Its continued public availability is meant to preserve useful technical work and allow others to inspect, learn from, or continue it independently through forks.

