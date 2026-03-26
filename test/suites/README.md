Test Suite Manifest Format
==========================

Each .suite file defines one test scenario: a base ROM plus one or more
patches that should all produce the same target when applied.

Format
------

    # Comments start with #
    # Blank lines are ignored

    base:   path/to/base.rom
    sha1:   <expected target SHA1>
    desc:   Human-readable description of this test scenario

    # Then one line per patch:
    # FORMAT | PATH | CONFIDENCE | PROVENANCE
    #
    # CONFIDENCE is one of:
    #   real       — real patch from a real project, used as-is
    #   converted  — real patch applied to get a target, then re-diffed
    #                in a new format by an external tool
    #   synthetic  — target fabricated for testing, then diffed by an
    #                external tool
    #   broken     — known broken, skipped by runner (with reason in provenance)
    #
    # Lines with confidence "broken" are skipped, not counted as failures.

    IPS   | test/dm4y/dm4y-patch.ips | synthetic | Flips
    BPS   | test/dm4y/dm4y-patch.bps | real      | dm4-hacking translation project

Paths are relative to the repository root.

Adding a new test
-----------------

1. Drop the base ROM and patch file(s) somewhere under test/ or homework/
2. Create a .suite file (or add a line to an existing one)
3. Run test/run.sh — the runner discovers all .suite files automatically
