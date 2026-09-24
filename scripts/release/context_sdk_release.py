#!/usr/bin/env python3
"""Assemble or verify the exact stable 0.11.0 release using the shared qualified-build gates.

The fixed profile binds the stable version, signing workflow and tag. The existing
beta entrypoint keeps its original identity and cannot verify a stable release.
The shared parser accepts --evidence-dir and rejects it for this explicit-directory command.
"""

from context_distribution_release import main

if __name__ == "__main__":
    main()
