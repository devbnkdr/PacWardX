from . import changes, files, hardening, network, opsec, packages  # noqa: F401

CHECKS = {
    "packages": packages.run,
    "network": network.run,
    "system": hardening.run,
    "files": files.run,
    "changes": changes.run,
    "opsec": opsec.run,
}
