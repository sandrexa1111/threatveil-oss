"""Install pinned scanner binaries, verifying publisher release SHA256 values.

No shell pipe-to-execution or archive extraction of arbitrary paths.
"""
import hashlib
import io
from pathlib import Path
import platform
import tarfile
import urllib.request

LINUX_TOOLS = {
    "gitleaks": ("https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz", "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"),
    "osv-scanner": ("https://github.com/google/osv-scanner/releases/download/v2.5.1/osv-scanner_linux_amd64", "f9f25499a2c8cc367b3af45df2ea7eeca7fbccceab9c35079968f4b3652194be"),
    "trivy": ("https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_Linux-64bit.tar.gz", "2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a"),
    "syft": ("https://github.com/anchore/syft/releases/download/v1.51.1/syft_1.51.1_linux_amd64.tar.gz", "8fcb33017a0dc1058298c923c436d19dfa68ae93968e0b423248542e3afb9fc3"),
}
MAC_TOOLS = {
    "gitleaks": ("https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_darwin_arm64.tar.gz", "b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5"),
    "osv-scanner": ("https://github.com/google/osv-scanner/releases/download/v2.5.1/osv-scanner_darwin_arm64", "75c44d6332f892a1e56286f4105a98ed751ae28d215ca0a8b65cc00d84103054"),
    "trivy": ("https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_macOS-ARM64.tar.gz", "1caada5e0e2091909357c7525d3aa76f4b660b13821bc143b190c7483e31cc11"),
    "syft": ("https://github.com/anchore/syft/releases/download/v1.51.1/syft_1.51.1_darwin_arm64.tar.gz", "ac063af3b9874769deb7ea1e6d76841e68f9e3bb50cd654226fc977de65532c1"),
}
if platform.system() == "Linux" and platform.machine() == "x86_64":
    tools = LINUX_TOOLS
elif platform.system() == "Darwin" and platform.machine() == "arm64":
    tools = MAC_TOOLS
else:
    raise SystemExit("Supported platforms: Linux x86_64 CI, Darwin arm64 development.")
directory = Path(".local/security-bin")
directory.mkdir(parents=True, exist_ok=True)
for name, (url, expected) in tools.items():
    # URLs are fixed publisher HTTPS releases above; no user-selected scheme or location.
    with urllib.request.urlopen(url, timeout=60) as response:  # noqa: S310
        content = response.read()
    if hashlib.sha256(content).hexdigest() != expected:
        raise SystemExit(f"Checksum mismatch: {name}")
    if url.endswith(".tar.gz"):
        with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as archive:
            member = next(member for member in archive.getmembers() if member.name in {name, f"./{name}"} and member.isfile())
            content = archive.extractfile(member).read()
    destination = directory / name
    destination.write_bytes(content)
    destination.chmod(0o755)
    print(f"Verified and installed {name}.")
