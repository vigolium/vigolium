# Real-Environment Validation

Procedures for provisioning real test environments and capturing exploitation evidence. Used by cold verification, PoC construction, and confirmation workflows.

## Mandatory Scope

Real-environment reproduction is required for:
- Cold verification: findings that survive analytical FP checking and meet the active mode's severity gate
- Final PoC construction: all CRITICAL/HIGH findings being promoted to `vigolium-results/findings/`

---

## Environment Types by Project

### Web Applications

Preferred: Docker Compose from repo.

```bash
# Clone and build
git clone <repo-url> target-app
cd target-app
git checkout <vulnerable-commit>

# If docker-compose.yml exists
docker compose up -d

# Verify app serves requests before testing
curl -f http://localhost:8080/healthz || curl -f http://localhost:3000/
```

If no Dockerfile exists, create a minimal one:

```dockerfile
FROM node:20-alpine
WORKDIR /app
COPY . .
RUN npm ci --omit=dev
EXPOSE 3000
CMD ["node", "server.js"]
```

Alternative (cloud VM):

```bash
# DigitalOcean
doctl compute droplet create test-env \
  --image ubuntu-22-04-x64 \
  --size s-1vcpu-1gb \
  --region nyc3 \
  --ssh-keys <key-id> \
  --wait

# Azure
az vm create \
  --resource-group audit-rg \
  --name test-env \
  --image Ubuntu2204 \
  --size Standard_B1s \
  --admin-username auditor \
  --generate-ssh-keys \
  --output json
```

### Libraries

Create a minimal consumer app that uses the library realistically (not designed to trigger the bug). Install at the vulnerable version. Confirm normal usage works before testing.

```bash
# Node.js
mkdir consumer-app && cd consumer-app
npm init -y
npm install <library-name>@<vulnerable-version>
cat > index.js << 'EOF'
const lib = require('<library-name>');
// Normal usage that exercises the relevant API
EOF
node index.js

# Python
python -m venv venv && source venv/bin/activate
pip install <library-name>==<vulnerable-version>
python -c "import <library>; <normal-usage>"
```

The consumer app must reflect real-world usage patterns. Do not construct an artificial harness designed to be exploitable.

### CLI Tools

Install at the vulnerable version in a clean container or VM. Use production-like config and realistic test data. Reproduce via normal CLI interface only.

```bash
# Install in clean container
docker run --rm -it ubuntu:22.04 bash
apt-get update -q && apt-get install -y <tool-deps>
pip install <tool>==<vulnerable-version>   # or npm install -g, go install, etc.

# Production-like config
mkdir -p ~/.config/<tool>
cp /dev/null ~/.config/<tool>/config

# Verify normal operation first
<tool> --version
<tool> <normal-subcommand> <realistic-args>
```

### Protocols and Infrastructure

Provision a VM with realistic network topology. Deploy dependent services. Configure TLS and auth as production would.

```bash
# Azure VM with networking
az group create --name audit-rg --location eastus
az vm create \
  --resource-group audit-rg \
  --name proto-test \
  --image Ubuntu2204 \
  --size Standard_B2s \
  --admin-username auditor \
  --generate-ssh-keys

# Open test port
az vm open-port --resource-group audit-rg --name proto-test --port 8443

# Deploy target service on VM
ssh auditor@<vm-ip> 'sudo apt-get install -y <service-deps> && <service-start-cmd>'
```

---

## Evidence Capture

For every reproduction attempt, capture and store:

1. Setup commands (exact commands run, with output)
2. Pre-exploitation health check (confirms the environment is working normally)
3. Exploitation attempt output (exact command and full stdout/stderr)
4. Impact proof (evidence that the vulnerability had the claimed effect)

Store all evidence under `vigolium-results/real-env-evidence/<finding-slug>/`:

```
vigolium-results/real-env-evidence/<finding-slug>/
  setup.sh          # provisioning commands
  setup.log         # output of setup commands
  healthcheck.log   # pre-exploit health check output
  exploit.sh        # exploitation attempt
  exploit.log       # full output of exploitation attempt
  impact.log        # impact evidence (file read, token, screenshot, etc.)
  env-info.txt      # docker version / OS / tool version used
```

---

## Reproduction Attempt Protocol

1. Run the exploitation attempt as written.
2. If it fails, try up to 3 variations (different payloads, encodings, or parameter positions).
3. Document each variation and its result.
4. If all 3 attempts fail, the finding is not reproduced.

---

## When Blocked

If real-environment reproduction is not feasible (no Docker, no cloud credentials, proprietary dependencies, hardware required), document the specific blocker and annotate the finding:

```
PoC-Status: theoretical
PoC-Block-Reason: <specific reason reproduction was not attempted>
```

Disclose the theoretical status in the final report. Do not silently report unexecuted PoCs as confirmed.

---

## Cleanup

Destroy ephemeral environments after evidence is captured:

```bash
# Docker
docker compose down -v
docker system prune -f

# DigitalOcean
doctl compute droplet delete <droplet-id> --force

# Azure
az group delete --name audit-rg --yes --no-wait
```
