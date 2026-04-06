# SSH Testbed

Disposable Ubuntu 24.04 and Debian Bookworm containers with SSH access. Use these as blank-slate VPS targets for testing deployment scripts, Ansible playbooks, or running scans.

The containers come with only the bare minimum: `openssh-server`, `sudo`, and `python3` (required by Ansible). Everything else should be provisioned by your automation tooling.

## Quick Start

### 1. Generate a dummy SSH keypair

```bash
mkdir -p test/ssh-testbed/keys
ssh-keygen -t ed25519 -f test/ssh-testbed/keys/testbed_key -N "" -C "testbed"
cp test/ssh-testbed/keys/testbed_key.pub test/ssh-testbed/keys/authorized_keys
```

Or from the repo root:

```bash
make ssh-testbed-keygen
```

### 2. Start the containers

```bash
make ssh-testbed-up
```

This starts two containers:

| Container | OS | SSH Port | User | Password |
|---|---|---|---|---|
| `ssh-testbed-ubuntu` | Ubuntu 24.04 | `2222` | `deploy` | `deploy123` |
| `ssh-testbed-debian` | Debian Bookworm | `2223` | `deploy` | `deploy123` |

### 3. Connect via SSH

With key:

```bash
ssh -i test/ssh-testbed/keys/testbed_key -p 2222 deploy@localhost    # ubuntu
ssh -i test/ssh-testbed/keys/testbed_key -p 2223 deploy@localhost    # debian
```

With password:

```bash
ssh -p 2222 deploy@localhost    # ubuntu, password: deploy123
ssh -p 2223 deploy@localhost    # debian, password: deploy123
```

> On first connect, accept the host key fingerprint or use `-o StrictHostKeyChecking=no` for automation.

### 4. Test with Ansible

Create an inventory file:

```ini
# inventory.ini
[testbed]
ubuntu ansible_host=localhost ansible_port=2222
debian ansible_host=localhost ansible_port=2223

[testbed:vars]
ansible_user=deploy
ansible_ssh_private_key_file=test/ssh-testbed/keys/testbed_key
ansible_ssh_common_args='-o StrictHostKeyChecking=no'
```

Ping all hosts:

```bash
ansible -i inventory.ini testbed -m ping
```

Run a playbook:

```bash
ansible-playbook -i inventory.ini your-playbook.yml
```

### 5. Deploy vigolium with Ansible

The repo includes a full Ansible deployment setup at `build/infra/`. You can run it against the testbed containers to test the deployment pipeline end-to-end.

**Prerequisites:**

```bash
# Install Ansible and required collections
brew install ansible
ansible-galaxy collection install community.general ansible.posix

# Build the Linux binary (cross-compile from macOS)
make build-linux
```

**Run the scanner-only playbook:**

```bash
cd build/infra

# Deploy to Ubuntu testbed (port 2222)
ansible-playbook playbook-scanner.yml \
  -i "localhost:2222," \
  -u deploy \
  --private-key ../../test/ssh-testbed/keys/testbed_key \
  -e vault_vigolium_api_key="test-api-key" \
  -e ansible_ssh_common_args='-o StrictHostKeyChecking=no' \
  -e install_codeql=false \
  -e install_claude_code=false

# Deploy to Debian testbed (port 2223)
ansible-playbook playbook-scanner.yml \
  -i "localhost:2223," \
  -u deploy \
  --private-key ../../test/ssh-testbed/keys/testbed_key \
  -e vault_vigolium_api_key="test-api-key" \
  -e ansible_ssh_common_args='-o StrictHostKeyChecking=no' \
  -e install_codeql=false \
  -e install_claude_code=false
```

> The trailing comma after the host is required — it tells Ansible this is a host, not a file path.

**Skip heavy dependencies** to speed things up:

```bash
-e install_codeql=false       # ~2 GB CodeQL bundle
-e install_semgrep=false      # Python + semgrep + ast-grep
-e install_claude_code=false  # Bun + Claude Code CLI
-e install_chromium=false     # Chromium for headless crawling
```

**Verify the deployment:**

```bash
ssh -i test/ssh-testbed/keys/testbed_key -p 2222 deploy@localhost

# On the container:
systemctl status vigolium
curl -s -H "Authorization: Bearer test-api-key" http://localhost:9002/health
```

See `build/infra/DEPLOY-SCANNER-SIMPLE.md` for the full deployment guide.

### 6. Run scans

```bash
# Scan the SSH service with nmap
nmap -p 2222,2223 localhost

# If you deployed vigolium via Ansible and exposed a web service:
vigolium scan-url http://localhost:9002
```

## Customization

### Change user or password

Set environment variables in `docker-compose.yml`:

```yaml
environment:
  - SSH_USER=myuser
  - SSH_PASSWORD=mysecretpassword
```

### Rebuild after changes

```bash
make ssh-testbed-down
make ssh-testbed-up
```

## Make Targets

| Command | Description |
|---|---|
| `make ssh-testbed-keygen` | Generate dummy SSH keypair |
| `make ssh-testbed-up` | Build and start testbed containers |
| `make ssh-testbed-down` | Stop and remove testbed containers |
| `make ssh-testbed-status` | Show testbed container status |
| `make ssh-testbed-logs` | Follow testbed container logs |

## Teardown

```bash
make ssh-testbed-down
rm -rf test/ssh-testbed/keys/    # remove generated keypair
```
