# VulnLab Advanced (Multi-Tier Vulnerable Environment)

A comprehensive, reproducible penetration testing laboratory featuring multiple vulnerable web applications, network services, and Active Directory simulation. **Ubuntu** hosts containerized vulnerable applications, **Parrot OS** serves as the primary attacker workstation, and **Windows Server** provides AD/domain services—all isolated in a VirtualBox environment.

> ⚠️ **WARNING**: This lab contains intentionally vulnerable systems. Use only in isolated, controlled environments you own. Never expose to public networks.

---

## Architecture Overview

### Network Topology
```
┌─────────────────────────────────────────────────────────┐
│                   VirtualBox Host-Only                  │
│                   Network: 192.168.56.0/24              │
└─────────────────────────────────────────────────────────┘
         │                    │                    │
    ┌────▼────┐         ┌─────▼─────┐      ┌──────▼──────┐
    │ Parrot  │         │  Ubuntu   │      │  Windows    │
    │ Attacker│◄────────┤  Target   │──────┤  Server     │
    │  .100   │         │   .101    │      │   .102      │
    └─────────┘         └───────────┘      └─────────────┘
```

### Virtual Machines

#### **Parrot OS (Attacker Workstation)** - `192.168.56.100`
- Security-focused Linux distribution
- Pre-installed penetration testing tools
- Anonymous surfing capabilities (AnonSurf)
- Lightweight and privacy-oriented
- Custom exploitation scripts
- Network packet capture capabilities

#### **Ubuntu Server (Target Host)** - `192.168.56.101`
Containerized services:
- **DVWA** (HTTP :8080) - Classic web vulnerabilities
- **OWASP Juice Shop** (HTTP :3000) - Modern web app testing
- **Mutillidae II** (HTTP :8081, HTTPS :8443) - OWASP Top 10
- **WebGoat** (HTTP :8082) - Interactive security lessons
- **bWAPP** (HTTP :8083) - 100+ web vulnerabilities
- **VulnHub's Metasploitable3** (SSH :2222, multiple services)
- **Vulnerable GraphQL** (HTTP :4000)
- **SSRF Lab** (HTTP :5000)

#### **Windows Server 2019/2022 (Optional)** - `192.168.56.102`
- Active Directory Domain Services
- Vulnerable SMB configurations
- Misconfigured permissions
- Weak service accounts

---

## Prerequisites

### Host System Requirements
- **Hypervisor**: Oracle VirtualBox 7.0+
- **CPU**: 8+ threads (Intel VT-x/AMD-V enabled)
- **RAM**: 16GB minimum, 32GB recommended
- **Storage**: 150GB+ free space (SSD recommended)
- **OS**: Windows 10/11, macOS, or Linux

### ISO Downloads
- [Parrot OS Security Edition](https://www.parrotsec.org/download/) (latest)
- [Ubuntu Server 22.04 LTS](https://ubuntu.com/download/server)
- [Windows Server 2019 Evaluation](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2019) (optional)

---

## Step-by-Step Setup

### Phase 1: Network Configuration

#### 1.1 Create Host-Only Network
```bash
# VirtualBox → Tools → Network Manager → Host-only Networks
# Click "Create" and configure:
```

**Settings**:
- **Network Name**: `vboxnet0` (or similar)
- **IPv4 Address**: `192.168.56.1`
- **IPv4 Network Mask**: `255.255.255.0`
- **DHCP Server**: Disabled (we'll use static IPs)

#### 1.2 VM Network Adapters

For **all three VMs**, configure:

| Adapter | Type | Purpose | Network |
|---------|------|---------|---------|
| Adapter 1 | NAT | Internet access (updates) | Default NAT |
| Adapter 2 | Host-Only | Lab isolation | vboxnet0 |

---

### Phase 2: Parrot OS Setup

#### 2.1 Install Parrot OS
1. Create VM: 4GB RAM, 2 CPU cores, 80GB disk
2. Install from ISO (Security Edition recommended)
3. Username: `parrot`, Password: `parrot` (change in production)

#### 2.2 Configure Static IP
```bash
sudo nano /etc/network/interfaces
```

Add:
```bash
auto eth1
iface eth1 inet static
    address 192.168.56.100
    netmask 255.255.255.0
```

Apply changes:
```bash
sudo systemctl restart networking
ip a show eth1
```

#### 2.3 Update System & Install Additional Tools
```bash
# Update Parrot repositories
sudo parrot-upgrade

# Install additional tools not in default Parrot
sudo apt update && sudo apt install -y \
    zaproxy seclists feroxbuster chisel \
    bloodhound neo4j crackmapexec impacket-scripts \
    powershell-empire starkiller enum4linux-ng \
    kerbrute mitm6 responder

# Install additional Python tools
pip3 install --user pypykatz lsassy
```

#### 2.4 Configure Burp Suite
```bash
# Launch Burp (already installed in Parrot)
burpsuite &

# Import CA certificate to browser:
# Burp → Proxy → Options → Import/Export CA Certificate
```

#### 2.5 Enable AnonSurf (Optional - for anonymity)
```bash
# AnonSurf comes pre-installed in Parrot Security
# Start anonymous mode
sudo anonsurf start

# Check status
sudo anonsurf status

# Stop when done testing
sudo anonsurf stop
```

---

### Phase 3: Ubuntu Target Setup

#### 3.1 Install Ubuntu Server
1. Create VM: 4GB RAM, 2 CPU cores, 80GB disk
2. Install Ubuntu Server (minimal installation)
3. Username: `vulnadmin`, Password: `VulnLab2024!`

#### 3.2 Configure Static IP
```bash
sudo nano /etc/netplan/01-netcfg.yaml
```

```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    enp0s3:
      dhcp4: true
    enp0s8:
      addresses:
        - 192.168.56.101/24
      dhcp4: false
```

Apply:
```bash
sudo netplan apply
ip a show enp0s8
```

#### 3.3 Install Docker & Docker Compose
```bash
# Remove old versions
sudo apt remove docker docker-engine docker.io containerd runc

# Install prerequisites
sudo apt update
sudo apt install -y ca-certificates curl gnupg lsb-release

# Add Docker's official GPG key
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
    sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

# Set up repository
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker Engine
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io \
    docker-buildx-plugin docker-compose-plugin

# Enable and start
sudo systemctl enable docker
sudo systemctl start docker

# Add user to docker group
sudo usermod -aG docker $USER
newgrp docker

# Verify
docker --version
docker compose version
```

#### 3.4 Deploy Vulnerable Applications
```bash
mkdir -p ~/vulnlab && cd ~/vulnlab
nano docker-compose.yml
```

**Enhanced `docker-compose.yml`**:
```yaml
version: '3.8'

services:
  # Classic DVWA
  dvwa:
    image: vulnerables/web-dvwa
    container_name: dvwa
    ports:
      - "8080:80"
    environment:
      - MYSQL_ROOT_PASSWORD=dvwa
      - MYSQL_DATABASE=dvwa
      - MYSQL_USER=dvwa
      - MYSQL_PASSWORD=p@ssw0rd
    restart: unless-stopped
    networks:
      - vulnlab

  # Modern JS vulnerabilities
  juiceshop:
    image: bkimminich/juice-shop
    container_name: juiceshop
    ports:
      - "3000:3000"
    restart: unless-stopped
    networks:
      - vulnlab

  # OWASP Top 10
  mutillidae:
    image: bltsec/mutillidae-docker
    container_name: mutillidae
    ports:
      - "8081:80"
      - "8443:443"
    restart: unless-stopped
    networks:
      - vulnlab

  # Interactive lessons
  webgoat:
    image: webgoat/webgoat
    container_name: webgoat
    ports:
      - "8082:8080"
      - "9090:9090"
    environment:
      - WEBGOAT_HOST=0.0.0.0
    restart: unless-stopped
    networks:
      - vulnlab

  # 100+ vulnerabilities
  bwapp:
    image: raesene/bwapp
    container_name: bwapp
    ports:
      - "8083:80"
    restart: unless-stopped
    networks:
      - vulnlab

  # GraphQL vulnerabilities
  vulnerable-graphql:
    image: carvesystems/vulnerable-graphql
    container_name: vulnerable-graphql
    ports:
      - "4000:4000"
    restart: unless-stopped
    networks:
      - vulnlab

  # SSRF practice
  ssrf-lab:
    image: jfloff/alpine-python:3.8
    container_name: ssrf-lab
    command: sh -c "pip install flask requests && python -c 'from flask import Flask, request; import requests; app = Flask(__name__); @app.route(\"/fetch\") \ndef fetch(): url = request.args.get(\"url\"); return requests.get(url).text; app.run(host=\"0.0.0.0\", port=5000)'"
    ports:
      - "5000:5000"
    restart: unless-stopped
    networks:
      - vulnlab

  # Metasploitable3 (Ubuntu)
  metasploitable3:
    image: tleemcjr/metasploitable3
    container_name: metasploitable3
    ports:
      - "2222:22"
      - "21:21"
      - "445:445"
      - "3306:3306"
      - "5432:5432"
      - "6200:6200"
      - "8585:8585"
    restart: unless-stopped
    networks:
      - vulnlab
    privileged: true

networks:
  vulnlab:
    driver: bridge
```

Start the lab:
```bash
docker compose up -d
docker compose ps
docker compose logs -f
```

#### 3.5 Configure Firewall (UFW)
```bash
# Reset UFW
sudo ufw --force reset

# Default policies
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow from Kali only
KALI_IP="192.168.56.100"

sudo ufw allow from $KALI_IP to any port 22 proto tcp comment 'SSH from Kali'
sudo ufw allow from $KALI_IP to any port 8080 proto tcp comment 'DVWA'
sudo ufw allow from $KALI_IP to any port 3000 proto tcp comment 'Juice Shop'
sudo ufw allow from $KALI_IP to any port 8081 proto tcp comment 'Mutillidae HTTP'
sudo ufw allow from $KALI_IP to any port 8443 proto tcp comment 'Mutillidae HTTPS'
sudo ufw allow from $KALI_IP to any port 8082 proto tcp comment 'WebGoat'
sudo ufw allow from $KALI_IP to any port 8083 proto tcp comment 'bWAPP'
sudo ufw allow from $KALI_IP to any port 4000 proto tcp comment 'GraphQL'
sudo ufw allow from $KALI_IP to any port 5000 proto tcp comment 'SSRF Lab'
sudo ufw allow from $KALI_IP to any port 2222 proto tcp comment 'Metasploitable SSH'
sudo ufw allow from $KALI_IP to any port 21 proto tcp comment 'FTP'
sudo ufw allow from $KALI_IP to any port 445 proto tcp comment 'SMB'
sudo ufw allow from $KALI_IP to any port 3306 proto tcp comment 'MySQL'
sudo ufw allow from $KALI_IP to any port 5432 proto tcp comment 'PostgreSQL'

# Enable firewall
sudo ufw enable
sudo ufw status numbered
```

---

### Phase 4: Windows Server AD Setup (Optional)

#### 4.1 Install Windows Server
1. Create VM: 4GB RAM, 2 CPU cores, 80GB disk
2. Install Windows Server 2019/2022
3. Set Administrator password: `P@ssw0rd123!`

#### 4.2 Configure Static IP
```powershell
# PowerShell as Administrator
New-NetIPAddress -InterfaceAlias "Ethernet 2" -IPAddress 192.168.56.102 `
    -PrefixLength 24 -DefaultGateway 192.168.56.1

Set-DnsClientServerAddress -InterfaceAlias "Ethernet 2" `
    -ServerAddresses 192.168.56.102
```

#### 4.3 Install Active Directory
```powershell
# Install AD DS role
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

# Promote to domain controller
Install-ADDSForest `
    -DomainName "vulnlab.local" `
    -DomainNetbiosName "VULNLAB" `
    -SafeModeAdministratorPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) `
    -Force

# Reboot when prompted
```

#### 4.4 Create Vulnerable AD Environment
```powershell
# Create OUs
New-ADOrganizationalUnit -Name "VulnLab Users" -Path "DC=vulnlab,DC=local"
New-ADOrganizationalUnit -Name "VulnLab Computers" -Path "DC=vulnlab,DC=local"

# Create vulnerable users
New-ADUser -Name "SQL Service" -SamAccountName "sqlsvc" `
    -UserPrincipalName "sqlsvc@vulnlab.local" `
    -AccountPassword (ConvertTo-SecureString "MYpassword123#" -AsPlainText -Force) `
    -PasswordNeverExpires $true -Enabled $true `
    -Path "OU=VulnLab Users,DC=vulnlab,DC=local"

New-ADUser -Name "Backup Admin" -SamAccountName "backupadmin" `
    -UserPrincipalName "backupadmin@vulnlab.local" `
    -AccountPassword (ConvertTo-SecureString "backup2024!" -AsPlainText -Force) `
    -PasswordNeverExpires $true -Enabled $true `
    -Path "OU=VulnLab Users,DC=vulnlab,DC=local"

# Add to privileged groups
Add-ADGroupMember -Identity "Backup Operators" -Members backupadmin

# Set SPN for Kerberoasting
setspn -A MSSQLSvc/sqlserver.vulnlab.local:1433 vulnlab\sqlsvc

# Create SMB share with weak permissions
New-Item -Path "C:\Shares\Public" -ItemType Directory
New-SmbShare -Name "Public" -Path "C:\Shares\Public" -FullAccess "Everyone"
```

---

## Testing & Usage

### Initial Connectivity Tests (from Parrot)
```bash
# Ping sweep
nmap -sn 192.168.56.0/24

# Port scan Ubuntu target
nmap -sV -sC -p- 192.168.56.101 -oA ubuntu_scan

# Port scan Windows target (if deployed)
nmap -sV -sC -p- 192.168.56.102 -oA windows_scan
```

### Web Application Access
Open in Parrot's browser (Firefox ESR):

| Application | URL | Default Credentials |
|-------------|-----|---------------------|
| DVWA | http://192.168.56.101:8080 | admin / password |
| Juice Shop | http://192.168.56.101:3000 | (create account) |
| Mutillidae | http://192.168.56.101:8081 | (no auth needed) |
| WebGoat | http://192.168.56.101:8082/WebGoat | (create account) |
| bWAPP | http://192.168.56.101:8083 | bee / bug |
| GraphQL | http://192.168.56.101:4000 | N/A |

### DVWA Initial Setup
1. Navigate to http://192.168.56.101:8080
2. Login: `admin` / `password`
3. Click **Setup/Reset Database**
4. Re-login after database creation
5. Set security level: DVWA Security → Low/Medium/High

### Active Directory Testing (from Parrot)
```bash
# SMB enumeration
crackmapexec smb 192.168.56.102 -u '' -p ''
smbclient -L //192.168.56.102 -N

# Kerberoasting
impacket-GetUserSPNs vulnlab.local/sqlsvc:MYpassword123# \
    -dc-ip 192.168.56.102 -request

# BloodHound data collection
bloodhound-python -d vulnlab.local -u sqlsvc -p 'MYpassword123#' \
    -ns 192.168.56.102 -c all

# Start Neo4j and BloodHound
sudo neo4j console
# In new terminal:
bloodhound
```

---

## Lab Management

### Start All Services
```bash
# Ubuntu
cd ~/vulnlab
docker compose up -d

# Check status
docker compose ps
```

### Stop All Services
```bash
docker compose down
```

### Complete Reset (including data)
```bash
docker compose down -v
docker system prune -af
```

### View Logs
```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f dvwa
```

### Resource Monitoring
```bash
# Ubuntu
docker stats

# Container resource limits (add to docker-compose.yml)
deploy:
  resources:
    limits:
      cpus: '1'
      memory: 512M
```

---

## Advanced Scenarios

### 1. Multi-Stage Attack Chain
```bash
# Reconnaissance
nmap -sV 192.168.56.101 -p-

# Vulnerability scanning
nikto -h http://192.168.56.101:8080

# Exploitation (DVWA SQL injection)
sqlmap -u "http://192.168.56.101:8080/vulnerabilities/sqli/?id=1&Submit=Submit#" \
    --cookie="security=low; PHPSESSID=<session>" --dbs

# Post-exploitation
# Establish reverse shell, pivot to Windows AD
```

### 2. Capture-the-Flag Setup
Create flag files in containers:
```bash
# Ubuntu host
docker exec dvwa sh -c "echo 'FLAG{dvwa_root_access}' > /var/www/html/flag.txt"
docker exec juiceshop sh -c "echo 'FLAG{juice_admin_panel}' > /juice-shop/flag.txt"
```

### 3. Custom Vulnerable Application
Add to `docker-compose.yml`:
```yaml
  custom-app:
    build: ./custom-vuln-app
    ports:
      - "9000:9000"
    networks:
      - vulnlab
```

---

## Troubleshooting

### Port Conflicts
```bash
# Check what's using a port
sudo lsof -i :8080

# Change docker-compose.yml port mapping
# "8084:80" instead of "8080:80"
```

### Docker Container Won't Start
```bash
# Check logs
docker compose logs <service_name>

# Restart individual service
docker compose restart <service_name>

# Force recreate
docker compose up -d --force-recreate <service_name>
```

### Network Connectivity Issues
```bash
# Verify VirtualBox network
VBoxManage list hostonlyifs

# Check Ubuntu routing
ip route show

# Verify UFW isn't blocking
sudo ufw status verbose
sudo ufw allow from 192.168.56.100
```

### DVWA Database Connection Errors
```bash
# Exec into container
docker exec -it dvwa bash

# Check MySQL
mysql -u root -pdvwa -e "SHOW DATABASES;"

# Reset DVWA
docker compose restart dvwa
```

### Windows AD Not Accessible
```powershell
# Check Windows Firewall
Get-NetFirewallProfile | Select Name, Enabled

# Temporarily disable (testing only)
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

# Check DNS
nslookup vulnlab.local
```

---

## Security Best Practices

### ⚠️ Critical Safety Measures

1. **Network Isolation**
   - Never bridge VMs to physical network
   - Use host-only networking exclusively for lab traffic
   - Disable internet on target VMs after setup

2. **Snapshot Management**
   ```bash
   # Take clean snapshot before testing
   VBoxManage snapshot "Ubuntu-Target" take "Clean-State"
   
   # Restore after tests
   VBoxManage snapshot "Ubuntu-Target" restore "Clean-State"
   ```

3. **Regular Updates** (Kali only)
   ```bash
   sudo apt update && sudo apt full-upgrade -y
   ```

4. **Password Hygiene**
   - Change all default passwords
   - Use password manager for tracking
   - Never use these credentials elsewhere

5. **Legal Compliance**
   - Only test systems you own
   - Obtain written authorization for any testing
   - Follow responsible disclosure practices

---

## Backup & Restore

### Export VMs
```bash
# VirtualBox → File → Export Appliance
# Select all VMs, choose .ova format
```

### Clone Configuration
```bash
# Ubuntu
cd ~/vulnlab
tar -czf vulnlab-backup.tar.gz docker-compose.yml

# Kali
# Backup custom scripts and configs
tar -czf kali-configs.tar.gz ~/.bashrc ~/.zshrc ~/scripts
```

---

## Performance Optimization

### Reduce Resource Usage
```yaml
# docker-compose.yml adjustments
services:
  dvwa:
    deploy:
      resources:
        limits:
          memory: 256M
    environment:
      - PHP_MEMORY_LIMIT=128M
```

### VirtualBox Tweaks
```bash
# Increase video memory
VBoxManage modifyvm "Ubuntu-Target" --vram 128

# Enable nested virtualization
VBoxManage modifyvm "Parrot-Attacker" --nested-hw-virt on

# Allocate more CPUs
VBoxManage modifyvm "Ubuntu-Target" --cpus 4
```

---

## Extending the Lab

### Add More Targets
- **OWASP NodeGoat**: Node.js vulnerabilities
- **VulnHub VMs**: Import pre-built vulnerable systems
- **HackTheBox retired machines**: Download .ova files
- **Custom Windows 10**: Simulate workstation attacks

### Monitoring & Logging
```yaml
# Add ELK stack for centralized logging
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.11.0
    ports:
      - "9200:9200"
      
  kibana:
    image: docker.elastic.co/kibana/kibana:8.11.0
    ports:
      - "5601:5601"
```

### CTF Platform Integration
```yaml
  ctfd:
    image: ctfd/ctfd
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=mysql+pymysql://ctfd:ctfd@db/ctfd
```

---

## Learning Resources

### Recommended Path
1. **Web Fundamentals**: Start with DVWA (Low security)
2. **Modern Apps**: Progress to Juice Shop
3. **GraphQL/APIs**: Test vulnerable-graphql
4. **Network Services**: Exploit Metasploitable3
5. **Active Directory**: Practice AD attack paths

### Documentation Links
- [DVWA Guide](https://github.com/digininja/DVWA)
- [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)
- [WebGoat Lessons](https://owasp.org/www-project-webgoat/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

---

## Contributing

To enhance this lab:
1. Fork and create feature branch
2. Test thoroughly in isolated environment
3. Document all changes
4. Submit pull request with detailed description

---

## License

This configuration is provided as-is for educational purposes only.

Individual components retain their respective licenses:
- **DVWA**: GPL-3.0
- **OWASP Juice Shop**: MIT
- **Mutillidae II**: GPL-3.0
- **WebGoat**: LGPL-2.1
- **bWAPP**: CC BY-NC-ND

---

## Acknowledgments

- OWASP Foundation
- Parrot Security Team
- Offensive Security community
- Docker community
- VulnHub & HackTheBox platforms
- Security researchers worldwide

---

## Support

For issues or questions:
- Check Troubleshooting section
- Review container logs: `docker compose logs`
- Verify network configuration: `ip a`
- Search existing GitHub issues
- Create new issue with full error details

**Lab Version**: 2.0  
**Last Updated**: January 2026  
**Tested On**: VirtualBox 7.0, Ubuntu 22.04, Parrot OS 6.1 Security Edition
