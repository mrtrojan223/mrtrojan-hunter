#!/bin/bash
# install_missing_tools.sh
# Install all missing bug bounty/recon tools for MrTrojan

set -e

echo "[*] Checking for Go..."
if ! command -v go &> /dev/null; then
    echo "[!] Go is not installed. Many tools require it."
    echo "    Install Go first: https://go.dev/doc/install"
    exit 1
fi

export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin:$HOME/.local/bin

echo "[*] Updating Go environment..."
go env -w GO111MODULE=on

# ─── SUBDOMAIN ENUMERATION ───────────────────────────────────
echo "[*] Installing subfinder..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

echo "[*] Installing assetfinder..."
go install -v github.com/tomnomnom/assetfinder@latest

echo "[*] Installing findomain..."
# findomain is Rust-based, use prebuilt binary
if ! command -v findomain &> /dev/null; then
    curl -LO https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip
    unzip -o findomain-linux.zip -d /tmp/
    chmod +x /tmp/findomain
    sudo mv /tmp/findomain /usr/local/bin/ 2>/dev/null || mv /tmp/findomain $GOPATH/bin/
    rm -f findomain-linux.zip
fi

echo "[*] Installing amass..."
go install -v github.com/owasp-amass/amass/v4/...@latest

echo "[*] Installing dnsx..."
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# ─── HTTP PROBING ────────────────────────────────────────────
echo "[*] Installing httprobe..."
go install -v github.com/tomnomnom/httprobe@latest

# ─── CRAWLING / URL DISCOVERY ────────────────────────────────
echo "[*] Installing katana..."
go install -v github.com/projectdiscovery/katana/cmd/katana@latest

echo "[*] Installing hakrawler..."
go install -v github.com/hakluke/hakrawler@latest

echo "[*] Installing gau (GetAllUrls)..."
go install -v github.com/lc/gau/v2/cmd/gau@latest

# ─── PORT SCANNING ───────────────────────────────────────────
echo "[*] Installing naabu..."
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# ─── PARAMETER DISCOVERY ─────────────────────────────────────
echo "[*] Installing arjun..."
pip3 install arjun 2>/dev/null || pip install arjun

# ─── PATTERN MATCHING / FILTERING ────────────────────────────
echo "[*] Installing gf..."
go install -v github.com/tomnomnom/gf@latest
# Install gf patterns
if [ ! -d "$HOME/.gf" ]; then
    git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf 2>/dev/null || \
    git clone https://github.com/tomnomnom/gf ~/.gf-tmp && cp -r ~/.gf-tmp/examples ~/.gf && rm -rf ~/.gf-tmp
fi

echo "[*] Installing qsreplace..."
go install -v github.com/tomnomnom/qsreplace@latest

# ─── XSS TESTING ─────────────────────────────────────────────
echo "[*] Installing dalfox..."
go install -v github.com/hahwul/dalfox/v2@latest

echo "[*] Installing Gxss..."
go install -v github.com/KathanP19/Gxss@latest

echo "[*] Installing kxss..."
go install -v github.com/Emoe/kxss@latest

# ─── VULNERABILITY SCANNING ──────────────────────────────────
echo "[*] Installing nuclei..."
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates 2>/dev/null || true

echo "[*] Installing subzy..."
go install -v github.com/LukaSikic/subzy@latest
subzy --update 2>/dev/null || true

# ─── SCREENSHOTS ─────────────────────────────────────────────
echo "[*] Installing gowitness..."
go install -v github.com/sensepost/gowitness@latest

# ─── VERIFY ──────────────────────────────────────────────────
echo ""
echo "[*] Verification — checking installed tools:"
for tool in subfinder assetfinder findomain amass dnsx httprobe katana hakrawler gau naabu arjun gf qsreplace dalfox Gxss kxss nuclei subzy gowitness; do
    if command -v $tool &> /dev/null; then
        echo "[+] $tool installed"
    else
        echo "[!] $tool still missing (check PATH or $GOPATH/bin)"
    fi
done

echo ""
echo "[*] Add this to your ~/.bashrc or ~/.zshrc if not already present:"
echo '    export PATH=$PATH:$HOME/go/bin:$HOME/.local/bin'
