#!/usr/bin/env bash
#
# NSE System Scan (Linux bash version)
#
# - Scans user home directories and trash for files changed within last N days
# - Scans external mounts (/media, /mnt, /run/media, /Volumes)
# - Optionally scans file contents for sensitive keywords
#
# Usage:
#   ./LinuxScan.sh
#   ./LinuxScan.sh -d 30
#   ./LinuxScan.sh -d 30 -c -k "nextstar,nse confidential"
#
# This script was tested on 6.1.0.31-cloud-amd64 (Debian 6.1.128-1)
#

set -euo pipefail

#######################################
# Argument parsing
#######################################
DAYS=56
CONTENT_SCAN=0
KEYWORDS_EXTRA=()

usage() {
  cat <<EOF
Usage: $0 [options]

Options:
  -d <days>     Number of days to look back for modified files (default: 56)
  -c            Enable content scanning (grep-based)
  -k <list>     Comma-separated extra keywords (e.g. "projectx,top secret")
  -h            Show this help

Examples:
  $0
  $0 -d 30
  $0 -d 30 -c -k "nextstar,nse,confidential"
EOF
}

while getopts ":d:ck:h" opt; do
  case "$opt" in
    d) DAYS="$OPTARG" ;;
    c) CONTENT_SCAN=1 ;;
    k)
      IFS=',' read -r -a KEYWORDS_EXTRA <<< "$OPTARG"
      ;;
    h)
      usage
      exit 0
      ;;
    \?)
      echo "Unknown option: -$OPTARG" >&2
      usage
      exit 1
      ;;
    :)
      echo "Option -$OPTARG requires an argument." >&2
      usage
      exit 1
      ;;
  esac
done

#######################################
# Logging setup
#######################################
TIMESTAMP=$(date +%Y%m%d_%H%M)
LOG_FILE="/tmp/NSE_SYSTEM_SCAN_${TIMESTAMP}.log"

# Log everything to both stdout and log file
exec > >(tee -a "$LOG_FILE") 2>&1

#######################################
# System info
#######################################
HOSTNAME=$(hostname)
OS_INFO=$(uname -srv 2>/dev/null || uname -a)
CURRENT_USER=${USER:-$(whoami)}

echo
echo "************************************************************"
echo "***   Starting NSE system scan (bash) ..."
echo "************************************************************"
echo "***   System Name    : $HOSTNAME"
echo "***   OS             : $OS_INFO"
echo "***   Username       : $CURRENT_USER"
echo "***   Days to scan   : $DAYS"
echo "************************************************************"
echo

START_EPOCH=$(date +%s)

# For find -mtime
MTIME_SPEC="-$DAYS"

#######################################
# Helpers
#######################################

# Temp file to store "path|mtime"
FOUND_LIST=$(mktemp)
trap 'rm -f "$FOUND_LIST"' EXIT

TOTAL_FILES=0

# stat wrapper (Linux/macOS)
get_mtime() {
  local path="$1"
  local epoch

  epoch=$(stat -c '%Y' "$path" 2>/dev/null || return 1)
  date -d "@$epoch" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "unknown"

  # local path="$1"
  # if stat --version >/dev/null 2>&1; then
  #   # GNU stat (Linux)
  #   stat -c '%Y-%m-%d %H:%M:%S' "$path"
  # else
  #   # BSD stat (macOS)
  #   stat -f '%Sm' -t '%Y-%m-%d %H:%M:%S' "$path"
  # fi
}

# Scan a given directory root
scan_dir() {
  local root="$1"
  local label="$2"

  [[ -d "$root" ]] || return 0

  # Skip NSE_Scripts inspection drive (like Windows version)
  if [[ -d "$root/NSE_Scripts" ]]; then
    echo "***   Skipping $label ($root): NSE_Scripts detected (inspection drive)."
    return 0
  fi

  echo "***   Scanning: $label ($root)"

  # Use process substitution to keep TOTAL_FILES mutable in current shell
  while IFS= read -r -d '' path; do
    # mtime
    local mtime
    mtime=$(get_mtime "$path" 2>/dev/null || echo "unknown")

    printf '%s|%s\n' "$path" "$mtime" >> "$FOUND_LIST"
    TOTAL_FILES=$((TOTAL_FILES + 1))
  done < <(
    find "$root" \
      \( \
        -name ".cache" -o \
        -name ".Trash" -o \
        -path "*/.local/share/Trash/*" -o \
        -path "*/Library/*" \
      \) -prune -o \
      -type f \
      \( \
        -iname "*.jpg"  -o -iname "*.jpeg" -o \
        -iname "*.tif"  -o -iname "*.tiff" -o \
        -iname "*.png"  -o \
        -iname "*.mp4"  -o -iname "*.mov"  -o \
        -iname "*.docx" -o -iname "*.xlsx" -o -iname "*.pptx" -o \
        -iname "*.txt"  -o -iname "*.pdf"  -o \
        -iname "*.csv"  -o -iname "*.zip" \
      \) \
      -mtime "$MTIME_SPEC" \
      -size +0c \
      -print0 2>/dev/null
  )
}

#######################################
# Define default keywords
#######################################
DEFAULT_KEYWORDS=(
  "confidential"
  "secret"
  "nextstar energy"
  "nse "
  "esst"
)

ALL_KEYWORDS=("${DEFAULT_KEYWORDS[@]}")
if ((${#KEYWORDS_EXTRA[@]} > 0)); then
  ALL_KEYWORDS+=("${KEYWORDS_EXTRA[@]}")
fi

# Build grep regex pattern: word1|word2|...
KEYWORD_PATTERN=""
for kw in "${ALL_KEYWORDS[@]}"; do
  if [[ -z "$KEYWORD_PATTERN" ]]; then
    KEYWORD_PATTERN="$kw"
  else
    KEYWORD_PATTERN="$KEYWORD_PATTERN|$kw"
  fi
done

#######################################
# Scan user home directories
#######################################
OS_TYPE=$(uname)

echo "************************************************************"
echo "***   Scanning home directories for files modified in last $DAYS days..."
echo "************************************************************"

USER_BASES=()

if [[ "$OS_TYPE" == "Darwin" ]]; then
  USER_BASES=(/Users/*)
else
  USER_BASES=(/home/*)
fi

for udir in "${USER_BASES[@]}"; do
  [[ -d "$udir" ]] || continue
  scan_dir "$udir" "$udir"
done

#######################################
# Scan Trash / Recycle Bin equivalents
#######################################
echo
echo "************************************************************"
echo "***   Scanning Trash / Recycle Bin..."
echo "************************************************************"

for udir in "${USER_BASES[@]}"; do
  [[ -d "$udir" ]] || continue

  # Linux typical trash
  if [[ -d "$udir/.local/share/Trash/files" ]]; then
    scan_dir "$udir/.local/share/Trash/files" "Trash of $(basename "$udir") (~/.local/share/Trash/files)"
  fi

  # Generic .Trash
  if [[ -d "$udir/.Trash" ]]; then
    scan_dir "$udir/.Trash" "Trash of $(basename "$udir") (~/.Trash)"
  fi
done

#######################################
# Scan additional mount points (external drives)
#######################################
echo
echo "************************************************************"
echo "***   Scanning additional partitions and external drives..."
echo "************************************************************"

MOUNTS=()

if [[ "$OS_TYPE" == "Darwin" ]]; then
  # macOS external volumes
  if [[ -d /Volumes ]]; then
    while IFS= read -r mp; do
      MOUNTS+=("$mp")
    done < <(find /Volumes -mindepth 1 -maxdepth 1 -type d 2>/dev/null)
  fi
else
  # Linux style mounts
  for base in /media /mnt /run/media; do
    if [[ -d "$base" ]]; then
      while IFS= read -r mp; do
        MOUNTS+=("$mp")
      done < <(find "$base" -mindepth 1 -maxdepth 2 -type d 2>/dev/null)
    fi
  done
fi

# Deduplicate mounts
if ((${#MOUNTS[@]} > 0)); then
  mapfile -t UNIQUE_MOUNTS < <(printf '%s\n' "${MOUNTS[@]}" | sort -u)
  for mp in "${UNIQUE_MOUNTS[@]}"; do
    scan_dir "$mp" "External / Additional mount"
  done
else
  echo "***   No additional mount points detected under /media, /mnt, /run/media, /Volumes."
fi

#######################################
# Print file list grouped by directory
#######################################
echo
echo "************************************************************"
if [[ -s "$FOUND_LIST" ]]; then
  echo "***   Total files found: $TOTAL_FILES"
  echo "***   Directories containing data files:"
  echo "************************************************************"

  sort -t'|' -k1,1 "$FOUND_LIST" | awk -F'|' '
    function print_dir_header(d) {
      print "***"
      printf "***   [DIR] %s\n", d
    }
    {
      path = $1
      mtime = $2
      dir = path
      sub(/\/[^/]+$/, "", dir)
      if (dir == "") dir = "/"
      if (dir != current_dir) {
        current_dir = dir
        print_dir_header(dir)
      }
      printf "***     [FILE] %s - Modified: %s\n", path, mtime
    }
  '
else
  echo "***   No relevant files found in home directories, trash, or external mounts."
fi

#######################################
# Content scanning (optional)
#######################################
if (( CONTENT_SCAN )); then
  echo
  echo "************************************************************"
  echo "***   Scanning file contents for keywords..."
  echo "***   Keywords: ${ALL_KEYWORDS[*]}"
  echo "************************************************************"

  # For each file path in FOUND_LIST
  while IFS='|' read -r path mtime; do
    [[ -f "$path" ]] || continue

    filename=${path##*/}
    ext=${filename##*.}
    # normalize extension to lowercase (portable)
    ext=$(printf '%s' "$ext" | tr 'A-Z' 'a-z')

    case "$ext" in
      txt|log|md|csv|conf|ini|json|xml|html|htm|py|sh|c|cpp|h|java|js|ts)
        if grep -Einq -- "$KEYWORD_PATTERN" "$path" 2>/dev/null; then
          echo "***   [File]: $path"
          grep -Ein -- "$KEYWORD_PATTERN" "$path" 2>/dev/null | sed 's/^/***      [Line &]/' | head -n 20
          echo "***"
        fi
        ;;
      docx|pptx|xlsx)
        if command -v unzip >/dev/null 2>&1; then
          # Rough OOXML text extraction: dump XML, strip tags, grep
          if unzip -p "$path" 2>/dev/null | \
             tr '\r' ' ' | \
             sed 's/<[^>]*>/ /g' | \
             grep -Einq -- "$KEYWORD_PATTERN" 2>/dev/null; then
            echo "***   [File]: $path"
            unzip -p "$path" 2>/dev/null | \
              tr '\r' ' ' | \
              sed 's/<[^>]*>/ /g' | \
              grep -Ein -- "$KEYWORD_PATTERN" 2>/dev/null | head -n 20 | \
              sed 's/^/***      [Line &]/'
            echo "***"
          fi
        fi
        ;;
      pdf)
        if command -v pdftotext >/dev/null 2>&1; then
          tmp_pdf_txt=$(mktemp)
          if pdftotext -q "$path" "$tmp_pdf_txt" 2>/dev/null; then
            if grep -Einq -- "$KEYWORD_PATTERN" "$tmp_pdf_txt" 2>/dev/null; then
              echo "***   [File]: $path"
              grep -Ein -- "$KEYWORD_PATTERN" "$tmp_pdf_txt" 2>/dev/null | head -n 20 | \
                sed 's/^/***      [Line &]/'
              echo "***"
            fi
          fi
          rm -f "$tmp_pdf_txt"
        fi
        ;;
      jpg|jpeg|png|tif|tiff|bmp)
        # OCR not implemented in this bash version.
        # You could integrate tesseract or other CLI OCR engine here if needed.
        ;;
      *)
        # Other extensions: skip for content scan
        ;;
    esac
  done < "$FOUND_LIST"
fi

#######################################
# Finish
#######################################
END_EPOCH=$(date +%s)
ELAPSED=$((END_EPOCH - START_EPOCH))

hours=$((ELAPSED / 3600))
mins=$(((ELAPSED % 3600) / 60))
secs=$((ELAPSED % 60))

printf "\n************************************************************\n"
printf "***   NSE System scan completed.\n"
printf "***   Scan duration: %02d:%02d:%02d\n" "$hours" "$mins" "$secs"
printf "***   Log file: %s\n" "$LOG_FILE"
printf "************************************************************\n"
