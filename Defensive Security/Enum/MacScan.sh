#!/bin/bash
#
# NSE System Scan (macOS bash version)
#
# - Scans user home directories and trash for files changed within last N days
# - Scans external mounts (/Volumes)
# - Optionally scans file contents for sensitive keywords
#
# Usage:
#   ./OSX-Scan2.sh
#   ./OSX-Scan2.sh -d 30
#   ./OSX-Scan2.sh -d 30 -c -k "nextstar,nse confidential"
#
#

set -uo pipefail  # Removed -e to continue on errors

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
# OS check (Darwin only)
#######################################
OS_TYPE=$(uname)
if [[ "$OS_TYPE" != "Darwin" ]]; then
  echo "This script is intended for macOS (Darwin). Detected: $OS_TYPE" >&2
  exit 1
fi

#######################################
# Logging setup
#######################################
TIMESTAMP=$(date +%Y%m%d_%H%M)
LOG_FILE="/tmp/NSE_SYSTEM_SCAN_${TIMESTAMP}.log"
ERROR_LOG="/tmp/NSE_SYSTEM_SCAN_${TIMESTAMP}_errors.log"

# Log everything to both stdout and log file
exec > >(tee -a "$LOG_FILE") 2>&1

#######################################
# Error tracking
#######################################
ERROR_COUNT=0

log_error() {
  local msg="$1"
  echo "***   [ERROR] $msg" | tee -a "$ERROR_LOG"
  ERROR_COUNT=$((ERROR_COUNT + 1))
}

#######################################
# System info
#######################################
HOSTNAME=$(hostname)
OS_INFO=$(uname -srv 2>/dev/null || uname -a)
CURRENT_USER=${USER:-$(whoami)}

echo
echo "************************************************************"
echo "***   Starting NSE system scan (macOS bash) ..."
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

# stat wrapper (macOS / BSD stat)
get_mtime() {
  local path="$1"
  # Format directly using BSD stat
  stat -f '%Sm' -t '%Y-%m-%d %H:%M:%S' "$path" 2>/dev/null || echo "unknown"
}

# Scan a given directory root
scan_dir() {
  local root="$1"
  local label="$2"

  if [[ ! -d "$root" ]]; then
    log_error "Directory not found or not accessible: $root"
    return 0
  fi

  # Skip NSE_Scripts inspection drive (like Windows version)
  if [[ -d "$root/NSE_Scripts" ]]; then
    echo "***   Skipping $label ($root): NSE Security Team Inspection Drive... Skipping Scanning."
    return 0
  fi

  echo "***   Scanning: $label ($root)"

  # Use process substitution to keep TOTAL_FILES mutable in current shell
  while IFS= read -r -d '' path; do
    # mtime
    local mtime
    if ! mtime=$(get_mtime "$path" 2>/dev/null); then
      log_error "Failed to get mtime for: $path"
      mtime="unknown"
    fi

    printf '%s|%s\n' "$path" "$mtime" >> "$FOUND_LIST" || {
      log_error "Failed to write to FOUND_LIST: $path"
      continue
    }
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
# Scan user home directories (macOS)
#######################################
echo "************************************************************"
echo "***   Scanning home directories for files modified in last $DAYS days..."
echo "************************************************************"

USER_BASES=(/Users/*)

for udir in "${USER_BASES[@]}"; do
  [[ -d "$udir" ]] || continue
  if ! scan_dir "$udir" "$udir"; then
    log_error "Failed to scan directory: $udir"
  fi
done

#######################################
# Scan Trash
#######################################
echo
echo "************************************************************"
echo "***   Scanning Trash ..."
echo "************************************************************"

for udir in "${USER_BASES[@]}"; do
  [[ -d "$udir" ]] || continue

  # Typical macOS Trash
  if [[ -d "$udir/.Trash" ]]; then
    if ! scan_dir "$udir/.Trash" "Trash of $(basename "$udir") (~/.Trash)"; then
      log_error "Failed to scan trash: $udir/.Trash"
    fi
  fi

  # In case some Linux-ish trash exists (e.g. from ports)
  if [[ -d "$udir/.local/share/Trash/files" ]]; then
    if ! scan_dir "$udir/.local/share/Trash/files" "Trash of $(basename "$udir") (~/.local/share/Trash/files)"; then
      log_error "Failed to scan trash: $udir/.local/share/Trash/files"
    fi
  fi
done

#######################################
# Scan additional mount points (external drives, macOS)
#######################################
echo
echo "************************************************************"
echo "***   Scanning additional partitions and external drives..."
echo "************************************************************"

MOUNTS=()

# macOS external volumes
if [[ -d /Volumes ]]; then
  while IFS= read -r mp; do
    MOUNTS+=("$mp")
  done < <(find /Volumes -mindepth 1 -maxdepth 1 -type d 2>/dev/null)
fi

# Deduplicate mounts (bash 3.2 compatible)
if ((${#MOUNTS[@]} > 0)); then
  UNIQUE_MOUNTS=()
  while IFS= read -r mp; do
    UNIQUE_MOUNTS+=("$mp")
  done < <(printf '%s\n' "${MOUNTS[@]}" | sort -u)
  
  for mp in "${UNIQUE_MOUNTS[@]}"; do
    if ! scan_dir "$mp" "External / Additional mount"; then
      log_error "Failed to scan mount point: $mp"
    fi
  done
else
  echo "***   No additional mount points detected under /Volumes."
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

  if ! sort -t'|' -k1,1 "$FOUND_LIST" | awk -F'|' '
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
  '; then
    log_error "Failed to process and display file list"
  fi
else
  echo "***   No relevant files found in home directories, trash, or external mounts."
fi

########################################
# Content scanning (optional) - macOS optimized
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
    # normalize extension to lowercase
    ext=$(printf '%s' "$ext" | tr 'A-Z' 'a-z')

    case "$ext" in
      # Plain text files - direct grep
      txt|log|csv)
        if grep -Einq -- "$KEYWORD_PATTERN" "$path" 2>/dev/null; then
          echo "***   [File]: $path"
          if ! grep -Ein -- "$KEYWORD_PATTERN" "$path" 2>/dev/null | sed 's/^/***      [Line] /' | head -n 20; then
            log_error "Failed to grep content: $path"
          fi
          echo "***"
        fi
        ;;
      
      # Microsoft Office files (new and old formats) - use textutil
      docx|pptx|xlsx|doc|xls|ppt|rtf)
        if command -v textutil >/dev/null 2>&1; then
          tmp_txt=$(mktemp) || {
            log_error "Failed to create temp file for: $path"
            continue
          }
          
          # textutil can convert many formats to plain text
          if textutil -convert txt -stdout "$path" > "$tmp_txt" 2>/dev/null; then
            if [[ -s "$tmp_txt" ]] && grep -Einq -- "$KEYWORD_PATTERN" "$tmp_txt" 2>/dev/null; then
              echo "***   [File]: $path"
              if ! grep -Ein -- "$KEYWORD_PATTERN" "$tmp_txt" 2>/dev/null | head -n 20 | sed 's/^/***      [Line] /'; then
                log_error "Failed to grep textutil output: $path"
              fi
              echo "***"
            fi
          else
            log_error "Failed to convert with textutil: $path"
          fi
          rm -f "$tmp_txt"
        else
          echo "***   [Warning] textutil not found - skipping Office document: $path"
        fi
        ;;
      
      # PDF files
      pdf)
        if command -v pdftotext >/dev/null 2>&1; then
          tmp_pdf_txt=$(mktemp) || {
            log_error "Failed to create temp file for PDF: $path"
            continue
          }
          
          if pdftotext -q "$path" "$tmp_pdf_txt" 2>/dev/null; then
            if grep -Einq -- "$KEYWORD_PATTERN" "$tmp_pdf_txt" 2>/dev/null; then
              echo "***   [File]: $path"
              if ! grep -Ein -- "$KEYWORD_PATTERN" "$tmp_pdf_txt" 2>/dev/null | head -n 20 | sed 's/^/***      [Line] /'; then
                log_error "Failed to grep PDF content: $path"
              fi
              echo "***"
            fi
          else
            log_error "Failed to extract text from PDF: $path"
          fi
          rm -f "$tmp_pdf_txt"
        else
          echo "***   [Warning] pdftotext not found - skipping PDF: $path"
        fi
        ;;
      
      # Images - placeholder for future OCR
      jpg|jpeg|png|tif|tiff|bmp)
        # OCR not implemented yet
        # To add OCR: brew install tesseract
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
printf "***   Total errors encountered: %d\n" "$ERROR_COUNT"
printf "***   Log file: %s\n" "$LOG_FILE"
if [[ -f "$ERROR_LOG" && -s "$ERROR_LOG" ]]; then
  printf "***   Error log: %s\n" "$ERROR_LOG"
fi
printf "************************************************************\n"

#######################################
# Copy log file to location where the script was executed
#######################################

SCRIPT_DIR="$(cd "$(dirname "${$BASH_SOURCE[0]}")" && pwd)"

if [[ -f "$LOG_FILE" ]]; then
	LOG_FILE_NAME="$(basename "$LOG_FILE")"
	DEST_PATH="$SCRIPT_DIR/$LOG_FILE_NAME"
	
	if cp "$LOG_FILE" "$DEST_PATH"; then
		echo "The file successfully copied to: $DEST_PATH"
	else
		echo "Something went wrong while copying the file."
	fi
else
	echo "Cannot find the log file: $LOG_FILE"
fi
		
