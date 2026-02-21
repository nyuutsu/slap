# 035-metadata.sh — metadata preservation for self-conversions
# Converts each overlay format to itself and verifies metadata fields survive.

# Extract a field value from slap info output.
# Strips the field label and leading whitespace from the matched line.
_meta_field() {
  local field="$1"
  echo "$2" | grep -m1 "^${field}:" | sed "s/^${field}:[[:space:]]*//"
}

# Compare a single metadata field between source and converted info output.
_check_meta() {
  local label="$1" field="$2" src_info="$3" conv_info="$4"
  local src_val conv_val
  src_val=$(_meta_field "$field" "$src_info")
  conv_val=$(_meta_field "$field" "$conv_info")
  if [ -z "$src_val" ] && [ -z "$conv_val" ]; then
    bad "$label" "field '$field' absent in both"
  elif [ "$src_val" = "$conv_val" ]; then
    ok "$label"
  else
    bad "$label" "'$src_val' ≠ '$conv_val'"
  fi
}

_run_metadata() {
  echo "--- metadata preservation ---"

  # ---- PPF3→PPF3 ----
  local ppf3_src="$REPO/test/data/stadium2/heavy-diff/patch.ppf"
  local ppf3_label="meta/ppf3→ppf3"
  if ! matches_filter "$ppf3_label" && ! matches_filter "meta" && ! matches_filter "ppf3"; then :
  elif [ ! -f "$ppf3_src" ]; then
    skp "$ppf3_label" "patch not found"
  else
    local ppf3_conv; ppf3_conv=$(mktmp)
    if "$SLAP" convert "$ppf3_src" --to ppf3 -o "$ppf3_conv" >/dev/null 2>&1; then
      local ppf3_si ppf3_ci
      ppf3_si=$("$SLAP" info "$ppf3_src" 2>&1)
      ppf3_ci=$("$SLAP" info "$ppf3_conv" 2>&1)
      _check_meta "$ppf3_label/description" "description" "$ppf3_si" "$ppf3_ci"
      _check_meta "$ppf3_label/undo-data"   "undo data"   "$ppf3_si" "$ppf3_ci"
      _check_meta "$ppf3_label/validation"  "validation"  "$ppf3_si" "$ppf3_ci"
    else
      bad "$ppf3_label" "conversion failed"
    fi
  fi

  # ---- NINJA1→NINJA1 ----
  local ninja1_src="$REPO/test/data/emerald/heavy-diff/patch.ninja1"
  local ninja1_label="meta/ninja1→ninja1"
  if ! matches_filter "$ninja1_label" && ! matches_filter "meta" && ! matches_filter "ninja1"; then :
  elif [ ! -f "$ninja1_src" ]; then
    skp "$ninja1_label" "patch not found"
  else
    local ninja1_conv; ninja1_conv=$(mktmp)
    if "$SLAP" convert "$ninja1_src" --to ninja1 -o "$ninja1_conv" >/dev/null 2>&1; then
      local ninja1_si ninja1_ci
      ninja1_si=$("$SLAP" info "$ninja1_src" 2>&1)
      ninja1_ci=$("$SLAP" info "$ninja1_conv" 2>&1)
      _check_meta "$ninja1_label/source-crc"  "source CRC"  "$ninja1_si" "$ninja1_ci"
      _check_meta "$ninja1_label/source-md5"  "source MD5"  "$ninja1_si" "$ninja1_ci"
      _check_meta "$ninja1_label/source-sha1" "source SHA1" "$ninja1_si" "$ninja1_ci"
    else
      bad "$ninja1_label" "conversion failed"
    fi
  fi

  # ---- APS-N64→APS-N64 ----
  local aps_src="$REPO/test/data/stadium2/heavy-diff/patch.aps.aps"
  local aps_label="meta/aps-n64→aps-n64"
  if ! matches_filter "$aps_label" && ! matches_filter "meta" && ! matches_filter "aps-n64"; then :
  elif [ ! -f "$aps_src" ]; then
    skp "$aps_label" "patch not found"
  else
    local aps_conv; aps_conv=$(mktmp)
    if "$SLAP" convert "$aps_src" --to aps-n64 -o "$aps_conv" >/dev/null 2>&1; then
      local aps_si aps_ci
      aps_si=$("$SLAP" info "$aps_src" 2>&1)
      aps_ci=$("$SLAP" info "$aps_conv" 2>&1)
      _check_meta "$aps_label/dest-size"    "dest size"   "$aps_si" "$aps_ci"
      _check_meta "$aps_label/description"  "description" "$aps_si" "$aps_ci"
    else
      bad "$aps_label" "conversion failed"
    fi
  fi

  # ---- EBP→EBP ----
  local ebp_src="$REPO/test/data/emerald/heavy-diff/patch.ebp.ebp"
  local ebp_label="meta/ebp→ebp"
  if ! matches_filter "$ebp_label" && ! matches_filter "meta" && ! matches_filter "ebp"; then :
  elif [ ! -f "$ebp_src" ]; then
    skp "$ebp_label" "patch not found"
  else
    local ebp_conv; ebp_conv=$(mktmp)
    if "$SLAP" convert "$ebp_src" --to ebp -o "$ebp_conv" >/dev/null 2>&1; then
      local ebp_si ebp_ci
      ebp_si=$("$SLAP" info "$ebp_src" 2>&1)
      ebp_ci=$("$SLAP" info "$ebp_conv" 2>&1)
      _check_meta "$ebp_label/title"       "title"       "$ebp_si" "$ebp_ci"
      _check_meta "$ebp_label/author"      "author"      "$ebp_si" "$ebp_ci"
      _check_meta "$ebp_label/description" "description" "$ebp_si" "$ebp_ci"
    else
      bad "$ebp_label" "conversion failed"
    fi
  fi

  echo ""
}

_run_metadata
