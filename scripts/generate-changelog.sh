#!/usr/bin/env bash
# generate-changelog.sh — produce CHANGELOG.md from git tag history.
#
# Reads the repository's git history and emits a Keep-A-Changelog formatted
# CHANGELOG.md grouped by version tag and conventional-commit type.
#
# Conventions:
#   - Only includes commit types: feat, fix, chore, BREAKING (explicit user
#     choice). ci/test/refactor/docs/style/perf are intentionally excluded as
#     end-user noise. Promote anything security-relevant to chore: or fix:.
#   - Excludes scopes: memory-bank, audit (the same scopes scrubbed from the
#     GitHub mirror) so the public CHANGELOG matches what readers can see.
#   - "Unreleased" section captures commits since the most recent tag.
#   - BREAKING is detected via either `!:` after type or `BREAKING CHANGE:`
#     anywhere in the commit body.
#
# Usage:
#   ./scripts/generate-changelog.sh > CHANGELOG.md          # full backfill
#   ./scripts/generate-changelog.sh --since v0.13.0 > tmp   # incremental

set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/c-premus/mcp-gate}"
SINCE_TAG=""
HEAD_AS=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --since) SINCE_TAG="$2"; shift 2 ;;
    --head-as)
      # Render HEAD as if it were already tagged as this version. Used by
      # version-release.yaml so the CHANGELOG entry for an upcoming release
      # can be committed and included in the same tagged commit.
      HEAD_AS="$2"; shift 2
      ;;
    -h | --help)
      sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

# Excluded scopes — anchored to the start of the subject so a body-mention
# of "memory-bank" in a real code commit doesn't get filtered.
EXCLUDE_RE='^[0-9a-f]+ ([a-z]+\(memory-bank\)|docs\(audit\))'

# List "<hash> <subject>" pairs in range, with the scope filter applied.
list_commits() {
  local range="$1"
  git log "$range" --no-merges --pretty=format:'%h %s' \
    | grep -vE "$EXCLUDE_RE" || true
}

# List "<hash>" for commits whose body contains "BREAKING CHANGE", with the
# scope filter applied.
list_breaking_body() {
  local range="$1"
  git log "$range" --no-merges --pretty=format:'%H%x00%s%x00%b%x1e' \
    | awk -v RS=$'\x1e' -F'\x00' '
        $3 ~ /BREAKING CHANGE/ { print $1 " " $2 }
      ' \
    | grep -vE "$EXCLUDE_RE" || true
}

format_line() {
  # Commit subjects only. Per-commit links would point at Forgejo SHAs which
  # the GitHub mirror rewrites via filter-repo, so the URLs would 404 on the
  # public side. The per-version compare links in the footer still resolve
  # correctly because tags survive the rewrite.
  local hash="$1" subject="$2"
  printf -- '- %s\n' "$subject"
}

# Render a section if it has any commits matching the regex over the range.
print_section() {
  local heading="$1" pattern="$2" range="$3"
  local lines
  lines=$(list_commits "$range" | grep -E "$pattern" || true)
  if [ -n "$lines" ]; then
    printf '\n### %s\n\n' "$heading"
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      hash=${line%% *}
      subject=${line#* }
      format_line "$hash" "$subject"
    done <<< "$lines"
  fi
}

# Render BREAKING section: union of subjects matching `^type(...)!:` and bodies
# containing `BREAKING CHANGE`. De-duplicated by hash.
print_breaking() {
  local range="$1"
  local subj_lines body_lines combined
  subj_lines=$(list_commits "$range" \
                 | grep -E '^[0-9a-f]+ [a-z]+(\(.+\))?!:' || true)
  body_lines=$(list_breaking_body "$range")

  combined=$(printf '%s\n%s\n' "$subj_lines" "$body_lines" \
               | grep -vE '^$' \
               | awk '!seen[$1]++' || true)

  if [ -n "$combined" ]; then
    printf '\n### BREAKING CHANGES\n\n'
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      hash=${line%% *}
      subject=${line#* }
      # Re-shorten body-detected hashes (they're full SHA, %H)
      short=$(git rev-parse --short "$hash" 2>/dev/null || echo "$hash")
      format_line "$short" "$subject"
    done <<< "$combined"
  fi
}

# True (0) if the range has at least one commit matching feat|fix|chore|BREAKING
range_has_changes() {
  local range="$1"
  local has
  has=$(list_commits "$range" \
          | grep -cE '^[0-9a-f]+ (feat|fix|chore)(\(.+\))?!?:' || true)
  if [ "${has:-0}" -gt 0 ]; then return 0; fi
  if [ -n "$(list_breaking_body "$range")" ]; then return 0; fi
  return 1
}

render_version() {
  local heading="$1" range="$2"
  if ! range_has_changes "$range"; then
    return 0
  fi
  printf '\n## %s\n' "$heading"
  print_breaking "$range"
  print_section "Features"    '^[0-9a-f]+ feat(\(.+\))?!?:' "$range"
  print_section "Fixes"       '^[0-9a-f]+ fix(\(.+\))?!?:'  "$range"
  print_section "Maintenance" '^[0-9a-f]+ chore(\(.+\))?!?:' "$range"
}

cat <<'EOF'
# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This file lists end-user-facing changes only — `feat`, `fix`, `chore`, and
`BREAKING`. CI, test, refactor, and docs commits are visible in the git log
but intentionally omitted here to keep the changelog signal-dense.
EOF

mapfile -t TAGS < <(git tag --list 'v*' --sort=-v:refname)

# When --head-as VERSION is set, prepend a synthetic section for HEAD treated
# as that version, dated today, sourced from the range latest-tag..HEAD. The
# real Unreleased section is then suppressed (HEAD is "released").
if [ -n "$HEAD_AS" ] && [ "${#TAGS[@]}" -gt 0 ]; then
  HEAD_DATE=$(date -u +%Y-%m-%d)
  render_version "[${HEAD_AS#v}] - ${HEAD_DATE}" "${TAGS[0]}..HEAD"
elif [ "${#TAGS[@]}" -gt 0 ] && { [ -z "$SINCE_TAG" ] || [ "$SINCE_TAG" = "HEAD" ]; }; then
  render_version "[Unreleased]" "${TAGS[0]}..HEAD"
fi

for ((i = 0; i < ${#TAGS[@]}; i++)); do
  TAG="${TAGS[i]}"
  PREV=""
  if [ $((i + 1)) -lt "${#TAGS[@]}" ]; then
    PREV="${TAGS[$((i + 1))]}"
  fi

  if [ -n "$SINCE_TAG" ] && [ "$TAG" = "$SINCE_TAG" ]; then
    break
  fi

  TAG_DATE=$(git log -1 --format='%ad' --date=short "$TAG")
  VERSION="${TAG#v}"

  if [ -n "$PREV" ]; then
    render_version "[${VERSION}] - ${TAG_DATE}" "${PREV}..${TAG}"
  else
    render_version "[${VERSION}] - ${TAG_DATE}" "$TAG"
  fi
done

printf '\n'
if [ "${#TAGS[@]}" -gt 0 ]; then
  if [ -n "$HEAD_AS" ]; then
    printf '[%s]: %s/compare/%s...%s\n' \
      "${HEAD_AS#v}" "$REPO_URL" "${TAGS[0]}" "$HEAD_AS"
  else
    printf '[Unreleased]: %s/compare/%s...HEAD\n' "$REPO_URL" "${TAGS[0]}"
  fi
  for ((i = 0; i < ${#TAGS[@]} - 1; i++)); do
    printf '[%s]: %s/compare/%s...%s\n' \
      "${TAGS[i]#v}" "$REPO_URL" "${TAGS[$((i + 1))]}" "${TAGS[i]}"
  done
  OLDEST="${TAGS[-1]}"
  printf '[%s]: %s/releases/tag/%s\n' "${OLDEST#v}" "$REPO_URL" "$OLDEST"
fi
