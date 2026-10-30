#!/bin/sh
# Install or update: curl -fsSL https://raw.githubusercontent.com/paoloanzn/audit-content/main/install.sh | sh
#
# Puts the program in $PREFIX/share/audit-content and the `audit-content` command in $PREFIX/bin
# (default PREFIX=/usr/local, which asks for your password once). `audit-content uninstall` removes both.
# SOURCE_DIR=/path/to/checkout installs from a local copy instead of downloading REPO at REF.
set -eu

REPO="${REPO:-paoloanzn/audit-content}"
REF="${REF:-main}"
PREFIX="${PREFIX:-/usr/local}"
PREFIX="${PREFIX%/}"
APP_DIR="$PREFIX/share/audit-content"
LINK="$PREFIX/bin/audit-content"
TEMPORARY=""
STAGE=""
BACKUP=""
SUDO=""

cleanup() {
  if [ -n "$STAGE" ] && [ -e "$STAGE" ]; then $SUDO rm -rf "$STAGE"; fi
  if [ -n "$BACKUP" ] && [ -e "$BACKUP" ]; then
    if [ ! -e "$APP_DIR" ]; then $SUDO mv "$BACKUP" "$APP_DIR"; else $SUDO rm -rf "$BACKUP"; fi
  fi
  if [ -n "$TEMPORARY" ] && [ -e "$TEMPORARY" ]; then rm -rf "$TEMPORARY"; fi
}

fail() {
  echo "Error: $*" >&2
  exit 1
}

# True when the nearest existing ancestor of $1 is writable without sudo.
writable() {
  d="$1"
  while [ ! -e "$d" ]; do d="$(dirname "$d")"; done
  [ -w "$d" ]
}

main() {
  trap cleanup EXIT
  trap 'exit 130' INT TERM

  if [ "$(uname -s)" != Darwin ] || [ "$(uname -m)" != arm64 ]; then
    fail "audit-content needs a Mac with Apple silicon"
  fi
  if ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 9))' >/dev/null 2>&1; then
    fail "Python 3.9 or later is required (run: xcode-select --install)"
  fi
  if [ -e "$LINK" ] && [ ! -L "$LINK" ]; then
    fail "$LINK already exists and is not a link; move it away first"
  fi

  TEMPORARY="$(mktemp -d)"
  if [ -n "${SOURCE_DIR:-}" ]; then
    src="${SOURCE_DIR%/}"
  else
    curl -fsSL "https://codeload.github.com/$REPO/tar.gz/$REF" -o "$TEMPORARY/repository.tar.gz" \
      || fail "could not download $REPO at $REF"
    tar -xzf "$TEMPORARY/repository.tar.gz" -C "$TEMPORARY"
    src=""
    for candidate in "$TEMPORARY"/*/; do src="${candidate%/}"; break; done
  fi
  for f in audit-content.py context_menu.py telegram.py mail.py known-domains.txt sandbox.py Containerfile; do
    [ -f "$src/$f" ] || fail "missing $f in $src"
  done

  updating=""
  sandbox_changed=""
  if [ -d "$APP_DIR" ]; then
    updating=1
    for f in sandbox.py Containerfile; do
      cmp -s "$src/$f" "$APP_DIR/$f" || sandbox_changed=1
    done
  fi

  if ! writable "$PREFIX/share" || ! writable "$PREFIX/bin"; then
    echo "Installing into $PREFIX needs administrator rights."
    SUDO="sudo"
    # Not `sudo -v`: it asks for a password even when the sudoers rules let commands run without one.
    sudo true || fail "could not get administrator rights"
  fi

  STAGE="$PREFIX/share/.audit-content.new.$$"
  BACKUP="$PREFIX/share/.audit-content.old.$$"
  $SUDO mkdir -p "$PREFIX/share" "$PREFIX/bin"
  $SUDO install -d -m 755 "$STAGE"
  $SUDO install -m 755 "$src/audit-content.py" "$STAGE/audit-content.py"
  $SUDO install -m 644 "$src/context_menu.py" "$src/telegram.py" "$src/mail.py" "$src/known-domains.txt" \
    "$src/sandbox.py" "$src/Containerfile" "$STAGE/"
  # Tells `audit-content uninstall` which command link to remove along with this folder.
  printf '%s\n' "$LINK" | $SUDO tee "$STAGE/.install-link" >/dev/null

  if [ -e "$APP_DIR" ]; then $SUDO mv "$APP_DIR" "$BACKUP"; fi
  $SUDO mv "$STAGE" "$APP_DIR"
  STAGE=""
  $SUDO ln -sfn "$APP_DIR/audit-content.py" "$LINK"
  if [ -e "$BACKUP" ]; then $SUDO rm -rf "$BACKUP"; fi
  BACKUP=""

  if [ -n "$updating" ]; then
    echo "Updated audit-content in $APP_DIR"
    if [ -n "$sandbox_changed" ]; then
      echo "The sandbox changed. Rebuild the image with: audit-content setup --rebuild"
    fi
  else
    echo "Installed audit-content in $APP_DIR, with the command at $LINK"
    echo "Next: audit-content setup   (once, about 8 minutes)"
    echo "      audit-content auth"
  fi
  case ":$PATH:" in
    *":$PREFIX/bin:"*) ;;
    *) echo "Note: $PREFIX/bin is not on your PATH; add it to run audit-content by name." ;;
  esac
}

main "$@"
