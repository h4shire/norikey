#!/usr/bin/env bash
set -euo pipefail

YKBIN="${1:-ykman}"
TEST_SLOT="${NORIKEY_TEST_SLOT:-}"
TEST_CHALLENGE="${NORIKEY_TEST_CHALLENGE:-00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000}"

echo "[1/3] Prüfe, ob '$YKBIN' verfügbar ist ..."
command -v "$YKBIN" >/dev/null 2>&1 || {
  echo "FEHLER: '$YKBIN' wurde nicht gefunden." >&2
  exit 1
}

echo "[2/3] Liste YubiKey-Seriennummern ..."
SERIALS="$($YKBIN list --serials || true)"
if [[ -z "${SERIALS// }" ]]; then
  echo "Keine YubiKeys gefunden oder ykman liefert keine Seriennummern."
  exit 2
fi
printf '%s
' "$SERIALS"

if [[ -z "$TEST_SLOT" ]]; then
  echo "[3/3] Kein Slot-Test angefordert."
  echo "Setze NORIKEY_TEST_SLOT=1 oder 2, um Challenge-Response zu testen."
  echo "Beispiel: NORIKEY_TEST_SLOT=1 bash scripts/check_ykman.sh"
  exit 0
fi

echo "[3/3] Teste Challenge-Response auf Slot $TEST_SLOT ..."
while IFS= read -r SERIAL; do
  [[ -z "$SERIAL" ]] && continue
  echo "- Gerät $SERIAL"
  if "$YKBIN" --device "$SERIAL" otp calculate "$TEST_SLOT" "$TEST_CHALLENGE"; then
    echo "  OK: Slot $TEST_SLOT antwortet auf Gerät $SERIAL"
  else
    echo "  FEHLER: Slot $TEST_SLOT antwortet nicht auf Gerät $SERIAL" >&2
  fi
done <<< "$SERIALS"
