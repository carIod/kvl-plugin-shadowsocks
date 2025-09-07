#!/bin/bash

# Автоматическое определение путей
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="$SCRIPT_DIR/../.."
BUILD_DIR="$SCRIPT_DIR"
OUTPUT_DIR="$WORK_DIR/ipk"
DATA_DIR="$BUILD_DIR/data"
VERSION_FILE="$WORK_DIR/plugins/shadowsocks.sh"

get_version_param() {
    grep -m1 "^VERSION=" "$VERSION_FILE" | cut -d'=' -f2-
}


# ===== Настройки =====
PKG_NAME="kvl-plugin-shadowsocks"
PKG_VERSION=$(get_version_param "APP_VERSION")
PKG_ARCH="all"


# ===== Функция установки прав =====
set_perms() {
    local path="$1"
    local mode="$2"
    
    # Для Cygwin сначала сбрасываем все права
    /bin/chmod 000 "$path" 2>/dev/null
    
    case $mode in
        644) /bin/chmod u+rw-x,go+r-wx "$path" ;;  # -rw-r--r--
        755) /bin/chmod u+rwx,go+rx-w "$path" ;;   # -rwxr-xr-x
        700) /bin/chmod u+rwx,go-rwx "$path" ;;    # -rwx------
    esac
}

# ===== Очистка и подготовка =====
rm -rf "$DATA_DIR" "$BUILD_DIR"/{control,data}.tar.gz "$BUILD_DIR"/*.ipk 2>/dev/null
mkdir -p "$DATA_DIR"/opt/apps/kvl/bin/plugins
mkdir -p "$DATA_DIR"/opt/etc/kvl

# ===== 3. data.tar.gz =====
# Копирование содержимого plugins/
cp -r "$WORK_DIR/plugins/shadowsocks.sh" "$DATA_DIR/opt/apps/kvl/bin/plugins/"
# Копирование содержимого etc
cp -r "$WORK_DIR/plugins/etc/shadowsocks.json" "$DATA_DIR/opt/etc/kvl/shadowsocks.json"

find "$DATA_DIR" -type d -print0 | while IFS= read -r -d $'\0' dir; do
    set_perms "$dir" 755
done

set_perms "$DATA_DIR/opt/etc/kvl/shadowsocks.json" 644
set_perms "$DATA_DIR/opt/apps/kvl/bin/plugins/shadowsocks.sh" 755


# Упаковка data.tar.gz
cd "$DATA_DIR" || exit 1
tar -czf "$BUILD_DIR/data.tar.gz" --owner=0 --group=0 *


# ===== 1. debian-binary =====
echo "2.0" > "$BUILD_DIR/debian-binary"

# ===== 2. control.tar.gz =====
CONTROL_FILE="$BUILD_DIR/control/control"
# Версия
sed -i "s/^Version: .*/Version: ${PKG_VERSION}/" "$CONTROL_FILE"
# Дата сборки (Unix timestamp)
CURRENT_EPOCH=$(date +%s)
sed -i "s/^SourceDateEpoch: .*/SourceDateEpoch: $CURRENT_EPOCH/" "$CONTROL_FILE"
# Считаем размер data/opt и control
SIZE_DATA=$(du -sb "$DATA_DIR" | cut -f1)
SIZE_CONTROL=$(du -sb "$BUILD_DIR/control" | cut -f1)
INSTALLED_SIZE=$((SIZE_DATA + SIZE_CONTROL))
sed -i "s/^Installed-Size: .*/Installed-Size: $INSTALLED_SIZE/" "$CONTROL_FILE"

cd "$BUILD_DIR/control" || exit 1
set_perms control 644
set_perms conffiles 644
set_perms postinst 755
set_perms postrm 755
tar -czf "$BUILD_DIR/control.tar.gz" --owner=0 --group=0 *


# ===== 4. Сборка .ipk =====
cd "$BUILD_DIR" || exit 1
mkdir -p "$OUTPUT_DIR"
tar -czf "$OUTPUT_DIR/${PKG_NAME}_${PKG_VERSION}_${PKG_ARCH}.ipk" \
    debian-binary control.tar.gz data.tar.gz

# Чистка
cd "$BUILD_DIR" || exit 1
rm -rf "$DATA_DIR" control.tar.gz data.tar.gz debian-binary

echo "Готово! Создан:"
echo "  - Пакет: $(cygpath -w "$OUTPUT_DIR/${PKG_NAME}_${PKG_VERSION}_${PKG_ARCH}.ipk")"
