#!/usr/bin/env bash
set -e
#
# Helper script to create patched version of the littlefs
#

##
# Helper log function
##

function log() {
    echo "$*" 1>&2
}

function log_error() {
    log "ERROR: $*"
}

function log_info() {
    log "INFO: $*"
}

##
# Miscellaneous routine function
##

function prepare_dir() {
    local dir_path="$1"
    local cleanup_dir="$2"
    local ret_code=0

    if [[ -z "$dir_path" ]]; then
        log_error "prepare_dir: dir_path isn't set"
        exit 1
    fi

    if [[ ! -e "$dir_path" ]]; then
        mkdir "$dir_path" || ret_code=$?
        if [[ "$ret_code" -ne 0 ]]; then
            log_error "prepare_dir: fail to create directory \"$dir_path\""
            exit "$ret_code"
        fi
    fi

    if [[ "$cleanup_dir" -eq 1 ]]; then
        find "$dir_path" -mindepth 1 -delete || ret_code=$?
        if [[ "$ret_code" -ne 0 ]]; then
            log_error "prepare_dir: fail to cleanup directory \"$dir_path\""
            exit "$ret_code"
        fi
    fi

    return 0
}

function build_path_from_conf() {
    local base_path="$1"
    local conf="$2"
    local index="$3"
    local conf_sep="${4:-:}"

    if [[ -z "$base_path" ]]; then
        log_error "build_path_from_conf: base_path isn't set"
        exit 1
    fi
    if [[ -z "$conf" ]]; then
        log_error "build_path_from_conf: conf isn't set"
        exit 1
    fi
    if [[ -z "$index" ]]; then
        log_error "build_path_from_conf: index isn't set"
        exit 1
    fi

    local conf_values
    IFS="$conf_sep" read -ra conf_values <<<"$conf"
    if [[ "$index" -ge "${#conf_values[@]}" ]]; then
        log_error "Cannot find element $index in the \"$conf\""
        exit 1
    fi

    echo "${base_path%/}/${conf_values[$index]}"
    return 0
}

function join_by() {
    local IFS="$1"
    shift
    echo "$*"
}

##
# Code modification functions
##

function lfs_download() {
    local dst_dir="$1"
    local lfs_url="$2"
    local ret_code
    local unpack_command

    log_info "Download littlefs sources"

    prepare_dir "$dst_dir" 1

    if [[ "$lfs_url" == *.tar.gz ]]; then
        unpack_command=("tar" "-xvz" "--strip-components=1" "-C" "$dst_dir")
    else
        log_error "Non *.tar.gz archive aren't supported now ..."
        return 1
    fi

    curl --show-error --location "$lfs_url" | "${unpack_command[@]}"
    ret_code="$?"

    if [[ "$ret_code" -ne 0 ]]; then
        log_error "Fail to download and unpack littlefs sources"
    fi
    return "$ret_code"
}

function lfs_add_prefix() {
    local src_dir="$1"
    local dst_dir="$2"
    local files_to_process="$3"
    local prefix="$4"

    local file_to_process
    local src_file
    local dst_file
    local prefix_upper="$(tr '[:lower:]' '[:upper:]' <<<"${prefix}")"
    local prefix_lower="$(tr '[:upper:]' '[:lower:]' <<<"${prefix}")"

    echo "$prefix_lower"

    log_info "Add prefixes to lfs files"

    if [[ -z "$files_to_process" ]]; then
        log_error "lfs_add_prefix: files_to_process aren't set"
        exit 1
    fi
    if [[ -z "$prefix" ]]; then
        log_error "lfs_add_prefix: prefix isn't set"
        exit 1
    fi

    prepare_dir "$dst_dir" 1

    IFS="|" read -ra files_to_process <<<"$files_to_process"
    for file_to_process in "${files_to_process[@]}"; do
        src_file="$(build_path_from_conf "$src_dir" "$file_to_process" 0)"
        dst_file="$(build_path_from_conf "$dst_dir" "$file_to_process" 1)"
        log_info "Process: $src_file -> $dst_file"
        sed -e "s/\<lfs/${prefix_lower}lfs/g" -e "s/\<LFS/${prefix_upper}LFS/g" <"$src_file" >"$dst_file"
    done

    return 0
}

function lfs_apply_patch() {
    local src_dir="$1"
    local dst_dir="$2"
    local patch_dir="$3"
    local files_to_process="$4"

    local ret_code
    local file_to_process
    local src_file
    local patch_file
    local dst_file

    log_info "Generate patched littlefs sources"
    prepare_dir "$dst_dir" 1
    prepare_dir "$patch_dir"

    IFS="|" read -ra files_to_process <<<"$files_to_process"
    for file_to_process in "${files_to_process[@]}"; do
        src_file="$(build_path_from_conf "$src_dir" "$file_to_process" 0)"
        patch_file="$(build_path_from_conf "$patch_dir" "$file_to_process" 1)"
        dst_file="$(build_path_from_conf "$dst_dir" "$file_to_process" 2)"

        log_info "Create/update file \"$dst_file\" ..."
        if [[ -e "$patch_file" ]]; then
            # apply patch
            patch --output "$dst_file" "$src_file" "$patch_file"
            ret_code="$?"
        else
            cp "$src_file" "$dst_file"
            ret_code="$?"
        fi
        if [[ "$ret_code" -ne 0 ]]; then
            log_error "Fail to apply patch/copy file: \"$src_file\" -> \"$dst_file\""
            return "$ret_code"
        fi
    done

    return 0
}

function lfs_create_patch() {
    local src_dir="$1"
    local dst_dir="$2"
    local patch_dir="$3"
    local files_to_process="$4"

    local ret_code
    local file_to_process
    local src_file
    local patch_file
    local dst_file

    log_info "Generate littlefs patches"
    prepare_dir "$patch_dir" 1

    IFS="|" read -ra files_to_process <<<"$files_to_process"
    for file_to_process in "${files_to_process[@]}"; do
        src_file="$(build_path_from_conf "$src_dir" "$file_to_process" 0)"
        patch_file="$(build_path_from_conf "$patch_dir" "$file_to_process" 1)"
        dst_file="$(build_path_from_conf "$dst_dir" "$file_to_process" 2)"

        log_info "Create patch \"$patch_file\" ..."
        if [[ ! -e "$src_file" ]]; then
            log_error "Original file \"$src_file\" not found"
            return 1
        fi
        if [[ ! -e "$dst_file" ]]; then
            log_error "Patched file \"$dst_file\" not found"
            return 1
        fi

        # calculate patch
        ret_code=0
        diff -u "$src_file" "$dst_file" >"$patch_file" || ret_code="$?"
        if [[ "$ret_code" -ne 0 && "$ret_code" -ne 1 ]]; then
            log_error "Fail to create patch file \"$patch_file\" ($ret_code)"
            return "$ret_code"
        fi
    done

    return 0
}

##
# Project settings
##

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

source "$SCRIPT_DIR/lfs.env"
RET_CODE="$?"
if [[ "$RET_CODE" -ne 0 ]]; then
    exit "$RET_CODE"
fi

LITTLEFS_URL="$LITTLEFS_GITHUB_REPO/archive/v{$LITTLEFS_VERSISON}.tar.gz"
LITTLEFS_ORIGINAL_SOURCE_DIR="$SCRIPT_DIR/littlefs_original"
LITTLEFS_PREFIX_SOURCE_DIR="$SCRIPT_DIR/littlefs_prefix"
LITTLEFS_PATCHED_SOURCE_DIR="$SCRIPT_DIR/littlefs_patched"
LITTLEFS_PATCHES_SOURCE_DIR="$SCRIPT_DIR/littlefs_patches"
LITTLEFS_CUSTOM_PREFIX="vznncv_"
LITTLEFS_PROCESS_PREFIX_FILES=(
    "lfs_util.h:vznncv_lfs_util.h"
    "lfs_util.c:vznncv_lfs_util.c"
    "lfs.h:vznncv_lfs.h"
    "lfs.c:vznncv_lfs.c"
    "LICENSE.md:LICENSE.md"
)
LITTLEFS_PROCESS_PATCH_FILES=(
    "vznncv_lfs_util.h:vznncv_lfs_util.h.patch:vznncv_lfs_util.h"
    "vznncv_lfs_util.c:vznncv_lfs_util.c.patch:vznncv_lfs_util.c"
    "vznncv_lfs.h:vznncv_lfs.h.patch:vznncv_lfs.h"
    "vznncv_lfs.c:vznncv_lfs.c.patch:vznncv_lfs.c"
    "LICENSE.md:LICENSE.md.patch:LICENSE.md"
)

##
# CLI parsing
##

command="$1"
case "$command" in
generate-sources)
    log_info "Update littlefs sources"
    lfs_download "$LITTLEFS_ORIGINAL_SOURCE_DIR" "$LITTLEFS_URL"
    lfs_add_prefix "$LITTLEFS_ORIGINAL_SOURCE_DIR" "$LITTLEFS_PREFIX_SOURCE_DIR" "$(join_by "|" "${LITTLEFS_PROCESS_PREFIX_FILES[@]}")" "$LITTLEFS_CUSTOM_PREFIX"
    lfs_apply_patch "$LITTLEFS_PREFIX_SOURCE_DIR" "$LITTLEFS_PATCHED_SOURCE_DIR" "$LITTLEFS_PATCHES_SOURCE_DIR" "$(join_by "|" "${LITTLEFS_PROCESS_PATCH_FILES[@]}")"
    log_info "Complete"
    ;;
generate-patches)
    log_info "Generate-patches"
    lfs_create_patch "$LITTLEFS_PREFIX_SOURCE_DIR" "$LITTLEFS_PATCHED_SOURCE_DIR" "$LITTLEFS_PATCHES_SOURCE_DIR" "$(join_by "|" "${LITTLEFS_PROCESS_PATCH_FILES[@]}")"
    log_info "Complete"
    ;;
*)
    log_error "Unknown command: $command"
    ;;
esac
