#pragma once

#include "lkm_image_core.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace ksud::boot::lkm_image {

struct GkiAbiInfo {
    std::optional<std::uint64_t> load_info_structure_size;
    std::uint64_t load_info_storage_size = 256;
    std::uint64_t load_info_hdr_offset = 16;
    std::uint64_t load_info_len_offset = 24;
    std::uint64_t gfp_kernel = 0xcc0;
};

struct InjectionReport {
    std::string kernel_release;
    std::optional<std::size_t> btf_offset;
    std::optional<std::size_t> btf_size;
    std::size_t btf_type_count = 0;
    std::string kallsyms_layout;
    std::size_t kallsyms_count = 0;
    GkiAbiInfo gki_abi;
    std::size_t code_offset = 0;
    std::size_t code_size = 0;
    std::size_t memblock_call_offset = 0;
    std::uint64_t page_offset = 0;
    std::size_t fixup_count = 0;
    std::vector<std::string> unresolved;
    std::size_t image_size = 0;
};

struct InjectionResult {
    std::vector<std::uint8_t> image;
    InjectionReport report;
};

// Mark a KernelSU module as being loaded by the direct image patch path.
Result<void> mark_module_image_patch(std::vector<std::uint8_t>* module);

Result<InjectionResult> inject_image(const std::vector<std::uint8_t>& original_image,
                                     const std::vector<std::uint8_t>& module);

// Replace the module capsule in an image that already contains the direct-LKM
// bootstrap. The existing bootstrap and kernel call-site patches are retained.
Result<InjectionResult> replace_capsule_module(const std::vector<std::uint8_t>& patched_image,
                                               const std::vector<std::uint8_t>& module);

// Remove the direct-LKM capsule and restore the exact pre-patch raw Image when metadata is present.
Result<std::vector<std::uint8_t>> remove_capsule(const std::vector<std::uint8_t>& patched_image);

// Recover the KMI string from a raw kernel banner for embedded asset lookup.
std::optional<std::string> detect_kmi(const std::vector<std::uint8_t>& image);

}  // namespace ksud::boot::lkm_image
