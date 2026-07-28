# Ramdisk editor protocol

Two commands expose the same persistent in-memory CPIO protocol:

```text
ksud ramdisk-editor <ramdisk.cpio>
ksud boot-ramdisk-editor <source.img> <output.img>
```

The boot-image form accepts standard AOSP boot/init_boot header v3-v4 images.
It decompresses the ramdisk directly into the document and rebuilds the image
without creating `kernel`, `ramdisk.cpio`, or other unpacked workspace shards.
The original ramdisk compression and supported AVB footer layout are retained.

Both commands read request frames from standard input and write response frames
to the original standard output. Diagnostic output is redirected to standard
error.

Closing the process without `DUMP` discards all changes. In raw-CPIO mode,
`DUMP` atomically replaces the session CPIO. In boot-image mode it atomically
creates or replaces `output.img`; the source image remains untouched unless the
caller explicitly uses the same path. Neither mode writes a block device by
itself.

## Framing

All integers are unsigned little-endian values. Every request and response
starts with a 20-byte header:

| Field | Type | Value |
| --- | --- | --- |
| magic | 4 bytes | ASCII `YRCP` |
| version | `u16` | `3` |
| opcode | `u16` | request opcode; responses set bit `0x8000` |
| request ID | `u32` | echoed in the response |
| payload size | `u64` | bytes following the header |

Every response payload starts with a `u32` status:

| Value | Meaning |
| --- | --- |
| 0 | OK |
| 1 | invalid request |
| 2 | node not found |
| 3 | operation failed |
| 4 | I/O error |
| 5 | configured limit exceeded |
| 6 | unsupported protocol version |

A string is encoded as `u32 length` followed by exactly that many bytes.
Strings are UTF-8 at the Android boundary. An absent optional string uses
length `0xffffffff`.

## Node record

`STAT` and `LIST` return node records in this order:

```text
u64 id
u64 parent_id
u64 size
u32 inode
u32 mode
u32 uid
u32 gid
u32 nlink
u32 mtime_seconds
u32 dev_major
u32 dev_minor
u32 rdev_major
u32 rdev_minor
u8  synthetic_directory
u8  content_kind
string name
string normalized_path
optional-string symbolic_link_target
```

Local CPIO node ID `0` is the synthetic root of each ramdisk. Wire node IDs
encode the ramdisk index in their high bits, so clients must use the root IDs
returned by `HELLO` and `LIST_RAMDISKS` rather than assuming a wire ID of zero.
IDs remain stable for the lifetime of the process, including across rename and
move operations.

`content_kind` is detected from file contents while servicing `STAT` or
`LIST`. Value `0` means unknown and value `1` means ELF. ELF recognition is
based on the file magic, so a damaged or truncated ELF is still kept out of
the text-decoding path.

## Requests

| Opcode | Name | Request payload | Successful response body |
| ---: | --- | --- | --- |
| 1 | HELLO | empty | `u32 version`, `u64 root_id`, `u64 max_content`, `u64 max_entries`, `u32 capabilities`, `u8 dirty` |
| 2 | STAT | `u64 id` | one node record |
| 3 | LIST | `u64 directory_id` | `u32 count`, then node records |
| 4 | READ | `u64 id`, `u64 offset`, `u64 length` | raw file bytes |
| 5 | REPLACE | `u64 id`, then raw replacement bytes | empty |
| 6 | CREATE_FILE | `u64 parent`, `u32 permissions`, `u32 uid`, `u32 gid`, `string name`, then raw content | `u64 created_id` |
| 7 | CREATE_DIRECTORY | `u64 parent`, `u32 permissions`, `u32 uid`, `u32 gid`, `string name` | `u64 created_id` |
| 8 | CREATE_SYMBOLIC_LINK | `u64 parent`, `u32 uid`, `u32 gid`, `string name`, `string target` | `u64 created_id` |
| 9 | CREATE_HARD_LINK | `u64 parent`, `u64 target_id`, `string name` | `u64 created_id` |
| 10 | COPY | `u64 id`, `u64 destination`, `string new_name` | `u64 created_id` |
| 11 | MOVE | `u64 id`, `u64 destination`, `string new_name` | empty |
| 12 | REMOVE | `u64 id`, `u8 recursive` | empty |
| 13 | UPDATE_METADATA | `u64 id`, `u32 mask`, then selected `u32` values | empty |
| 14 | DUMP | empty | empty |
| 15 | CLOSE | empty | empty, then the process exits |
| 16 | LIST_RAMDISKS | empty | `u32 count`, then ramdisk fragment records |
| 17 | ELF_HEADER | `u64 id` | one versioned, structured ELF header record |

The `HELLO` capability mask uses these bits:

| Bit | Capability |
| ---: | --- |
| 0 | read content |
| 1 | replace content |
| 2 | create regular file |
| 3 | create directory |
| 4 | create symbolic link |
| 5 | create hard link |
| 6 | copy |
| 7 | move or rename |
| 8 | remove |
| 9 | update metadata |
| 10 | atomic dump |
| 11 | ranged read |
| 12 | implicit-directory synthesis |
| 13 | multiple ramdisk fragments |
| 14 | node content types |
| 15 | structured ELF header inspection |

The metadata mask uses bit `1` for permission bits, `2` for UID, `4` for GID,
and `8` for mtime. Values occur in that order when their bits are present.

`ELF_HEADER` version 1 is a fixed 96-byte record. All multibyte wire values are
little-endian regardless of the target ELF encoding:

```text
u16 schema_version = 1
u16 fixed_size = 96
u32 readelf_api_version
u32 header_flags
u32 reserved
u64 file_size
u8  ident[16]
u8  elf_class
u8  data_encoding
u8  ident_version
u8  os_abi
u8  abi_version
u8  reserved[3]
u16 type
u16 machine
u32 elf_version
u64 entry
u64 program_header_offset
u64 section_header_offset
u32 flags
u16 header_size
u16 program_header_entry_size
u16 program_header_count
u16 section_header_entry_size
u16 section_header_count
u16 section_name_index
```

Header flag bits `0`, `1`, and `2` mark extended program-header count,
section-header count, and section-name index encodings respectively. The
backend reads only the class-specific ELF header from the CPIO entry and passes
it to the reentrant structured API exported by `readelf_toyboxAlone`. The
Toybox CLI uses the same decoder. No ROM executable, stdout parsing, or
second ELF parser in `ksud` is involved.

For streamed requests, the frame payload size is authoritative. A producer
must finish writing the complete frame before waiting for its response.
