#ifndef MVHDPP_H
#define MVHDPP_H

#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <list>
#include <memory>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>

#if defined(_WIN32) && defined(MVHDPP_DLL)
#if defined(MVHDPP_DLL_EXPORT)
#define MVHDPP_API __declspec(dllexport)
#else
#define MVHDPP_API __declspec(dllimport)
#endif
#else
#define MVHDPP_API
#endif

namespace MVHDPP {

namespace fs = std::filesystem;

constexpr int footer_size = 512L;
constexpr int sparse_size = 1024L;

constexpr int sector_size = 512;

enum class ErrorCode {
	NotVHD = 10,
	NotFile,
	NotFound,
	FileExists,
	InvalidArgs,
	NoAttributes,
	OpenError,
	IOSeek,
	IORead,
	IOWrite,
	Corrupt,
	InvalidSize,
	NoParent,
	UnsupportedBlockSize,
	SectorOutOfRange,
	UseBeforeOpen,
	ReadOnly,
};

enum class BlockSize { Large, Small };

struct MVHDPP_API Geom {
	uint16_t cyl  = 0;
	uint8_t heads = 0;
	uint8_t spt   = 0;

	bool operator==(const Geom& rhs);
	bool operator!=(const Geom& rhs);
	uint32_t num_sectors() const;
	uint64_t size_bytes() const;
};
static_assert(sizeof(Geom) == 4);

class VHD {
	using open_variant = std::variant<VHD, std::error_code>;

public:
	MVHDPP_API  VHD();
	/* Allow move but not copy */
	VHD(const VHD&)            = delete;
	VHD& operator=(const VHD&) = delete;
	VHD(VHD&&)                 = default;
	VHD& operator=(VHD&&)      = default;

	MVHDPP_API std::error_code open(fs::path const& vhd_path, bool read_only = false);

	MVHDPP_API std::error_code create_fixed(fs::path const& vhd_path, Geom const& geom);

	MVHDPP_API std::error_code create_sparse(fs::path const& vhd_path, Geom const& geom,
	                              BlockSize block_size = BlockSize::Large);

	MVHDPP_API std::error_code create_diff(fs::path const& vhd_path, fs::path const& par_path,
	                            BlockSize block_size = BlockSize::Large);

	MVHDPP_API static bool file_is_vhd(std::filebuf& file);
	MVHDPP_API static bool file_is_vhd(std::fstream& file);
	MVHDPP_API static bool file_is_vhd(FILE* file);

	MVHDPP_API std::error_code read_sector(uint32_t const sector_num, void* dest);
	MVHDPP_API std::error_code write_sector(uint32_t const sector_num, const void* src);
	MVHDPP_API Geom get_geometry();

private:
	enum VHDType { Fixed = 2, Sparse = 3, Diff = 4 };

	std::error_code create_diff_sparse(fs::path const& vhd_path,
	                                   VHDType const vhd_type,
	                                   Geom const& geom, BlockSize block_size,
	                                   fs::path const& par_path);
	
	class LRUCache {
	public:
		LRUCache(std::size_t size);

		bool in_cache(const uint64_t key);
		uint8_t* get(const uint64_t key);
		void set(const uint64_t key, const void* val);
		void clear();

	private:
		struct Node {
			uint64_t key;
			uint8_t* val;
		};
		std::list<Node> cache_list;
		std::unordered_map<uint64_t, typename std::list<Node>::iterator> cache_map;
		std::vector<uint8_t> backing_store;
		std::size_t cache_size = 0;

		void move_to_front(typename std::list<Node>::iterator it);
	};

	class IOManager {
	public:
		using ios = std::ios_base;
		IOManager(std::size_t cache_size);

		std::error_code open_file(fs::path path, ios::openmode open_mode);
		std::error_code create_file(fs::path path, uintmax_t size = 0);

		std::filebuf& file();

		std::error_code read_chunk(void* dest, uint64_t chunk, std::streamoff offset);
		std::error_code write_chunk(const void* src, uint64_t chunk,
									std::streamoff offset);
		std::error_code read_bytes(void* dest, uint64_t num_bytes,
								std::streamoff offset,
								ios::seekdir dir = ios::beg);
		std::error_code write_bytes(const void* src, uint64_t num_bytes,
									std::streamoff offset,
									ios::seekdir dir = ios::beg);
		template <typename Structure>
		std::error_code read_structure(Structure& s, std::streamoff offset,
									ios::seekdir dir = ios::beg);
		template <typename Structure>
		std::error_code write_structure(Structure const& s, std::streamoff offset,
										ios::seekdir dir = ios::beg);
		std::streamoff offset_at(std::streamoff rel_offset,
								ios::seekdir dir = ios::beg);
		int flush();
		void next_write_preserve_cache();

	private:
		enum class PrevState { Read, Write, Unknown };
		std::filebuf img;
		LRUCache chunk_cache;

		std::streamoff curr_offset = 0;
		PrevState prev_state       = PrevState::Unknown;
		bool preserve_cache        = false;
	};
	
	struct Uuid {
		std::array<uint8_t, 16> uuid = {0};

		void generate_v4();
		bool operator==(const Uuid& rhs);
		bool operator!=(const Uuid& rhs);
	};
	static_assert(sizeof(Uuid) == 16);

	struct ParentLocEntry {
		std::array<char, 4> plat_code = {0};
		uint32_t plat_data_space      = 0;
		uint32_t plat_data_len        = 0;
		uint32_t reserved             = 0;
		uint64_t plat_data_offset     = 0;
	};
	static_assert(sizeof(ParentLocEntry) == 24);

	struct Footer {
		std::array<char, 8> cookie;
		uint32_t features;
		uint32_t fi_fmt_vers;
		uint64_t data_offset;
		uint32_t timestamp;
		std::array<char, 4> cr_app;
		uint32_t cr_vers;
		std::array<char, 4> cr_host_os;
		uint64_t orig_sz;
		uint64_t curr_sz;
		Geom geom;
		uint32_t disk_type;
		uint32_t checksum;
		Uuid uuid;
		uint8_t saved_st;
		uint8_t reserved[427];

		Footer();

		bool operator==(const Footer& rhs);
		bool operator!=(const Footer& rhs);

		void from_be();
		void to_be();
		uint32_t calc_checksum();
		bool is_valid();
	};
	static_assert(sizeof(Footer) == footer_size);

	struct SparseHeader {
		std::array<char, 8> cookie;
		uint64_t data_offset;
		uint64_t bat_offset;
		uint32_t head_vers;
		uint32_t max_bat_ent;
		uint32_t block_sz;
		uint32_t checksum;
		Uuid par_uuid;
		uint32_t par_timestamp;
		uint32_t reserved_1;
		std::array<char16_t, 256> par_utf16_name;
		std::array<ParentLocEntry, 8> par_loc_entries;
		uint8_t reserved_2[256];

		SparseHeader();
		bool is_valid();
		uint32_t calc_checksum();
		void from_be();
		void to_be();
	};
	static_assert(sizeof(SparseHeader) == sparse_size);

	bool vhd_is_open;
	bool ro;

	Footer footer;
	SparseHeader header;

	int sectors_per_block = 0;

	std::unique_ptr<VHD> parent = nullptr;

	bool parent_is_valid();
	void calc_block_sizes();
	uint32_t calc_block_num(uint32_t sector_num);
	uint32_t calc_sib(uint32_t sector_num);

	/* BAT */
	std::vector<uint32_t> bat;

	std::error_code bat_read_table();
	void bat_create_table();
	std::error_code bat_write_table();
	uint32_t bat_size_sectors();
	uint32_t bat_size_bytes();
	uint32_t bat_total_elements();
	std::error_code bat_create_block(uint32_t block_num);
	bool bat_block_is_sparse(uint32_t block_num);

	bool sparse_header_populated();

	/* File I/O */
	IOManager io;

	std::error_code write_sector_padding(const uint32_t count,
	                                     const std::streamoff offset);

	std::array<uint8_t, sector_size> curr_sb = {0};
	std::error_code sb_get(uint32_t block_num);
	std::error_code sb_save(uint32_t block_num);
	bool sb_test(uint32_t sib);
	void sb_set(uint32_t sib);
};

} // namespace MVHDPP

#endif // MVHDPP_H
