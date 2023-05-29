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

namespace MVHDPP {

namespace fs = std::filesystem;

constexpr int footer_size = 512L;
constexpr int sparse_size = 1024L;

constexpr int sector_size = 512;

/* I/O Cache constants */
constexpr int lru_chunk_size    = 4096;
constexpr int sector_chunk_size = 4096;

constexpr size_t cache_limits_bytes = 512 * 1024;
constexpr size_t lru_cache_limit    = cache_limits_bytes / sector_chunk_size;
constexpr size_t sb_cache_limit     = cache_limits_bytes / 512;

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
	ReadOnly,
};

enum class BlockSize { Large, Small };

template <typename K, typename V>
class LRUCache {
public:

	LRUCache(std::size_t size) : cache_size(size), cache_list {}, cache_map {} {}
	bool in_cache(const K key)
	{
		return cache_map.find(key) != cache_map.end();
	}

	V& get(const K key)
	{
		auto it = cache_map[key];
		move_to_front(it);
		return (*it).second;
	}

	void set(const K key, V const& val)
	{
		if (in_cache(key)) {
			move_to_front(cache_map[key]);
			V& front = cache_list.front().second;
			front    = val;
			return;
		}
		if (cache_map.size() < cache_size) {
			cache_list.emplace_front(std::pair<K, V> {key, V(val)});
			cache_map.emplace(key, cache_list.begin());
		} else {
			auto last = --cache_list.end();
			move_to_front(last);
			cache_map.erase(cache_list.front().first);
			cache_list.front().first  = key;
			cache_list.front().second = val;
			cache_map.try_emplace(key, cache_list.begin());
		}
	}

	void clear()
	{
		cache_map.clear();
		cache_list.clear();
	}

private:
	std::size_t cache_size;
	std::list<std::pair<K, V>> cache_list;
	std::unordered_map<K, typename std::list<std::pair<K, V>>::iterator> cache_map;

	void move_to_front(typename std::list<std::pair<K, V>>::iterator it)
	{
		cache_list.splice(cache_list.begin(), cache_list, it);
	}
};

struct Geom {
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
	/* Allow move but not copy */
	VHD(const VHD&)            = delete;
	VHD& operator=(const VHD&) = delete;
	VHD(VHD&&)                 = default;
	VHD& operator=(VHD&&)      = default;

	static open_variant open(fs::path const& vhd_path, bool read_only = false);

	static open_variant create_fixed(fs::path const& vhd_path, Geom const& geom);

	static open_variant create_sparse(fs::path const& vhd_path, Geom const& geom,
	                                  BlockSize block_size = BlockSize::Large);

	static open_variant create_diff(fs::path const& vhd_path,
	                                fs::path const& par_path,
	                                BlockSize block_size = BlockSize::Large);

	static bool file_is_vhd(std::filebuf& file);
	static bool file_is_vhd(std::fstream& file);
	static bool file_is_vhd(FILE* file);

	std::error_code read_sector(uint32_t const sector_num, void* dest);
	std::error_code write_sector(uint32_t const sector_num, const void* src);
	Geom get_geometry();

private:
	enum VHDType { Fixed = 2, Sparse = 3, Diff = 4 };
	static open_variant create(fs::path const& vhd_path, Geom const& geom,
	                           BlockSize block_size,
	                           fs::path const& par_path, VHDType vhd_type);
	VHD(fs::path const& vhd_path, bool read_only);
	VHD(fs::path const& vhd_path, Geom const& geom);
	VHD(fs::path const& vhd_path, VHDType const vhd_type, Geom const& geom,
	    BlockSize block_size, fs::path const& par_path);
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

	std::filebuf f;
	bool ro;

	Footer footer;
	SparseHeader header;

	int sectors_per_block  = 0;

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
	LRUCache<uint32_t, std::array<uint8_t, sector_chunk_size>> sector_cache;
	LRUCache<uint32_t, std::array<uint8_t, sector_size>> sb_cache;

	bool sector_in_cache(uint32_t sector_num);
	void read_sector_from_cache(uint32_t sector_num, void* dest);
	void write_sector_to_cache(uint32_t sector_num, const void* src);

	bool sb_in_cache(uint32_t block_num);
	bool sb_test(uint32_t block_num, uint32_t sib);
	void sb_set(uint32_t block_num, uint32_t sib);

	std::error_code sb_read_from_file(uint32_t block_num);
	std::error_code sb_write_to_file(uint32_t block_num);

	void clear_caches();
};

} // namespace MVHDPP

#endif // MVHDPP_H
