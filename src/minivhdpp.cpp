#include "minivhdpp.h"

#include <algorithm>
#include <cassert>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <random>
#include <string>
#include <string_view>

namespace MVHDPP {

/******************************************
 * Constants
 *****************************************/

/* Entry in Block Allocation Table for a sparse block */
constexpr uint32_t sparse_block_off  = 0xffffffff;
constexpr uint64_t data_offset_unset = 0xffffffffffffffff;

/* Structure signature constants */
constexpr std::string_view footer_sig = "conectix";
constexpr std::string_view sparse_sig = "cxsparse";

/* Block size constants */
constexpr uint32_t block_size_small = 1 << 19;
constexpr uint32_t block_size_large = 1 << 21;

/* Misc constants */
constexpr uint32_t footer_features     = 0x2;
constexpr uint32_t vhd_vers            = 0x00010000;
constexpr uint32_t footer_creator_vers = 0x00000001;

constexpr std::string_view creator_app     = "mvpp";
constexpr std::string_view creator_host_os = "Wi2k";

/* Blocks <= 2MiB have one sector bitmap sector */
constexpr int sb_num_sectors = 1;
constexpr int sb_sector_size = sb_num_sectors * sector_size;

/* Parent locator constants */
constexpr std::string_view plat_code_win_rel = "W2ru";

constexpr std::streamoff footer_offset = footer_size * -1;

/* Error returned by filebuf::pubseekoff */
static const std::filebuf::pos_type pos_err(-1);

/* File modes */
constexpr auto create_mode = std::ios_base::out | std::ios_base::trunc |
                             std::ios_base::binary;
constexpr auto rw_mode = std::ios_base::in | std::ios_base::out |
                         std::ios_base::binary;
constexpr auto ro_mode = std::ios_base::in | std::ios_base::binary;

constexpr std::array<uint8_t, sector_size> zero_data = {0};

/******************************************
 * Error Codes
 *****************************************/

/* Setup custom error codes */
struct VHDErrCat : std::error_category {
	const char* name() const noexcept override
	{
		return "MiniVHD++";
	}
	std::string message(int ec) const override
	{
		switch (static_cast<ErrorCode>(ec)) {
		case ErrorCode::NotVHD: return "not VHD file";
		case ErrorCode::NotFile: return "not regular file";
		case ErrorCode::NotFound: return "file not found";
		case ErrorCode::FileExists: return "file already exists";
		case ErrorCode::InvalidArgs: return "invalid arguments";
		case ErrorCode::NoAttributes:
			return "cannot determine file attributes (permission issue?)";
		case ErrorCode::OpenError: return "error opening file";
		case ErrorCode::IOSeek: return "error seeking file";
		case ErrorCode::IORead: return "error reading file";
		case ErrorCode::IOWrite: return "err writing file";
		case ErrorCode::Corrupt: return "file is corrupt";
		case ErrorCode::InvalidSize: return "file size invalid";
		case ErrorCode::NoParent: return "parent not found";
		case ErrorCode::UnsupportedBlockSize:
			return "unsupported block size";
		case ErrorCode::SectorOutOfRange: return "sector out of range";
		case ErrorCode::ReadOnly: return "write to read only image forbidden";
		default: return "unkown error";
		}
	}
};

const VHDErrCat vhd_error_category{};

std::error_code make_ec(ErrorCode ec)
{
	return std::error_code(static_cast<int>(ec), vhd_error_category);
}

/******************************************
 * Endian Conversion
 *****************************************/

template <typename T>
static inline void be_to_h(T& val)
{
	static_assert(std::is_integral_v<T>, "val must be integral");
	T tmp  = 0;
	auto v = reinterpret_cast<unsigned char*>(&val);
	for (std::size_t i = 0; i < sizeof(T); ++i) {
		tmp |= (static_cast<T>(v[i]) << ((sizeof(T) - 1 - i) * 8));
	}
	val = tmp;
}

template <typename T>
static inline void h_to_be(T& val)
{
	static_assert(std::is_integral_v<T>, "val must be integral");
	const auto size = sizeof(T);
	static_assert(size == 8 || size == 4 || size == 2 || size == 1,
	              "val must be valid integral");
	T temp    = 0;
	auto tmp  = reinterpret_cast<unsigned char*>(&temp);
	int index = 0;
	switch (size) {
	case 8:
		tmp[index++] = (uint8_t)(((uint64_t)val & 0xff00000000000000) >> 56);
		tmp[index++] = (uint8_t)(((uint64_t)val & 0x00ff000000000000) >> 48);
		tmp[index++] = (uint8_t)(((uint64_t)val & 0x0000ff0000000000) >> 40);
		tmp[index++] = (uint8_t)(((uint64_t)val & 0x000000ff00000000) >> 32);
		[[fallthrough]];
	case 4:
		tmp[index++] = (uint8_t)(((uint64_t)val & 0x00000000ff000000) >> 24);
		tmp[index++] = (uint8_t)(((uint64_t)val & 0x0000000000ff0000) >> 16);
		[[fallthrough]];
	case 2:
		tmp[index++] = (uint8_t)(((uint64_t)val & 0x000000000000ff00) >> 8);
		tmp[index++] = (uint8_t)(((uint64_t)val & 0x00000000000000ff) >> 0);
		break;
	case 1: tmp[0] = (uint8_t)val; break;
	}
	val = temp;
}

template <typename... Ts>
static inline void betoh(Ts&&... Args)
{
	(be_to_h(std::forward<Ts>(Args)), ...);
}

template <typename... Ts>
static inline void htobe(Ts&&... Args)
{
	(h_to_be(std::forward<Ts>(Args)), ...);
}

/******************************************
 * Utility functions
 *****************************************/

template <typename F, typename... Ts>
static bool is_one_of(F const& first, Ts const&... args)
{
	return ((first == args) || ...);
}

template <typename T>
static uint32_t calculate_checksum(T const& s, uint32_t& chk_member)
{
	uint32_t orig_chk = chk_member;
	chk_member        = 0;
	auto tmp          = reinterpret_cast<const unsigned char*>(&s);
	uint32_t chk      = 0;
	for (size_t i = 0; i < sizeof(T); ++i) {
		chk += tmp[i];
	}
	chk_member = orig_chk;
	return ~chk;
}

template <int bit_num, typename T>
static inline void set_bit(T& val)
{
	static_assert(std::is_integral_v<T>, "val must be integral");
	static_assert(std::is_unsigned_v<T>, "val must be unsigned");
	val |= static_cast<T>(1) << bit_num;
}

template <int bit_num, typename T>
static inline void clear_bit(T& val)
{
	static_assert(std::is_integral_v<T>, "val must be integral");
	static_assert(std::is_unsigned_v<T>, "val must be unsigned");
	val &= ~(static_cast<T>(1) << bit_num);
}

static inline void set_nibble_upper(uint8_t& val, uint8_t nibble)
{
	val &= 0x0f;
	val |= ((nibble << 4) & 0xf0);
}

/******************************************
 * Structure I/O
 *****************************************/

/* Common function to read bytes from a file */
static std::error_code read_bytes(void* bytes, const size_t size,
                                  std::filebuf& file, const std::streamoff offset,
                                  const std::ios_base::seekdir dir = std::ios_base::beg)
{
	auto ssize = static_cast<std::streamsize>(size);
	auto b     = reinterpret_cast<char*>(bytes);
	if (file.pubseekoff(offset, dir) == pos_err) {
		return make_ec(ErrorCode::IOSeek);
	}
	if (file.sgetn(b, ssize) != ssize) {
		return make_ec(ErrorCode::IORead);
	}
	return std::error_code{};
}

/* Common function to write bytes to a file */
static std::error_code write_bytes(const void* bytes, const size_t size,
                                   std::filebuf& file, const std::streamoff offset,
                                   const std::ios_base::seekdir dir = std::ios_base::beg)
{
	auto ssize = static_cast<std::streamsize>(size);
	auto b     = reinterpret_cast<const char*>(bytes);
	if (file.pubseekoff(offset, dir) == pos_err) {
		return make_ec(ErrorCode::IOSeek);
	}
	if (file.sputn(b, ssize) != ssize) {
		return make_ec(ErrorCode::IOWrite);
	}
	return std::error_code{};
}

/* Writes zero sectors to the file */
static std::error_code write_sector_padding(std::filebuf& file, const uint32_t count,
                                            const std::streamoff offset)
{
	std::error_code ec;
	std::streamoff off = offset;
	for (uint32_t i = 0; i < count; ++i) {
		if ((ec = write_bytes(zero_data.data(), zero_data.size(), file, off))) {
			return ec;
		}
		off += zero_data.size();
	}
	return ec;
}

/* Reads a structure from file into a struct/class
   The struct or class must NOT have padding */
template <typename S>
static std::error_code read_structure(S& structure, std::filebuf& file,
                                      const std::streamoff offset,
                                      const std::ios_base::seekdir dir = std::ios_base::beg)
{
	constexpr auto size = sizeof(S);
	auto b              = reinterpret_cast<void*>(&structure);
	return read_bytes(b, size, file, offset, dir);
}

/* Writes a structure to file from a struct/class
   The struct or class must NOT have padding */
template <typename S>
static std::error_code write_structure(
        S const& structure, std::filebuf& file, const std::streamoff offset,
        const std::ios_base::seekdir dir = std::ios_base::beg)
{
	constexpr auto size = sizeof(S);
	auto b              = reinterpret_cast<const void*>(&structure);
	return write_bytes(b, size, file, offset, dir);
}

/* Check if a buffer contains the "conectix" string */
static bool buffer_has_vhd_id(std::array<char, footer_sig.size()> const& buff)
{
	return std::string_view(buff.data(), buff.size()) == footer_sig;
}

/* Check if the provided filebuf is a VHD */
bool VHD::file_is_vhd(std::filebuf& file)
{
	if (!file.is_open()) {
		return false;
	}
	std::array<char, footer_sig.size()> buff = {};
	file.pubseekoff(footer_offset, std::ios_base::end);
	file.sgetn(buff.data(), footer_sig.size());
	if (buffer_has_vhd_id(buff)) {
		return true;
	}
	/* Try the beginning */
	file.pubseekoff(0, std::ios_base::beg);
	file.sgetn(buff.data(), footer_sig.size());
	return buffer_has_vhd_id(buff);
}

/* Check if the provided fstream is a VHD */
bool VHD::file_is_vhd(std::fstream& file)
{
	return file_is_vhd(*file.rdbuf());
}

/* Test if the FILE* is a VHD */
bool VHD::file_is_vhd(FILE* file)
{
	if (!file) {
		return false;
	}
	std::array<char, footer_sig.size()> buff = {};
	fseek(file, footer_offset, SEEK_END);
	fread(buff.data(), sizeof(char), buff.size(), file);
	if (buffer_has_vhd_id(buff)) {
		return true;
	}
	/* Try the beginning */
	fseek(file, 0, SEEK_SET);
	fread(buff.data(), sizeof(char), buff.size(), file);
	return buffer_has_vhd_id(buff);
}

bool Geom::operator==(const Geom& rhs)
{
	return cyl == rhs.cyl && heads == rhs.heads && spt == rhs.spt;
}

bool Geom::operator!=(const Geom& rhs)
{
	return !(*this == rhs);
}

uint32_t Geom::num_sectors() const
{
	return static_cast<uint32_t>(cyl) * heads * spt;
}

uint64_t Geom::size_bytes() const
{
	return static_cast<uint64_t>(num_sectors()) * sector_size;
}

void VHD::Uuid::generate_v4()
{
	uint64_t seed  = 0;
	seed           = std::random_device{}();
	uint64_t seed2 = std::random_device{}();
	/* There is no guarantee that random_device is truly random
	   Eg: some versions of MinGW have a hardcoded value */
	if (seed == seed2) {
		auto clock = std::chrono::high_resolution_clock::now()
		                     .time_since_epoch()
		                     .count();
		seed = static_cast<uint64_t>(clock);
	}
	std::mt19937_64 mt(seed);
	std::uniform_int_distribution<> dist(0u, 255u);

	/* Generate a v4 (random) UUID */
	for (auto& b : uuid) {
		b = static_cast<uint8_t>(dist(mt));
	}
	clear_bit<6>(uuid[8]);
	set_bit<7>(uuid[8]);
	set_nibble_upper(uuid[6], 4);
}

bool VHD::Uuid::operator==(const Uuid& rhs)
{
	return std::equal(std::begin(uuid),
	                  std::end(uuid),
	                  std::begin(rhs.uuid),
	                  std::end(rhs.uuid));
}

bool VHD::Uuid::operator!=(const Uuid& rhs)
{
	return !(*this == rhs);
}

VHD::Footer::Footer()
        : cookie{},
          features(footer_features),
          fi_fmt_vers(vhd_vers),
          data_offset(data_offset_unset),
          timestamp(0),
          cr_app{},
          cr_vers(footer_creator_vers),
          cr_host_os{},
          orig_sz(0),
          curr_sz(0),
          geom{0},
          disk_type(0),
          checksum(0),
          uuid(),
          saved_st(0),
          reserved{0}
{
	std::copy(footer_sig.begin(), footer_sig.end(), cookie.begin());
	std::copy(creator_app.begin(), creator_app.end(), cr_app.begin());
	std::copy(creator_host_os.begin(), creator_host_os.end(), cr_host_os.begin());
	uuid.generate_v4();
}

bool VHD::Footer::operator==(const Footer& rhs)
{
	/* Note, no padding to mess this up */
	return std::memcmp(this, &rhs, sizeof(*this)) == 0;
}

bool VHD::Footer::operator!=(const Footer& rhs)
{
	return !(*this == rhs);
}

void VHD::Footer::from_be()
{
	betoh(features,
	      fi_fmt_vers,
	      data_offset,
	      timestamp,
	      cr_vers,
	      orig_sz,
	      curr_sz,
	      geom.cyl,
	      disk_type,
	      checksum);
}

void VHD::Footer::to_be()
{
	htobe(features,
	      fi_fmt_vers,
	      data_offset,
	      timestamp,
	      cr_vers,
	      orig_sz,
	      curr_sz,
	      geom.cyl,
	      disk_type,
	      checksum);
}

uint32_t VHD::Footer::calc_checksum()
{
	return calculate_checksum(*this, checksum);
}

/* Perform various checks to see if the footer is valid */
bool VHD::Footer::is_valid()
{
	if (std::string_view(cookie.data(), cookie.size()) != footer_sig ||
	    checksum != calc_checksum() ||
	    !is_one_of(disk_type, VHDType::Fixed, VHDType::Sparse, VHDType::Diff)) {
		return false;
	}
	if (disk_type == VHDType::Fixed && data_offset != data_offset_unset) {
		return false;
	}
	if (disk_type != VHDType::Fixed && data_offset == data_offset_unset) {
		return false;
	}
	if (curr_sz < geom.size_bytes()) {
		return false;
	}
	return true;
}

VHD::SparseHeader::SparseHeader()
        : cookie{},
          data_offset(data_offset_unset),
          bat_offset(0),
          head_vers(vhd_vers),
          max_bat_ent(0),
          block_sz(0),
          checksum(0),
          par_uuid(),
          par_timestamp(0),
          reserved_1(0),
          par_utf16_name{0},
          par_loc_entries{},
          reserved_2{0}
{
	std::copy(sparse_sig.begin(), sparse_sig.end(), cookie.begin());
}

/* Perform various check to see if the sparse header is valid */
bool VHD::SparseHeader::is_valid()
{
	if (std::string_view(cookie.data(), cookie.size()) != sparse_sig ||
	    checksum != calc_checksum() || data_offset != data_offset_unset ||
	    max_bat_ent == 0) {
		return false;
	}
	/* Block size must be a power of two
	 * test adapted from
	 * http://graphics.stanford.edu/~seander/bithacks.html#DetermineIfPowerOf2
	 */
	if (!(block_sz && !(block_sz & (block_sz - 1)))) {
		return false;
	}
	return true;
}

uint32_t VHD::SparseHeader::calc_checksum()
{
	return calculate_checksum(*this, checksum);
}

void VHD::SparseHeader::from_be()
{
	betoh(data_offset,
	      bat_offset,
	      head_vers,
	      max_bat_ent,
	      block_sz,
	      checksum,
	      par_timestamp,
	      reserved_1);
	for (auto& c : par_utf16_name) {
		betoh(c);
	}
	for (auto& p : par_loc_entries) {
		betoh(p.plat_data_space, p.plat_data_len, p.reserved, p.plat_data_offset);
	}
}

void VHD::SparseHeader::to_be()
{
	htobe(data_offset,
	      bat_offset,
	      head_vers,
	      max_bat_ent,
	      block_sz,
	      checksum,
	      par_timestamp,
	      reserved_1);
	for (auto& c : par_utf16_name) {
		htobe(c);
	}
	for (auto& p : par_loc_entries) {
		htobe(p.plat_data_space, p.plat_data_len, p.reserved, p.plat_data_offset);
	}
}

bool VHD::sparse_header_populated()
{
	return header.bat_offset > 0 && header.block_sz > 0 &&
	       header.max_bat_ent > 0;
}

/* Read the BAT from file */
std::error_code VHD::bat_read_table()
{
	assert(sparse_header_populated());
	std::error_code ec;
	bat.resize(bat_total_elements(), sparse_block_off);
	auto b      = reinterpret_cast<char*>(bat.data());
	auto offset = static_cast<std::streamoff>(header.bat_offset);
	if ((ec = read_bytes(b, bat_size_bytes(), f, offset))) {
		return ec;
	}
	for (auto& bat_offset : bat) {
		betoh(bat_offset);
	}
	return ec;
}

/* Create a blank BAT in memory */
void VHD::bat_create_table()
{
	assert(sparse_header_populated());
	bat.resize(bat_total_elements(), sparse_block_off);
}

/* Write the BAT out to file */
std::error_code VHD::bat_write_table()
{
	std::error_code ec;
	assert(sparse_header_populated() && bat.size() == bat_total_elements());
	std::vector<uint32_t> bat_buff = bat;
	for (auto& bat_offset : bat_buff) {
		htobe(bat_offset);
	}
	auto b      = reinterpret_cast<char*>(bat_buff.data());
	auto offset = static_cast<std::streamoff>(header.bat_offset);
	if ((ec = write_bytes(b, bat_size_bytes(), f, offset))) {
		return ec;
	}
	return ec;
}

/* Get the size of the BAT in sectors. Note the BAT
   must be padded to the sector boundary */
uint32_t VHD::bat_size_sectors()
{
	assert(sparse_header_populated());
	uint32_t num_ent_bytes   = header.max_bat_ent * sizeof(uint32_t);
	uint32_t size_in_sectors = num_ent_bytes / sector_size;
	if (num_ent_bytes % sector_size) {
		size_in_sectors++;
	}
	return size_in_sectors;
}

uint32_t VHD::bat_size_bytes()
{
	return bat_size_sectors() * sector_size;
}

uint32_t VHD::bat_total_elements()
{
	return bat_size_bytes() / sizeof(uint32_t);
}

/* Create a new block in a sparse or differencing VHD */
std::error_code VHD::bat_create_block(uint32_t block_num)
{
	assert(sparse_header_populated() && bat.size() == bat_total_elements());
	auto end = std::ios_base::end;
	std::error_code ec;
	std::string footer_cookie("conectix");
	if ((ec = read_bytes(footer_cookie.data(), footer_cookie.size(), f, footer_offset, end))) {
		return ec;
	}
	std::streamoff rel_offset = footer_offset;
	/* if the start of the footer is not in the expected location
	   append the block to the end of the file instead. */
	if (footer_cookie != footer_sig) {
		rel_offset = 0;
	}
	auto pos = std::streamoff(f.pubseekoff(rel_offset, end));
	/* Writes must be aligned to sector boundary, add margin if required */
	auto margin        = pos % sector_size;
	auto offset        = pos + margin;
	auto sector_offset = static_cast<uint32_t>(offset / sector_size);
	/* Read the spare "footer" into memory to write at the end of the file*/
	std::array<char, footer_size> header_buff;
	if ((ec = read_bytes(header_buff.data(), footer_size, f, 0))) {
		return ec;
	}
	/* Write the new sector bitmap + block */
	if (margin > 0) {
		if ((ec = write_bytes(zero_data.data(),
		                      static_cast<std::size_t>(margin),
		                      f,
		                      pos))) {
			return ec;
		}
	}
	for (int i = 0; i < sectors_per_block + sb_num_sectors; ++i) {
		if ((ec = write_bytes(zero_data.data(), zero_data.size(), f, offset))) {
			return ec;
		}
		offset += sector_size;
	}
	/* Append the footer back to the end of the file */
	if ((ec = write_bytes(header_buff.data(), header_buff.size(), f, 0, end))) {
		return ec;
	}
	/* Finally update the block offset and write table */
	bat[block_num] = sector_offset;
	if ((ec = bat_write_table())) {
		return ec;
	}
	return ec;
}

/* A sparse block is not allocated, and therefore the sectors
   it contains are zero sectors */
bool VHD::bat_block_is_sparse(uint32_t block_num)
{
	return bat[block_num] == sparse_block_off;
}

/******************************************
 * I/O Management
 *****************************************/

/* File I/O uses a Least Recently Used (LRU) cache for caching
   sector reads. Sectors are cached in 4KiB chunks. Only reads
   populate the cache. Writes will update the cache if an entry
   exists.

   There is also a LRU cache to manage the sector bitmaps. This
   cache is populated on both reads and writes */

/* Get the 4KiB chunk that a sector is in */
static inline uint32_t calc_chunk_num(uint32_t sector_num)
{
	return (sector_num * sector_size) / lru_chunk_size;
}

/* How many sectors into the chunk is a given sector */
static inline uint32_t offset_in_chunk(uint32_t sector_num)
{
	return (sector_num * sector_size) % lru_chunk_size;
}

/* What is the absolute offset for a given chunk */
static inline std::streamoff abs_chunk_offset(uint32_t chunk_num)
{
	return static_cast<std::streamoff>(chunk_num) * lru_chunk_size;
}

bool VHD::sector_in_cache(uint32_t sector_num)
{
	return sector_cache.in_cache(calc_chunk_num(sector_num));
}

void VHD::read_sector_from_cache(uint32_t sector_num, void* dest)
{
	uint32_t chunk_num = calc_chunk_num(sector_num);
	uint32_t oic       = offset_in_chunk(sector_num);
	auto d             = reinterpret_cast<uint8_t*>(dest);
	auto& chunk        = sector_cache.get(chunk_num);
	memcpy(d, chunk.data() + oic, sector_size);
}

void VHD::write_sector_to_cache(uint32_t sector_num, const void* src)
{
	uint32_t chunk_num = calc_chunk_num(sector_num);
	if (sector_in_cache(sector_num)) {
		uint32_t oic = offset_in_chunk(sector_num);
		auto& chunk  = sector_cache.get(chunk_num);
		auto s       = reinterpret_cast<const uint8_t*>(src);
		memcpy(chunk.data() + oic, s, sector_size);
	}
}

bool VHD::sb_in_cache(uint32_t block_num)
{
	return sb_cache.in_cache(block_num);
}

/* Test for a dirty sector */
bool VHD::sb_test(uint32_t block_num, uint32_t sib)
{
	auto& sb = sb_cache.get(block_num);
	return static_cast<bool>(sb[sib / 8] & (1 << (7 - (sib % 8))));
}

/* Set a sector to be dirty */
void VHD::sb_set(uint32_t block_num, uint32_t sib)
{
	auto& sb = sb_cache.get(block_num);
	sb[sib / 8] |= 1 << (7 - (sib % 8));
}

/* Read the sector bitmap for a block from file */
std::error_code VHD::sb_read_from_file(uint32_t block_num)
{
	std::error_code ec;
	auto sb_offset = static_cast<std::streamoff>(bat[block_num]) * sector_size;
	sb_cache.set(block_num, zero_data);
	if (bat_block_is_sparse(block_num)) {
		return ec;
	}
	auto& cache_ent = sb_cache.get(block_num);
	return read_bytes(cache_ent.data(), cache_ent.size(), f, sb_offset);
}

/* Write the sector bitmap for a block to file */
std::error_code VHD::sb_write_to_file(uint32_t block_num)
{
	std::error_code ec;
	auto sb_offset = static_cast<std::streamoff>(bat[block_num]) * sector_size;
	if (bat_block_is_sparse(block_num) || !sb_in_cache(block_num)) {
		return ec;
	}
	auto& cache_ent = sb_cache.get(block_num);
	return write_bytes(cache_ent.data(), cache_ent.size(), f, sb_offset);
}

/* Clear caches in an emergency */
void VHD::clear_caches()
{
	sector_cache.clear();
	sb_cache.clear();
}

/* Constructor to open an existing VHD image
   Called by VHD::open */
VHD::VHD(fs::path const& vhd_path, bool read_only)
        : f(),
          footer{},
          header{},
		  ro(read_only),
          bat{},
          sector_cache(lru_cache_limit),
          sb_cache(sb_cache_limit)
{
	auto mode = read_only ? ro_mode : rw_mode;
	std::error_code ec;

	/* Sanity check that path points to a valid file */
	auto file_status = fs::status(vhd_path, ec);
	if (ec) {
		throw std::system_error(ec);
	}

	auto ft = file_status.type();
	if (ft == fs::file_type::not_found) {
		throw std::system_error(make_ec(ErrorCode::NotFound));
	} else if (ft == fs::file_type::unknown) {
		throw std::system_error(make_ec(ErrorCode::NoAttributes));
	} else if (ft != fs::file_type::regular) {
		throw std::system_error(make_ec(ErrorCode::NotFile));
	}

	const auto file_size = fs::file_size(vhd_path, ec);
	if (ec) {
		throw std::system_error(ec);
	}

	/* Because this library is likely to perform random I/O, a buffer
	   is not necessary, and simplifies book keeping by not having one */
	f.pubsetbuf(nullptr, 0);

	if (!f.open(vhd_path, mode)) {
		/* Unfortunately a more specific error isn't available */
		throw std::system_error(make_ec(ErrorCode::OpenError));
	}

	if (!VHD::file_is_vhd(f)) {
		throw std::system_error(make_ec(ErrorCode::NotVHD));
	}

	if ((ec = read_structure(footer, f, footer_offset, std::ios_base::end))) {
		throw std::system_error(ec);
	}

	bool end_footer_missing = false;
	if (!buffer_has_vhd_id(footer.cookie)) {
		end_footer_missing = true;
		/* Try the beginning */
		if ((ec = read_structure(footer, f, 0, std::ios_base::beg))) {
			throw std::system_error(ec);
		}
	}

	footer.from_be();

	if (!footer.is_valid()) {
		throw std::system_error(make_ec(ErrorCode::Corrupt));
	}

	/* Fixed VHD images should never be missing the footer */
	if (footer.disk_type == VHDType::Fixed && end_footer_missing) {
		throw std::system_error(make_ec(ErrorCode::Corrupt));
	}
	/* For fixed VHD files, this is all that is required */
	if (footer.disk_type == VHDType::Fixed) {
		// Sanity check the file size
		if (footer.curr_sz + footer_size > file_size) {
			throw std::system_error(make_ec(ErrorCode::InvalidSize));
		}
		return;
	}
	/* Otherwise, continue loading the file */
	Footer backup_footer;
	if ((ec = read_structure(backup_footer, f, 0))) {
		throw std::system_error(ec);
	}
	backup_footer.from_be();
	if (backup_footer != footer) {
		throw std::system_error(make_ec(ErrorCode::Corrupt));
	}

	/* Let's be paranoid */
	if (footer.data_offset == data_offset_unset ||
	    footer.data_offset > (file_size - footer_size - sparse_size)) {
		throw std::system_error(make_ec(ErrorCode::Corrupt));
	}

	if ((ec = read_structure(header,
	                         f,
	                         static_cast<std::streamoff>(footer.data_offset)))) {
		throw std::system_error(ec);
	}
	header.from_be();
	if (!header.is_valid()) {
		throw std::system_error(make_ec(ErrorCode::Corrupt));
	}

	/* To make the sector bitmap easier to work with, don't support blocks
	   larger than 2MiB. Most, if not all VHD implementations use 512KiB
	   or 2MiB block sizes. Block sizes larger than 2MiB require multiple
	   sectors to store the sector bitmap. */
	if (header.block_sz > block_size_large) {
		throw std::system_error(make_ec(ErrorCode::UnsupportedBlockSize));
	}

	calc_block_sizes();

	/* Continue being paranoid... */
	if (header.bat_offset >
	    (file_size - footer_size - header.max_bat_ent * sizeof(uint32_t))) {
		throw std::system_error(make_ec(ErrorCode::Corrupt));
	}

	if ((ec = bat_read_table())) {
		throw std::system_error(ec);
	}

	/* Is this too paranoid? */
	for (uint32_t i = 0; i < bat.size(); ++i) {
		if (!bat_block_is_sparse(i)) {
			const auto o = static_cast<uint64_t>(bat[i]) * sector_size;
			if (o > (file_size - footer_size -
			         (sb_sector_size + header.block_sz))) {
				throw std::system_error(make_ec(ErrorCode::Corrupt));
			}
		}
	}

	/* Done loading a sparse image */
	if (footer.disk_type == VHDType::Sparse) {
		return;
	}
	/* Continue loading parent */
	for (auto& loc : header.par_loc_entries) {
		std::string_view plat_code(loc.plat_code.data(),
		                           loc.plat_code.size());
		if (plat_code == plat_code_win_rel) {
			std::vector<char16_t> path_buff;
			path_buff.resize(loc.plat_data_len / sizeof(char16_t));
			if ((ec = read_bytes(path_buff.data(),
			                     path_buff.size() * sizeof(char16_t),
			                     f,
			                     static_cast<std::streamoff>(
			                             loc.plat_data_offset)))) {
				throw std::system_error(ec);
			}
			/* TODO: Handle path endianess */
			std::replace(path_buff.begin(), path_buff.end(), u'\\', u'/');
			const fs::path rel_path(path_buff.begin(), path_buff.end());
			const fs::path new_path = fs::path(vhd_path.parent_path()) /
			                          rel_path;
			const fs::path par_path = fs::canonical(new_path, ec);
			if (ec) {
				throw std::system_error(ec);
			}
			// Not using std::make_unique because of private
			// constructor
			parent = std::unique_ptr<VHD>(new VHD(par_path, true));
			break;
		}
	}
	if (!parent_is_valid()) {
		throw std::system_error(make_ec(ErrorCode::NoParent));
	}
	/* Success! */
	return;
}

/* Constructor to create a fixed VHD image
   Called by VHD::create_fixed */
VHD::VHD(fs::path const& vhd_path, Geom const& geom)
        : f(),
          footer{},
          header{},
          bat{},
          sector_cache(lru_cache_limit),
          sb_cache(sb_cache_limit)
{
	std::error_code ec;
	if (vhd_path.empty() || geom.num_sectors() == 0) {
		throw std::system_error(make_ec(ErrorCode::InvalidArgs));
	}

	footer.orig_sz   = geom.size_bytes();
	footer.curr_sz   = geom.size_bytes();
	footer.geom      = geom;
	footer.disk_type = VHDType::Fixed;
	footer.checksum  = footer.calc_checksum();

	Footer tmp_footer = footer;
	tmp_footer.to_be();

	f.pubsetbuf(nullptr, 0);

	if (!f.open(vhd_path, create_mode)) {
		/* Unfortunately a more specific error isn't available */
		throw std::system_error(make_ec(ErrorCode::OpenError));
	}
	f.close();
	fs::resize_file(vhd_path, footer.curr_sz, ec);
	if (ec) {
		throw std::system_error(ec);
	}
	if (!f.open(vhd_path, rw_mode)) {
		/* Unfortunately a more specific error isn't available */
		throw std::system_error(make_ec(ErrorCode::OpenError));
	}
	if ((ec = write_structure(tmp_footer, f, 0, std::ios_base::end))) {
		throw std::system_error(ec);
	}
}

/* Constructor to create a sparse or differencing VHD
   Called by VHD::create_sparse and VHD::create_diff */
VHD::VHD(fs::path const& vhd_path, VHDType const vhd_type, Geom const& geom,
         BlockSize block_size, fs::path const& par_path)
        : f(),
          footer{},
          header{},
          bat{},
          sector_cache(lru_cache_limit),
          sb_cache(sb_cache_limit)
{
	std::error_code ec;
	if (vhd_path.empty() || !is_one_of(vhd_type, VHDType::Sparse, VHDType::Diff)) {
		throw std::system_error(make_ec(ErrorCode::InvalidArgs));
	}
	if (vhd_type == VHDType::Sparse && geom.num_sectors() == 0) {
		throw std::system_error(make_ec(ErrorCode::InvalidArgs));
	}
	if (vhd_type == VHDType::Diff && par_path.empty()) {
		throw std::system_error(make_ec(ErrorCode::InvalidArgs));
	}

	if (vhd_type == VHDType::Diff) {
		// Not using std::make_unique because of private constructor
		parent = std::unique_ptr<VHD>(new VHD(par_path, true));
	}
	if (vhd_type == VHDType::Diff) {
		footer.orig_sz = parent->footer.orig_sz;
		footer.curr_sz = parent->footer.curr_sz;
		footer.geom    = parent->footer.geom;
	} else {
		footer.orig_sz = geom.size_bytes();
		footer.curr_sz = geom.size_bytes();
		footer.geom    = geom;
	}
	footer.data_offset = footer_size;
	footer.disk_type   = vhd_type;
	footer.checksum    = footer.calc_checksum();

	Footer tmp_footer = footer;
	tmp_footer.to_be();

	/* Calculate block size, and number of blocks*/
	header.bat_offset = footer_size + sparse_size;
	header.block_sz   = (block_size == BlockSize::Large) ? block_size_large
	                                                     : block_size_small;
	header.max_bat_ent = static_cast<uint32_t>(footer.curr_sz / header.block_sz);
	if (footer.curr_sz % header.block_sz != 0) {
		header.max_bat_ent++;
	}

	calc_block_sizes();
	bat_create_table();
	/* Note: ignore setting parent timestamp. It's essentially
	   useless anyway, and besides, Microsoft's Diskpart doesn't set
	   it */
	header.par_timestamp = 0;

	uint32_t bat_loc_padding       = 5;
	uint32_t bat_loc_padding_bytes = bat_loc_padding * sector_size;

	std::u16string rel_parent_path;
	if (vhd_type == VHDType::Diff) {
		uint32_t par_loc_beginning = footer_size + sparse_size +
		                             bat_size_bytes() + bat_loc_padding_bytes;
		header.par_uuid = parent->footer.uuid;
		/* Obtain a relative path to parent */
		auto par_name = par_path.filename().generic_u16string();
		std::copy(par_name.begin(),
		          par_name.end(),
		          header.par_utf16_name.begin());
		auto vhd_dir  = vhd_path.parent_path();
		auto rel_path = fs::relative(par_path, vhd_dir, ec);
		if (ec) {
			throw std::system_error(ec);
		}
		rel_parent_path = rel_path.generic_u16string();
		std::replace(rel_parent_path.begin(), rel_parent_path.end(), u'/', u'\\');

		/* Populate the first parent locator entry */
		ParentLocEntry& loc = header.par_loc_entries[0];
		std::copy(plat_code_win_rel.begin(),
		          plat_code_win_rel.end(),
		          loc.plat_code.begin());
		loc.plat_data_len = static_cast<uint32_t>(
		        rel_parent_path.size() * sizeof(char16_t));
		loc.plat_data_offset = par_loc_beginning;
		/* Note about the plat_data_space field: The VHD spec says this
		   field stores the number of sectors needed to store the
		   locator path. However, Hyper-V and VPC store the number of
		   bytes, not the number of sectors, and will refuse to open
		   VHDs which have the number of sectors in this field. See
		   https://stackoverflow.com/questions/40760181/mistake-in-virtual-hard-disk-image-format-specification
		 */
		loc.plat_data_space = loc.plat_data_len / sector_size;
		if (loc.plat_data_len % sector_size != 0) {
			loc.plat_data_space += 1;
		}
		loc.plat_data_space *= sector_size;
	}
	header.checksum         = header.calc_checksum();
	SparseHeader tmp_header = header;
	tmp_header.to_be();

	/* Start writing out to file */

	f.pubsetbuf(nullptr, 0);

	if (!f.open(vhd_path, create_mode)) {
		/* Unfortunately a more specific error isn't available */
		throw std::system_error(make_ec(ErrorCode::OpenError));
	}
	f.close();
	if (!f.open(vhd_path, rw_mode)) {
		/* Unfortunately a more specific error isn't available */
		throw std::system_error(make_ec(ErrorCode::OpenError));
	}
	if ((ec = write_structure(tmp_footer, f, 0))) {
		throw std::system_error(ec);
	}
	if ((ec = write_structure(tmp_header,
	                          f,
	                          static_cast<std::streamoff>(footer.data_offset)))) {
		throw std::system_error(ec);
	}

	if ((ec = bat_write_table())) {
		throw std::system_error(ec);
	}
	if ((ec = write_sector_padding(f,
	                               bat_loc_padding,
	                               static_cast<std::streamoff>(
	                                       header.bat_offset + bat_size_bytes())))) {
		throw std::system_error(ec);
	}

	if (vhd_type == VHDType::Diff) {
		uint32_t num_char = header.par_loc_entries[0].plat_data_space /
		                    sizeof(char16_t);
		std::vector<char16_t> par_loc_buff(num_char, 0);
		std::copy(rel_parent_path.begin(),
		          rel_parent_path.end(),
		          par_loc_buff.begin());
		if ((ec = write_bytes(par_loc_buff.data(),
		                      par_loc_buff.size() * sizeof(char16_t),
		                      f,
		                      static_cast<std::streamoff>(
		                              header.par_loc_entries[0].plat_data_offset)))) {
			throw std::system_error(ec);
		}
	}
	if ((ec = write_structure(tmp_footer, f, 0, std::ios_base::end))) {
		throw std::system_error(ec);
	}
}

/* Check that a differencing VHD has a valid parent */
bool VHD::parent_is_valid()
{
	return parent && parent->footer.geom == footer.geom &&
	       parent->footer.curr_sz == footer.curr_sz &&
	       parent->footer.uuid == header.par_uuid;
}

void VHD::calc_block_sizes()
{
	sectors_per_block = header.block_sz / sector_size;
}

uint32_t VHD::calc_block_num(uint32_t sector_num)
{
	return sector_num / static_cast<uint32_t>(sectors_per_block);
}

uint32_t VHD::calc_sib(uint32_t sector_num)
{
	return sector_num % static_cast<uint32_t>(sectors_per_block);
}

/* Open an existing VHD, at vhd_path. If read_only is set, the image
   will be open in read_only mode */
VHD::open_variant VHD::open(fs::path const& vhd_path, bool read_only)
{
	try {
		VHD vhd(vhd_path, read_only);
		return open_variant(std::move(vhd));
	} catch (const std::system_error& e) {
		return open_variant(std::error_code(e.code()));
	}
}

/* Create a fixed VHD at vhd_path, with geometry geom. */
VHD::open_variant VHD::create_fixed(fs::path const& vhd_path, Geom const& geom)
{
	return create(vhd_path, geom, BlockSize::Large, fs::path(), VHDType::Fixed);
}

/* Create a sparse VHD at vhd_path with geometry geom. If block_size
   is BlockSize::Large (default) then the image will be created with
   2MiB block sizes. Otherwise if BlockSize::Small, the blocks will
   512KiB in size */
VHD::open_variant VHD::create_sparse(fs::path const& vhd_path, Geom const& geom,
                                     BlockSize block_size)
{
	return create(vhd_path, geom, block_size, fs::path(), VHDType::Sparse);
}

/* Create a sparse VHD at vhd_path, which has a parent at par_path.
   If block_size is BlockSize::Large (default) then the image will
   be created with 2MiB block sizes. Otherwise if BlockSize::Small,
   the blocks will 512KiB in size.  */
VHD::open_variant VHD::create_diff(fs::path const& vhd_path,
                                   fs::path const& par_path, BlockSize block_size)
{
	return create(vhd_path, Geom(), block_size, par_path, VHDType::Diff);
}

/* Common function to create VHD images, with exception handling */
VHD::open_variant VHD::create(fs::path const& vhd_path, Geom const& geom,
                              BlockSize block_size, fs::path const& par_path,
                              VHDType vhd_type)
{
	try {
		if (vhd_type == VHDType::Fixed) {
			return open_variant(VHD(vhd_path, geom));
		} else if (is_one_of(vhd_type, VHDType::Sparse, VHDType::Diff)) {
			return open_variant(
			        VHD(vhd_path, vhd_type, geom, block_size, par_path));
		} else {
			return open_variant(make_ec(ErrorCode::InvalidArgs));
		}
	} catch (const std::system_error& e) {
		return open_variant(std::error_code(e.code()));
	}
}

/* Read a single sector at sector_num offset from the VHD
   and store the data in the buffer pointed to by dest.
   The buffer MUST be large enough to hold the size of
   a sector. */
std::error_code VHD::read_sector(uint32_t const sector_num, void* dest)
{
	if (sector_num >= footer.geom.num_sectors()) {
		return make_ec(ErrorCode::SectorOutOfRange);
	}
	std::error_code ec;
	uint32_t chunk_num = calc_chunk_num(sector_num);
	std::streamoff chunk_offset;

	if (footer.disk_type == VHDType::Fixed) {
		chunk_offset = abs_chunk_offset(chunk_num);
	} else {
		uint32_t block_num = calc_block_num(sector_num);
		uint32_t sib       = calc_sib(sector_num);
		if (!sb_in_cache(block_num)) {
			if ((ec = sb_read_from_file(block_num))) {
				return ec;
			}
		}
		bool sector_is_dirty = sb_test(block_num, sib);
		if (!sector_is_dirty && footer.disk_type == VHDType::Diff) {
			return parent->read_sector(sector_num, dest);
		}
		if (bat_block_is_sparse(block_num)) {
			memcpy(dest, zero_data.data(), sector_size);
			return ec;
		}
		auto abs_block_offset = static_cast<std::streamoff>(
		                                bat[block_num] + 1) *
		                        sector_size;
		uint32_t chunk_num_in_block = calc_chunk_num(sib);
		chunk_offset                = abs_block_offset +
		               abs_chunk_offset(chunk_num_in_block);
	}
	if (!sector_in_cache(sector_num)) {
		sector_cache.set(chunk_num, std::array<uint8_t, lru_chunk_size>{});
		auto& c = sector_cache.get(chunk_num);
		if ((ec = read_bytes(c.data(), c.size(), f, chunk_offset))) {
			return ec;
		}
	}
	read_sector_from_cache(sector_num, dest);
	return ec;
}

/* Write a single sector at sector_num offset to the VHD
   from the data in the buffer pointed to by src.
   The buffer MUST be large enough to hold the size of
   a sector. */
std::error_code VHD::write_sector(uint32_t const sector_num, const void* src)
{
	if (sector_num >= footer.geom.num_sectors()) {
		return make_ec(ErrorCode::SectorOutOfRange);
	}
	if (ro) {
		return make_ec(ErrorCode::ReadOnly);
	}
	std::error_code ec;
	if (footer.disk_type == VHDType::Fixed) {
		auto offset = static_cast<std::streamoff>(sector_num) * sector_size;
		if ((ec = write_bytes(src, sector_size, f, offset))) {
			clear_caches();
			return ec;
		}
	} else {
		uint32_t block_num = calc_block_num(sector_num);
		uint32_t sib       = calc_sib(sector_num);
		if (!sb_in_cache(block_num)) {
			if ((ec = sb_read_from_file(block_num))) {
				clear_caches();
				return ec;
			}
		}
		bool sector_is_dirty = sb_test(block_num, sib);
		if (!sector_is_dirty) {
			sb_set(block_num, sib);
			if ((ec = sb_write_to_file(block_num))) {
				clear_caches();
				return ec;
			}
		}
		bool sourcce_is_zero = (memcmp(src, zero_data.data(), sector_size) ==
		                        0);
		if (bat_block_is_sparse(block_num)) {
			if (sourcce_is_zero) {
				return ec;
			}
			if ((ec = bat_create_block(block_num))) {
				clear_caches();
				return ec;
			}
		}
		auto abs_sector_offset = static_cast<std::streamoff>(
		                                 bat[block_num] + 1 + sib) *
		                         sector_size;
		if ((ec = write_bytes(src, sector_size, f, abs_sector_offset))) {
			clear_caches();
			return ec;
		}
	}
	if (sector_in_cache(sector_num)) {
		write_sector_to_cache(sector_num, src);
	}
	return ec;
}

/* Get the geometry (CHS) of a VHD image */
Geom VHD::get_geometry()
{
	return footer.geom;
}

} // namespace MVHDPP
