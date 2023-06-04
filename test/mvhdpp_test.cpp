#include "minivhdpp.h"

#include <array>
#include <filesystem>
#include <iostream>
#include <sstream>

#include "fatfs/ff.h"
#include "fatfs/diskio.h"
#include "amosnier-sha2/sha-256.h"

constexpr int test_file_size = 64 * 1024 * 1024;

std::array<MVHDPP::VHD*, 10> vhds = {}; 

#ifdef __cplusplus
extern "C" {
#endif

DSTATUS disk_initialize (BYTE pdrv)
{
    if (vhds[pdrv] == nullptr) {
        return STA_NOINIT;
    }
    return 0;
}

DSTATUS disk_status (BYTE pdrv)
{
    if (vhds[pdrv] == nullptr) {
        return STA_NOINIT;
    }
    return 0;
}

DRESULT disk_read (BYTE pdrv, BYTE* buff, LBA_t sector, UINT count)
{
    auto v = vhds[pdrv];
    if (v == nullptr) {
        return RES_NOTRDY;
    }
    std::error_code ec;
    BYTE* b = buff;
    for (UINT i = 0; i < count; ++i) {
        if ((ec = v->read_sector(sector, b))) {
            return RES_ERROR;
        }
        b += MVHDPP::sector_size;
    }
    return RES_OK;
}

DRESULT disk_write (BYTE pdrv, const BYTE* buff, LBA_t sector, UINT count)
{
    auto v = vhds[pdrv];
    if (v == nullptr) {
        return RES_NOTRDY;
    }
    std::error_code ec;
    const BYTE* b = buff;
    for (UINT i = 0; i < count; ++i) {
        if ((ec = v->write_sector(sector, b))) {
            return RES_ERROR;
        }
        b += MVHDPP::sector_size;
    }
    return RES_OK;
}

DRESULT disk_ioctl (BYTE pdrv, BYTE cmd, void* buff)
{
    auto v = vhds[pdrv];
    if (v == nullptr) {
        return RES_NOTRDY;
    }
    DRESULT res = RES_OK;
    if (cmd == GET_SECTOR_COUNT) {
        auto sector_count = reinterpret_cast<LBA_t*>(buff);
        auto geom = v->get_geometry();
        *sector_count = geom.cyl * geom.heads * geom.spt;
    } else if (cmd == GET_SECTOR_SIZE) {
        auto ss = reinterpret_cast<WORD*>(buff);
        *ss = MVHDPP::sector_size;
    } else if (cmd == GET_BLOCK_SIZE) {
        auto bs = reinterpret_cast<DWORD*>(buff);
        *bs = 1;
    } else if (cmd != CTRL_TRIM && cmd != CTRL_SYNC) {
        res = RES_PARERR;
    }
    return res;
}

DWORD get_fattime (void)
{
    time_t t;
    struct tm *stm;


    t = time(0);
    stm = localtime(&t);

    return (DWORD)(stm->tm_year - 80) << 25 |
           (DWORD)(stm->tm_mon + 1) << 21 |
           (DWORD)stm->tm_mday << 16 |
           (DWORD)stm->tm_hour << 11 |
           (DWORD)stm->tm_min << 5 |
           (DWORD)stm->tm_sec >> 1;
}

void* ff_memalloc (UINT msize) 
{
    return malloc(msize);
}
void ff_memfree (void* mblock)
{
    return free(mblock);
}

PARTITION VolToPart[FF_VOLUMES] = {
    {0, 1},    /* "0:" ==> 1st partition in PD#0 */
};

#ifdef __cplusplus
}
#endif

class TesTData
{
public:
    TesTData() {
        sha_256_init(&sha, hash.data());
    }
    std::array<uint64_t, 16> const& get_next() {
        if (!finalized) {
            advance();
            sha_256_write(&sha, data.data(), data.size() * sizeof(uint64_t));
        }
        return data;
    }

    std::array<uint8_t, SIZE_OF_SHA_256_HASH> const& finalize() {
        sha_256_close(&sha);
        finalized = true;
        return hash;
    }

    void reset() {
        data.fill(0);
        hash.fill(0);
        memset(&sha, 0, sizeof sha);
        finalized = false;
    }

private:
    std::array<uint64_t, 16> data = {};
    void advance() {
        for (auto& d : data) {
            d++;
        }
    }
    std::array<uint8_t, SIZE_OF_SHA_256_HASH> hash = {};
    struct Sha_256 sha = {};
    bool finalized = false;
};

static std::string hash_digest(std::array<uint8_t, SIZE_OF_SHA_256_HASH> const& hash) {
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (auto byte : hash) {
        ss << std::setw(2) << byte;
    }
    return ss.str();
}

int prepare_img(MVHDPP::VHD* vhd)
{
    vhds[0] = vhd;
    BYTE work[FF_MAX_SS];
    LBA_t plist[] = {100, 0};
    FRESULT res;

    if ((res = f_fdisk(0, plist, work))) {
        std::cout << "fdisk failed" << std::endl;
        return 10;
    }
    if ((res = f_mkfs("0:", 0, work, sizeof work))) {
        std::cout << "fdisk failed" << std::endl;
        return 11;
    }
    vhds[0] = nullptr;
    return 0;
}

std::string create_write_file(MVHDPP::VHD* vhd, const char* file_path)
{
    vhds[0] = vhd;
    FATFS fs;           /* Filesystem object */
    FIL fil;            /* File object */
    FRESULT res;        /* API result code */
    UINT bw;            /* Bytes written */
    if ((res = f_mount(&fs, "0:", 0))) {
        std::cout << "mount failed" << std::endl;
        return "";
    }
    if ((res = f_open(&fil, file_path, FA_CREATE_NEW | FA_WRITE))) {
        f_mount(0, "", 0);
        std::cout << "open failed" << std::endl;
        return "";
    }
    TesTData td;
    int pos = 0;
    while (pos < test_file_size) {
        auto& data = td.get_next();
        UINT size = data.size() * sizeof *data.data();
        f_write(&fil, data.data(), size, &bw); 
        if (bw != size) {
            f_close(&fil);
            f_mount(0, "", 0);
            std::cout << "Write failed at " << pos << std::endl;
            return "";
        }
        pos += size;
    }
    const auto& hash = td.finalize();
    std::string ret = hash_digest(hash);
    f_close(&fil);
    f_mount(0, "", 0);
    vhds[0] = nullptr;
    return ret;
}

int read_file(MVHDPP::VHD* vhd, const char* file_path, std::string const& expected_digest) {
    vhds[0] = vhd;
    FATFS fs;           /* Filesystem object */
    FIL fil;            /* File object */
    FRESULT res;        /* API result code */
    UINT br;            /* Bytes read */
    if ((res = f_mount(&fs, "0:", 0))) {
        std::cout << "mount failed" << std::endl;
        return 10;
    }
    if ((res = f_open(&fil, file_path, FA_READ))) {
        f_mount(0, "", 0);
        std::cout << "open failed" << std::endl;
        return 11;
    }
    std::array<uint8_t, 64> buff = {};
    struct Sha_256 sha = {};
    std::array<uint8_t, SIZE_OF_SHA_256_HASH> hash = {};
    sha_256_init(&sha, hash.data());
    for (;;) {
        f_read(&fil, buff.data(), buff.size(), &br);
        if (br > 0) {
            sha_256_write(&sha, buff.data(), br);
        }
        if (br < (UINT)buff.size()) {
            break;
        }
    }
    sha_256_close(&sha);
    std::string digest = hash_digest(hash);
    if (digest != expected_digest) {
        f_close(&fil);
        f_mount(0, "", 0);
        return 1;
    }
    f_close(&fil);
    f_mount(0, "", 0);
    vhds[0] = nullptr;
    return 0;
}

const char test_data_0_path[] = "test-file-0.bin";
std::string test_data_0_digest = "";

const char test_data_1_path[] = "test-file-1.bin";
std::string test_data_1_digest = "";

const char test_data_2_path[] = "test-file-2.bin";
std::string test_data_2_digest = "";

int test_open(std::filesystem::path& path)
{
    auto res = MVHDPP::VHD::open(path);
    if (std::holds_alternative<std::error_code>(res)) {
        auto ec = std::get<std::error_code>(res);
        std::cout << ec.message() << std::endl;
        return 1;
    }
    return 0;
}

int test_create_fixed(std::filesystem::path& path, MVHDPP::Geom& geom) 
{
    auto res = MVHDPP::VHD::create_fixed(path, geom);
    if (std::holds_alternative<std::error_code>(res)) {
        auto ec = std::get<std::error_code>(res);
        std::cout << ec.message() << std::endl;
        return 1;
    }
    auto vhd = std::get<MVHDPP::VHD>(std::move(res));
    if (prepare_img(&vhd)) {
        return 4;
    }
    test_data_0_digest = create_write_file(&vhd, test_data_0_path);
    if (test_data_0_digest == "") {
        return 2;
    }
    if (read_file(&vhd, test_data_0_path, test_data_0_digest) != 0) {
        return 3;
    }
    return 0;
}

int test_create_sparse(std::filesystem::path& path, MVHDPP::Geom& geom)
{
    auto res = MVHDPP::VHD::create_sparse(path, geom);
    if (std::holds_alternative<std::error_code>(res)) {
        auto ec = std::get<std::error_code>(res);
        std::cout << ec.message() << std::endl;
        return 1;
    }
    auto vhd = std::get<MVHDPP::VHD>(std::move(res));
    if (prepare_img(&vhd)) {
        return 4;
    }
    test_data_1_digest = create_write_file(&vhd, test_data_1_path);
    if (test_data_1_digest == "") {
        return 2;
    }
    if (read_file(&vhd, test_data_1_path, test_data_1_digest) != 0) {
        return 3;
    }
    return 0;
}

int test_create_diff(std::filesystem::path& path, std::filesystem::path& parent)
{
    auto res = MVHDPP::VHD::create_diff(path, parent);
    if (std::holds_alternative<std::error_code>(res)) {
        auto ec = std::get<std::error_code>(res);
        std::cout << ec.message() << std::endl;
        return 1;
    }
    auto vhd = std::get<MVHDPP::VHD>(std::move(res));
    test_data_2_digest = create_write_file(&vhd, test_data_2_path);
    if (test_data_2_digest == "") {
        return 2;
    }
    if (read_file(&vhd, test_data_2_path, test_data_2_digest) != 0) {
        return 3;
    }
    if (read_file(&vhd, test_data_1_path, test_data_1_digest) != 0) {
        return 3;
    }
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        std::cout << "Exactly one argument expected";
        return 2;
    }
    auto arg_path = std::filesystem::path(argv[1]);
    auto dir = arg_path.parent_path();
    auto fixed_path = std::filesystem::weakly_canonical(dir / "fixed.vhd");
    auto sparse_path = std::filesystem::weakly_canonical(dir / "sparse.vhd");
    auto diff_path = std::filesystem::weakly_canonical(dir / "diff.vhd");

    if (test_open(arg_path)) {
        return 3;
    }
    auto geom = MVHDPP::Geom{1024, 16, 63};
    if (test_create_fixed(fixed_path, geom)) {
        return 64;
    }

    if (test_create_sparse(sparse_path, geom)) {
        return 65;
    }

    if (test_create_diff(diff_path, sparse_path)) {
        return 66;
    }

    if (test_open(diff_path)) {
        return 67;
    }
    
    return 0;
}
