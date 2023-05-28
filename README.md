# MiniVHD++ - A C++17 reimagine of MiniVHD

This is a reimagine of my C MiniVHD library, written in C++17.

The library is simple, and easy to use. It has no external dependencies beyond what is already bundled.

## Project Status

This project is still a work in progress. The basic functionality is implemented, but the open/create API is subject to change until I release an initial version.

## Building

MiniVHD++ uses the Meson build system, so projects that use Meson can consume it as a wrap.

Alternative, the library is simple enough that you can place the `minivhdpp.h`, `minivhdpp.cpp` and `randutils.hpp` files in your source directory and compile with your preferred build system.

## API usage

### Open existing VHD

```cpp
auto res = MVHDPP::VHD::open(path);
if (std::holds_alternative<std::error_code>(res)) {
    auto ec = std::get<std::error_code>(res);
    std::cout << ec.message() << std::endl;
    // handle error
}
auto vhd = std::get<MVHDPP::VHD>(std::move(res));
std::array<uint8_t, 512> buff;
uint32_t sector_num = 0;
vhd.read_sector(sector_num, buff.data())
// continue using VHD image. It will automatically close when
// the object goes out of scope
```

### Create a VHD

```cpp
auto geom = MVHDPP::Geom{1024, 16, 63};
auto res = MVHDPP::VHD::create_fixed(path, geom);
if (std::holds_alternative<std::error_code>(res)) {
    auto ec = std::get<std::error_code>(res);
    std::cout << ec.message() << std::endl;
    // handle error
}
auto vhd = std::get<MVHDPP::VHD>(std::move(res));
std::array<uint8_t, 512> buff;
uint32_t sector_num = 0;
vhd.read_sector(sector_num, buff.data())
// continue using VHD image. It will automatically close when
// the object goes out of scope
```

