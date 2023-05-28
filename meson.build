project(
    'MiniVHD++',
    ['c','cpp'],
    version: '0.0.1',
    license: 'MIT',
    meson_version: '>= 0.57.0',
    default_options: [
        'cpp_std=c++17',
        'buildtype=release',
        'warning_level=3'
    ],
)

cc = meson.get_compiler('c')
cxx = meson.get_compiler('cpp')

extra_flags = ['-Wno-unknown-pragmas', 
               '-Wconversion', 
               '-Wnarrowing', 
               '-Wmaybe-uninitialized', 
               '-Weffc++', 
               '-Wextra-semi']

cc_flags = []
cxx_flags = []

foreach flag : extra_flags
    if cc.has_argument(flag)
        cc_flags += flag
    endif
    if cxx.has_argument(flag)
        cxx_flags += flag
    endif
endforeach

incdir = include_directories('include')

mvhdpp_sources = files(
    'src/minivhdpp.cpp'
)

library(
    'mvhdpp',
    sources : mvhdpp_sources,
    include_directories : incdir,
    c_args: cc_flags,
    cpp_args: cxx_flags
)

test_sources = files(
    'test/mvhdpp_test.cpp',
    'test/fatfs/ff.c',
    'test/fatfs/ffunicode.c',
    'test/amosnier-sha2/sha-256.c'
)

t = executable('vhd-test', 
               mvhdpp_sources + test_sources, 
               include_directories : incdir)
test('VHD Test', t, args : ['test_img.vhd'])
