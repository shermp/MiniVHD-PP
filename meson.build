project(
    'MiniVHD++',
    ['c','cpp'],
    version: '0.0.2',
    license: 'MIT',
    meson_version: '>= 0.57.0',
    default_options: [
        'cpp_std=c++17',
        'buildtype=release',
        'warning_level=3'
    ],
)

host_os = host_machine.system()

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

test_cc_flags = []
test_cxx_flags = []

if get_option('default_library') == 'shared'
    cc_flags += ['-DMVHDPP_DLL', '-DMVHDPP_DLL_EXPORT']
    cxx_flags += ['-DMVHDPP_DLL', '-DMVHDPP_DLL_EXPORT']
    test_cc_flags += '-DMVHDPP_DLL'
    test_cxx_flags += '-DMVHDPP_DLL'
endif

incdir = include_directories('include')

mvhdpp_sources = files(
    'src/minivhdpp.cpp'
)

mvhdpp_lib = library(
    'mvhdpp',
    sources : mvhdpp_sources,
    include_directories : incdir,
    c_args: cc_flags,
    cpp_args: cxx_flags
)

mvhdpp_dep = declare_dependency(link_with : mvhdpp_lib, include_directories : incdir)

test_sources = files(
    'test/mvhdpp_test.cpp',
    'test/fatfs/ff.c',
    'test/fatfs/ffunicode.c',
    'test/amosnier-sha2/sha-256.c'
)

t = executable('vhd-test', test_sources, c_args : test_cc_flags, cpp_args : test_cxx_flags, dependencies : [mvhdpp_dep])
test('VHD Test', t, workdir : meson.current_source_dir(), args : ['test/test_img_diff.vhd'])
