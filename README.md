My implementaiton of https://epi052.gitlab.io/notes-to-self/blog/2021-11-26-fuzzing-101-with-libafl-part-4

To setup run:

```
ARCH=aarch64 just rootfs    # Build rootfs first (needs sudo, takes time)
ARCH=aarch64 just tiffinfo   # Downloads tiff source and builds tiffinfo + corpus
ARCH=aarch64 just run        # Builds fuzzer and runs it regularly

ARCH=aarch64 just run_snapshots # trying snapshot fuzzing. Currently broken

```
