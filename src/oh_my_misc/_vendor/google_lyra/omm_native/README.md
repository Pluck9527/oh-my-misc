# oh-my-misc Lyra native wrapper

This directory adds a tiny C ABI around the vendored Apache-2.0 Google Lyra
source tree so Python can call Lyra through `ctypes` instead of spawning
`encoder_main` or `decoder_main`.

Build from `src/oh_my_misc/_vendor/google_lyra`:

```bash
bazel build -c opt //omm_native:libomm_lyra_native.so
```

The Python wrapper searches the produced Bazel output automatically. You can
also copy the shared object next to this file, or set `OMM_LYRA_LIBRARY`.
