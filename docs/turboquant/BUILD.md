# Building llama.cpp-adaptive-turboquant

## Source

```
<path-to>/llama.cpp-adaptive-turboquant
```

Lineage: TurboQuant paper -> TheTom -> signalnine -> Madreag -> craftogrammer

## Hardware

- GPU: NVIDIA GeForce RTX 5090 (sm_120, 32 GB GDDR7)
- Driver: 595.71.05
- CUDA runtime capability: 13.2

## CUDA Toolchain

The fork README recommends CUDA 12.9.x. CUDA 13.1 was tested on Windows
and produced garbage output / segfaults in MMQ kernels.

### Host Toolchain Issue (Fedora 44)

Native build on Fedora 44 fails because:
1. CUDA 13.1 does not support GCC 16 (Fedora 44 default)
2. GCC 15 compat package (`gcc15-c++`) passes the GCC version check
   but Fedora 44's glibc headers use `noexcept(true)` on `rsqrtf`
   which conflicts with CUDA's `math_functions.h` declaration
3. This is a glibc-vs-CUDA incompatibility, not a compiler issue

**Solution**: Container-based build with CUDA 12.9 on Ubuntu 24.04.

## Build Procedure (Container)

### Step 1: Configure

```bash
cd <path-to>/llama.cpp-adaptive-turboquant

podman run --rm \
  -v $(pwd):/src:Z \
  docker.io/nvidia/cuda:12.9.0-devel-ubuntu24.04 \
  bash -c "
    apt-get update -qq && apt-get install -y -qq cmake git && \
    cd /src && \
    cmake -B build-container \
      -DGGML_CUDA=ON \
      -DCMAKE_CUDA_ARCHITECTURES=120 \
      -DCMAKE_BUILD_TYPE=Release
  "
```

### Step 2: Build

```bash
podman run --rm \
  -v $(pwd):/src:Z \
  docker.io/nvidia/cuda:12.9.0-devel-ubuntu24.04 \
  bash -c "
    apt-get update -qq && apt-get install -y -qq cmake git && \
    cd /src && \
    cmake --build build-container --config Release -j\$(nproc)
  "
```

The build output (binaries) land in `build-container/bin/` on the host.
They are dynamically linked against:
- libcudart.so (from the host CUDA runtime)
- libcublas.so (from the host CUDA libs)
- Standard C/C++ libs (compatible across Ubuntu 24.04 -> Fedora 44)

### Step 3: Run (native, with GPU)

```bash
export LD_LIBRARY_PATH=/usr/local/cuda/lib64:$LD_LIBRARY_PATH

# Quick benchmark
./build-container/bin/llama-bench \
  -m <model.gguf> \
  -ctk turbo3 -ctv turbo3 \
  -ngl 999 \
  -p 512 -n 128

# Server for tool calling tests
./build-container/bin/llama-server \
  --model <model.gguf> \
  --ctx-size 8192 \
  --cache-type-k q8_0 \
  --cache-type-v turbo3 \
  --host 127.0.0.1 \
  --port 8080 \
  --n-gpu-layers 999
```

## Validation

Compare perplexity with published numbers (Qwen 3.5 27B Q6_K on RTX 5090):

| Type | Published PPL ctx=512 | Published PPL ctx=2048 |
|------|:----:|:----:|
| q8_0 | 6.759 | 5.674 |
| turbo4 | 6.825 (+0.97%) | 5.694 |
| turbo3 | 6.852 (+1.38%) | 5.674 (=q8_0) |
| turbo2 | 7.121 (+5.35%) | 5.873 |

If measured PPL matches within ~2%, the build is correct.
If PPL is wildly off or the process crashes, the CUDA 13.x
compatibility issue from the fork README may still apply.

### Step 3: Extract CUDA Runtime Libs

The binaries link against CUDA 12.9 runtime. If the host has CUDA 13.x,
extract the 12.9 libs from the container:

```bash
mkdir -p build-container/cuda-libs
podman run --rm \
  -v $(pwd)/build-container/cuda-libs:/out:Z \
  docker.io/nvidia/cuda:12.9.0-devel-ubuntu24.04 \
  bash -c "
    cp /usr/local/cuda-12.9/targets/x86_64-linux/lib/libcudart.so.12* /out/ && \
    cp /usr/local/cuda-12.9/targets/x86_64-linux/lib/libcublas.so.12* /out/ && \
    cp /usr/local/cuda-12.9/targets/x86_64-linux/lib/libcublasLt.so.12* /out/
  "
```

### Step 4: Run

Use the wrapper script:

```bash
./run.sh llama-bench --help
./run.sh llama-server --model <model.gguf> --ctx-size 8192 \
  --cache-type-k q8_0 --cache-type-v turbo3 \
  --host 127.0.0.1 --port 8080 --n-gpu-layers 999
```

Or set LD_LIBRARY_PATH manually:

```bash
export LD_LIBRARY_PATH="$(pwd)/build-container/bin:$(pwd)/build-container/cuda-libs:$LD_LIBRARY_PATH"
./build-container/bin/llama-server ...
```

### Build Notes

- **cmake flag `-DCMAKE_EXE_LINKER_FLAGS='-Wl,--allow-shlib-undefined'`**
  is required because `libggml-cuda.so` references CUDA driver API symbols
  (`cuGetErrorString`, `cuMemCreate`, etc.) that only exist on the host at
  runtime (via `/lib64/libcuda.so.1` from the NVIDIA driver)
- The container image provides stubs at
  `/usr/local/cuda-12.9/targets/x86_64-linux/lib/stubs/libcuda.so` for the
  shared library link, but executables need `--allow-shlib-undefined`

## Alternative: Native Build (if glibc issue is resolved)

If CUDA 13.2+ or a future CUDA 12.9 update fixes the glibc
incompatibility:

```bash
cmake -B build \
  -DGGML_CUDA=ON \
  -DCMAKE_CUDA_ARCHITECTURES="120" \
  -DCMAKE_CUDA_COMPILER=/usr/local/cuda/bin/nvcc \
  -DCMAKE_C_COMPILER=/usr/bin/gcc-15 \
  -DCMAKE_CXX_COMPILER=/usr/bin/g++-15 \
  -DCMAKE_CUDA_HOST_COMPILER=/usr/bin/g++-15 \
  -DCMAKE_BUILD_TYPE=Release

cmake --build build --config Release -j$(nproc)
```
