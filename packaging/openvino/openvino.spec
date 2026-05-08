# OpenVINO 2026.1.0 spec for Fedora 44
#
# Based on the Fedora 44 openvino-2025.1.0-14.fc44 spec by
# Ali Erdinc Koroglu <aekoroglu@linux.intel.com> and contributors.
#
# Changes from 2025.1.0:
#   - Version bump to 2026.1.0
#   - SO version bump 2510 -> 2610
#   - Add openvino-genai as OPENVINO_EXTRA_MODULES
#   - Add openvino-tokenizers as OPENVINO_EXTRA_MODULES
#   - New subpackages: openvino-genai, openvino-genai-devel,
#     python3-openvino-genai, python3-openvino-tokenizers
#   - NPU compiler sources will need updating (commit hashes TBD)
#   - gcc 15 cstdint patches may be upstreamed — verify before applying
#
# Build:
#   dnf builddep openvino.spec
#   rpmbuild -ba openvino.spec
#
# TODO for the build agent:
#   1. Fetch openvino 2026.1.0 tarball and verify sha256
#   2. Identify matching oneDNN, MLAS, level-zero-npu-extensions,
#      npu_compiler commits from 2026.1.0 tag's submodule pins
#   3. Identify matching openvino.genai and openvino_tokenizers
#      release tags compatible with 2026.1.0
#   4. Verify which gcc 15 cstdint patches are still needed
#   5. Update flatbuffers snapshot if needed
#   6. Test build in mock

%global so_ver 2610
%global ov_version 2026.1.0
%global genai_version 2026.1.0

%global desc %{expand: \
OpenVINO is an open-source toolkit for optimizing and deploying deep learning
models from cloud to edge. It accelerates deep learning inference across
various use cases, such as generative AI, video, audio, and language with
models from popular frameworks like PyTorch, TensorFlow, ONNX, and more.}

Name:           openvino
Version:        %{ov_version}
Release:        1%{?dist}
Summary:        Toolkit for optimizing and deploying AI inference

License:        Apache-2.0 AND MIT AND BSL-1.0 AND HPND AND BSD-3-Clause AND (GPL-2.0-only OR BSD-3-Clause)
URL:            https://github.com/openvinotoolkit/openvino

# --- Sources ---
# Core OpenVINO
Source0:        %{url}/archive/%{version}/%{name}-%{version}.tar.gz
Source1:        dependencies.cmake
Source2:        pyproject.toml

# Bundled dependencies (update commit hashes from 2026.1.0 submodule pins)
# TODO: replace these placeholder hashes with actual 2026.1.0 submodule commits
Source3:        https://github.com/openvinotoolkit/oneDNN/archive/COMMIT/onednn-COMMIT.tar.gz
Source4:        https://github.com/openvinotoolkit/mlas/archive/COMMIT/mlas-COMMIT.tar.gz
Source5:        https://github.com/intel/level-zero-npu-extensions/archive/COMMIT/level-zero-npu-extensions-COMMIT.tar.gz

# NPU compiler and dependencies
# TODO: identify the npu_compiler release tag for 2026.1.0
Source6:        https://github.com/openvinotoolkit/npu_compiler/archive/RELEASE_TAG/npu_compiler-RELEASE_TAG.tar.gz
Source7:        npu-compiler-thirdparty-CMakeLists.txt
Source8:        https://github.com/openvinotoolkit/npu_plugin_elf/archive/COMMIT/npu_plugin_elf-COMMIT.tar.gz
Source9:        https://github.com/intel/npu-nn-cost-model/archive/COMMIT/npu-nn-cost-model-COMMIT.tar.gz
Source10:       https://github.com/intel/npu-plugin-llvm/archive/COMMIT/npu-plugin-llvm-COMMIT.tar.gz
Source11:       https://github.com/google/flatbuffers/archive/COMMIT/flatbuffers-COMMIT.tar.gz

# OpenVINO GenAI (built as OPENVINO_EXTRA_MODULES)
Source20:       https://github.com/openvinotoolkit/openvino.genai/archive/%{genai_version}/openvino.genai-%{genai_version}.tar.gz
# OpenVINO Tokenizers (dependency of GenAI, also extra module)
Source21:       https://github.com/openvinotoolkit/openvino_tokenizers/archive/%{genai_version}/openvino_tokenizers-%{genai_version}.tar.gz

# --- Patches ---
# Fedora-specific build fixes
Patch0:         openvino-fedora.patch
Patch1:         npu-level-zero.patch
Patch2:         npu-compiler-disable-git.patch
Patch3:         npu-compiler-fix-install.patch
Patch4:         npu-compiler-vpux-driver-compiler.patch
# TODO: check if gcc 15 cstdint patches are still needed in 2026.1.0
# Patch5:       openvino-gcc15-cstdint.patch
# GenAI pybind11 compat: def_readwrite does not support keep_alive in
# pybind11 >= 2.13. Replace with def_property + explicit lambdas.
Patch10:        genai-pybind11-keep-alive.patch
# GenAI gguf format() template: GCC 16 strips instantiation from .so
# when defined in .cpp with -fvisibility=hidden. Move to header.
Patch11:        genai-gguf-format-template.patch

ExclusiveArch:  x86_64

# --- Build dependencies ---
BuildRequires:  cmake >= 3.23
%if 0%{?fedora} >= 42 || 0%{?rhel} > 10
BuildRequires:  gcc14
BuildRequires:  gcc14-c++
%else
BuildRequires:  gcc
BuildRequires:  gcc-c++
%endif
BuildRequires:  gflags-devel
BuildRequires:  glibc-devel
BuildRequires:  flatbuffers-compiler
BuildRequires:  flatbuffers-devel
BuildRequires:  json-devel
BuildRequires:  libedit-devel
BuildRequires:  libffi-devel
BuildRequires:  libxml2-devel
BuildRequires:  oneapi-level-zero-devel
BuildRequires:  patchelf
BuildRequires:  pugixml-devel
BuildRequires:  pybind11-devel
BuildRequires:  python3-devel
BuildRequires:  python3-onnx
BuildRequires:  python3-pip
BuildRequires:  python3-numpy
BuildRequires:  python3-setuptools
BuildRequires:  python3-pytest
BuildRequires:  python3-wheel
BuildRequires:  snappy-devel
BuildRequires:  zlib-ng-compat-devel
BuildRequires:  xbyak-devel
BuildRequires:  yaml-cpp-devel
BuildRequires:  tbb-devel
BuildRequires:  onnx-devel
BuildRequires:  protobuf-devel
BuildRequires:  opencv-devel
BuildRequires:  pkgconfig(OpenCL)
BuildRequires:  opencl-headers
# GenAI additional deps
BuildRequires:  jinja2-cli

Requires:       lib%{name}-ir-frontend = %{version}
Requires:       lib%{name}-pytorch-frontend = %{version}
Requires:       lib%{name}-onnx-frontend = %{version}
Requires:       lib%{name}-paddle-frontend = %{version}
Requires:       lib%{name}-tensorflow-frontend = %{version}
Requires:       lib%{name}-tensorflow-lite-frontend = %{version}
Recommends:     %{name}-plugins = %{version}

%description
%{desc}

# =====================================================================
# Subpackages
# =====================================================================

%package devel
Summary:        Development files for %{name}
Requires:       %{name}%{?_isa} = %{version}-%{release}

%description devel
The %{name}-devel package contains libraries and header files for
applications that use %{name}.

%package plugins
Summary:        OpenVINO Plugins
Provides:       bundled(onednn)
Provides:       bundled(mlas)
Provides:       bundled(level-zero-npu-extensions)
Requires:       %{name}%{?_isa} = %{version}-%{release}
Requires:       python3-opencv

%description plugins
The OpenVINO plugins package provides support for various hardware devices.
It includes auto, auto_batch, hetero, intel_cpu, intel_npu, intel_gpu and
template plugins.

%package -n lib%{name}-ir-frontend
Summary:        OpenVINO IR Frontend
Requires:       %{name}%{?_isa} = %{version}-%{release}

%description -n lib%{name}-ir-frontend
The primary function of the OpenVINO IR Frontend is to load an OpenVINO IR
into memory.

%package -n lib%{name}-pytorch-frontend
Summary:        OpenVINO PyTorch Frontend
Requires:       %{name}%{?_isa} = %{version}-%{release}
Requires:       python3-torch

%description -n lib%{name}-pytorch-frontend
The PyTorch Frontend is a C++ based OpenVINO Frontend component that is
responsible for reading and converting a PyTorch model to an ov::Model object.

%package -n lib%{name}-onnx-frontend
Summary:        OpenVINO ONNX Frontend
Requires:       %{name}%{?_isa} = %{version}-%{release}

%description -n lib%{name}-onnx-frontend
The main responsibility of the ONNX Frontend is to import ONNX models and
convert them into the ov::Model representation.

%package -n lib%{name}-paddle-frontend
Summary:        OpenVINO Paddle Frontend
Requires:       %{name}%{?_isa} = %{version}-%{release}

%description -n lib%{name}-paddle-frontend
OpenVINO Paddle Frontend is responsible for reading and converting
a PaddlePaddle model.

%package -n lib%{name}-tensorflow-frontend
Summary:        OpenVINO Tensorflow Frontend
Requires:       %{name}%{?_isa} = %{version}-%{release}

%description -n lib%{name}-tensorflow-frontend
OpenVINO TensorFlow Frontend is responsible for reading and converting
a TensorFlow model to an ov::Model object.

%package -n lib%{name}-tensorflow-lite-frontend
Summary:        OpenVINO Tensorflow-lite Frontend
Requires:       %{name}%{?_isa} = %{version}-%{release}

%description -n lib%{name}-tensorflow-lite-frontend
OpenVINO TensorFlow Lite Frontend for lower latency and smaller
binary size on mobile and edge devices.

%package -n intel-npu-compiler
Summary:        OpenVINO NPU Compiler
Provides:       bundled(npu_compiler)
Provides:       bundled(npu-nn-cost-model)
Provides:       bundled(npu_plugin_elf)
Provides:       bundled(npu-plugin-llvm)
Provides:       bundled(flatbuffers)
Requires:       %{name}%{?_isa} = %{version}-%{release}
Requires:       intel-npu-driver

%description -n intel-npu-compiler
Intel NPU device is an AI inference accelerator integrated with Intel client
CPUs, starting from Intel Core Ultra generation of CPUs.

%package -n python3-%{name}
Summary:        OpenVINO Python API
Requires:       %{name}%{?_isa} = %{version}-%{release}
Requires:       python3-numpy

%description -n python3-%{name}
OpenVINO Python API allowing users to use the OpenVINO library in their
Python code.

# --- GenAI subpackages ---

%package genai
Summary:        OpenVINO GenAI library
Requires:       %{name}%{?_isa} = %{version}-%{release}

%description genai
OpenVINO GenAI provides optimized pipelines for generative AI models
including LLMs, image generation, and speech. Features continuous
batching, speculative decoding (EAGLE-3), sparse attention, and KV
cache management. Supports CPU, GPU, and NPU inference.

%package genai-devel
Summary:        Development files for OpenVINO GenAI
Requires:       %{name}-genai%{?_isa} = %{version}-%{release}
Requires:       %{name}-devel%{?_isa} = %{version}-%{release}

%description genai-devel
Headers and CMake config for building against the OpenVINO GenAI library.

%package -n python3-%{name}-genai
Summary:        OpenVINO GenAI Python API
Requires:       python3-%{name} = %{version}-%{release}
Requires:       %{name}-genai%{?_isa} = %{version}-%{release}

%description -n python3-%{name}-genai
Python bindings for OpenVINO GenAI providing LLMPipeline,
WhisperPipeline, ImageGenerationPipeline and other high-level
generative AI interfaces.

%package -n python3-%{name}-tokenizers
Summary:        OpenVINO Tokenizers
Requires:       python3-%{name} = %{version}-%{release}

%description -n python3-%{name}-tokenizers
OpenVINO Tokenizers converts HuggingFace tokenizers to OpenVINO
models for efficient text preprocessing on CPU, GPU, and NPU.

# =====================================================================
# Prep
# =====================================================================

%prep
%autosetup -N
%patch -P 0 -p1

# Remove bundled thirdparty deps
rm -rf thirdparty/*
cp %{SOURCE1} thirdparty/

# Python: remove telemetry dep, relax numpy
sed -i '/openvino-telemetry/d' src/bindings/python/requirements.txt
sed -i 's/numpy>=1.16.6,<2.3.0/numpy>=1.16.6/' src/bindings/python/requirements.txt
cp %{SOURCE2} src/bindings/python

# Intel CPU plugin thirdparty deps
tar xf %{SOURCE3}
cp -r oneDNN-*/* src/plugins/intel_cpu/thirdparty/onednn
tar xf %{SOURCE4}
cp -r mlas-*/* src/plugins/intel_cpu/thirdparty/mlas

# Intel NPU plugin thirdparty deps
rm -rf src/plugins/intel_npu/thirdparty/yaml-cpp
tar xf %{SOURCE5}
cp -r level-*/* src/plugins/intel_npu/thirdparty/level-zero-ext
%patch -P 1 -p1

# Intel GPU plugin cache.json install path
sed -i -e 's|CACHE_JSON_INSTALL_DIR ${OV_CPACK_PLUGINSDIR}|CACHE_JSON_INSTALL_DIR %{_datadir}/%{name}|g' src/plugins/intel_gpu/src/kernel_selector/CMakeLists.txt

# TODO: verify gcc 15 cstdint patches are still needed in 2026.1.0
# If the upstream fixed these, remove the sed lines below.
# sed -i '/#include <vector>.*/a#include <cstdint>' ...

# Intel NPU compiler
tar xf %{SOURCE6} -C thirdparty
rm -rf thirdparty/npu_compiler-*/thirdparty/*
cp %{SOURCE7} thirdparty/npu_compiler-*/thirdparty/CMakeLists.txt
%patch -d thirdparty/npu_compiler-* -P 2 -p1
%patch -d thirdparty/npu_compiler-* -P 3 -p1
%patch -d thirdparty/npu_compiler-* -P 4 -p1
# ov::pass::KeepConstPrecision fix — verify still needed
# sed -i -e 's|ov::pass::KeepConstsPrecision|ov::pass::KeepConstPrecision|g' thirdparty/npu_compiler-*/src/vpux_compiler/src/frontend/IE.cpp
# Disable npu_compiler tests
sed -i '/^add_subdirectory(test)/s/^/#/' thirdparty/npu_compiler-*/src/vpux_driver_compiler/CMakeLists.txt

# Intel NPU compiler thirdparty deps
tar xf %{SOURCE8}
mv npu_plugin_elf-* thirdparty/npu_compiler-*/thirdparty/elf
tar xf %{SOURCE9}
mv npu-nn-cost-model-* thirdparty/npu_compiler-*/thirdparty/vpucostmodel
tar xf %{SOURCE10}
mv npu-plugin-llvm-* thirdparty/npu_compiler-*/thirdparty/llvm-project
sed -i '/^include(CheckAtomic)/s/^/#/' thirdparty/npu_compiler-*/thirdparty/llvm-project/llvm/cmake/config-ix.cmake
tar xf %{SOURCE11}
mv flatbuffers-* thirdparty/npu_compiler-*/thirdparty/flatbuffers

# OpenVINO GenAI (extra module)
tar xf %{SOURCE20}
mv openvino.genai-* openvino.genai
%patch -d openvino.genai -P 10 -p1
%patch -d openvino.genai -P 11 -p1

# OpenVINO Tokenizers (extra module, used by GenAI)
tar xf %{SOURCE21}
mv openvino_tokenizers-* openvino_tokenizers

# =====================================================================
# Build
# =====================================================================

%build
export NPU_PLUGIN_HOME="$PWD/thirdparty/npu_compiler-*"
# Expand the glob for NPU_PLUGIN_HOME
NPU_PLUGIN_HOME=$(echo $NPU_PLUGIN_HOME)

export CFLAGS="${CFLAGS/-Werror=format-security/} -Wno-error=stringop-overflow -Wno-error=maybe-uninitialized -Wno-error=dangling-reference -Wno-error=template-id-cdtor"
export CXXFLAGS="${CXXFLAGS/-Werror=format-security/} -Wno-error=stringop-overflow -Wno-error=maybe-uninitialized -Wno-error=dangling-reference -Wno-error=template-id-cdtor"

%cmake \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_POLICY_VERSION_MINIMUM="3.5.0" \
%if 0%{?fedora} >= 42 || 0%{?rhel} > 10
    -DCMAKE_C_COMPILER=gcc-14 \
    -DCMAKE_CXX_COMPILER=g++-14 \
%endif
    -DCMAKE_COMPILE_WARNING_AS_ERROR=OFF \
    -DENABLE_CLANG_FORMAT=OFF \
    -DENABLE_PRECOMPILED_HEADERS=OFF \
    -DCMAKE_NO_SYSTEM_FROM_IMPORTED=ON \
    -DENABLE_QSPECTRE=OFF \
    -DENABLE_INTEGRITYCHECK=OFF \
    -DENABLE_SANITIZER=OFF \
    -DENABLE_UB_SANITIZER=OFF \
    -DENABLE_THREAD_SANITIZER=OFF \
    -DENABLE_COVERAGE=OFF \
    -DENABLE_FASTER_BUILD=OFF \
    -DENABLE_CPPLINT=OFF \
    -DENABLE_CPPLINT_REPORT=OFF \
    -DENABLE_GAPI_PREPROCESSING=OFF \
    -DENABLE_NCC_STYLE=OFF \
    -DENABLE_UNSAFE_LOCATIONS=OFF \
    -DENABLE_FUZZING=OFF \
    -DENABLE_PROFILING_ITT=OFF \
    -DENABLE_PKGCONFIG_GEN=ON \
    -DENABLE_STRICT_DEPENDENCIES=OFF \
    -DENABLE_DEBUG_CAPS=ON \
    -DENABLE_AUTO=ON \
    -DENABLE_AUTO_BATCH=ON \
    -DENABLE_HETERO=ON \
    -DENABLE_INTEL_CPU=ON \
    -DENABLE_MLAS_FOR_CPU=ON \
    -DENABLE_MLAS_FOR_CPU_DEFAULT=ON \
    -DENABLE_INTEL_GNA=OFF \
    -DENABLE_INTEL_GPU=ON \
    -DENABLE_SYSTEM_LEVEL_ZERO=ON \
    -DENABLE_INTEL_NPU=ON \
    -DENABLE_NPU_PLUGIN_ENGINE=ON \
    -DENABLE_ZEROAPI_BACKEND=ON \
    -DENABLE_INTEL_NPU_INTERNAL=ON \
    -DENABLE_INTEL_NPU_PROTOPIPE=ON \
    -DENABLE_ONEDNN_FOR_GPU=OFF \
    -DENABLE_MULTI=ON \
    -DENABLE_PROXY=ON \
    -DENABLE_TEMPLATE=ON \
    -DENABLE_OV_ONNX_FRONTEND=ON \
    -DENABLE_OV_PADDLE_FRONTEND=ON \
    -DENABLE_OV_JAX_FRONTEND=OFF \
    -DENABLE_OV_IR_FRONTEND=ON \
    -DENABLE_OV_PYTORCH_FRONTEND=ON \
    -DENABLE_OV_TF_FRONTEND=ON \
    -DENABLE_OV_TF_LITE_FRONTEND=ON \
    -DENABLE_PYTHON=ON \
    -DPython3_EXECUTABLE=%{python3} \
    -DENABLE_WHEEL=OFF \
    -DENABLE_JS=OFF \
    -DENABLE_SYSTEM_LIBS_DEFAULT=ON \
    -DENABLE_SYSTEM_OPENCL=ON \
    -DENABLE_SYSTEM_PUGIXML=ON \
    -DENABLE_SYSTEM_SNAPPY=ON \
    -DENABLE_SYSTEM_PROTOBUF=ON \
    -DProtobuf_LIBRARIES=%{_libdir} \
    -DProtobuf_INCLUDE_DIRS=%{_includedir} \
    -DProtobuf_USE_STATIC_LIBS=OFF \
    -DTHREADING=TBB \
    -DENABLE_SYSTEM_TBB=ON \
    -DTBB_LIB_INSTALL_DIR=%{_libdir} \
    -DENABLE_TBBBIND_2_5=OFF \
    -DENABLE_TBB_RELEASE_ONLY=ON \
    -DENABLE_SAMPLES=OFF \
    -DENABLE_TESTS=OFF \
    -DBUILD_SHARED_LIBS=ON \
    -DBLAS_LIBRARIES=%{_libdir} \
    -DOPENVINO_EXTRA_MODULES="$PWD/openvino.genai;$PWD/openvino_tokenizers;$NPU_PLUGIN_HOME" \
    -DDENABLE_PRIVATE_TESTS=OFF \
    -DENABLE_NPU_LSP_SERVER=OFF \
    -DENABLE_PREBUILT_LLVM_MLIR_LIBS=OFF \
    -DDENABLE_DEVELOPER_BUILD=OFF \
    -DENABLE_MLIR_COMPILER=ON \
    -DBUILD_COMPILER_FOR_DRIVER=ON \
    -DENABLE_DRIVER_COMPILER_ADAPTER=OFF \
    -DENABLE_SOURCE_PACKAGE=OFF \
    -DLibEdit_LIBRARIES=%{_libdir}/libedit.so \
    -DLibEdit_INCLUDE_DIRS=%{_includedir}/histedit.h \

%cmake_build

# =====================================================================
# Install
# =====================================================================

%install
%cmake_install

# Generate python dist-info
export WHEEL_VERSION=%{version}
%{python3} src/bindings/python/wheel/setup.py dist_info -o %{buildroot}/%{python3_sitearch}
rm -v %{buildroot}/%{python3_sitearch}/requirements.txt
rm -vf %{buildroot}/%{python3_sitearch}/%{name}/preprocess/torchvision/requirements.txt
mkdir -p -m 755 %{buildroot}%{_datadir}/%{name}

# =====================================================================
# Check
# =====================================================================

%check
LD_LIBRARY_PATH=$LD_LIBRARY_PATH:%{buildroot}%{_libdir} PYTHONPATH=%{buildroot}%{python3_sitearch} %{python3} samples/python/hello_query_device/hello_query_device.py
LD_LIBRARY_PATH=$LD_LIBRARY_PATH:%{buildroot}%{_libdir} PYTHONPATH=%{buildroot}%{python3_sitearch} %{python3} samples/python/model_creation_sample/model_creation_sample.py samples/python/model_creation_sample/lenet.bin CPU
# ONNX frontend tests
LD_LIBRARY_PATH=$LD_LIBRARY_PATH:%{buildroot}%{_libdir} PYTHONPATH=%{buildroot}%{python3_sitearch}:src/frontends/onnx %pytest -v src/frontends/onnx/tests/tests_python/test_frontend_onnx*

# =====================================================================
# Files
# =====================================================================

%files
%license LICENSE
%doc CONTRIBUTING.md README.md
%{_libdir}/lib%{name}.so.%{version}
%{_libdir}/lib%{name}.so.%{so_ver}
%{_libdir}/lib%{name}_c.so.%{version}
%{_libdir}/lib%{name}_c.so.%{so_ver}

%files devel
%{_includedir}/%{name}
%{_includedir}/npu_driver_compiler.h
%{_libdir}/lib%{name}.so
%{_libdir}/lib%{name}_c.so
%{_libdir}/lib%{name}_pytorch_frontend.so
%{_libdir}/lib%{name}_onnx_frontend.so
%{_libdir}/lib%{name}_paddle_frontend.so
%{_libdir}/lib%{name}_tensorflow_frontend.so
%{_libdir}/lib%{name}_tensorflow_lite_frontend.so
%{_libdir}/cmake/openvino-%{version}
%{_libdir}/pkgconfig/%{name}.pc

%files plugins
%dir %{_libdir}/%{name}-%{version}
%{_libdir}/%{name}-%{version}/lib%{name}_auto_plugin.so
%{_libdir}/%{name}-%{version}/lib%{name}_auto_batch_plugin.so
%{_libdir}/%{name}-%{version}/lib%{name}_hetero_plugin.so
%{_libdir}/%{name}-%{version}/lib%{name}_intel_cpu_plugin.so
%{_libdir}/%{name}-%{version}/lib%{name}_intel_gpu_plugin.so
%{_libdir}/%{name}-%{version}/lib%{name}_intel_npu_plugin.so
%{_bindir}/compile_tool
%{_bindir}/protopipe
%{_bindir}/single-image-test
%{_datadir}/%{name}

%files -n lib%{name}-ir-frontend
%{_libdir}/lib%{name}_ir_frontend.so.%{version}
%{_libdir}/lib%{name}_ir_frontend.so.%{so_ver}

%files -n lib%{name}-pytorch-frontend
%{_libdir}/lib%{name}_pytorch_frontend.so.%{version}
%{_libdir}/lib%{name}_pytorch_frontend.so.%{so_ver}

%files -n lib%{name}-onnx-frontend
%{_libdir}/lib%{name}_onnx_frontend.so.%{version}
%{_libdir}/lib%{name}_onnx_frontend.so.%{so_ver}

%files -n lib%{name}-paddle-frontend
%{_libdir}/lib%{name}_paddle_frontend.so.%{version}
%{_libdir}/lib%{name}_paddle_frontend.so.%{so_ver}

%files -n lib%{name}-tensorflow-frontend
%{_libdir}/lib%{name}_tensorflow_frontend.so.%{version}
%{_libdir}/lib%{name}_tensorflow_frontend.so.%{so_ver}

%files -n lib%{name}-tensorflow-lite-frontend
%{_libdir}/lib%{name}_tensorflow_lite_frontend.so.%{version}
%{_libdir}/lib%{name}_tensorflow_lite_frontend.so.%{so_ver}

%files -n intel-npu-compiler
%{_libdir}/libnpu_driver_compiler.so

%files -n python3-%{name}
%{python3_sitearch}/%{name}
%{python3_sitearch}/%{name}-%{version}.dist-info

# --- GenAI files ---
# TODO: verify exact library names and paths after first successful build

%files genai
%{_libdir}/lib%{name}_genai.so.%{genai_version}
%{_libdir}/lib%{name}_genai.so.%{so_ver}

%files genai-devel
%{_libdir}/lib%{name}_genai.so
%{_includedir}/%{name}/genai
%{_libdir}/cmake/openvino_genai

%files -n python3-%{name}-genai
%{python3_sitearch}/%{name}_genai

%files -n python3-%{name}-tokenizers
%{python3_sitearch}/%{name}_tokenizers

# =====================================================================
# Changelog
# =====================================================================

%changelog
* Thu May 08 2026 Fabien Dupont <fdupont@redhat.com> - 2026.1.0-1
- Update to 2026.1.0
- Add openvino-genai and openvino-tokenizers as extra modules
- New subpackages: openvino-genai, openvino-genai-devel,
  python3-openvino-genai, python3-openvino-tokenizers
