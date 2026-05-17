# OpenVINO 2026.1.0 spec for Fedora 44
#
# Based on the Fedora 44 openvino-2025.1.0-14.fc44 spec by
# Ali Erdinc Koroglu <aekoroglu@linux.intel.com> and contributors.
#
# Changes from 2025.1.0:
#   - Version bump to 2026.1.0
#   - SO version bump 2510 -> 2610
#   - GenAI moved to separate openvino-genai.spec
#   - NPU compiler updated to npu_ud_2026_12_1_rc1
#   - gcc 15 cstdint patches dropped (upstreamed)
#   - KeepConstsPrecision typo fix dropped (fixed upstream)
#
# Build:
#   dnf builddep openvino.spec
#   rpmbuild -ba openvino.spec

%global so_ver 2610
%global ov_version 2026.1.0

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
Source0:        %{url}/archive/%{version}/%{name}-%{version}.tar.gz
Source1:        dependencies.cmake
Source2:        pyproject.toml

# Bundled dependencies (from 2026.1.0 submodule pins)
Source3:        https://github.com/openvinotoolkit/oneDNN/archive/6b6492b1ea9ef5ca9ff3c5c59ed71dcca683a446/onednn-6b6492b.tar.gz
Source4:        https://github.com/openvinotoolkit/mlas/archive/d1bc25ec4660cddd87804fcf03b2411b5dfb2e94/mlas-d1bc25e.tar.gz
Source5:        https://github.com/intel/level-zero-npu-extensions/archive/42768cc73e74f6d371bd9dd51b1860b07774e7ec/level-zero-npu-extensions-42768cc.tar.gz

# NPU compiler and dependencies (npu_ud_2026_12_1_rc1 targets OV commit
# b7f9dbfa which is 227 commits behind 2026.1.0 — compatible)
Source6:        https://github.com/openvinotoolkit/npu_compiler/archive/npu_ud_2026_12_1_rc1/npu_compiler-npu_ud_2026_12_1_rc1.tar.gz
Source7:        npu-compiler-thirdparty-CMakeLists.txt
Source8:        https://github.com/openvinotoolkit/npu_plugin_elf/archive/82c444bcb9feb0f55fa33e18fbd711ec35426fba/npu_plugin_elf-82c444b.tar.gz
Source9:        https://github.com/intel/npu-nn-cost-model/archive/33ef9a69b4e694ad5bfc521af829a9cc9ce19b4c/npu-nn-cost-model-33ef9a6.tar.gz
Source10:       https://github.com/intel/npu-plugin-llvm/archive/cf3934f4e8ada928544a743481e037935a21e857/npu-plugin-llvm-cf3934f.tar.gz
Source11:       https://github.com/google/flatbuffers/archive/595bf0007ab1929570c7671f091313c8fc20644e/flatbuffers-595bf00.tar.gz

# --- Patches ---
Patch0:         openvino-fedora.patch
Patch1:         npu-level-zero.patch
Patch2:         npu-compiler-disable-git.patch
Patch3:         npu-compiler-fix-install.patch
Patch4:         npu-compiler-vpux-driver-compiler.patch

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

# Intel NPU compiler
tar xf %{SOURCE6} -C thirdparty
rm -rf thirdparty/npu_compiler-npu_ud_2026_12_1_rc1/thirdparty/*
cp %{SOURCE7} thirdparty/npu_compiler-npu_ud_2026_12_1_rc1/thirdparty/CMakeLists.txt
%patch -d thirdparty/npu_compiler-npu_ud_2026_12_1_rc1 -P 2 -p1
%patch -d thirdparty/npu_compiler-npu_ud_2026_12_1_rc1 -P 3 -p1
%patch -d thirdparty/npu_compiler-npu_ud_2026_12_1_rc1 -P 4 -p1
# Disable npu_compiler tests
sed -i '/^add_subdirectory(test)/s/^/#/' thirdparty/npu_compiler-npu_ud_2026_12_1_rc1/src/vpux_driver_compiler/CMakeLists.txt

# Intel NPU compiler thirdparty deps
tar xf %{SOURCE8}
mv npu_plugin_elf-* thirdparty/npu_compiler-npu_ud_2026_12_1_rc1/thirdparty/elf
tar xf %{SOURCE9}
mv npu-nn-cost-model-* thirdparty/npu_compiler-npu_ud_2026_12_1_rc1/thirdparty/vpucostmodel
tar xf %{SOURCE10}
mv npu-plugin-llvm-* thirdparty/npu_compiler-npu_ud_2026_12_1_rc1/thirdparty/llvm-project
sed -i '/^include(CheckAtomic)/s/^/#/' thirdparty/npu_compiler-npu_ud_2026_12_1_rc1/thirdparty/llvm-project/llvm/cmake/config-ix.cmake
tar xf %{SOURCE11}
mv flatbuffers-* thirdparty/npu_compiler-npu_ud_2026_12_1_rc1/thirdparty/flatbuffers

# =====================================================================
# Build
# =====================================================================

%build
export NPU_PLUGIN_HOME="$PWD/thirdparty/npu_compiler-npu_ud_2026_12_1_rc1"

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
    -DOPENVINO_EXTRA_MODULES="$NPU_PLUGIN_HOME" \
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

# =====================================================================
# Changelog
# =====================================================================

%changelog
* Thu May 08 2026 Fabien Dupont <fdupont@redhat.com> - 2026.1.0-1
- Update to 2026.1.0
