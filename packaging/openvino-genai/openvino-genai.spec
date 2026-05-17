# OpenVINO GenAI 2026.1.0 spec for Fedora 44
#
# Standalone package built against installed openvino-devel.
# Tracks the openvino.genai release cycle independently from
# core OpenVINO (upstream ships point releases like 2026.1.1.0,
# 2026.1.2.0 without requiring a core OpenVINO rebuild).
#
# Build:
#   dnf builddep openvino-genai.spec
#   rpmbuild -ba openvino-genai.spec

%global so_ver 2610
%global genai_version 2026.1.0.0
%global ov_version 2026.1.0

Name:           openvino-genai
Version:        %{genai_version}
Release:        1%{?dist}
Summary:        Generative AI pipelines for OpenVINO

License:        Apache-2.0
URL:            https://github.com/openvinotoolkit/openvino.genai

Source0:        %{url}/archive/%{genai_version}/%{name}-%{genai_version}.tar.gz
Source1:        https://github.com/openvinotoolkit/openvino_tokenizers/archive/d0dd22d077ec587f90951e77c47796138385284a/openvino_tokenizers-d0dd22d.tar.gz

# pybind11 >= 2.13 rejects keep_alive on def_readwrite/def_property.
# Wrap in py::cpp_function as recommended by pybind11 docs.
# Upstream PR: https://github.com/openvinotoolkit/openvino.genai/pull/XXXX
Patch0:         genai-pybind11-keep-alive.patch

# GCC 16 with -fvisibility=hidden strips template instantiation when
# defined in .cpp. Move format() template definition to header.
# Upstream PR: https://github.com/openvinotoolkit/openvino.genai/pull/XXXX
Patch1:         genai-gguf-format-template.patch

ExclusiveArch:  x86_64

BuildRequires:  cmake >= 3.23
%if 0%{?fedora} >= 42 || 0%{?rhel} > 10
BuildRequires:  gcc14
BuildRequires:  gcc14-c++
%else
BuildRequires:  gcc
BuildRequires:  gcc-c++
%endif
BuildRequires:  openvino-devel >= %{ov_version}
BuildRequires:  python3-openvino >= %{ov_version}
BuildRequires:  pybind11-devel
BuildRequires:  python3-devel
BuildRequires:  python3-numpy
BuildRequires:  python3-setuptools
BuildRequires:  python3-wheel

Requires:       openvino%{?_isa} >= %{ov_version}

%description
OpenVINO GenAI provides optimized pipelines for generative AI models
including LLMs, image generation, and speech. Features continuous
batching, speculative decoding (EAGLE-3), sparse attention, and KV
cache management. Supports CPU, GPU, and NPU inference.

Key APIs:
- LLMPipeline — text generation with tool calling
- WhisperPipeline — speech recognition
- ImageGenerationPipeline — image synthesis
- VLMPipeline — vision-language models

# =====================================================================
# Subpackages
# =====================================================================

%package devel
Summary:        Development files for OpenVINO GenAI
Requires:       %{name}%{?_isa} = %{version}-%{release}
Requires:       openvino-devel%{?_isa} >= %{ov_version}

%description devel
Headers and CMake config for building C++ applications against the
OpenVINO GenAI library.

%package -n python3-%{name}
Summary:        OpenVINO GenAI Python API
Requires:       %{name}%{?_isa} = %{version}-%{release}
Requires:       python3-openvino >= %{ov_version}
Requires:       python3-openvino-tokenizers = %{version}-%{release}

%description -n python3-%{name}
Python bindings for OpenVINO GenAI providing LLMPipeline,
WhisperPipeline, ImageGenerationPipeline and other high-level
generative AI interfaces.

%package -n python3-openvino-tokenizers
Summary:        OpenVINO Tokenizers
Requires:       python3-openvino >= %{ov_version}

%description -n python3-openvino-tokenizers
OpenVINO Tokenizers converts HuggingFace tokenizers to OpenVINO
models for efficient text preprocessing on CPU, GPU, and NPU.

# =====================================================================
# Prep
# =====================================================================

%prep
%autosetup -n openvino.genai-%{genai_version} -p1

# Extract tokenizers submodule (not included in GitHub release archive)
tar xf %{SOURCE1}
mv openvino_tokenizers-* thirdparty/openvino_tokenizers

# =====================================================================
# Build
# =====================================================================

%build
export CFLAGS="${CFLAGS/-Werror=format-security/} -Wno-error=stringop-overflow -Wno-error=maybe-uninitialized -Wno-error=template-id-cdtor"
export CXXFLAGS="${CXXFLAGS/-Werror=format-security/} -Wno-error=stringop-overflow -Wno-error=maybe-uninitialized -Wno-error=template-id-cdtor"

# Source the installed OpenVINO environment
source %{_datadir}/openvino/setupvars.sh || true

%cmake \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
%if 0%{?fedora} >= 42 || 0%{?rhel} > 10
    -DCMAKE_C_COMPILER=gcc-14 \
    -DCMAKE_CXX_COMPILER=g++-14 \
%endif
    -DCMAKE_COMPILE_WARNING_AS_ERROR=OFF \
    -DENABLE_PYTHON=ON \
    -DPython3_EXECUTABLE=%{python3} \
    -DENABLE_WHEEL=OFF \
    -DENABLE_JS=OFF \
    -DENABLE_TESTS=OFF \
    -DBUILD_SHARED_LIBS=ON \

%cmake_build

# =====================================================================
# Install
# =====================================================================

%install
%cmake_install

# =====================================================================
# Check
# =====================================================================

%check
LD_LIBRARY_PATH=$LD_LIBRARY_PATH:%{buildroot}%{_libdir} \
PYTHONPATH=%{buildroot}%{python3_sitearch} \
%{python3} -c "
import openvino_genai
assert hasattr(openvino_genai, 'LLMPipeline'), 'LLMPipeline not found'
print('OpenVINO GenAI imported successfully')
"

# =====================================================================
# Files
# =====================================================================

%files
%license LICENSE
%doc README.md
%{_libdir}/libopenvino_genai.so.%{genai_version}
%{_libdir}/libopenvino_genai.so.%{so_ver}
%{_libdir}/libopenvino_genai_c.so.%{genai_version}
%{_libdir}/libopenvino_genai_c.so.%{so_ver}

%files devel
%{_includedir}/openvino/genai
%{_libdir}/libopenvino_genai.so
%{_libdir}/libopenvino_genai_c.so
%{_libdir}/cmake/openvino_genai

%files -n python3-%{name}
%{python3_sitearch}/openvino_genai

%files -n python3-openvino-tokenizers
%{_libdir}/libopenvino_tokenizers.so
%{python3_sitearch}/openvino_tokenizers

# =====================================================================
# Changelog
# =====================================================================

%changelog
* Fri May 09 2026 Fabien Dupont <fdupont@redhat.com> - 2026.1.0.0-1
- Initial package
- Patches for pybind11 >= 2.13 and GCC 16 compatibility
