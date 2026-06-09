%global utf8_range_commit 72c943dea2b9240cd09efde15191e144bc7c7d38
%global utf8_range_name utf8_range-%( echo %utf8_range_commit | cut -c1-7 )

%bcond test 0

# ORT 1.26 dropped the in-tree ROCm provider (now a plugin EP).
%bcond rocm 0

Summary:    A cross-platform inferencing and training accelerator
Name:       onnxruntime
Version:    1.26.0
Release:    1%{?dist}
License:    MIT AND Apache-2.0 AND BSL-1.0 AND BSD-3-Clause
URL:        https://github.com/microsoft/onnxruntime
Source0:    https://github.com/microsoft/onnxruntime/archive/v%{version}/%{name}-%{version}.tar.gz
Source1:    https://github.com/protocolbuffers/utf8_range/archive/%{utf8_range_commit}/%{utf8_range_name}.zip

# GCC 16 false positives: demote free-nonheap-object and
# maybe-uninitialized from error to warning for GCC >= 16 only.
# Keeps COMPILE_WARNING_AS_ERROR ON for everything else.
Patch0:     0000-gcc16-false-positives.patch
# System flatbuffers provides flatbuffers::flatbuffers_shared, not
# flatbuffers::flatbuffers. Create an alias.
Patch1:     0001-system-flatbuffers.patch
# Use system protobuf instead of FetchContent download.
Patch2:     0002-system-protobuf.patch

ExcludeArch:    s390x %{arm} %{ix86}

BuildRequires:  cmake >= 3.26
BuildRequires:  make
BuildRequires:  gcc
BuildRequires:  gcc-c++
BuildRequires:  onnx-devel >= 1.21.0
BuildRequires:  abseil-cpp-devel
BuildRequires:  boost-devel >= 1.66
BuildRequires:  bzip2
%ifnarch ppc64le
BuildRequires:  cpuinfo-devel
%endif
BuildRequires:  date-devel
BuildRequires:  flatbuffers-compiler
BuildRequires:  flatbuffers-devel >= 23.5.26
BuildRequires:  gsl-devel
BuildRequires:  guidelines-support-library-devel
BuildRequires:  json-devel
BuildRequires:  protobuf-devel
BuildRequires:  re2-devel >= 20211101
BuildRequires:  safeint-devel
BuildRequires:  zlib-devel
BuildRequires:  eigen3-devel >= 3.4
BuildRequires:  python3-devel

Provides:       bundled(utf8_range)

%description
%{name} is a cross-platform inferencing and training accelerator compatible
with many popular ML/DNN frameworks, including PyTorch, TensorFlow/Keras,
scikit-learn, and more.

%package devel
Summary:    The development part of the %{name} package
Requires:   %{name}%{_isa} = %{version}-%{release}

%description devel
The development part of the %{name} package

%package doc
Summary:    Documentation files for the %{name} package

%description doc
Documentation files for the %{name} package

%prep
%autosetup -p1

# Use whatever abseil version the system provides
sed -r -i 's/(FIND_PACKAGE_ARGS[[:blank:]]+)[0-9]{8}/\1/' \
    cmake/external/abseil-cpp.cmake

# Provide utf8_range source for FetchContent
for backend in cpu; do
  mkdir -p ./%{_vendor}-%{_target_os}-build-${backend}/_deps/utf8_range-subbuild/utf8_range-populate-prefix/src/
  cp -r %{SOURCE1} ./%{_vendor}-%{_target_os}-build-${backend}/_deps/utf8_range-subbuild/utf8_range-populate-prefix/src/%{utf8_range_commit}.zip
done

%build
# Re-compile flatbuffers schemas with system flatc
%{python3} onnxruntime/core/flatbuffers/schema/compile_schema.py --flatc /usr/bin/flatc
%{python3} onnxruntime/lora/adapter_format/compile_schema.py --flatc /usr/bin/flatc

%global _vpath_builddir %{_vendor}-%{_target_os}-build-cpu

# ORT 1.26 has FIND_PACKAGE_ARGS on all deps — system libraries are
# found automatically via find_package() when *-devel is installed.
# No "use system X" patches needed.
%cmake \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_INSTALL_LIBDIR=%{_lib} \
    -DCMAKE_INSTALL_INCLUDEDIR=include \
    -Donnxruntime_BUILD_BENCHMARKS=OFF \
    -Donnxruntime_BUILD_SHARED_LIB=ON \
    -Donnxruntime_BUILD_UNIT_TESTS=%{?with_test:ON}%{?!with_test:OFF} \
    -Donnxruntime_INSTALL_UNIT_TESTS=OFF \
    -Donnxruntime_ENABLE_PYTHON=OFF \
    -Donnxruntime_ENABLE_DLPACK=OFF \
    -Donnxruntime_USE_FULL_PROTOBUF=ON \
    -Donnxruntime_USE_PREINSTALLED_EIGEN=ON \
    -Deigen_SOURCE_PATH=/usr/include/eigen3 \
%ifarch ppc64le
    -Donnxruntime_ENABLE_CPUINFO=OFF \
%else
    -Donnxruntime_ENABLE_CPUINFO=ON \
%endif
    -S cmake

%cmake_build -- -j8

%install
%cmake_install
mkdir -p "%{buildroot}/%{_docdir}/"
cp --preserve=timestamps -r "./docs/" "%{buildroot}/%{_docdir}/%{name}"

%if %{with test}
%check
export GTEST_FILTER=-CApiTensorTest.load_huge_tensor_with_external_data
%ctest
%endif

%files
%license LICENSE
%doc ThirdPartyNotices.txt
%{_libdir}/libonnxruntime.so.%{version}
%{_libdir}/libonnxruntime_providers_shared.so*

%files devel
%dir %{_includedir}/onnxruntime/
%{_includedir}/onnxruntime/*
%{_libdir}/libonnxruntime.so*
%{_libdir}/pkgconfig/libonnxruntime.pc
%{_libdir}/cmake/onnxruntime/*

%files doc
%{_docdir}/%{name}

%changelog
* Mon Jun 09 2026 Fabien Dupont <fdupont@redhat.com> - 1.26.0-1
- Update to 1.26.0
- Drop 20 patches merged upstream or no longer needed
- Drop ROCm subpackages (provider moved to plugin EP)
- Drop Python subpackage (build separately if needed)
- Require onnx >= 1.21.0
