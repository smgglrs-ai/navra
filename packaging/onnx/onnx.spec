Name:       onnx
Version:    1.21.0
Release:    1%{?dist}
Summary:    Open standard for machine learning interoperability
License:    Apache-2.0

URL:        https://github.com/onnx/onnx
Source0:    https://github.com/onnx/onnx/archive/v%{version}/%{name}-%{version}.tar.gz

# Set VERSION/SOVERSION on shared libraries for proper soname versioning.
# Upstream builds static by default; the old Fedora patch also forced SHARED
# and installed Python files, but BUILD_SHARED_LIBS=ON handles the former
# and we skip Python.
Patch0:     0000-versioned-sonames.patch

%if %{undefined fc40} && %{undefined fc41}
ExcludeArch:    %{ix86}
%endif

BuildRequires:  cmake >= 3.13
BuildRequires:  make
BuildRequires:  findutils
BuildRequires:  gcc
BuildRequires:  gcc-c++
BuildRequires:  zlib-devel
BuildRequires:  protobuf-devel

%global _description %{expand:
%{name} provides an open source format for AI models, both deep learning and
traditional ML. It defines an extensible computation graph model, as well as
definitions of built-in operators and standard data types.}

%description %_description

%package libs
Summary:    Libraries for %{name}

%description libs %_description

%package devel
Summary:    Development files for %{name}
Requires:   %{name}-libs = %{version}-%{release}

%description devel %_description

%prep
%autosetup -p1 -n onnx-%{version}

%build
%cmake \
    -DONNX_USE_LITE_PROTO=OFF \
    -DONNX_USE_PROTOBUF_SHARED_LIBS=ON \
    -DBUILD_SHARED_LIBS=ON \
    -DBUILD_ONNX_PYTHON=OFF \
    -DONNX_BUILD_TESTS=OFF \
    -DCMAKE_SKIP_RPATH:BOOL=ON

%cmake_build

%install
%cmake_install
find "%{buildroot}/%{_includedir}" -type d -empty -delete
install -p "./onnx/"*.proto -t "%{buildroot}/%{_includedir}/onnx/"

%files libs
%license LICENSE
%doc README.md
%{_libdir}/libonnx.so.%{version}
%{_libdir}/libonnx_proto.so.%{version}

%files devel
%{_libdir}/libonnx.so
%{_libdir}/libonnx_proto.so
%{_libdir}/cmake/ONNX
%{_includedir}/%{name}/

%changelog
* Mon Jun 09 2026 Fabien Dupont <fdupont@redhat.com> - 1.21.0-1
- Update to 1.21.0 (required by onnxruntime 1.26.0)
- Drop all 5 Fedora patches — all fixed upstream or not applicable
- Drop Python subpackage (build separately if needed)
