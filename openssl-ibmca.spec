#
# spec file for package openssl-ibmca-engine (Version 1.0.0)
#
# Copyright (c) 2006 SUSE LINUX Products GmbH, Nuernberg, Germany.
# This file and all modifications and additions to the pristine
# package are under the same license as the package itself.
#
# Please submit bugfixes or comments via http://bugs.opensuse.org/
#

# norootforbuild
# usedforbuild    aaa_base acl attr audit-libs autoconf automake bash bind-libs bind-utils binutils bison bzip2 coreutils cpio cpp cracklib cvs cyrus-sasl db diffutils e2fsprogs file filesystem fillup findutils flex gawk gcc gdbm gdbm-devel gettext gettext-devel glibc glibc-devel glibc-locale gpm grep groff gzip info insserv klogd less libacl libattr libcom_err libgcc libnscd libstdc++ libtool libxcrypt libzio m4 make man mktemp module-init-tools ncurses ncurses-devel net-tools netcfg openldap2-client openssl openssl-devel pam pam-modules patch perl permissions popt procinfo procps psmisc pwdutils rcs readline rpm sed strace sysvinit tar tcpd texinfo timezone unzip util-linux vim zlib zlib-devel libica

Name:           ibmca
BuildRequires:  openssl-devel
Summary:        An IBMCA OpenSSL dynamic engine
Version:        1.2.0
Release:        0
License:        Other License(s), see package, IBM Public License
Group:          Hardware/Other
Source:         openssl-ibmca-1.2.0.tar.bz2
URL:            http://sourceforge.net/projects/opencryptoki
BuildRoot:      %{_tmppath}/%{name}-%{version}-build
PreReq:         %fillup_prereq %insserv_prereq

%define ibmca_64bit_arch s390x ppc64
%define ibmca_32bit_arch %ix86 s390 ppc %arm
ExclusiveArch: %ibmca_32bit_arch %ibmca_64bit_arch

%description
This package contains a shared object OpenSSL dynamic engine which interfaces
to libica, a library enabling the IBM s390/x CPACF crypto instructions.

%prep
%setup -n openssl-ibmca-1.2.0

%build
autoreconf --force --install
export CFLAGS="$RPM_OPT_FLAGS"
export CPPFLAGS="$RPM_OPT_FLAGS"
./configure --with-engines-dir=%_libdir/engines
make

%install
%makeinstall

%post
%run_ldconfig

%postun

%files
%defattr(-, root, root)
%doc README
%doc openssl.cnf.sample
%{_libdir}/engines/libibmca.so

%changelog -n ibmca
* Mon May 2 2011 - yoder1@us.ibm.com
- updates for s390 MSA4 features, engine version 1.2

* Fri Mar 17 2006 - mhalcrow@us.ibm.com
- initial version
