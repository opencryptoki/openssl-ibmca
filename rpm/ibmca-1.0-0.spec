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
Version:        1.0.0
Release:        0
License:        Other License(s), see package, IBM Public License
Group:          Hardware/Other
Source:         http://sourceforge.net/project/showfiles.php?group_id=128009&package_id=141377&release_id=384644
Source1:        openssl-ibmca-1.0.0-rc2.tar.bz2
URL:            http://sourceforge.net/projects/opencryptoki
BuildRoot:      %{_tmppath}/%{name}-%{version}-build
PreReq:         %fillup_prereq %insserv_prereq

%description
This package contains a shared object OpenSSL dynamic engine for the IBM
eServer Cryptographic Accelerator (ICA).

%prep
%setup -n ibmca-1.0.0-rc2

%build
autoreconf --force --install
export CFLAGS="$RPM_OPT_FLAGS"
export CPPFLAGS="$RPM_OPT_FLAGS"
./configure --with-engines-dir=%_libdir/engines
make

%install
make install

%post
%run_ldconfig

%postun

%files
%defattr(-, root, root)
%doc README
%ifarch s390
/usr/lib/engines/libibmca.so
%endif
%ifarch s390x
/usr/lib64/engines/libibmca.so
%endif

%changelog -n ibmca
* Fri Mar 17 2006 - mhalcrow@us.ibm.com
- initial version
