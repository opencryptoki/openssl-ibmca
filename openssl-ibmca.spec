Name:       openssl-ibmca
Version:    1.3.1
Release:    0
Summary:    An IBMCA OpenSSL dynamic engine

Group:      Hardware/Other
License:    ASL 2.0
Source:     https://github.com/opencryptoki/%{name}/archive/v%{version}.tar.gz
URL:        http://sourceforge.net/projects/opencryptoki

BuildRequires:  openssl-devel >= 0.9.8,
                libica-devel >= 2.4.0,
                autoconf,
                automake,
                libtool
Requires:       openssl >= 0.9.8,
                libica >= 2.4.0

ExclusiveArch: s390 s390x

%description
This package contains a shared object OpenSSL dynamic engine which interfaces
to libica, a library enabling the IBM s390/x CPACF crypto instructions.

%prep
%setup -q

%build
%configure
make

%install
%makeinstall
rm -f $RPM_BUILD_ROOT%{_libdir}/libibmca.la
mkdir -p $RPM_BUILD_ROOT%{_libdir}/openssl/engines
mv $RPM_BUILD_ROOT%{_libdir}/lib* $RPM_BUILD_ROOT%{_libdir}/openssl/engines

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%doc README INSTALL src/openssl.cnf.sample
%{_mandir}/man5/*
%{_libdir}/openssl/engines/*

%changelog
* Tue Aug 15 2017 Paulo Vital <pvital@linux.vnet.ibm.com> 1.3.1
- Update new License
- Update Source and URL pointing to GitHub

* Fri Feb 17 2017 Paulo Vital <pvital@linux.vnet.ibm.com> 1.3.1
- Support OpenSSL-1.1 and older versions

* Tue Dec 1 2015 Claudio Carvalho <cclaudio@br.ibm.com> 1.3.0
- openssl-ibmca-1.3.0 release

* Mon May 2 2011 Kent Yoder <yoder1@us.ibm.com> 1.2.0
- updates for s390 MSA4 features, engine version 1.2

* Fri Mar 17 2006 Michael A. Halcrow <mhalcrow@us.ibm.com> 1.0.0
- initial version
