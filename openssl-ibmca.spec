Name:           openssl-ibmca
Version:        1.3.0
Release:        0
Summary:        An IBMCA OpenSSL dynamic engine

Group:          Hardware/Other
License:        Other License(s), see package, IBM Public License
Source:         %{name}-%{version}.tar.bz2
URL:            http://sourceforge.net/projects/opencryptoki
BuildRoot:      %{_tmppath}/%{name}-%{version}-build

BuildRequires: openssl-devel >= 0.9.8, libica-devel >= 2.4.0, autoconf, automake, libtool
Requires: openssl >= 0.9.8, libica >= 2.4.0

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
* Tue Dec 1 2015 - cclaudio@br.ibm.com
- openssl-ibmca-1.3.0 release

* Mon May 2 2011 - yoder1@us.ibm.com
- updates for s390 MSA4 features, engine version 1.2

* Fri Mar 17 2006 - mhalcrow@us.ibm.com
- initial version
