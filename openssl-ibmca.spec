%global enginesdir %(pkg-config --variable=enginesdir libcrypto)

Name:       openssl-ibmca
Version:    2.0.2
Release:    1%{?dist}
Summary:    An IBMCA OpenSSL dynamic engine

License:    ASL 2.0
URL:        https://github.com/opencryptoki/openssl-ibmca
Source0:    https://github.com/opencryptoki/%{name}/archive/v%{version}/%{name}-%{version}.tar.gz

Requires:       openssl >= 0.9.8 libica >= 3.3.0
BuildRequires:  openssl-devel >= 0.9.8 libica-devel >= 3.3.0
BuildRequires:  autoconf automake libtool

ExclusiveArch: s390 s390x

%description
This package contains a shared object OpenSSL dynamic engine which interfaces
to libica, a library enabling the IBM s390/x CPACF crypto instructions.

%prep
%setup -q -n %{name}-%{version}

./bootstrap.sh

%build
%configure --libdir=%{enginesdir}
%make_build

%install
%make_install
rm -f $RPM_BUILD_ROOT%{enginesdir}/ibmca.la

pushd src
sed -e 's|/usr/local/lib|%{_libdir}/openssl/engines|' openssl.cnf.sample > openssl.cnf.sample.%{_arch}
popd


%files
%license LICENSE
%doc ChangeLog README.md src/openssl.cnf.sample.%{_arch}
%{enginesdir}/ibmca.so
%{_mandir}/man5/ibmca.5*

%changelog
* Tue Nov 27 2018 Patrick Steuer <patrick.steuer@de.ibm.com> 2.0.2
- Update Version

* Thu Nov 08 2018 Patrick Steuer <patrick.steuer@de.ibm.com> 2.0.1
- Update Version

* Wed Jun 06 2018 Eduardo Barretto <ebarretto@linux.vnet.ibm.com> 2.0.0
- Update Version
- Update libica version required for building ibmca

* Wed Feb 21 2018 Eduardo Barretto <ebarretto@linux.vnet.ibm.com> 1.4.1
- Updated to 1.4.1

* Thu Jan 25 2018 Eduardo Barretto <ebarretto@linux.vnet.ibm.com>
- Update engine filename
- Spec cleanup

* Thu Oct 26 2017 Patrick Steuer <patrick.steuer@de.ibm.com>
- Fix build warning about comma and newlines
- Remove INSTALL file from doc
- Fix README name on doc

* Fri Sep 8 2017 Paulo Vital <pvital@linux.vnet.ibm.com> 1.4.0
- Update new License
- Update Source and URL pointing to GitHub
- Added support to AES-GCM
- Fix bugs/issues

* Fri Feb 17 2017 Paulo Vital <pvital@linux.vnet.ibm.com> 1.3.1
- Support OpenSSL-1.1 and older versions

* Tue Dec 1 2015 Claudio Carvalho <cclaudio@br.ibm.com> 1.3.0
- openssl-ibmca-1.3.0 release

* Mon May 2 2011 Kent Yoder <yoder1@us.ibm.com> 1.2.0
- updates for s390 MSA4 features, engine version 1.2

* Fri Mar 17 2006 Michael A. Halcrow <mhalcrow@us.ibm.com> 1.0.0
- initial version
