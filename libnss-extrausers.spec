Name:           libnss-extrausers
Version:        0.6
Release:        0
Summary:        nss module to have an additional passwd, shadow and group file
Group:          System Environment/Libraries
Requires:       nss-system-init
Requires:	nss
License:        GPL
URL:            https://anonscm.debian.org/git/collab-maint/libnss-extrausers.git
Vendor:         Debian
Source:         http://http.debian.net/debian/pool/main/libn/libnss-extrausers/libnss-extrausers_0.6.orig.tar.gz
Prefix:         %{_prefix}
Packager: 	Rodrigo
BuildRoot:      %{_tmppath}/%{name}-root

%description
nss module to have an additional passwd, shadow and group file
This Name Service Switch (NSS) module reads /var/lib/extrausers/passwd, /var/lib/extrausers/shadow and /var/lib/extrausers/groups, allowing to store system accounts and accounts copied from other systems in different files.

%prep
%setup -q -n %{name}-%{version}

%build
CFLAGS="$RPM_OPT_FLAGS" 
make BITSOFS=64 prefix=$RPM_BUILD_ROOT/usr

%install
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT

make BITSOFS=64 prefix=$RPM_BUILD_ROOT/usr install 
%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT

%files
/usr/lib64/libnss_extrausers.so.2

%changelog

%post
mkdir -p /var/lib/extrausers
