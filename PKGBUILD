pkgname='zdcclient'
pkgver='1.6'
pkgrel=1
pkgdesc="Nettool for school in china,Connect x802.1fixed"
url="git+https://github.com/isombyt/zdcclient.git"
arch=('x86_64' 'i386')
license=('GPL')
source=($pkgname::git://github.com/acoret/zdcclient.git)
gitsource=($pkgname::https://github.com/acoret/zdcclient.git)
makedepends=('libcap' 'make' 'git')
depends=('libcap')

md5sums=('SKIP')
build()
{
  cd $pkgname
  make -j
}
package()
{
  echo 'please edit runzdclient...'
  cd $pkgname
  install -Dm4755 zdclient ${pkgdir}/usr/local/bin/zdclient
  install -Dm0755 runzdclient ${pkgdir}/usr/local/bin/runzdclient
}
post_install()
{
  echo 'please check if /usr/local/bin/runzdclient contain right user and passwd'
}
