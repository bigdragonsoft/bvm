# Created by: Qiang Guo <guoqiang_cn@126.com>
# $FreeBSD$

PORTNAME=	bvm
PORTVERSION=	1.1.2
CATEGORIES=	sysutils

MAINTAINER=	guoqiang_cn@126.com
COMMENT=	Bhyve VM Manager

LICENSE=	BSD2CLAUSE
LICENSE_FILE=	${WRKSRC}/LICENSE

ONLY_FOR_ARCHS=	amd64
ONLY_FOR_ARCHS_REASON=	Bhyve VM Manager is required to be built on a 64bit machine

RUN_DEPENDS=	bhyve-firmware>=0:sysutils/bhyve-firmware \
		grub-bhyve:sysutils/grub2-bhyve \
		tmux:sysutils/tmux
USE_GITHUB=	yes
GH_ACCOUNT=	bigdragonsoft

do-build:
	(cd ${WRKSRC}/src && ${MAKE})

do-install:
	${MKDIR} ${STAGEDIR}${PREFIX}/etc/bvm
	(cd ${WRKSRC}/conf && ${COPYTREE_SHARE} "*.conf" ${STAGEDIR}${PREFIX}/etc/bvm)
	${MKDIR} ${STAGEDIR}${PREFIX}/etc/rc.d
	(cd ${WRKSRC}/conf && ${COPYTREE_SHARE} "bvmd" ${STAGEDIR}${PREFIX}/etc/rc.d)
#	${CHMOD} +x ${STAGEDIR}${PREFIX}/etc/rc.d/bvmd
	${MKDIR} ${STAGEDIR}${PREFIX}/bin
	(cd ${WRKSRC}/src && ${COPYTREE_SHARE} "bvm bvmb" ${STAGEDIR}${PREFIX}/bin)
	${CHMOD} +x ${STAGEDIR}${PREFIX}/bin/bvm
	${CHMOD} +x ${STAGEDIR}${PREFIX}/bin/bvmb

.include <bsd.port.mk>
