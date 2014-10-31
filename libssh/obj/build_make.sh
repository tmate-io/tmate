#!/bin/bash
#
# Last Change: 2008-06-18 14:13:46
#
# Script to build libssh on UNIX.
#
# Copyright (c) 2006-2007 Andreas Schneider <asn@cryptomilk.org>
#

SOURCE_DIR=".."

LANG=C
export LANG

SCRIPT="$0"
COUNT=0
while [ -L "${SCRIPT}" ]
do
	SCRIPT=$(readlink ${SCRIPT})
	COUNT=$(expr ${COUNT} + 1)
	if [ ${COUNT} -gt 100 ]; then
		echo "Too many symbolic links"
		exit 1
	fi
done
BUILDDIR=$(dirname ${SCRIPT})

cleanup_and_exit () {
	if test "$1" = 0 -o -z "$1" ; then
		exit 0
	else
		exit $1
	fi
}

function configure() {
	if [ -n "${CMAKEDIR}" ]; then
		${CMAKEDIR}/bin/cmake "$@" ${SOURCE_DIR} || cleanup_and_exit $?
	else
		cmake "$@" ${SOURCE_DIR} || cleanup_and_exit $?
	fi
}

function compile() {
	if [ -f /proc/cpuinfo ]; then
		CPUCOUNT=$(grep -c processor /proc/cpuinfo)
	elif test `uname` = "SunOS" ; then
		CPUCOUNT=$(psrinfo -p)
	else
		CPUCOUNT="1"
	fi

	if [ "${CPUCOUNT}" -gt "1" ]; then
		${MAKE} -j${CPUCOUNT} $1 || cleanup_and_exit $?
	else
		${MAKE} $1 || exit $?
	fi
}

function clean_build_dir() {
	find ! -path "*.svn*" ! -name "*.bat" ! -name "*.sh" ! -name "." -print0 | xargs -0 rm -rf
}

function usage () {
echo "Usage: `basename $0` [--prefix /install_prefix|--build [debug|final]|--clean|--verbose|--libsuffix (32|64)|--help|--clang|--cmakedir /directory|--make
(gmake|make)|--ccompiler (gcc|cc)|--withstaticlib|--unittesting|--clientunittesting|--withssh1|--withserver]"
    cleanup_and_exit
}

cd ${BUILDDIR}

# the default CMake options:
OPTIONS="--graphviz=${BUILDDIR}/libssh.dot"

# the default 'make' utility:
MAKE="make"

while test -n "$1"; do
	PARAM="$1"
	ARG="$2"
	shift
	case ${PARAM} in
		*-*=*)
		ARG=${PARAM#*=}
		PARAM=${PARAM%%=*}
		set -- "----noarg=${PARAM}" "$@"
	esac
	case ${PARAM} in
		*-help|-h)
			#echo_help
			usage
			cleanup_and_exit
		;;
		*-build)
			DOMAKE="1"
			BUILD_TYPE="${ARG}"
			test -n "${BUILD_TYPE}" && shift
		;;
		*-clean)
			clean_build_dir
			cleanup_and_exit
		;;
		*-clang)
			OPTIONS="${OPTIONS} -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++"
		;;
		*-verbose)
			DOVERBOSE="1"
		;;
		*-memtest)
			OPTIONS="${OPTIONS} -DMEM_NULL_TESTS=ON"
		;;
		*-libsuffix)
			OPTIONS="${OPTIONS} -DLIB_SUFFIX=${ARG}"
			shift
		;;
		*-prefix)
			OPTIONS="${OPTIONS} -DCMAKE_INSTALL_PREFIX=${ARG}"
			shift
		;;
		*-sysconfdir)
			OPTIONS="${OPTIONS} -DSYSCONF_INSTALL_DIR=${ARG}"
			shift
		;;
		*-cmakedir)
			CMAKEDIR="${ARG}"
			shift
		;;
		*-make)
			MAKE="${ARG}"
			shift
		;;
		*-ccompiler)
			OPTIONS="${OPTIONS} -DCMAKE_C_COMPILER=${ARG}"
			shift
		;;
		*-withstaticlib)
			OPTIONS="${OPTIONS} -DWITH_STATIC_LIB=ON"
		;;
		*-unittesting)
			OPTIONS="${OPTIONS} -DWITH_TESTING=ON"
		;;
		*-clientunittesting)
			OPTIONS="${OPTIONS} -DWITH_CLIENT_TESTING=ON"
		;;
		*-withssh1)
			OPTIONS="${OPTIONS} -DWITH_SSH1=ON"
		;;
		*-withserver)
			OPTIONS="${OPTIONS} -DWITH_SERVER=ON"
		;;
		----noarg)
			echo "$ARG does not take an argument"
			cleanup_and_exit
		;;
		-*)
			echo Unknown Option "$PARAM". Exit.
			cleanup_and_exit 1
		;;
		*)
			usage
		;;
	esac
done

if [ "${DOMAKE}" == "1" ]; then
	OPTIONS="${OPTIONS} -DCMAKE_BUILD_TYPE=${BUILD_TYPE}"
fi

if [ -n "${DOVERBOSE}" ]; then
	OPTIONS="${OPTIONS} -DCMAKE_VERBOSE_MAKEFILE=1"
else
	OPTIONS="${OPTIONS} -DCMAKE_VERBOSE_MAKEFILE=0"
fi

test -f "${BUILDDIR}/.build.log" && rm -f ${BUILDDIR}/.build.log
touch ${BUILDDIR}/.build.log
# log everything from here to .build.log
exec 1> >(exec -a 'build logging tee' tee -a ${BUILDDIR}/.build.log) 2>&1
echo "${HOST} started build at $(date)."
echo

configure ${OPTIONS} "$@"

if [ -n "${DOMAKE}" ]; then
	test -n "${DOVERBOSE}" && compile VERBOSE=1 || compile
fi

DOT=$(which dot 2>/dev/null)
if [ -n "${DOT}" ]; then
	${DOT} -Tpng -o${BUILDDIR}/libssh.png ${BUILDDIR}/libssh.dot
	${DOT} -Tsvg -o${BUILDDIR}/libssh.svg ${BUILDDIR}/libssh.dot
fi

exec >&0 2>&0		# so that the logging tee finishes
sleep 1			# wait till tee terminates

cleanup_and_exit 0
