#!/bin/sh

if [ $# -lt 1 ];then
    echo "You should input the dir of brcmSDK.tar.gz"
	exit 1
fi

INSTALL_DIR=$1
SDK_PATH=${INSTALL_DIR}/brcmSDK
CURDIR=`pwd`

if [ ! -f ${INSTALL_DIR}/brcmSDK.tar.gz ];then
	echo "brcmSDK.tar.gz does not exist"
	exit 1
fi


if [ ! -d ${SDK_PATH} ];then
	tar -zxf ${INSTALL_DIR}/brcmSDK.tar.gz -C ${INSTALL_DIR}
	if [ $? -ne 0 ];then
		echo "can not unzip brcmSDK.tar.gz "
		exit 1
	fi
fi

export PATH=${SDK_PATH}/tools/arm-linux-androideabi-4.7/bin:$PATH

echo "begin to config"
${CURDIR}/configure --prefix=${CURDIR}/out --host=arm-linux \
--with-cc=arm-linux-androideabi-gcc --with-linkcc=arm-linux-androideabi-gcc --with-ar=arm-linux-androideabi-ar \
--with-default-snmp-version="2" --with-sys-contact="contact" --with-sys-location="location" \
--with-logfile="/var/log/snmpd.log" --with-persistent-directory="/var/net-snmp" --with-persistent-directory="/var/net-snmp" \
--disable-mibs --disable-embedded-perl --without-perl-modules \
--with-out-mib-modules="snmpv3mibs mibII ucd_snmp notification notification-log-mib target agent_mibs agentx disman/event disman/schedule utilities host" \
--with-ldflags="-nostdlib -Wl,--gc-sections -Wl,-Bsymbolic -L${SDK_PATH}/lib -Wl,--no-whole-archive -lcutils -lc -lm -lgcc \
 -Wl,--no-undefined -Wl,--whole-archive -Wl,--fix-cortex-a8" \
--with-cflags="-I${SDK_PATH}/include/bionic/libc/include \
        -I${SDK_PATH}/include/bionic/libm/include \
        -I${SDK_PATH}/include/bionic/libc/arch-arm/include \
        -I${SDK_PATH}/include/bionic/libc/kernel/common \
        -I${SDK_PATH}/include/bionic/libc/kernel/arch-arm \
        -Dmmap64=mmap   -march=armv7-a -mfloat-abi=softfp -finline-functions -finline-limit=300 -fno-inline-functions-called-once -fgcse-after-reload -frerun-cse-after-loop \
        -frename-registers -fomit-frame-pointer -fstrict-aliasing -funswitch-loops   -msoft-float  -DBDBG_DEBUG_BUILD=1 -D_GNU_SOURCE=1 -DLINUX -pipe -D_FILE_OFFSET_BITS=64 \
        -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -DBSTD_CPU_ENDIAN=BSTD_ENDIAN_LITTLE -Wstrict-prototypes -Wno-unused-value" \
1>>${CURDIR}/build.log 2>&1

sed -i 's/CC -shared \\/CC -shared -nostdlib \\/g' ${CURDIR}/libtool
sed -i "s/^LIBS\t\t=/LIBS\t\t= ${SDK_PATH//\//\\/}\/lib\/crtbegin_dynamic.o ${SDK_PATH//\//\\/}\/lib\/crtend_android.o/g" apps/Makefile

if [ $? -ne 0 ];then
	echo "can not config net-snmp, check ${CURDIR}/build.log for more info"
	exit 1
fi
echo "config net-snmp success"

echo "begin to make"
make 1>>${CURDIR}/build.log 2>&1
if [ $? -ne 0 ];then
	echo "make failed, check ${CURDIR}/build.log for more info"
	exit 1
fi
echo "make success"

echo "begin to install"
make install 1>>${CURDIR}/build.log 2>&1
if [ $? -ne 0 ];then
	echo "install failed, check ${CURDIR}/build.log for more info"
	exit 1
fi
echo "install success"

mv ${CURDIR}/build.log ${CURDIR}/out/build.log
