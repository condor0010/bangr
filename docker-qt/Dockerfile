FROM debian:bookworm

# this is definitely too much, but it works so
RUN apt-get update && \
    apt-get install -y \
        apt-utils \
        firebird-dev \
        freetds-dev \
        gstreamer1.0-tools \
        gstreamer1.0-plugins-base \
        gstreamer1.0-plugins-good \
        gstreamer1.0-plugins-ugly \
        gstreamer1.0-x \
        libasound2-dev \
        libavcodec-dev \
        libavformat-dev \
        libavutil-dev \
        libbz2-dev \
        libcap-dev \
        libdbus-1-dev \
        libdbus-glib-1-dev \
        libdrm-dev \
        libegl1-mesa-dev \
        libevent-dev \
        libfontconfig1-dev \
        libfreetype6-dev \
        libgbm-dev \
        libgcrypt20-dev \
        libgles2-mesa-dev \
        libglib2.0-dev \
        libgstreamer-plugins-base1.0-dev \
        libgstreamer1.0-dev \
        libicu-dev \
        libinput-dev \
        libiodbc2-dev \
        libjpeg62-turbo-dev \
        libjsoncpp-dev \
        libminizip-dev \
        libnss3-dev \
        libopus-dev \
        libpci-dev \
        libpng-dev \
        libpng16-16 \
        libpq-dev \
        libpulse-dev \
        librsvg2-common \
        libsnappy-dev \
        libsqlite3-dev \
        libsrtp2-dev \
        libssl-dev \
        libswscale-dev \
        libsystemd-dev \
        libts-dev \
        libudev-dev \
        libvpx-dev \
        libwayland-dev \
        libwebp-dev \
        libx11-dev \
        libx11-xcb-dev \
        libx11-xcb1 \
        libxcb-glx0-dev \
        libxcb-icccm4 \
        libxcb-icccm4-dev \
        libxcb-image0 \
        libxcb-image0-dev \
        libxcb-keysyms1 \
        libxcb-keysyms1-dev \
        libxcb-randr0-dev \
        libxcb-render-util0 \
        libxcb-render-util0-dev \
        libxcb-shape0-dev \
        libxcb-shm0 \
        libxcb-shm0-dev \
        libxcb-sync-dev \
        libxcb-sync1 \
        libxcb-xfixes0-dev \
        libxcb-xinerama0 \
        libxcb-xinerama0-dev \
        libxcb1 \
        libxcb1-dev \
        libxext-dev \
        libxi-dev \
        libxcb-dri3-dev \
        libxkbcommon-dev \
        libxkbcommon-x11-dev \
        libxkbfile-dev \
        x11-xserver-utils \
        libxkbcommon-dev \
        libxrender-dev \
        libxslt1-dev \
        libxss-dev \
        libxtst-dev \
        nodejs \
        ruby \
        va-driver-all \
        wget

RUN apt-get update && \
    apt-get -y install \
        bison \
        build-essential \
        ccache \
        cowsay \
        curl \
        flex \
        freetds-dev \
        g++ \
        g++-multilib \
        gcc-multilib \
        git \
        gperf \
        gyp \
        lib32z1-dev \
        libasound2 \
        libasound2-dev \
        libavcodec-dev \
        libavformat-dev \
        libavutil-dev \
        libbz2-dev \
        libcap-dev \
        libdbus-1-dev \
        libdbus-glib-1-dev \
        libdrm-dev \
        libegl1-mesa-dev \
        libglu1-mesa-dev \
        libevent-dev \
        libfontconfig1 \
        libfontconfig1-dev \
        libfreetype6 \
        libgbm-dev \
        libgcrypt20-dev \
        libgles2-mesa-dev \
        libinput-dev \
        libjpeg62-turbo-dev \
        libjsoncpp-dev \
        libminizip-dev \
        libnss3 \
        libnss3-dev \
        libopus-dev \
        libpci-dev \
        libpng16-16 \
        libpulse-dev \
        libsecret-1-0 \
        libsnappy-dev \
        libsrtp2-dev \
        libssl-dev \
        libtiff6 \
        libts-dev \
        libudev-dev \
        libvpx-dev \
        libwebp-dev \
        libxss-dev \
        libxss1 \
        libxtst-dev \
        lsb-release \
        ninja-build \
        nodejs \
        rsync \
        ruby \
        subversion \
        wget \
        make \ 
        cmake && \
    apt-get clean

COPY ./xcb_deps.txt /xcb_deps.txt
RUN xargs apt install -y < /xcb_deps.txt

#RUN git clone --branch v6.7.2 git://code.qt.io/qt/qt5.git qt6
#RUN mkdir /qt6-build
#RUN mkdir /qt6-install

#WORKDIR /qt6
#RUN perl init-repository --module-subset=qtbase

#WORKDIR /qt6-build
#RUN ../qt6/configure -submodules qtbase -xcb -prefix /qt6-install/

RUN wget https://binary.ninja/qt6.7.2.tar.xz
RUN tar xf qt6.7.2.tar.xz
RUN git clone https://github.com/Vector35/qt-build.git
RUN apt install -y python3-pip
RUN pip3 install poetry --break-system-packages

RUN wget https://apt.llvm.org/llvm.sh
RUN chmod +x llvm.sh
RUN apt install -y software-properties-common
RUN ./llvm.sh 16 all
ENV LLVM_INSTALL_DIR=/usr/lib/
WORKDIR /qt-build
RUN sed -i "s/16\.0\.0/llvm-16/" target_qt6_version.py
RUN echo y | ./build_linux --qt-source ../qt6.7.2 --pyside-source ../pyside6.7.2/
