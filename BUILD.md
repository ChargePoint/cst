# Build CST

This README explains how to create a build environment using the Dockerfile and build the CST source code.

### Create a build environment

This guide assumes some familiarity with Docker. If unfamiliar, it may be helpful to understand what a Docker Image and Container provide.
The Dockerfile takes some arguments that create a user. This helps provide consistency to permissions and ownership when mounting a local volume on the Docker host.

**Dockerfile Arguments**
   `hostUserName` - Specifies the User username to be created.
   `hostUID` - Specifies the UID for the created user.
   `hostGID` - Specifies the GID for the created user.

**Build the Docker Image**
To create the Docker image, use the following command line:

` $ docker build --build-arg hostUserName="$USER" --build-arg hostUID=$(id -u) --build-arg hostGID=$(id -g) -t cst:build -f Dockerfile . `

**Create Docker Container**
After the Docker Image is available, create a container based on it. It is convenient to mount a volume on the docker host where the source will be built. This will allow easy access to the source and build artifacts from the host when the container is not running.
Modify the path to your host directory to be mounted:

` $ docker run -it -v $(pwd):/home/$USER/cst cst:build /bin/bash `

You should now be at a bash prompt inside the running container...

### Build CST

The CST makefile is designed to run by default on the host machine's operating system. However, it also offers the flexibility to specify a target operating system if needed. This is accomplished by setting the `OSTYPE` variable when invoking the makefile. The makefile supports  the following host OS types:

 - `linux64` - 64-bit Linux 
 - `linux32` - 32-bit Linux 
 - `mingw32` - Windows
 - `osx` - macOS

The makefile supports the following targets: 

 - `make`: Only builds the binaries. 
 - `make all`: Builds binaries only for all supported systems. 
 - `make install`: In addition to binaires, copies scripts and documentation to the output folder. 
 - `make clean`: Cleans build objects.
 - `make clobber`: Remove all build output files.
 - `make package`: Creates a complete package (a compressed file) containing binaries for all supported hosts, the source code, documentation, and scripts.

**NOTE** 
The `linux32`, `linux64`, and `mingw32` types are all tested to build in the Docker container. Building natively in Windows is not tested. The `osx` can be built natively in macOS.

The CST makefile has a rule to build OpenSSL. It will download, unpack, configure, and build OpenSSL. There are two ways the makefile can locate OpenSSL:

 1. Use the environment variable, `OPENSSL_PATH`. 
 2. If `OPENSSL_PATH` is not set, the makefile will download and build OpenSSL version 3.2.0 in the current directory. The OpenSSL version can be changed  using `OPENSSL_VERION` environment variable.

To build for a target host, type the following command

` $ make install`

To initiate the build process for a specific target host, for exmaple 64-bit Linux, please enter the command below:

` $ OSTYPE=linux64 make install`

The object files from this build can be found in code/obj.linux64
The build result is located in a ``build`` directory.

```
    build
    |-- ca
        |-- openssl.cnf
        |-- v3_ca.cnf
        |-- v3_usr.cnf
    |-- crts
    |-- keys
        |-- add_key.bat
        |-- add_key.sh
        |-- ahab_pki_tree.bat
        |-- ahab_pki_tree.sh
        |-- hab4_pki_tree.bat
        |-- hab4_pki_tree.sh
    |-- linux64
        |-- bin
            |-- cst
            |-- srktool
```

### License
Copyright 2023 NXP
