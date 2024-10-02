# Sen Proj

## should probably put shit here


marcus & dyaln use the following link if you have issues - Louie 
`https://docs.binary.ninja/dev/plugins.html#project-setup`


### setup repo

```
git clone git@github.com:condor0010/bangr.git
cd bangr
git submodule update --init --recursive
```

### build with this

```
export BN_API_PATH=/home/senproj/proj/binaryninjaapi/
export BN_INSTALL_DIR=/opt/binaryninja/
cmake -S . -B build
pushd build
make
```

### or this (if issues with ^)

```
podman build . -t senproj -f .oci
podman run --rm -v "$(pwd):/root/bangr" -v /opt/binaryninja/:/opt/binaryninja -ti senproj
```

