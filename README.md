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

### useage

```
build/out/bin/bangr test_bins/num 0x00401146
```

# TODO list

## states

🔴 - not done

🔵 - started

🟡 - done & untested

🟢 - done & tested

| task                                                                                                                 | person | state |
|----------------------------------------------------------------------------------------------------------------------|--------|-------|
| Setting up multi-threading                                                                                           |        |       |
| Reorganizing SSA operations into sets based off their taint level                                                    |        |       |
| Insert comments into the UI                                                                                          |        |       |
| Make it show up as a plugin in the UI                                                                                |        |       |
| Tree that is analogous to CFG tree in step 3, each node will store the change of taint that block will cause         |        |       |
| Condense basic blocks with only one parent so that all such blocks in a sequence can be started on a singular thread |        |       |

