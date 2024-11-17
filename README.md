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

| task                                                                                                                 | person | state                     | Due date   | commit hash |
|----------------------------------------------------------------------------------------------------------------------|--------|---------------------------|------------|-------------|
| Setting up multi-threading / codeblock grouping                                                                      |Louie         | :large_blue_circle: | 2024/12/13 |             |
| Reorganizing SSA operations into sets based off their taint level                                                    |Marcus        | :red_circle:        | 2024/12/13 |             |
| Insert comments into the UI                                                                                          |Marcus        | :red_circle:        | 2024/12/13 |             |
| Make it show up as a plugin in the UI                                                                                |Dylan         | :large_blue_circle: | 2024/11/29 |             |
| coalescing codeblocks/functions to track the inheritence of taint                                                    |Louie/Marcus  | :red_circle:        | TBD        |             |
| DataStructure paired to each group of codeblocks to facliatete the tracking of taint                                 |Marcus        | :red_circle:        | TBD        |             |
