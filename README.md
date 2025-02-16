# Senior Project - Bangr


Marcus & Dylan, use the following link if you have issues - Louie 
`https://docs.binary.ninja/dev/plugins.html#project-setup`


### Setup Repository

```
git clone git@github.com:condor0010/bangr.git
cd bangr
git submodule update --init --recursive
```

### Build Commands (if you don't want to use build.sh)

You might need to change the paths listed in these commands.

```
export BN_API_PATH=/home/senproj/proj/binaryninjaapi/
export BN_INSTALL_DIR=/opt/binaryninja/
cmake -S . -B build
pushd build
make
```

### Use this if issues arise with the codeblock above

```
podman build . -t senproj -f .oci
podman run --rm -v "$(pwd):/root/bangr" -v /opt/binaryninja/:/opt/binaryninja -ti senproj
```

### Usage

```
build/out/bin/bangr test_bins/num 0x00401146
```

# TODO list

## States

🔴 - Not done

🔵 - Started

🟡 - Done & Untested

🟢 - Done & Tested

| Task                                                                                                                 | Person | State                     | Due Date   | Commit Hash |
|----------------------------------------------------------------------------------------------------------------------|--------|---------------------------|------------|-------------|
| Setting up multi-threading / codeblock grouping.                                                                     |Louie         | :large_blue_circle: | 2025/01/31 |             |
| Reorganizing SSA operations into sets based off their taint level.                                                   |Marcus        | :large_blue_circle: | 2025/01/31 |             |
| Insert comments into the BinaryNinja UI.                                                                             |Marcus        | :large_blue_circle: | 2025/01/31 |             |
| Make it show up as a plugin in the BinaryNinja UI.                                                                   |Dylan         | :large_blue_circle: | 2025/01/31 |             |
| Coalescing codeblocks/functions to track the inheritance of taint.                                                   |Louie/Marcus  | :red_circle:        | TBD        |             |
| Develop a Data Structure paired to each group of codeblocks to facilitate the tracking of taint.                     |Marcus        | :red_circle:        | TBD        |             |
