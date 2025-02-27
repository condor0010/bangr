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
| Setting up multi-threading by functions.                                                                             |Louie         | :large_blue_circle: | 2025/03/07 |             |
| Reorganizing SSA operations into sets based off their taint level.                                                   |Dylan         | :green_circle: | 2025/03/07 |             |
| Insert comments into the BinaryNinja UI.                                                                             |Marcus        | :large_blue_circle: | 2025/03/07 |             |
| Make it show up as a plugin in the BinaryNinja UI.                                                                   |Louie         | :green_circle:      | 2025/03/07 |             |
| Implement the translation of BinaryNinja MLIL to use in Z3.                                                          |Marcus        | :large_blue_circle: | 2025/03/07 |             |
| Coalescing functions to track the inheritance of taint.                                                              |Louie/Marcus  | :red_circle:        | TBD        |             |
| Develop a Data Structure paired to each group of codeblocks to facilitate the tracking of taint.                     |Marcus        | :red_circle:        | N/A        | N/A         |
