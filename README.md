# bpf-armour-ml
A high-performance network anomaly detection framework powered by eBPF, XDP (eXpress Data Path), and ML(decision tree and neural network). This project allows for packet inspection and filtering at the earliest possible point in the kernel driver, providing low-overhead monitoring and security enforcement.

This repository also contains our fixed-point library under lib/fixed-point directory.
This library is specifically implemented to target eBPF programs, and to circumvent restrictions imposed by the verifier. It is also an extension of our previous work in [FIDe](https://github.com/fukuda-lab/FIDe). For more details on dynamic fixed-point, visit  [FIDe](https://github.com/fukuda-lab/FIDe) or our [paper](https://dl.acm.org/doi/10.1145/3674213.3674219).

## Prerequisites

To build and run this project, you need a Linux environment with the following dependencies.

### Build Dependencies
* **Clang/LLVM** 
* **Make**
* **bpftool**
* **GCC**

#### Installing xdp-tools (Ubuntu/Debian)
```bash
sudo apt update
sudo apt install xdp-tools

```


## Getting Started

### 1. Clone the Repository

This repository uses `libbpf` as a git submodule. Please clone with the recursive flag.

```bash
git clone --recursive git@github.com:fukuda-lab/bpf-armour-ml.git
cd bpf-armour-ml
```

> **Note:** If you cloned without `--recursive`, run the following to fetch the submodule:
> ```bash
> git submodule update --init --recursive
> 
> ```
> 
> 

### 2. Build

Run `make` to compile the eBPF program. You might need to be root.

```bash
cd main
make

```

Upon success, the eBPF object file will be generated as:

* `bpf-armour.o`

## Usage

We recommend using `xdp-loader` to manage the lifecycle of the XDP program. This ensures proper attachment and map pinning.

### Loading the Program

Attach the program to your network interface (e.g., `eth0`).

```bash
# Generic Mode (Works on most drivers, good for testing)
sudo xdp-loader load [interface_name] .bpf-armour.o

# Native Mode (High performance, requires driver support)
# sudo xdp-loader load -m native eth0 .output/detector.bpf.o

```

### Checking Status

Verify that the program is loaded and running.

```bash
sudo xdp-loader status
```

### Unloading

To detach the program and clean up:

```bash
sudo xdp-loader unload [interface_name] --all

```

## Directory Structure

* `main/`: Source code for eBPF programs.
* `lib/fixed-point`: Directory that contains fixed-point library. (header files)
* `lib/libbpf/`: Submodule for libbpf.

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License

[MIT](https://www.google.com/search?q=LICENSE)