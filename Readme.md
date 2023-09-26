# Hyperproofs

Hyperproofs, the first vector commitment (VC) scheme that is efficiently maintainable and aggregatable.
This repo contains the implementation of Hyperproofs in go.

This repo depends on:
- [go-mcl](https://github.com/alinush/go-mcl/) for elliptic curve operations.
- [kzg-go](https://github.com/hyperproofs/kzg-go) for KZG commitments.
- [gipa-go](https://github.com/hyperproofs/gipa-go) for proof aggregation.

[hyperproofs]: https://ia.cr/2021/599
## Instructions

### Software requirements
- Install golang, python
   ```bash
   $ sudo apt-get install git python curl python3-pip libgmp-dev libflint-dev
   $ sudo add-apt-repository ppa:longsleep/golang-backports
   $ sudo apt-get install golang golang-go golang-doc golang-golang-x-tools
   $ pip3 install -U pip pandas matplotlib
   ```
- Install ```mcl```
   ```bash
   $ git clone https://github.com/herumi/mcl
   $ cd mcl/
   $ git checkout caf27db2 #herumi/mcl v1.86.0
   $ cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
   $ cmake --build build
   $ sudo cmake --build build --target install
   $ sudo ldconfig
   ```

### Hyperproofs
0. See [v1.0.0](https://github.com/hyperproofs/hyperproofs-go/tree/51cc725b150c839987c26a3edf89fc2808fe4231) for the USENIX 2022 version
1. Run ```time bash scripts/hyper-go.sh``` to setup PRK, VRK, UPK, etc.
2. Run ```time bash scripts/hyper-bench.sh``` to replicate the benchmarks reported in the [paper][hyperproofs].
   - Does not benchmark OpenAll and Commit by default. Uncomment the [corresponding lines](https://github.com/hyperproofs/hyperproofs-go/blob/main/scripts/hyper-bench.sh#L23) in the shell script to run the benchmarks.
3. Copy ```pedersen-30-single.csv``` and ```poseidon-30-single.csv``` from [bellman-bignat](https://github.com/hyperproofs/bellman-bignat) to [hyperproofs-go/plots](https://github.com/hyperproofs/hyperproofs-go/tree/main/plots). Then, run ```cd plots; time python3 gen-plots.py``` to generate the plots.
## Reference

[_Hyperproofs: Aggregating and Maintaining Proofs in Vector Commitments_][hyperproofs]\
[Shravan Srinivasan](https://github.com/sshravan), Alexander Chepurnoy, Charalampos Papamanthou, [Alin Tomescu](https://github.com/alinush), and Yupeng Zhang\
ePrint, 2021
