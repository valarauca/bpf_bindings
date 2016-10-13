Berkely Packet Filter Bindings
---

[docs](https://valarauca.github.io/bpf_bindings/pbf_bindings/index.html)

This crate has a _semi_ high level bindings to the 32bit orginal bpf bindings. If you jump the gun and try to run this on Linux it will fail. You need to apply options to your Linux Kernel for it to support BPF filtering. 

FreeBSD, OpenBSD, and OSX support BPF out of the box. I need to do tests to esnure this crate is compatiable with all of them.

This crate is not compatible with the Linux eBPF extensions/layout. 
