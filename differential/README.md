# differential package

*differential search with branch-and-bound method*

there has been used multithreading with goroutines. the process was split into 8 independent threads and data was read from the channels. there was no delay in communication between channels since the channel was buffered by 0x10000.