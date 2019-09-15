# IEEE 802.15.4 packet logs to PCAP files 

In this repository resides Pcapify, a simple Python script for converting log files of IEEE 802.15.4 traffic, for instance, collected with Bitsniff, to PCAP files.

## Introduction

For ease of use Pcapify supports a couple of user-defined log formats out-of-box and two link layer types for IEEE 802.15.4 packets having either an FCS or not. To get an idea of what user-defined log formats mean, a few examples are listed below.

```no-highlight
[2017-04-02 18:01:06,967]c0ffee
[2017-04-02 18:01:06,967] 0xc0 0xff 0xee
1500566466.965 c0 ff ee
1500566466965c0ffee
25 1500566466.965     1000 c0 ff ee
```

Perhaps one could use, Pcapify as a starting point for developing more complex conversions of log files to PCAP files including AES decryption, decomposition of MAC and NET headers for in-depth analysis of proprietary protocols and so on.

## Usage

Pcapify needs in the first place two arguments to get to work. One of these is for declaring where to look for input, the other is meant to provide knowledge about where to store the output.

```no-highlight
-id, --input-directory: a directory containing log files
-if, --input-file: a single log file
```

```no-highlight
-od, --output-directory: directory for storing PCAP files
-of, --output-file: just one PCAP file
```

Pcapify wants to know either FCS has been captured or not. This is just for setting a value for the IEEE 802.15.4 link layer, which is respected by almost every dissector capable of reading PCAP files.

```no-highlight
-fc, --frame-check: frame check sequence is present
```

The last argument is also optional. It can be used to split the output with regard to time. This option prevents creating massive PCAP files taking hours to load and process by splitting the output into chunks, each getting its own file.

```no-highlight
-cp, --chunk-period: split PCAP files into chunks of seconds
```

## Examples

### Convert log files in a directory to PCAP

Providing the arguments as follows, Pcapify reads all files in the subdirectory *./log* and stores the subsequent PCAP files in the subdirectory *./out*. Due to the chunking, each PCAP file obtains a maximum timeframe of 86400 seconds, which equals one day. Since frame check is set, the IEEE 802.15.4 link layer in all PCAP files is set to 195 (0xC3) signaling a frame check sequence (FCS) at the end of each packet.

```bash
$ python3 pcapify.py -id ./log -od ./out -cp 86400 -fc
```

### Pipe to Wireshark

Pcapify can read content on stdin (e.g. created by [Bitsniff](https://github.com/m6c7l/bitsniff)) and forward the output to another pipe, which is observed by another process (e.g. Wireshark). Since Bitsniff appends an FCS to all received frames, the frame check should be  set.

```bash
$ mkfifo wireshark.in
$ wireshark -k -i wireshark.in &
$ java -jar bitsniff.jar -c 26 -p /dev/ttyACM0 | python3 pcapify.py -sf /dev/stdin -tf wireshark.in -fc
```


