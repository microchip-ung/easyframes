# EasyFrames (`ef`)

This is a small and simple command-line tool for network testing. The tool makes
it simple to compose a frame, inject and express what and where frames are
expected to be received.

The tool can be used as a stand-alone tool, or it can be integrated in other
scripts or testing frame works.

To learn more, have a look at the help message below.

    $ ef -h
    Usage: ef [options] <command> args [<command> args]...
    
    The ef (easy frame) tool allow to easily transmit frames, and
    optionally specify what frames it expect to receive.
    
    Options:
      -h                    Top level help message.
      -t <timeout-in-ms>    When listening on an interface (rx),
         When listening on an interface (rx), the tool will always
         listen during the entire timeout period. This is needed,
         as we must also check that no frames are received during
         the test.  Default is 100ms.
    
      -c <if>,[<snaplen>],[<sync>],[<file>],[cnt]
         Use tcpdump to capture traffic on an interface while the
         test is running. If file is not specified, then it will
         default to './<if>.pcap'
         tcpdump will be invoked with the following options:
         tcpdump -i <if> [-s <snaplen>] [-j <sync>] -w <file> -c <cnt>
    
    
    Valid commands:
      tx: Transmit a frame on a interface. Syntax:
      tx <interface> FRAME | help
    
      rx: Specify a frame which is expected to be received. If no 
          frame is specified, then the expectation is that no
          frames are received on the interface. Syntax:
      rx <interface> [FRAME] | help
    
      hex: Print a frame on stdout as a hex string. Syntax:
      hex FRAME
    
      name: Specify a frame, and provide a name (alias) for it.
            This alias can be used other places instead of the
            complete frame specification. Syntax:
      name <name> FRAME-SPEC | help
    
      pcap: Write a frame to a pcap file (appending if the file
      exists already). Syntax:
      pcap <file> FRAME | help
    
    Where FRAME is either a frame specification of a named frame.
    Syntax: FRAME ::= FRAME-SPEC | name <name>
    
    FRAME-SPEC is a textual specification of a frame.
    Syntax: FRAME-SPEC ::= [HDR-NAME [<HDR-FIELD> <HDR-FIELD-VAL>]...]...
            HDR-NAME ::= eth|stag|ctag|arp|ipv4|udp
    
    Examples:
      ef tx eth0 eth dmac ::1 smac ::2 stag vid 0x100 ipv4 dip 1 udp
    
      ef name f1 eth dmac ff:ff:ff:ff:ff:ff smac ::1\
         rx eth0 name f1\
         tx eth1 name f1
    
    A complete header or a given field in a header can be ignored by
    using the 'ign' or 'ignore' flag.
    Example:
      To ignore the ipv4 header completly:
      ef hex eth dmac 1::2 smac 3::4 ipv4 ign udp
    
      To ignore the ipv4 everything in the ipv4 header except the sip:
      ef hex eth dmac 1::2 smac 3::4 ipv4 ign sip 1.2.3.4 udp
    
      To ignore the sip field in ipv4:
      ef hex eth dmac 1::2 smac 3::4 ipv4 sip ign udp
    
    A frame can be repeated to utilize up to line speed bandwith (>512 byte frames)
    using the 'rep' or 'repeat' flag.
    Example:
       Send a frame 1 million times:
       ef tx eth0 rep 1000000 eth dmac ::1 smac ::2
       Note that the repeat flag must follow the tx <interface> key-word
       Results must be viewed through the PC or DUT interface counters, i.e. outside of 'ef'


# Build it, install run

    $ mkdir build
    $ cd build
    $ cmake ..
    $ make
    $ sudo make install


