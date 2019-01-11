TODO - Write a much better readme file

A small tool to rx/tx frames

    ./ef -h
    Usage: ef [options] <command> args [<command> args]...
    
    The ef (easy frame) tool allow to easily transmit frames, and
    optionally specify what frames it expect to receive.
    
    Options:
      -h                    Top level help message.
      -t <timeout-in-ms>    When listening on an interface (rx),
                            the tool will always listen during the
                            entire timeout period. This is needed,
                            as we must also check that no frames
                            are received during the test.
                            Default is 100ms.
    
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
            HDR-NAME ::= eth|stag|ctag|arp|ip|udp
    
    Examples:
      ef tx eth0 eth dmac ::1 smac ::2 stag vid 0x100 ip da 1 udp
    
      ef name f1 eth dmac ff:ff:ff:ff:ff:ff smac ::1\
         rx eth0 name f1\
         tx eth1 name f1
    

