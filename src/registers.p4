// We need to define 3 counters for each connection
//      - Timestamp delay per connection    -> float    -> 32 bits
//      - Connection frequency              -> float    -> 32 bits
//      - Connections / address             -> int      -> 32 bits

// We need to define 3 global counters
//      - Timestamp delay per connection    -> float    -> 32 bits
//      - Connection frequency              -> float    -> 32 bits
//      - Connections / address             -> int      -> 32 bits

#define INDIVIDUAL_COUNTER_ENTRIES 3

// -- Counters per connection --

counter(INDIVIDUAL_COUNTER_ENTRIES, CounterType.packets_and_bytes) Individual_packets_sent;
counter(INDIVIDUAL_COUNTER_ENTRIES, CounterType.packets) Individual_connections;

// We can count either Packets, Bytes, Packets & Bytes
//      -> Packets: Connections / address
//      -> Packets and Bytes: Average packet size