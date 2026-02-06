# Man-In-The-Middle (ARP poisoning) — EVE‑NG lab
______________________

## Summary
Controlled EVE‑NG laboratory demonstrating ARP cache poisoning to perform a transparent Man‑in‑the‑Middle (MITM) on a local subnet and comparing credential exposure between an insecure HTTP web application and a secured HTTPS application with application‑level protections.

- Objectives
Reproduce ARP spoofing to redirect traffic between a victim and the gateway.
Capture and analyze intercepted traffic to assess credential exposure.
Evaluate the effectiveness of transport encryption and application controls (TLS, CSRF, secure cookie attributes, security headers).

- Topology overview
Isolated EVE‑NG environment with gateway/router, victim host, and a combined server/attacker host. The server host runs two Flask test applications and also performs the ARP‑spoofing and packet capture; IP forwarding is enabled on that host to maintain transparent traffic relay while inspecting packets.

Tools and components
Scapy for crafting and sending forged ARP replies and for packet sniffing.

nmap for host and service discovery.

tcpdump / Wireshark for packet capture and analysis.

Flask test applications: one served over HTTP (no CSRF) and one over HTTPS with CSRF protection, HttpOnly/Secure/SameSite cookie attributes and common security headers.

Key operational steps
Discover hosts and identify gateway and targets via network scan.

Enable IP forwarding on the combined server/attacker host to allow transparent traffic relay.

Continuously send forged ARP replies to both victim and gateway to associate the attacker/server MAC with the gateway IP.

Capture traffic on the attacker/server host while performing form submissions to each web application and analyze packet contents.

Findings
HTTP application: POST bodies, session cookies and credentials were visible in cleartext and trivially captured by passive packet inspection.

HTTPS application: captured packets contained TLS records only; form fields and cookies remained encrypted and unreadable to a passive on‑path observer.

Transport encryption combined with application controls (CSRF tokens, secure cookie attributes, security headers) materially reduces the risk of credential theft from passive MITM attacks.

Ethical and legal considerations
All testing must be performed in an isolated, authorized environment. ARP spoofing and traffic interception without explicit permission are illegal and unethical. The lab was executed under explicit authorization and documented for defensive improvement.

Reproducibility notes
Run the lab only in a controlled environment. Required capabilities include root access on the combined server/attacker host, Scapy installed, and packet capture tools available. Isolate the lab network from production systems and obtain written authorization before testing.
