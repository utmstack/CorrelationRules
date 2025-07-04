# UTMStack Correlation Rules Project Structure and Comprehensive Rules List

## Project Folder Structure

```
utmstack/Correlation/v11/
├── antivirus/
│   ├── bitdefender_gz/
│   ├── deceptive-bytes/
│   ├── esmc-eset/
│   ├── kaspersky/
│   └── sentinel-one/
├── aws/
├── cisco/
│   ├── asa/
│   ├── cs_switch/
│   ├── firepower/
│   └── meraki/
├── cloud/
│   ├── azure/
│   └── google/
├── filebeat/
│   ├── apache_module/
│   ├── auditd_module/
│   ├── elasticsearch_module/
│   ├── haproxy_module/
│   ├── iis_module/
│   ├── kafka_module/
│   ├── kibana_module/
│   ├── logstash_module/
│   ├── mongodb_module/
│   ├── mysql_module/
│   ├── nats_module/
│   ├── nginx_module/
│   ├── osquery_module/
│   ├── postgresql_module/
│   ├── redis_module/
│   ├── system_linux_module/
│   └── traefik_module/
├── fortinet/
│   ├── fortinet/
│   └── fortiweb/
├── generic/
│   └── generic/
├── github/
│   └── github/
├── hids/
├── ibm/
│   ├── ibm_aix/
│   └── ibm_as_400/
├── json/
│   └── json-input/
├── linux/
│   ├── debian_family/
│   └── rhel_family/
├── macos/
├── mikrotik/
│   └── mikrotik_fw/
├── netflow/
├── nids/
├── office365/
├── paloalto/
│   └── pa_firewall/
├── pfsense/
├── sonicwall/
│   └── sonicwall_firewall/
├── sophos/
│   ├── sophos_central/
│   └── sophos_xg_firewall/
├── syslog/
│   ├── cef/
│   ├── rfc-5424/
│   ├── rfc-5425/
│   └── rfc-6587/
├── vmware/
│   └── vmware-esxi/
└── windows/
```

## Comprehensive Correlation Rules by Technology/Vendor

### 1. ANTIVIRUS

#### BitDefender
- Multiple malware detections from single source
- Malware outbreak detection (multiple hosts infected)
- Failed antivirus updates across multiple endpoints
- Antivirus service stopped or disabled
- Real-time protection disabled
- Quarantine failures
- Suspicious exclusions added
- License expiration alerts
- High-severity threat detection
- Zero-day malware detection
- Ransomware behavior detection
- Fileless malware detection
- Advanced persistent threat (APT) detection
- Crypto-mining detection
- Rootkit detection
- Bootkit detection
- Memory-based threat detection
- Network-based threat detection
- Email-based threat spreading
- USB-based malware propagation

#### Deceptive Bytes
- Deception token access patterns
- Honeypot interaction detection
- Decoy file access attempts
- Honey credential usage alerts
- Fake service connection attempts
- Decoy share access monitoring
- Honey table query detection
- Deception API call tracking
- Fake user authentication attempts
- Decoy system enumeration
- Lateral movement trap triggers
- Privilege escalation bait detection
- Data theft attempt indicators
- Ransomware behavior patterns
- Living off the land detection
- Advanced threat tactic identification
- Zero-day behavior patterns
- Insider threat indicators
- Supply chain compromise detection
- Industrial espionage patterns
- Nation-state tactic detection
- Criminal group signatures
- Threat actor attribution
- Campaign correlation
- Attack timeline construction

#### ESET
- Multiple threat detections in short timeframe
- Banking trojan detection
- Potentially unwanted application (PUA) surge
- Web protection blocks spike
- Email scanner threat detection pattern
- Network attack detection
- Host intrusion prevention triggers
- Suspicious PowerShell activity blocked
- Exploit detection events
- Botnet communication attempts
- Advanced heuristic detection triggers
- Machine learning detection anomalies
- Suspicious process behavior
- Registry modification attempts blocked
- Firewall rule violations
- Device control policy violations
- Data loss prevention triggers
- Suspicious encrypted file detection
- Webcam protection alerts
- Microphone hijacking attempts

#### Kaspersky
- Critical object detected patterns
- Application privilege escalation attempts
- Suspicious network activity patterns
- Vulnerability exploit attempts
- Suspicious file modification patterns
- System file tampering detection
- Trusted application compromise
- Certificate validation failures
- Sandbox evasion attempts
- Anti-analysis behavior detection
- Suspicious packed executables
- Code injection attempts
- Process hollowing detection
- Living off the land (LOLBins) abuse
- Lateral movement indicators
- Data exfiltration attempts
- Command and control communication
- Suspicious scheduled tasks
- WMI abuse detection
- Suspicious service installation

#### Sentinel One
- Behavioral threat detection patterns
- AI-based threat hunting alerts
- Endpoint detection and response (EDR) alerts
- Suspicious process tree analysis
- Memory injection detection
- Kernel-level threat detection
- Deep visibility threat indicators
- Storyline correlation events
- Threat intelligence matches
- Custom detection rule triggers
- Rollback operation patterns
- Threat mitigation failures
- Agent tampering attempts
- Offline agent detection patterns
- Mass deployment anomalies
- Policy violation patterns
- Suspicious script execution
- Container security alerts
- Cloud workload protection alerts
- IoT device compromise indicators

### 2. AWS
- Root account usage without MFA
- IAM backdoor creation attempts
- S3 bucket public exposure
- CloudTrail logging disabled
- Mass resource deletion
- Unusual API call patterns
- Cross-account access anomalies
- Security group modifications
- Network ACL changes
- VPC flow log anomalies
- Lambda function privilege escalation
- EBS snapshot sharing violations
- RDS security group changes
- EC2 instance metadata abuse
- AWS Systems Manager session anomalies
- GuardDuty high-severity findings
- Macie sensitive data exposure
- Config compliance violations
- CloudWatch alarm deletions
- KMS key policy modifications
- Secrets Manager access patterns
- STS token abuse
- Route 53 DNS hijacking attempts
- CloudFormation stack deletions
- Cost anomaly detection
- Reserved instance modifications
- Billing alarm triggers
- Support case anomalies
- AWS SSO suspicious activities
- Control Tower guardrail violations

### 3. CISCO NETWORK DEVICES

#### Cisco ASA
- VPN geographic impossibility travel
- Multiple failed VPN attempts
- Privilege escalation via enable mode
- Configuration changes outside maintenance
- Firewall rule modifications
- NAT rule changes
- Access list modifications
- Threat detection triggers
- Botnet traffic detection
- IPS signature matches
- High CPU/memory utilization
- Interface flapping patterns
- Failover events
- License violations
- SNMP community string changes
- Syslog server modifications
- Time synchronization failures
- Certificate expiration warnings
- WebVPN suspicious activities
- AnyConnect client anomalies
- Site-to-site VPN failures
- Object group modifications
- Security context changes
- Clustering anomalies
- Transparent firewall mode changes

#### Cisco Switches
- VLAN hopping attempts
- MAC address spoofing
- ARP poisoning detection
- Spanning tree attacks
- Port security violations
- DHCP snooping violations
- Dynamic ARP inspection failures
- IP source guard violations
- Storm control triggers
- Port mirroring configuration
- Unauthorized SNMP access
- Configuration rollback events
- High error rates
- Interface CRC errors
- Power over Ethernet anomalies
- Stack member failures
- VSS split-brain detection
- QoS policy violations
- Access control list changes
- Private VLAN violations
- 802.1X authentication failures
- MAC authentication bypass attempts
- Smartport macro executions
- NetFlow configuration changes
- ERSPAN session modifications

#### Cisco Firepower
- Advanced malware protection alerts
- Intrusion prevention high-priority events
- URL filtering policy violations
- SSL decryption policy bypasses
- File policy violations
- Network discovery anomalies
- User identity mapping failures
- Application visibility anomalies
- Security intelligence blocks
- Correlation policy triggers
- Threat intelligence director alerts
- Vulnerability assessment findings
- Compliance policy violations
- Network behavior anomaly detection
- Encrypted visibility engine alerts
- DNS security alerts
- Email security alerts
- Endpoint security integration events
- Cloud security analytics
- Threat hunting query results
- Custom detection rule matches
- IOC (Indicator of Compromise) matches
- Retrospective detection events
- Outbreak control alerts
- License compliance issues

#### Cisco Meraki
- Rogue SSID detection
- Wireless intrusion attempts
- Client isolation violations
- Splash page bypasses
- Content filtering violations
- Advanced malware protection alerts
- Intrusion detection alerts
- Air Marshal security events
- Bluetooth beacon anomalies
- Location analytics anomalies
- Systems Manager compliance violations
- MDM policy violations
- Network topology changes
- Switch port anomalies
- Security appliance events
- SD-WAN path selection anomalies
- Traffic shaping policy violations
- Group policy misconfigurations
- API access anomalies
- Dashboard authentication failures
- Organization admin changes
- Network-wide setting modifications
- Firmware upgrade failures
- High availability failover events
- Environmental sensor alerts

### 4. CLOUD PLATFORMS

#### Azure
- Privilege escalation attempts
- Key Vault access spikes
- MFA disabled for privileged users
- Conditional access policy bypasses
- Azure AD suspicious sign-ins
- Resource group mass modifications
- Network security group changes
- Storage account public access
- SQL database firewall modifications
- Virtual machine suspicious activities
- Azure Sentinel alert patterns
- Defender for Cloud critical alerts
- Policy compliance violations
- Resource lock removals
- Management group changes
- Subscription ownership transfers
- Service principal abuse
- Managed identity anomalies
- Azure DevOps pipeline compromises
- Logic Apps suspicious executions
- Function Apps security alerts
- Container registry vulnerabilities
- AKS cluster security events
- Cosmos DB access anomalies
- Azure Firewall rule modifications
- ExpressRoute configuration changes
- Application Gateway WAF alerts
- API Management security events
- Azure Monitor diagnostic setting changes
- Cost management anomalies

#### Google Cloud Platform (GCP)
- IAM policy modifications
- Service account key creation spikes
- Cloud Storage bucket permission changes
- Compute Engine suspicious activities
- Cloud SQL security modifications
- VPC firewall rule changes
- Cloud Functions abuse
- BigQuery data exfiltration attempts
- Cloud KMS key access anomalies
- Stackdriver logging disabled
- Cloud Identity suspicious sign-ins
- Organization policy violations
- Cloud Asset inventory changes
- Binary Authorization bypasses
- Container Analysis vulnerabilities
- Cloud Security Scanner findings
- Cloud DLP policy violations
- VPC Service Controls breaches
- Cloud Armor rule modifications
- Cloud CDN cache poisoning attempts
- Cloud Load Balancing anomalies
- Cloud DNS hijacking attempts
- Cloud Spanner access patterns
- Dataflow job anomalies
- AI Platform prediction abuse
- Cloud Composer environment changes
- Anthos security events
- Chronicle security alerts
- Resource Manager hierarchy changes
- Billing anomaly detection

### 5. FILEBEAT MODULES

#### Apache Module
- Web server compromise indicators
- Directory traversal attempts
- Configuration file access
- .htaccess modifications
- Module loading anomalies
- Virtual host tampering
- SSL certificate issues
- Reverse proxy abuse
- CGI script exploitation
- WebDAV vulnerabilities
- HTTP method tampering
- Request smuggling attempts
- Response splitting attacks
- Denial of service patterns
- Brute force attempts
- Information disclosure
- Source code disclosure
- Backup file access
- Log injection attacks
- Server-status exposure
- ModSecurity violations
- Rate limiting bypasses
- Cache poisoning attempts
- CORS misconfigurations
- Authentication bypass attempts

#### Auditd Module
- Kernel module loading
- System call anomalies
- File access violations
- Process execution monitoring
- Network connection tracking
- User authentication events
- Privilege escalation detection
- Configuration changes
- Time change detection
- Account modification tracking
- Group membership changes
- Audit rule modifications
- Log tampering attempts
- Syscall filtering bypasses
- Watch rule violations
- Key-based event correlation
- Executable monitoring
- Library loading tracking
- Mount operation monitoring
- IPC mechanism abuse
- Resource limit violations
- Capability usage tracking
- SELinux AVC denials
- AppArmor violations
- Audit daemon failures

#### Elasticsearch Module
- Unauthorized index access
- Cluster state modifications
- Node compromise indicators
- Query injection attempts
- Script execution abuse
- Plugin vulnerabilities
- Snapshot manipulation
- Index template tampering
- Pipeline processor abuse
- Watcher action exploitation
- Machine learning job tampering
- Security realm modifications
- Role mapping changes
- API key abuse
- Token service anomalies
- Audit log gaps
- Cross-cluster search abuse
- Data stream tampering
- ILM policy violations
- Transform abuse
- Enrich policy manipulation
- Fleet integration issues
- Beats compromise indicators
- Logstash pipeline injection
- Kibana space violations

#### HAProxy Module
- Backend server manipulation
- Health check tampering
- Stick table attacks
- ACL bypass attempts
- Rate limiting evasion
- SSL/TLS vulnerabilities
- HTTP request smuggling
- Load balancing algorithm abuse
- Connection exhaustion
- Memory pool attacks
- Stats page access
- Admin socket abuse
- Configuration injection
- Lua script vulnerabilities
- PROXY protocol attacks
- HTTP/2 vulnerabilities
- WebSocket hijacking
- Cache manipulation
- Compression attacks
- Logging bypass attempts
- Runtime API abuse
- Peer synchronization attacks
- DNS resolution manipulation
- Server state file tampering
- Map file injection

#### IIS Module
- Web shell uploads
- ASPX injection attempts
- Configuration file access
- Application pool attacks
- Handler mapping abuse
- ISAPI filter exploits
- WebDAV vulnerabilities
- URL rewrite bypasses
- Request filtering evasion
- FTP service attacks
- Certificate binding issues
- Virtual directory traversal
- Authentication provider attacks
- Session state poisoning
- Output cache manipulation
- Failed request tracing abuse
- Compression attacks
- MIME type confusion
- Double encoding attempts
- Unicode bypass attempts
- Case sensitivity exploits
- 8.3 filename enumeration
- Trace method detection
- Options method abuse
- Lock method exploitation

#### Kafka Module
- Unauthorized topic access
- Consumer group manipulation
- Producer anomalies
- Broker compromise indicators
- Zookeeper security events
- Schema registry tampering
- Connect worker exploitation
- Stream processing attacks
- KSQL injection attempts
- ACL modifications
- SASL authentication failures
- SSL/TLS issues
- Quota violations
- Offset manipulation
- Partition reassignment abuse
- Log compaction issues
- Transaction coordinator attacks
- Idempotent producer issues
- Exactly-once semantics violations
- Mirror maker attacks
- Replicator security events
- Control center access violations
- REST proxy abuse
- Client compatibility issues
- JMX access attempts

#### Kibana Module
- Unauthorized space access
- Saved object tampering
- Visualization injection
- Dashboard manipulation
- Canvas workpad exploits
- Timelion expression injection
- Machine learning job access
- Watcher UI exploitation
- Dev tools abuse
- Short URL manipulation
- Index pattern tampering
- Field formatter exploits
- Scripted field execution
- Plugin vulnerabilities
- API access violations
- Role mapping bypasses
- SAML authentication issues
- OIDC security events
- PKI authentication failures
- Session hijacking
- CSRF token bypasses
- XSS vulnerabilities
- Report generation abuse
- Alert action exploitation
- Space isolation violations

#### Logstash Module
- Pipeline injection
- Filter bypass attempts
- Input plugin exploits
- Output plugin abuse
- Codec vulnerabilities
- Grok pattern injection
- Ruby filter code execution
- Conditional bypasses
- Field reference attacks
- Event manipulation
- Plugin installation risks
- Configuration tampering
- Persistent queue attacks
- Dead letter queue abuse
- Pipeline reloading issues
- Monitoring API exposure
- Central management attacks
- Keystore tampering
- Environment variable leaks
- JVM security issues
- File input path traversal
- HTTP input vulnerabilities
- Beats input exploitation
- JDBC input injection
- Elasticsearch output attacks

#### MongoDB Module
- Authentication bypass attempts
- Injection attack patterns
- Database enumeration
- Collection dropping attempts
- Role privilege escalation
- Audit log tampering
- Replica set poisoning
- Sharding manipulation
- GridFS exploitation
- Aggregation pipeline abuse
- Change stream monitoring
- Index manipulation
- View security bypasses
- Stored JavaScript execution
- BSON injection attempts
- Connection pool exhaustion
- Wire protocol attacks
- LDAP injection via MongoDB
- Kerberos authentication failures
- x.509 certificate abuse
- SCRAM authentication attacks
- AWS IAM integration issues
- Encryption at rest bypasses
- Client-side field encryption issues
- Atlas security events

#### MySQL Module
- SQL injection attempts
- Privilege escalation
- User account manipulation
- Database schema changes
- Stored procedure abuse
- Trigger manipulation
- View security issues
- Event scheduler abuse
- Binary log tampering
- Slow query patterns
- Connection limit violations
- Plugin installation
- UDF exploitation
- File system access attempts
- Information schema queries
- Performance schema abuse
- System variable changes
- Replication attacks
- Partition manipulation
- Full-text search abuse
- JSON function exploitation
- Window function abuse
- Common table expression attacks
- Prepared statement issues
- Character set attacks

#### NATS Module
- Subject injection attacks
- Unauthorized subscription
- Publisher flooding
- Queue group manipulation
- Request-reply hijacking
- Cluster gossip attacks
- Route poisoning
- Gateway security issues
- Leaf node exploitation
- JetStream tampering
- Account isolation bypass
- JWT authentication failures
- Nkeys security issues
- TLS configuration attacks
- Authorization violations
- Connection limits bypass
- Message size violations
- Slow consumer attacks
- Interest propagation abuse
- System event monitoring
- Monitoring endpoint exposure
- Configuration reload attacks
- Resolver exploitation
- Operator security issues
- Memory usage attacks

#### Nginx Module
- Configuration injection
- Buffer overflow attempts
- Request smuggling
- Cache poisoning
- SSL/TLS vulnerabilities
- Reverse proxy bypasses
- Rate limiting evasion
- Load balancer manipulation
- FastCGI exploitation
- WebSocket hijacking
- HTTP/2 vulnerabilities
- gRPC security events
- Lua script injection
- Variable extraction attempts
- Upstream health check manipulation
- Access log tampering
- Error log injection
- Rewrite rule bypasses
- Location block bypasses
- Server block confusion
- DNS resolution attacks
- Connection limit bypasses
- Bandwidth exhaustion
- Memory exhaustion
- CPU exhaustion patterns

#### OSQuery Module
- Query performance issues
- Table access violations
- Extension exploitation
- Configuration tampering
- TLS plugin issues
- Logger plugin abuse
- Distributed query injection
- Decorator bypasses
- Pack manipulation
- Scheduled query abuse
- Event publisher attacks
- Subscription exhaustion
- SQLite exploitation
- JSON parsing attacks
- Flag override attempts
- Watchdog bypass
- Shard assignment issues
- Node key compromise
- Enrollment issues
- Config refresh attacks
- File carving abuse
- ATC table exploitation
- Yara rule bypasses
- Process auditing gaps
- FIM evasion attempts

#### PostgreSQL Module
- SQL injection patterns
- Privilege escalation attempts
- Extension abuse
- Function exploitation
- Foreign data wrapper attacks
- Publication/subscription tampering
- Logical replication issues
- Physical replication attacks
- WAL tampering
- Checkpoint manipulation
- Vacuum process abuse
- Statistics collector issues
- Background worker exploitation
- Shared memory attacks
- SSL certificate issues
- LDAP authentication bypass
- Kerberos authentication failures
- Row-level security bypasses
- Column encryption issues
- Audit log gaps
- Connection pooler attacks
- Query plan manipulation
- TOAST table attacks
- Sequence manipulation
- Domain constraint bypasses

#### Redis Module
- Command injection
- Unauthorized access patterns
- Data exfiltration attempts
- Persistence mechanism abuse
- Replication poisoning
- Cluster node attacks
- Pub/sub channel abuse
- Lua script injection
- Module exploitation
- Memory exhaustion attacks
- Keyspace notifications abuse
- Transaction manipulation
- Pipeline abuse
- Stream consumer group attacks
- Geo-spatial query abuse
- Bitmap operation attacks
- HyperLogLog manipulation
- Sorted set score attacks
- List operation abuse
- Hash operation exploits
- String operation limits
- Key pattern enumeration
- TTL manipulation
- Backup file access
- Configuration overwrites

#### System Linux Module
- SSH brute force attempts
- Sudo privilege escalation
- System service failures
- Package installation anomalies
- Kernel parameter changes
- User account modifications
- Group membership changes
- Cron job manipulations
- System file changes
- Log rotation anomalies
- PAM configuration changes
- Network configuration changes
- Firewall rule modifications
- SELinux policy violations
- AppArmor profile changes
- System resource exhaustion
- Process anomalies
- Memory usage spikes
- Disk space issues
- Network traffic anomalies
- System boot anomalies
- Hardware error patterns
- System update failures
- Service dependency issues
- System time changes

#### Traefik Module
- Router rule injection
- Middleware bypass attempts
- Service discovery poisoning
- Provider API abuse
- Plugin vulnerabilities
- TLS configuration attacks
- Rate limiter bypasses
- Circuit breaker manipulation
- Retry mechanism abuse
- Load balancer tampering
- Health check falsification
- Metrics endpoint exposure
- Tracing data leakage
- Access log injection
- Dynamic configuration attacks
- File provider exploits
- Docker provider abuse
- Kubernetes provider attacks
- Consul catalog poisoning
- Etcd data manipulation
- Redis provider issues
- HTTP/3 vulnerabilities
- gRPC routing attacks
- TCP routing manipulation
- UDP routing issues

### 6. FORTINET

#### Fortinet FortiGate
- Admin account compromise indicators
- Zero-day exploit attempts
- Botnet communication detection
- DDoS attack patterns
- Web filtering violations
- Application control violations
- IPS critical severity events
- Antivirus outbreak detection
- SSL inspection anomalies
- VPN tunnel failures
- FortiGuard threat feed matches
- Sandbox malicious verdict
- Email security threats
- Data loss prevention triggers
- User behavior analytics alerts
- FortiSandbox evasion attempts
- Industrial control system attacks
- DNS filtering blocks
- Endpoint compliance violations
- NAC policy violations
- SD-WAN SLA violations
- High availability split-brain
- Hardware acceleration bypasses
- Virtual domain security events
- API access anomalies

#### FortiWeb
- Web application attacks (SQLi, XSS, etc.)
- OWASP Top 10 violation attempts
- Bot detection and mitigation
- DDoS protection triggers
- API security violations
- Session management attacks
- Authentication bypass attempts
- File upload security violations
- XML/JSON attack attempts
- Cookie security violations
- CSRF protection triggers
- Rate limiting violations
- Geo-blocking events
- IP reputation blocks
- Machine learning anomaly detection
- Custom signature matches
- Protocol validation failures
- HTTP header injection attempts
- Response splitting attempts
- WAF bypass attempts
- Zero-day attack patterns
- Credential stuffing detection
- Account takeover attempts
- Credit card data exposure attempts
- PII leakage prevention

### 7. GENERIC

- Generic log parsing failures
- Unstructured data anomalies
- Format detection errors
- Parser timeout events
- Memory buffer overflows
- Input validation failures
- Encoding detection issues
- Character set problems
- Line length violations
- Field count mismatches
- Delimiter injection attempts
- Escape sequence abuse
- Binary data in text logs
- Timestamp parsing failures
- Timezone inconsistencies
- Log source identification failures
- Multi-line event issues
- Log truncation detection
- Compression bomb attempts
- Archive extraction failures
- Nested format exploitation
- Recursive parsing issues
- Stack overflow attempts
- Regular expression DoS
- Pattern matching timeouts

### 8. GITHUB

- Repository permission changes
- Mass repository cloning
- Sensitive data commits
- Branch protection bypasses
- Webhook modifications
- OAuth app installations
- Personal access token usage
- SSH key additions
- GPG key modifications
- Action secret access
- Workflow modifications
- Large file uploads
- License violations
- Dependency vulnerabilities
- Code scanning alerts
- Secret scanning alerts
- Advanced security events
- SAML SSO anomalies
- IP allowlist violations
- Audit log streaming events
- Enterprise member changes
- Organization creation spikes
- Team permission changes
- Outside collaborator additions
- Repository transfer attempts
- Archive/delete operations
- Fork permission changes
- Wiki modifications
- Release tampering
- Package registry events

### 9. HIDS (HOST INTRUSION DETECTION SYSTEMS)

- Agent disconnection patterns
- Rootcheck detection events
- System integrity monitoring alerts
- Policy compliance violations
- Vulnerability detection patterns
- Active response triggers
- Log collection anomalies
- Command monitoring alerts
- File integrity monitoring violations
- Registry monitoring events (Windows)
- Process monitoring alerts
- Network connection anomalies
- Docker container security events
- Cloud workload protection alerts
- Compliance mapping failures
- Threat intelligence matches
- Incident response triggers
- Security orchestration events
- Custom rule matches
- Decoder failures
- Database integrity issues
- API authentication failures
- Cluster synchronization issues
- Agent enrollment anomalies
- Manager overload conditions

### 10. IBM SYSTEMS

#### IBM AIX
- RBAC violations
- Trusted computing base events
- Security audit subsystem alerts
- Enhanced RBAC events
- Trusted execution violations
- Encrypted file system events
- Network security events
- System integrity violations
- Resource control violations
- Workload partition security
- LDAP client security issues
- Kerberos authentication events
- IPSec security events
- Firewall policy violations
- Intrusion detection events
- Compliance monitoring alerts
- Patch compliance failures
- Security policy enforcement
- Privileged command execution
- System configuration changes
- User administration events
- Performance anomalies
- Hardware monitoring alerts
- Error log analysis patterns
- Core dump security analysis

#### IBM AS/400 (IBM i)
- Security audit journal events
- Object authority violations
- Special authority usage
- System value changes
- User profile modifications
- Password policy violations
- Exit program security events
- Adopted authority abuse
- Library list manipulation
- Job security violations
- Spool file access violations
- Database security events
- Network security violations
- FTP/TELNET security events
- System service tools usage
- PTF application events
- Save/restore security
- Object ownership changes
- Authorization list events
- Security tools usage
- Audit journal tampering
- System security level changes
- Communication security events
- Cryptographic operation events
- Compliance violations

### 11. JSON INPUT

- Schema validation failures
- JSON injection attempts
- Parser exploitation attempts
- Nested object attacks
- Array manipulation attempts
- Type confusion attacks
- Encoding issues
- Size limit violations
- Depth limit violations
- Key collision attacks
- Prototype pollution attempts
- Deserialization attacks
- JSON hijacking attempts
- JSONP vulnerabilities
- JWT token security issues
- JSON-LD attacks
- JSON Patch exploits
- JSON Pointer abuse
- JSON Schema bypasses
- Transform errors
- Merge conflicts
- Reference loops
- Memory exhaustion via JSON
- CPU exhaustion via JSON
- Callback manipulation

### 12. LINUX SYSTEMS

#### Debian Family
- APT repository tampering
- Package signature failures
- Dpkg database corruption
- SystemD service manipulation
- AppArmor policy violations
- UFW firewall changes
- Unattended upgrades failures
- Snap package security events
- Debian-specific kernel exploits
- Init system tampering
- Network manager exploits
- Desktop environment attacks
- X11 security violations
- Wayland security events
- Debian security advisory matches
- CVE vulnerability detection
- System update failures
- Repository key issues
- Package dependency attacks
- Configuration file changes
- System service modifications
- Boot loader tampering
- GRUB security events
- Secure boot violations
- Debian-specific rootkits

#### RHEL Family
- YUM/DNF repository attacks
- RPM database tampering
- SELinux policy violations
- Firewalld rule changes
- Subscription manager issues
- Satellite client anomalies
- Kickstart exploitation
- Anaconda security events
- RHEL-specific kernel exploits
- SystemD unit file attacks
- NetworkManager exploits
- Cockpit security events
- Container platform attacks
- OpenShift security violations
- Red Hat security advisory matches
- CVE vulnerability detection
- System update failures
- Repository GPG key issues
- Package verification failures
- System configuration changes
- Service modifications
- Boot loader attacks
- GRUB2 security events
- Secure boot violations
- RHEL-specific malware

### 13. MACOS

- System Integrity Protection bypass
- Gatekeeper bypass attempts
- XProtect evasion
- TCC database manipulation
- Kernel extension loading
- Launch agent/daemon persistence
- Keychain access violations
- Apple script abuse
- Directory service modifications
- MDM profile removal
- FileVault tampering attempts
- Time Machine tampering
- Spotlight index manipulation
- Safari extension abuse
- Code signing violations
- Notarization bypass attempts
- Privacy preferences tampering
- Synthetic click detection
- Screen recording detection
- Microphone/camera access abuse
- Location services abuse
- Contacts/calendar access violations
- Full disk access abuse
- Developer tools abuse
- Homebrew package tampering
- Application firewall modifications
- Network extension abuse
- Endpoint security bypass
- T2 chip security events
- Apple ID authentication anomalies

### 14. MIKROTIK

- RouterOS brute force attempts
- Winbox exploitation attempts
- API access violations
- SSH brute force attempts
- Telnet access violations
- FTP security events
- Web interface attacks
- Configuration export attempts
- Backup file access
- Script execution anomalies
- Scheduler abuse
- Firewall rule bypasses
- NAT rule manipulation
- Routing table attacks
- DHCP server attacks
- DNS cache poisoning
- Hotspot authentication bypasses
- Wireless security breaches
- Bridge security issues
- VLAN hopping attempts
- Queue manipulation
- Bandwidth limit bypasses
- Connection limit violations
- Address list abuse
- Layer 7 protocol exploits
- Netinstall attempts
- License violations
- Hardware monitoring alerts
- Resource exhaustion
- Firmware vulnerability exploits

### 15. NETFLOW

- Traffic anomaly detection
- Bandwidth utilization spikes
- Connection pattern changes
- Geographic anomalies
- Port scanning patterns
- DDoS traffic patterns
- Data exfiltration indicators
- Beaconing behavior detection
- Peer-to-peer traffic detection
- Tor usage detection
- VPN tunnel anomalies
- Protocol distribution changes
- Application layer attacks
- Traffic redirection detection
- DNS query anomalies
- NTP amplification attacks
- SNMP reflection attacks
- Memcached amplification
- SSDP amplification attacks
- Network reconnaissance
- Asset enumeration attempts
- Service discovery patterns
- Flow export manipulation
- Collector overload attacks
- Template tampering

### 16. NIDS (NETWORK INTRUSION DETECTION SYSTEMS)

- Signature match patterns
- Protocol anomaly detection
- Traffic baseline deviations
- Evasion technique detection
- Fragmentation attacks
- Covert channel detection
- Tunneling detection
- DDoS attack patterns
- Port scan detection
- Service enumeration
- Exploit attempt detection
- Malware callbacks
- Data exfiltration patterns
- Lateral movement indicators
- Command and control traffic
- DNS tunneling detection
- ICMP tunneling detection
- SSL/TLS anomalies
- Certificate validation failures
- Known bad actor detection
- Threat intelligence IOCs
- Custom signature matches
- Preprocessor events
- Decoder alerts
- Stream reassembly issues

### 17. OFFICE365

- Mass email deletion
- Suspicious inbox rules
- SharePoint mass downloads
- Teams data exfiltration
- OneDrive mass file access
- Exchange admin changes
- Mail forwarding rules
- Calendar sharing violations
- Power Automate abuse
- Power Apps data leaks
- Azure AD integration events
- Guest user invitation spikes
- External sharing violations
- DLP policy violations
- Compliance alert patterns
- eDiscovery abuse
- Audit log tampering
- License assignment anomalies
- Multi-geo data violations
- Conditional access bypasses
- App consent grants
- OAuth app anomalies
- Mail flow rule changes
- Anti-phishing policy bypasses
- Safe attachment violations
- Safe links click patterns
- Threat intelligence alerts
- Insider risk indicators
- Communication compliance alerts
- Information barriers violations

### 18. PALO ALTO NETWORKS

- WildFire malware detection
- Zero-day exploit prevention
- Command and control traffic
- Data exfiltration attempts
- Credential theft detection
- Application dependency violations
- User behavior analytics alerts
- IOC matches from threat intel
- DNS security violations
- URL filtering violations
- File blocking policy violations
- DoS protection triggers
- Zone protection alerts
- GlobalProtect VPN anomalies
- Authentication failures spike
- Privileged user activity anomalies
- Cortex XDR integration alerts
- Container security violations
- Kubernetes security events
- Prisma Cloud compliance alerts
- SaaS security alerts
- CASB policy violations
- Hardware security module events
- High availability failover
- Commit and validation failures

### 19. PFSENSE

- Firewall rule violations
- NAT traversal attempts
- VPN authentication failures
- Package vulnerability alerts
- Snort/Suricata IDS alerts
- pfBlockerNG blocks
- Captive portal bypasses
- Traffic shaper anomalies
- Load balancer failures
- DHCP pool exhaustion
- DNS resolver cache poisoning
- Certificate management issues
- High availability CARP events
- State table exhaustion
- Interface queue drops
- Limiters and queues overflow
- Proxy server violations
- Squid cache poisoning
- RADIUS authentication failures
- LDAP integration issues
- Time synchronization failures
- UPS power events
- Temperature warnings
- Config backup failures
- Update server connectivity issues

### 20. SONICWALL

- Gateway anti-virus detections
- Intrusion prevention alerts
- App control violations
- Content filter blocks
- Anti-spyware detections
- Email security threats
- Capture ATP verdicts
- Botnet detection
- Geo-IP filter violations
- DPI-SSL inspection alerts
- VPN tunnel anomalies
- High availability failover
- DDoS attack mitigation
- Access rule violations
- NAT policy violations
- Bandwidth management alerts
- Real-time blacklist hits
- DNS filtering events
- Endpoint security alerts
- Capture Client threats
- SonicWave wireless threats
- Cloud App Security events
- Zero-day threat detection
- Encrypted threats detection
- License expiration warnings

### 21. SOPHOS

#### Sophos Central
- Synchronized security heartbeat failures
- Endpoint threat detection
- Server protection alerts
- Mobile device threats
- Email protection events
- Web protection violations
- Application control blocks
- Device control violations
- Data loss prevention triggers
- Peripheral control events
- Tamper protection alerts
- Exploit prevention triggers
- Ransomware detection
- Machine learning detections
- Behavioral analysis alerts
- Cloud security posture alerts
- Zero Trust Network Access events
- Managed threat response alerts
- Threat case investigations
- Policy compliance failures
- Update failures
- License compliance issues
- Integration failures
- API security events
- Admin activity anomalies

#### Sophos XG Firewall
- Advanced threat protection alerts
- Synchronized security events
- Web protection violations
- Email protection threats
- Lateral movement detection
- Heartbeat missing alerts
- RED tunnel failures
- SD-WAN link quality issues
- Application risk changes
- User threat quotient spikes
- ATP sandbox verdicts
- IPS high-severity events
- WAF security events
- Authentication anomalies
- VPN user behavior changes
- Wireless security threats
- DLP policy violations
- Cloud application risks
- IoT device security events
- Active threat response
- Security heartbeat failures
- Malware outbreak indicators
- C&C callback detection
- Data loss incidents
- Compliance violations

### 22. SYSLOG

#### CEF (Common Event Format)
- CEF parsing failures
- Field mapping errors
- Extension field violations
- Severity mismatches
- Device vendor anomalies
- Device product inconsistencies
- Device version changes
- Signature ID patterns
- Name field injections
- Extension key violations
- Custom field abuse
- Encoding issues
- Delimiter escaping failures
- Header malformation
- Timestamp inconsistencies
- Device event class anomalies
- Source/destination mismatches
- Protocol violations
- Action field patterns
- Outcome inconsistencies
- File hash mismatches
- User agent anomalies
- Request/response violations
- Message truncation
- CEF version incompatibilities

#### RFC-5424
- Structured data violations
- Priority calculation errors
- Facility/severity mismatches
- Version field anomalies
- Timestamp format violations
- Hostname spoofing
- App name injections
- Process ID anomalies
- Message ID patterns
- Structured data ID violations
- Parameter name injections
- Parameter value overflows
- UTF-8 encoding issues
- BOM handling errors
- Message length violations
- Nil value abuse
- SD-ID registry violations
- Private enterprise numbers
- Standardized SD-IDs abuse
- Meta SD-ID violations
- Origin SD-ID tampering
- Sequence ID gaps
- Language tag violations
- Truncation indicators
- Protocol compliance failures

#### RFC-5425 (TLS Syslog)
- TLS handshake failures
- Certificate validation errors
- Cipher suite downgrades
- Session resumption attacks
- Renegotiation vulnerabilities
- Frame length violations
- Message counting errors
- Octet counting mismatches
- TLS version downgrades
- Compression attacks
- Heartbleed detection
- POODLE attack indicators
- BEAST attack patterns
- CRIME attack detection
- Certificate pinning violations
- SNI spoofing attempts
- ALPN/NPN issues
- Session ticket abuse
- Key exchange weaknesses
- PRF vulnerabilities
- Record layer attacks
- Alert protocol abuse
- Handshake protocol violations
- Application data injection
- Close notify anomalies

#### RFC-6587 (Syslog over TCP)
- Octet counting violations
- Non-transparent framing issues
- Message delimiter injection
- Frame length manipulation
- TCP stream corruption
- Connection state attacks
- Keep-alive anomalies
- Window size attacks
- Sequence number prediction
- ACK flooding
- RST injection
- SYN flooding patterns
- FIN/ACK anomalies
- Urgent pointer abuse
- Option field exploitation
- MSS manipulation
- SACK exploitation
- Timestamp attacks
- Window scaling issues
- Congestion control abuse
- Retransmission patterns
- Connection hijacking
- Stream reassembly attacks
- Buffer overflow attempts
- Resource exhaustion patterns

### 23. VMWARE

#### VMware ESXi
- Hypervisor escape attempts
- VM escape detection
- vMotion security events
- Storage vMotion anomalies
- DRS (Distributed Resource Scheduler) manipulation
- HA (High Availability) failover anomalies
- vCenter Server attacks
- ESXi host compromise indicators
- Virtual machine sprawl
- Resource pool abuse
- Distributed switch attacks
- VLAN trunk attacks
- VMkernel interface abuse
- Management network exposure
- iSCSI/NFS storage attacks
- VMFS corruption attempts
- Snapshot manipulation
- Template tampering
- OVF/OVA deployment risks
- vSphere API abuse
- PowerCLI script execution
- Guest introspection bypass
- VMware Tools vulnerabilities
- VMCI/VMHGFS exploitation
- Virtual hardware manipulation
- Memory ballooning attacks
- CPU/Memory reservation abuse
- License compliance violations
- Certificate validation failures
- SSO authentication bypasses

### 24. WINDOWS

- Pass-the-hash attacks
- Golden ticket attacks
- Silver ticket attacks
- Kerberoasting attempts
- ASREPRoasting attacks
- PowerShell Empire detection
- Mimikatz tool usage
- BloodHound reconnaissance
- Process injection techniques
- DLL injection/hijacking
- UAC bypass attempts
- Windows Defender tampering
- AMSI bypass detection
- Event log clearing
- Volume shadow copy deletion
- Registry persistence mechanisms
- Scheduled task abuse
- Service creation anomalies
- WMI persistence and lateral movement
- LSASS memory dumping
- SAM database access
- NTDS.dit extraction attempts
- DCSync attacks
- DCShadow detection
- AdminSDHolder abuse
- GPO tampering
- ADFS authentication anomalies
- Certificate services abuse
- Print spooler exploitation
- SMBv1 usage detection
- RDP brute force attacks
- Windows Remote Management abuse
- DCOM lateral movement
- Named pipe impersonation
- Token manipulation
- SID history injection