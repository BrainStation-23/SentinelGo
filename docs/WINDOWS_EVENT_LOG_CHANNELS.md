# Windows Event Log Channels Being Captured

## 🔐 Security Channel (3 Groups)

| Channel | Source | Event Types Captured |
|---------|--------|---------------------|
| **Security - Authentication** | `windows_security` | Logon/Logoff events (4624, 4625, 4634, 4648, 4672) |
| **Security - User Management** | `windows_security` | Account creation/deletion/modification (4720-4738) |
| **Security - Policy & Network** | `windows_security` | Process creation, network access, object access (4656-4739, 5156-5157) |

### Security Events Include:
- **Login Success/Failure** (4624, 4625)
- **Account Lockout** (4740)
- **Logon Types** (4634, 4648, 4672)
- **User Account Changes** (4720-4738)
- **Process Creation** (4688)
- **Network/ Object Access** (4656, 4663, 5156, 5157)
- **Policy Changes** (4719, 4739)

---

## ⚙️ System Channel (2 Groups)

| Channel | Source | Event Types Captured |
|---------|--------|---------------------|
| **System - General** | `windows_system` | Critical, Error, Warning, Information events (Level 1-4) |
| **System - Time Service** | `windows_system_time_service` | Time synchronization & timezone events (24, 35) |

### System Events Include:
- **Critical System Errors** (Level 1)
- **System Failures** (Level 2)
- **System Warnings** (Level 3)
- **System Information** (Level 4)
- **Time Service Synchronization** (35)
- **Time Zone Refresh** (24)

---

## 📱 Application Channel

| Channel | Source | Event Types Captured |
|---------|--------|---------------------|
| **Application** | `windows_application` | Critical, Error, Warning events (Level 1-3) |

### Application Events Include:
- **Application Crashes** (Level 1)
- **Application Errors** (Level 2)
- **Application Warnings** (Level 3)
- **License Activation Failures** (8198)
- **Software Installation Issues**

---

## 🛡️ Microsoft Services (6 Channels)

| Channel | Source | Event Types Captured |
|---------|--------|---------------------|
| **Windows Defender** | `windows_microsoft_windows_windows_defender_operational` | All Defender events |
| **PowerShell** | `windows_microsoft_windows_powershell_operational` | Script execution, module operations (4103-4106) |
| **Task Scheduler** | `windows_microsoft_windows_taskscheduler_operational` | Task creation, execution, failures (100-201) |
| **Windows Firewall** | `windows_microsoft_windows_windows_firewall_with_advanced_security_firewall` | Firewall rules, connections (Level 1-3) |
| **Remote Desktop** | `windows_microsoft_windows_terminalservices_remoteconnectionmanager_operational` | RDP connections, disconnections (1149, 261, 1158) |
| **Group Policy** | `windows_microsoft_windows_grouppolicy_operational` | Policy application, processing (Level 1-3) |

### Microsoft Services Events Include:

#### Windows Defender
- **Threat Detections**
- **Scan Results**
- **Real-time Protection**
- **Update Status**

#### PowerShell
- **Script Block Logging** (4103)
- **Module Logging** (4104)
- **Script Execution** (4105, 4106)

#### Task Scheduler
- **Task Registration** (100, 102)
- **Task Execution** (103, 106)
- **Task Completion** (200, 201)
- **Task Failures** (141)

#### Windows Firewall
- **Rule Modifications**
- **Connection Blocking**
- **Security Events**

#### Remote Desktop Services
- **RDP Connections** (1149)
- **Connection Failures** (261)
- **RDP Disconnections** (1158)

#### Group Policy
- **Policy Application**
- **Policy Processing Errors**
- **Configuration Changes**

---

## 📊 Summary for Management

### Coverage Overview
- **Total Channels**: **11** active monitoring channels
- **Coverage Areas**: Security, System, Applications, Microsoft Services
- **Event Types**: 50+ specific event IDs and all critical/warning levels

### Severity Levels Captured
| Windows Level | Severity | Description |
|---------------|----------|-------------|
| **Level 1** | `critical` | Critical system failures |
| **Level 2** | `high` | Error conditions |
| **Level 3** | `medium` | Warning conditions |
| **Level 4** | `info` | Informational events |

### Key Monitoring Capabilities

#### 🔒 Security Monitoring
- **Authentication Events**: Track all login attempts, successes, and failures
- **Account Management**: Monitor user account creation, modification, and deletion
- **Privilege Usage**: Track privilege escalation and policy violations
- **Network Access**: Monitor file and network object access attempts

#### ⚙️ System Health Monitoring
- **Critical Errors**: System crashes and critical failures
- **Performance Issues**: Resource exhaustion and service failures
- **Time Synchronization**: NTP sync issues and timezone changes
- **Service Status**: Windows service start/stop events

#### 📱 Application Reliability
- **Application Crashes**: Software failures and exceptions
- **License Issues**: Windows activation and software licensing problems
- **Installation Failures**: Software update and installation issues

#### 🛡️ Microsoft Service Monitoring
- **Antivirus Protection**: Windows Defender threat detection and scanning
- **Script Execution**: PowerShell activity and security monitoring
- **Scheduled Tasks**: Automated task execution and failures
- **Network Security**: Firewall rule changes and connection blocking
- **Remote Access**: RDP session monitoring and security
- **Policy Compliance**: Group Policy application and processing

### Compliance & Audit Benefits
- **Complete Audit Trail**: All security-relevant events captured
- **Regulatory Compliance**: Meets common audit requirements
- **Incident Response**: Detailed event history for investigations
- **Operational Visibility**: Comprehensive system health monitoring

---

## 📈 Event Volume Estimates

### High-Volume Channels
- **Windows Defender**: Continuous threat monitoring
- **System**: Ongoing system operations
- **Security**: Authentication and access events

### Medium-Volume Channels
- **Application**: Application-specific events
- **PowerShell**: Script execution events
- **Task Scheduler**: Scheduled task executions

### Low-Volume Channels
- **Time Service**: Periodic synchronization events
- **Group Policy**: Policy application events
- **Remote Desktop**: Connection events

---

*Last Updated: April 26, 2026*
*Configuration File: `internal/auditlogs/collector/collector_windows.go`*
