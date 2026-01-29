import { NextRequest, NextResponse } from 'next/server';
import { XLogMCPClient, MCPTool } from '@/lib/mcp-client';
import { GoogleAuth } from 'google-auth-library';

const MCP_URL = process.env.MCP_URL || 'http://localhost:8080/api/v1/stream/mcp';
const MCP_TOKEN = process.env.MCP_TOKEN;
const GEMINI_API_KEY = process.env.GEMINI_API_KEY || '';
const GOOGLE_APPLICATION_CREDENTIALS = process.env.GOOGLE_APPLICATION_CREDENTIALS || '';
const GEMINI_MODEL = process.env.GEMINI_MODEL || 'gemini-3-pro-preview';
const GEMINI_API_BASE = 'https://generativelanguage.googleapis.com/v1beta';
const VERTEX_API_BASE = 'https://aiplatform.googleapis.com/v1';

type GeminiFunctionCall = {
  name: string;
  args?: Record<string, unknown>;
};

type GeminiPart = {
  text?: string;
  functionCall?: GeminiFunctionCall;
  functionResponse?: {
    name: string;
    response: Record<string, unknown>;
  };
};

type GeminiSystemInstruction = {
  role: 'system';
  parts: Array<{ text: string }>;
};

type GeminiContent = {
  role: 'user' | 'model';
  parts: GeminiPart[];
};

type DebugStep = {
  time: string;
  stage: string;
  detail: string;
};

function sanitizeSchema(
  schema: Record<string, unknown>,
  defs: Record<string, unknown> = {},
  depth = 0,
  processing: Set<string> = new Set()
): Record<string, unknown> {
  if (depth > 10) {
    return { type: 'object', description: 'Complex schema (truncated)' };
  }

  const localSchema = { ...schema };

  if ('$defs' in localSchema && typeof localSchema.$defs === 'object' && localSchema.$defs) {
    Object.assign(defs, localSchema.$defs as Record<string, unknown>);
    delete localSchema.$defs;
  }

  if ('definitions' in localSchema && typeof localSchema.definitions === 'object' && localSchema.definitions) {
    Object.assign(defs, localSchema.definitions as Record<string, unknown>);
    delete localSchema.definitions;
  }

  if ('$ref' in localSchema && typeof localSchema.$ref === 'string') {
    const ref = localSchema.$ref;
    const refName = ref.split('/').pop() || ref;
    delete localSchema.$ref;

    if (processing.has(refName)) {
      return { type: 'object', description: `Recursive reference to ${refName}` };
    }

    const resolved = defs[refName];
    if (resolved && typeof resolved === 'object') {
      processing.add(refName);
      const merged = sanitizeSchema(resolved as Record<string, unknown>, defs, depth + 1, new Set(processing));
      processing.delete(refName);
      return merged;
    }

    return { type: 'string', description: `Reference to ${refName}` };
  }

  const complexKeys = ['oneOf', 'anyOf', 'allOf'] as const;
  let hasComplex = false;
  for (const key of complexKeys) {
    if (key in localSchema) {
      delete localSchema[key];
      hasComplex = true;
    }
  }

  if (hasComplex) {
    return {
      ...localSchema,
      type: 'object',
      description: `${(localSchema.description as string) || 'Complex variant'} (simplified)`,
    };
  }

  if (typeof localSchema.properties === 'object' && localSchema.properties) {
    const props = localSchema.properties as Record<string, unknown>;
    for (const [key, value] of Object.entries(props)) {
      if (value && typeof value === 'object') {
        props[key] = sanitizeSchema(value as Record<string, unknown>, defs, depth + 1, new Set(processing));
      }
    }
  }

  if (typeof localSchema.items === 'object' && localSchema.items) {
    localSchema.items = sanitizeSchema(
      localSchema.items as Record<string, unknown>,
      defs,
      depth + 1,
      new Set(processing)
    );
  }

  return localSchema;
}

type GeminiCallPayload = {
  contents: GeminiContent[];
  tools: Array<{ functionDeclarations: unknown }>;
  systemInstruction?: GeminiSystemInstruction;
  generationConfig: {
    maxOutputTokens: number;
  };
};

function resolveVertexLocation(modelName: string) {
  if (modelName.toLowerCase().includes('gemini-3') || modelName.toLowerCase().includes('experimental')) {
    return 'global';
  }
  return 'us-central1';
}

function parseCredentialsInput(input: string) {
  const trimmed = input.trim();
  if (!trimmed) {
    return { credentials: null, keyFile: null };
  }

  if (trimmed.startsWith('{')) {
    try {
      return { credentials: JSON.parse(trimmed), keyFile: null };
    } catch (error) {
      throw new Error(`GOOGLE_APPLICATION_CREDENTIALS JSON parse failed: ${String(error)}`);
    }
  }

  return { credentials: null, keyFile: trimmed };
}

async function callGeminiWithApiKey(payload: GeminiCallPayload) {
  if (!GEMINI_API_KEY) {
    throw new Error('GEMINI_API_KEY is required for the Gemini API call.');
  }

  const response = await fetch(
    `${GEMINI_API_BASE}/models/${encodeURIComponent(GEMINI_MODEL)}:generateContent?key=${GEMINI_API_KEY}`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
    }
  );

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Gemini API error: ${response.status} ${errorText}`);
  }

  return response.json();
}

async function callGeminiWithVertex(payload: GeminiCallPayload) {
  if (!GOOGLE_APPLICATION_CREDENTIALS) {
    throw new Error('GOOGLE_APPLICATION_CREDENTIALS is required for Vertex AI.');
  }

  const { credentials, keyFile } = parseCredentialsInput(GOOGLE_APPLICATION_CREDENTIALS);
  const auth = new GoogleAuth({
    credentials: credentials || undefined,
    keyFile: keyFile || undefined,
    scopes: ['https://www.googleapis.com/auth/cloud-platform'],
  });

  const projectId =
    credentials?.project_id || (await auth.getProjectId());

  if (!projectId) {
    throw new Error('Vertex AI requires a project_id in GOOGLE_APPLICATION_CREDENTIALS.');
  }

  const location = resolveVertexLocation(GEMINI_MODEL);
  const accessToken = await auth.getAccessToken();

  if (!accessToken) {
    throw new Error('Failed to obtain Vertex AI access token.');
  }

  const response = await fetch(
    `${VERTEX_API_BASE}/projects/${encodeURIComponent(projectId)}/locations/${location}` +
      `/publishers/google/models/${encodeURIComponent(GEMINI_MODEL)}:generateContent`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${accessToken}`,
      },
      body: JSON.stringify(payload),
    }
  );

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Vertex AI error: ${response.status} ${errorText}`);
  }

  return response.json();
}

async function callGemini(contents: GeminiContent[], tools: Array<{ functionDeclarations: unknown }>) {
  const systemInstruction: GeminiSystemInstruction = {
    role: 'system',
    parts: [
      {
        text: `You are the XLog MCP Agent.
Your job is to help users generate synthetic security logs, discover supported fields, manage scenario workers, and generate threat intelligence data.

## CRITICAL - Pre-Generation Workflow

BEFORE generating ANY logs, you MUST call these tools in order:

1. **load_simulation_skills** (FIRST - Check for Matching Scenarios)
   - Call this FIRST to check if user request matches any existing scenario skills
   - Parameters: category (optional), attack_type (optional), complexity (optional)
   - If user request matches a skill (e.g., "port scan", "ransomware", "credential theft"), load that skill and follow its instructions
   - Available scenarios: port_scan, ransomware_attack, credential_theft_apt
   - Available foundation skills: generate_shared_iocs, create_device_topology, DEVICE_VENDOR_CATALOG, AUTHENTICATION_FIELDS_GUIDE
   - If NO matching skill found, proceed to steps 2-4 below to build logs manually

2. **xlog_get_technology_stack** (REQUIRED)
   - Returns organization's custom technology stack with specific vendors/products
   - If configured=true: USE ONLY vendors/products from this list
   - If configured=false: Use vendors from default catalog (step 1 load_simulation_skills to get DEVICE_VENDOR_CATALOG)

3. **xlog_get_field_info** (ALWAYS)
   - Validate field names before creating logs
   - Get supported required_fields and observables_dict fields

4. **xlog_generate_observables** (OPTIONAL - for realistic threat data)
   - Generate IPs, URLs, hashes, CVEs for observables_dict

## Tool Reference

**load_simulation_skills** - Load scenario and foundation skills:
   - CALL THIS FIRST to check if user request matches an existing scenario
   - Parameters: category ("foundation", "scenarios", "validation", "workflows"), attack_type (e.g., "reconnaissance", "ransomware", "apt"), complexity ("low", "medium", "high")
   - Returns: Skill content with step-by-step instructions, prerequisites, validation queries
   - Available scenarios: port_scan, ransomware_attack, credential_theft_apt
   - If user mentions: "port scan", "scanning", "reconnaissance" → Load port_scan skill
   - If user mentions: "ransomware", "encryption" → Load ransomware_attack skill
   - If user mentions: "credential theft", "APT", "domain compromise" → Load credential_theft_apt skill
   - If NO match found, proceed with manual log generation using other tools

**xlog_get_technology_stack** - Get organization's configured technology stack:
   - No parameters required
   - Returns: stack_name, log_destination (default syslog server), vendors list with vendor/product/category/formats/description
   - If configured=true: USE ONLY these vendors for log generation
   - If configured=false: Load DEVICE_VENDOR_CATALOG skill via load_simulation_skills for vendor selection
   - If log_destination is configured: Use it as the default destination when user doesn't specify one
   - Example response: {"stack_name": "Enterprise Security Stack", "log_destination": {"type": "syslog", "protocol": "udp", "host": "10.10.0.8", "port": 514, "full_address": "udp:10.10.0.8:514"}, "vendors": [{"vendor": "Fortinet", "product": "FortiGate", "category": "Firewall", "formats": ["CEF", "SYSLOG", "JSON"]}], "configured": true}

**xlog_generate_observables** - Generate threat intel indicators:
   - Types: IP, URL, SHA256, CVE, TERMS
   - Known: BAD (malicious) or GOOD (benign)
   - Use to populate observables with realistic threat data
   - Example: {"count": 10, "observable_type": "IP", "known": "BAD"}

**xlog_get_field_info** - Get supported fields for log types:
   - ALWAYS call before creating logs
   - Returns required_fields and observables_dict field names
   - IMPORTANT: The tool expects a request wrapper object
   - Example: {"request": {"log_type": "JSON", "include_observables": true}}

## Guidelines

- Observables use camelCase keys (e.g., srcHost, remotePort, winProcess)
- Be concise and actionable; provide working MCP tool payloads when asked
- When technology stack is configured, match vendor/product EXACTLY as specified
- Use the "formats" field from technology stack to determine compatible log types

## CRITICAL - Log Destination Configuration

When determining where to send logs:

1. **Default Destination from Technology Stack**:
   - ALWAYS call xlog_get_technology_stack FIRST
   - If log_destination is configured in the response, use log_destination.full_address as the default
   - Example: If log_destination.full_address = "udp:10.10.0.8:514", use this as the destination parameter
   - Only use this default when the user hasn't explicitly specified a different destination (webhook, file, etc.)

2. **User-Specified Destination**:
   - If user explicitly requests webhook, XSIAM_WEBHOOK, or another destination, use that instead
   - User specification always overrides the technology stack default

3. **No Configuration**:
   - If log_destination is not configured in technology stack AND user didn't specify, ask the user for destination

## CRITICAL - Worker Request Structure

When calling xlog_create_data_worker:

**Top-level parameters** (NOT in required_fields):
- vendor: String - Vendor name (e.g., "F5", "Fortinet")
- product: String - Product name (e.g., "ASM", "FortiGate")
- version: String - Version (optional)
- type: Log format (JSON, CEF, LEEF, SYSLOG, WINEVENT)
- destination: Where to send logs (use log_destination.full_address from tech stack if available and user didn't specify)
- count: Number of logs
- interval: Time between logs
- name: Worker name (optional)
- tags: List of tags (optional)
- tactic: MITRE tactic (optional)
- technique: MITRE technique (optional)
- procedure: Description (optional)

**Timestamp parameters** - ONLY include if user explicitly requests:
- start_date: Start date for logs (format: "YYYY-MM-DD")
- end_date: End date for logs (format: "YYYY-MM-DD")
- start_time: Start time for logs (format: "HH:MM:SS")
- end_time: End time for logs (format: "HH:MM:SS")
- DO NOT include timestamp parameters by default
- ONLY include if user specifically asks for historical timestamps or custom time ranges

**required_fields**: Array of field enums ONLY
- NEVER include "VENDOR" or "PRODUCT" in required_fields
- Use fields from xlog_get_field_info response
- Examples: ["LOCAL_IP", "REMOTE_IP", "PROTOCOL", "ACTION"]

**observables_dict**: Dictionary with camelCase keys
- Keys must match observable field names
- Examples: {"localIp": [...], "remoteIp": [...], "protocol": [...]}

IMPORTANT: For MCP tool calls, always use snake_case keys 'required_fields' and 'observables_dict'
in the request payload. Do NOT use GraphQL-style 'requiredFields' or 'observablesDict'.

## CRITICAL - Field Discovery

ALWAYS call xlog_get_field_info with include_observables=true to discover:
- Available required_fields (~300+ fields)
- Available observables_dict fields (~160+ observables)
- Field categories (authentication, kubernetes, cloud, threat_detection, etc.)
- Usage examples for each category
- Important notes about field usage

The tool returns comprehensive field catalogs with examples. Use the 'authentication' category for XDM-compatible authentication logs, 'kubernetes' for container logs, 'cloud' for cloud infrastructure, etc.

## CRITICAL - Authentication Logs

For AUTHENTICATION logs:
1. Call xlog_get_field_info to discover authentication fields
2. Review the 'authentication' category in observable_catalog
3. Include mandatory authentication fields (8 required for XSIAM Authentication Stories)
4. Add optional fields when user requests "all fields" or "maximum fields"
5. Match each required_field with corresponding observable value in observables_dict (camelCase)
6. Only use Identity products from technology stack (Microsoft AD, CyberArk Identity, Cisco ISE)

The xlog_get_field_info tool provides:
- Complete list of authentication fields with examples
- Field requirements (mandatory vs optional)
- Valid values for each field
- Usage examples showing proper structure

CRITICAL - Destination-Specific Log Type Requirements:
- When destination is XSIAM_WEBHOOK or contains "xsiam" or "http collector":
  - ONLY use type: "JSON"
  - NEVER use CEF, LEEF, SYSLOG, or WINEVENT
  - XSIAM HTTP Collector ONLY accepts JSON format
  - Other formats will be rejected or cause ingestion errors

- For other destinations (file output, syslog servers):
  - You may use CEF, LEEF, SYSLOG, WINEVENT, or JSON

CRITICAL - Vendor & Product Requirements (ARB CISD Standard - 46 Data Sources):
- ALWAYS use specific vendor and product names from the Device Vendor Catalog (load via load_simulation_skills tool if needed)
- NEVER use generic names like "XLog", "Generic", or "Unknown"
- CREATE VARIETY: Use DIFFERENT vendors for different logs in the same scenario

**Operating System (7 sources):**
- Windows Server: Microsoft Windows Server 2019/2022/2016
- Active Directory: Microsoft Active Directory, Microsoft Windows Active Directory
- Windows Workstation: Microsoft Windows 10 Enterprise, Microsoft Windows 11 Pro
- MS Exchange: Microsoft Exchange Server 2019/2016, Microsoft Exchange Online
- Sysmon: Microsoft Sysmon v14/v15
- Linux/Unix: Red Hat Enterprise Linux 8, Ubuntu Linux 22.04, CentOS 8, Debian 11, Oracle Linux 8
- AIX: IBM AIX 7.2/7.3

**Network & Infrastructure (14 sources):**
- Load Balancer: F5 BIG-IP LTM, Citrix NetScaler ADC, HAProxy, Nginx Plus, AWS ELB, Azure Load Balancer
- Middleware: IBM MQ 9.3, Apache Kafka 3.4, RabbitMQ 3.11, Oracle WebLogic, IBM WebSphere
- File Share: Microsoft Windows File Server 2019, NetApp ONTAP, EMC Isilon OneFS, Synology NAS
- Printing: Microsoft Windows Print Server 2019, CUPS, PaperCut Print Management
- Key Management: AWS KMS, Azure Key Vault, HashiCorp Vault, Thales CipherTrust Manager, Google Cloud KMS
- Web Server: Apache HTTP Server 2.4, Nginx 1.24, Microsoft IIS 10, Apache Tomcat 10
- Switch: Cisco Catalyst 9300, Juniper EX4400, Arista 7050X, HPE Aruba CX 6300
- Router: Cisco ISR 4000, Juniper MX Series, Fortinet FortiGate, Mikrotik RouterOS
- Hypervisor: VMware ESXi 7.0/8.0, Microsoft Hyper-V 2019, KVM/QEMU, Citrix XenServer
- Container: Kubernetes 1.28, Docker Engine 24.0, Red Hat OpenShift 4.13, AWS ECS, Azure AKS
- DNS: ISC BIND 9.18, Microsoft DNS Server 2019, Infoblox DDI, Cloudflare DNS, Unbound DNS
- DHCP: Microsoft DHCP Server 2019, ISC DHCP Server, Infoblox DHCP
- NTP: NTPd 4.2, Chrony 4.3, Microsoft Windows Time Service
- IAM: Oracle Identity Manager 12c, Microsoft Identity Manager 2016, Okta Identity Cloud, Azure AD, SailPoint IdentityIQ

**Security Controls (11 sources):**
- EDR: CrowdStrike Falcon, Microsoft Defender for Endpoint, SentinelOne Singularity, Carbon Black Cloud, Palo Alto Cortex XDR
- CSPM: Palo Alto Prisma Cloud, Microsoft Defender for Cloud, Wiz, Orca Security, Aqua Security
- Email Gateway: Proofpoint Email Protection, Mimecast Email Security, Cisco ESA, Microsoft EOP, Barracuda ESG
- FIM: Tripwire Enterprise, OSSEC FIM, Samhain, AIDE
- DLP: Symantec DLP, Microsoft Purview DLP, Forcepoint DLP, Digital Guardian DLP, McAfee DLP
- PAM: CyberArk Privileged Access Security, BeyondTrust Password Safe, Delinea Secret Server, Thycotic Privilege Manager
- MDM: Microsoft Intune, VMware Workspace ONE, MobileIron, Jamf Pro, Citrix Endpoint Management
- XSOAR: Palo Alto Cortex XSOAR, Splunk SOAR, IBM Security Resilient, Swimlane
- Threat Intel: Anomali ThreatStream, ThreatConnect, MISP, Recorded Future
- Vuln Management: Tenable Nessus Professional, Qualys VMDR, Rapid7 InsightVM, Greenbone OpenVAS
- EPP: Symantec Endpoint Protection, McAfee Endpoint Security, Trend Micro Apex One, ESET Endpoint Security

**Network Security (9 sources):**
- NDR: Darktrace Enterprise Immune System, Vectra AI Cognito, ExtraHop Reveal(x), Cisco Stealthwatch, Corelight Sensor
- TLS Inspection: Palo Alto SSL Decryption, Blue Coat SSL Visibility, Zscaler SSL Inspection, Cisco Firepower SSL
- DDoS: Cloudflare DDoS Protection, Akamai Prolexic, Arbor Networks TMS, Radware DefensePro, AWS Shield Advanced
- NGFW: Palo Alto PA-Series, Fortinet FortiGate, Cisco Firepower NGFW, Check Point NGFW, Juniper SRX Series
- IPS/IDS: Snort 3, Suricata IDS/IPS, Cisco Firepower IPS, Tipping Point TPS, Trend Micro TippingPoint
- VPN: Cisco AnyConnect VPN, Palo Alto GlobalProtect, Fortinet FortiClient VPN, Pulse Secure VPN, OpenVPN
- WLC: Cisco Wireless Controller 9800, Aruba Mobility Controller, Ruckus SmartZone, Meraki Cloud Controller
- Proxy: Zscaler Internet Access, Blue Coat ProxySG, Squid Proxy, Forcepoint Web Security, McAfee Web Gateway
- NAC: Cisco ISE, Aruba ClearPass, ForeScout CounterACT, PacketFence

**Database (2 sources):**
- Database Engine: Oracle Database 19c, Microsoft SQL Server 2019, MySQL 8.0, PostgreSQL 15, MongoDB 6.0, IBM DB2 11.5, MariaDB 10.11
- Database Security: Imperva SecureSphere DAM, IBM Guardium, Oracle Audit Vault, McAfee Database Security

**Applications (3 sources):**
- API Gateway: Kong Gateway, Apigee API Management, AWS API Gateway, Azure API Management, MuleSoft Anypoint
- WAF: Imperva WAF, F5 Advanced WAF, Cloudflare WAF, AWS WAF, ModSecurity, Akamai Kona Site Defender
- Custom Apps: [Company] Employee Portal, [Company] Payment Gateway, [Company] Customer Portal, Internal ERP System

**Format-Specific Vendors:**
- JSON (XSIAM): Azure, Corelight, Zscaler, Symantec, Akamai, CrowdStrike, Kong, AWS, Okta, HashiCorp, Darktrace, F5
- CEF: Palo Alto, Cisco, F5, Imperva, Fortinet, Check Point, Suricata, CrowdStrike
- LEEF: Proofpoint, Mimecast, Zscaler
- SYSLOG: Cisco, Infoblox, Pulse Secure, Red Hat, IBM, Juniper, Arista, Apache, Nginx
- WINEVENT: DO NOT specify vendor/product (not supported - use srcHost in observables instead)

CRITICAL - Network Observables for Network Devices (Firewalls, IDS/IPS, WAF, VPN, DNS, Routers, Load Balancers):

MANDATORY NETWORK FIELDS - Must include in BOTH places:

**Core Network Fields (REQUIRED for ALL network devices):**
1. sourceIp / SOURCE_IP - Attacker/source IP address
2. destinationIp / DESTINATION_IP - Target/destination IP address
3. sourcePort / SOURCE_PORT - Attacker/source port number
4. destinationPort / DESTINATION_PORT - Target/destination port number
5. protocol / PROTOCOL - Network protocol (TCP, UDP, ICMP, HTTP, HTTPS, DNS, SSH, FTP, etc.)

**Legacy Mapping (for backward compatibility):**
- localIp / LOCAL_IP - Can still be used (maps to destination/target IP)
- remoteIp / REMOTE_IP - Can still be used (maps to source/attacker IP)
- remotePort / REMOTE_PORT - Can still be used (maps to destination/target port)

**Recommended Additional Network Fields:**
- srcHost / SRC_HOST - Source hostname (when available)
- dstHost / DST_HOST - Destination hostname (when available)
- user / USER - Username (for authenticated connections)
- action / ACTION - Action taken (allow, deny, block, accept, drop, etc.)

**CRITICAL: Dual Field Specification**
Fields must be specified in BOTH places:
  1. observables_dict: camelCase format (e.g., sourceIp, destinationIp, sourcePort, destinationPort, protocol)
  2. required_fields: SCREAMING_SNAKE_CASE format (e.g., SOURCE_IP, DESTINATION_IP, SOURCE_PORT, DESTINATION_PORT, PROTOCOL)

Important notes:
- If field is ONLY in observables_dict, it will NOT be sent to destination
- If field is ONLY in required_fields, it will be sent with empty/generated values
- Always include appropriate fields for the device type (network fields for firewalls/routers, authentication fields for identity products, etc.)

**Network Device Types Requiring Network Observables:**
| Device Type | Required Observables | Example Products |
|-------------|---------------------|------------------|
| Firewall | sourceIp, destinationIp, sourcePort, destinationPort, protocol, action | Palo Alto PA-Series, Fortinet FortiGate, Azure Firewall |
| IDS/IPS | sourceIp, destinationIp, sourcePort, destinationPort, protocol, alertName, severity | Corelight Sensor, Suricata, Snort |
| WAF | sourceIp, destinationIp, destinationPort, protocol, httpMethod, httpUri, httpStatusCode | F5 Advanced WAF, Imperva WAF, Cloudflare WAF |
| VPN | sourceIp, destinationIp, protocol, user, action | Cisco AnyConnect, Palo Alto GlobalProtect |
| DNS | sourceIp, destinationIp, protocol, dnsQuery | Infoblox BloxOne, Microsoft DNS Server |
| Router | sourceIp, destinationIp, sourcePort, destinationPort, protocol | Cisco ISR, Juniper MX Series |
| Load Balancer | sourceIp, destinationIp, sourcePort, destinationPort, protocol | F5 BIG-IP, Citrix NetScaler |

**Port Scan Scenario - Special Observable Pattern:**
For port scans (reconnaissance/discovery):
- destinationIp: SINGLE target IP (the server being scanned)
- sourceIp: MULTIPLE attacker IPs (the scanners)
- sourcePort: Random high ports from attackers
- destinationPort: MULTIPLE ports being scanned
- protocol: Usually ["TCP"] for most scans
- action: Mostly ["DENY", "DROP"] for closed ports, occasionally ["ALLOW"] for open ports

CRITICAL - Field Discovery Workflow:
1. Call xlog_get_field_info with include_observables=true
2. Review the relevant category in observable_catalog (e.g., 'network', 'authentication', 'kubernetes')
3. Use EXACT field names from the tool response
4. Specify each field in BOTH observables_dict (camelCase) AND required_fields (UPPERCASE)

Example workflow for firewall logs:
1. Call xlog_get_field_info → Get 'network' and 'firewall' categories
2. Select relevant fields from examples provided
3. Add to both required_fields (UPPERCASE) and observables_dict (camelCase)
4. Populate observables_dict with appropriate values for the use case`,
      },
    ],
  };

  const payload: GeminiCallPayload = {
    contents,
    tools,
    systemInstruction,
    generationConfig: {
      maxOutputTokens: 4096,
    },
  };

  if (GEMINI_API_KEY) {
    return callGeminiWithApiKey(payload);
  }

  if (GOOGLE_APPLICATION_CREDENTIALS) {
    return callGeminiWithVertex(payload);
  }

  throw new Error('Set GEMINI_API_KEY or GOOGLE_APPLICATION_CREDENTIALS to use the Next.js agent.');
}

export async function POST(request: NextRequest) {
  const encoder = new TextEncoder();

  const stream = new ReadableStream({
    async start(controller) {
      const send = (type: string, payload: Record<string, unknown>) => {
        controller.enqueue(encoder.encode(`data: ${JSON.stringify({ type, ...payload })}\n\n`));
      };

      try {
        const { message } = await request.json();

        if (!message) {
          send('error', { error: 'Message is required' });
          controller.close();
          return;
        }

        const logDebug = (stage: string, detail: string) => {
          send('debug', {
            time: new Date().toISOString(),
            stage,
            detail,
          });
        };

        logDebug('mcp', `Connecting to MCP at ${MCP_URL}`);
        const mcpClient = new XLogMCPClient(MCP_URL, MCP_TOKEN);
        const mcpTools = await mcpClient.listTools();
        logDebug('mcp', `Loaded ${mcpTools.length} tools`);

        const tools = [
          {
            functionDeclarations: mcpTools.map((tool: MCPTool) => {
              const rawSchema = (tool.inputSchema || {}) as Record<string, unknown>;
              return {
                name: tool.name,
                description: tool.description || '',
                parameters: sanitizeSchema(rawSchema),
              };
            }),
          },
        ];

        const contents: GeminiContent[] = [
          {
            role: 'user',
            parts: [{ text: message }],
          },
        ];

        logDebug('model', `Sending prompt to ${GEMINI_MODEL}`);
        let response = await callGemini(contents, tools);
        logDebug('model', 'Received initial response');

        let finalText: string[] = [];
        let toolCalls: Array<{ tool: string; args: Record<string, unknown>; result: string }> = [];

        for (let step = 0; step < 8; step++) {
          const candidate = response.candidates?.[0];
          const parts: GeminiPart[] = candidate?.content?.parts || [];

          const functionCalls: GeminiFunctionCall[] = [];
          for (const part of parts) {
            if (part.text) {
              finalText.push(part.text);
              send('delta', { text: part.text });
            }
            if (part.functionCall) {
              functionCalls.push(part.functionCall);
            }
          }

          if (functionCalls.length === 0) {
            logDebug('model', 'No tool calls requested');
            break;
          }

          contents.push({ role: 'model', parts });

          const responseParts: GeminiPart[] = [];
          for (const call of functionCalls) {
            const toolName = call.name;
            const toolArgs = call.args || {};
            logDebug('tool', `Calling ${toolName}`);
            send('tool_call', { tool: toolName, args: toolArgs });
            const result = await mcpClient.callTool(toolName, toolArgs);
            const resultText = result.content[0]?.text || JSON.stringify(result.content);
            logDebug('tool', `Result from ${toolName} (${resultText.length} chars)`);
            send('tool_result', { tool: toolName, result: resultText });

            toolCalls.push({
              tool: toolName,
              args: toolArgs,
              result: resultText,
            });

            responseParts.push({
              functionResponse: {
                name: toolName,
                response: {
                  result: resultText,
                },
              },
            });
          }

          if (responseParts.length > 0) {
            contents.push({
              role: 'user',
              parts: responseParts,
            });
          }

          logDebug('model', 'Sending tool results to model');
          response = await callGemini(contents, tools);
          logDebug('model', 'Received follow-up response');
        }

        send('done', {
          response: finalText.join('\n'),
          toolCalls,
        });
      } catch (error) {
        console.error('Chat API error:', error);
        send('error', { error: error instanceof Error ? error.message : 'Unknown error' });
      } finally {
        controller.close();
      }
    },
  });

  return new Response(stream, {
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache, no-transform',
      Connection: 'keep-alive',
    },
  });
}
