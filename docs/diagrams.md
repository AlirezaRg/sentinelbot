# Diagrams

All diagrams are Mermaid, so they render on GitHub and stay under version control. Each diagram lists what it shows and what it deliberately leaves out.

## 1. Overall architecture

Shows the components and the protocols between them. Leaves out the dashboard's internal structure.

```mermaid
flowchart LR
    subgraph Host["Linux host"]
        SSHD["sshd / sudo"] --> LOG[("journal or auth.log")]
        AG["sentinelbot-agent"]
        LOG --> AG
        PROC["/proc and sockets"] --> AG
    end
    AG -- "HTTP POST /api/v1/events<br/>X-API-Key" --> API
    subgraph Server["SentinelBot server"]
        API["FastAPI API"]
        DET["detection and scoring"]
        COR["correlation"]
        API --> DET --> COR
        COR --> DB[("PostgreSQL")]
        DET -. "shared windows" .-> RDS[("Redis, optional")]
        COR --> ALR["alerts"]
        COR --> AI["analyst (optional)"]
        API --> MET["/metrics"]
    end
    BR["Browser"] -- "/backend/* with bearer token" --> UI["Next.js dashboard"] --> API
    MET --> PROM["Prometheus"] --> GRAF["Grafana"]
    ALR --> SMTP["SMTP server"]
    AI -. "optional" .-> LLM["model provider"]
```

## 2. Agent architecture

Shows the collectors and the sink. Leaves out the HTTP retry details.

```mermaid
flowchart TB
    CLI["cli: options and config"] --> RUN["agent: collection cycle"]
    RUN --> SYS["system collector<br/>CPU, memory"]
    RUN --> PRC["process collector<br/>top processes"]
    RUN --> NET["network collector<br/>listening sockets"]
    RUN --> AUTH["auth collector"]
    AUTH --> SRC{"journal available?"}
    SRC -- yes --> JRN["JournalSource<br/>journalctl, cursor"]
    SRC -- no --> FIL["FileSource<br/>byte offset, 1 MiB per cycle"]
    JRN --> PARSE["parsers: sshd, sudo"]
    FIL --> PARSE
    SYS --> EV["Event objects"]
    PRC --> EV
    NET --> EV
    PARSE --> EV
    EV --> SINK{"sink"}
    SINK -- "API URL set" --> HTTP["HttpBatchSink<br/>batches of 200"]
    SINK -- "no URL" --> JSONL["JsonLinesSink<br/>file or stdout"]
```

## 3. Event processing pipeline

Shows what happens to an event from arrival to storage. Leaves out database transactions.

```mermaid
sequenceDiagram
    participant A as Agent
    participant API as API ingest
    participant D as Detection
    participant S as Risk scorer
    participant C as Correlator
    participant DB as Store
    participant N as Alerts
    A->>API: batch of events (service key)
    API->>API: validate (pydantic)
    loop each telemetry event
        API->>D: process(event)
        D-->>API: detections (after cooldown)
        API->>S: score(detection)
        S-->>API: detection with score and factors
    end
    API->>DB: store events and detections
    loop each detection
        API->>C: ingest(detection)
        C-->>API: incident (new or joined)
    end
    API->>DB: save incidents
    API->>N: notify on new or escalated incidents
    API-->>A: 201 or 409 for duplicates
```

## 4. Detection and correlation pipeline

Shows how one attack moves from events to an incident. Uses the lab campaign as the example.

```mermaid
flowchart LR
    E1["8 x ssh_login_failed<br/>from 198.51.100.23"] --> R1["ssh_bruteforce<br/>threshold 5 in 300 s"]
    R1 --> D1["detection, score 40"]
    E2["ssh_root_login<br/>from the same IP, 3 min later"] --> R2["root_login<br/>every occurrence"]
    R2 --> D2["detection, score 60<br/>35 + 10 combination + 15 privilege"]
    D1 --> G{"same host and source,<br/>within 1800 s?"}
    D2 --> G
    G -- yes --> I["one incident<br/>severity high, score 60, 2 detections"]
```

## 5. Data flow

Shows which data crosses which component, and in what format. Leaves out error paths.

```mermaid
flowchart LR
    RAW["raw log line<br/>text"] -->|"parse"| AR["AuthRecord<br/>typed fields"]
    AR -->|"wrap"| EVT["Event<br/>JSON"]
    EVT -->|"HTTP batch"| STORE1[("events table")]
    EVT -->|"rules"| DET2["detection Event<br/>JSON with metadata"]
    DET2 -->|"score"| DET3["detection with factors"]
    DET3 -->|"correlate"| INC["Incident<br/>JSON"]
    INC -->|"JSON"| UI2["dashboard"]
    INC -->|"structured fields only"| LLM2["analyst prompt"]
    LLM2 -->|"JSON, validated"| EXP["explanation"]
```

## 6. Threat model and trust boundaries

Shows the boundaries described in `threat-model.md`. Each boundary is labeled with the protocol and the authentication used.

```mermaid
flowchart TB
    ATT["Remote attacker"] -->|"SSH"| HOSTK
    subgraph HOSTB["Monitored host (B1)"]
        HOSTK["sshd writes logs"] -->|"B2: untrusted text"| AG2["agent"]
    end
    AG2 -->|"B3: HTTP + service key<br/>no TLS by default"| APIB
    subgraph SRVB["Server (B4)"]
        APIB["API: auth, ingest, rules"]
    end
    APIB -->|"B5: SQL"| PG[("PostgreSQL")]
    APIB -->|"B6: Redis protocol"| RD2[("Redis")]
    APIB -->|"B7: SMTP STARTTLS"| MAIL["mail server"]
    APIB -->|"B8: HTTPS, optional"| MODEL["model provider"]
    USR["Dashboard user"] -->|"B10: HTTP + bearer token"| UI3["dashboard"] --> APIB
    PROM2["Prometheus"] -->|"B11: scrape with key"| APIB
```

## 7. Deployment architecture (Docker Compose, one host)

Shows the services and the ports published on the host. Leaves out volumes.

```mermaid
flowchart LR
    subgraph Host2["Docker host"]
        subgraph net["compose network"]
            PG2[(postgres)]
            RD3[(redis)]
            API2["sentinel-api :8000"]
            AG3["sentinel-agent<br/>pid: host"]
            FE["frontend :3000"]
            PR["prometheus :9090"]
            GR["grafana :3000"]
            API2 --> PG2
            API2 --> RD3
            AG3 --> API2
            FE --> API2
            PR --> API2
            GR --> PR
        end
    end
    P8000["127.0.0.1:8000"] --> API2
    P3001["127.0.0.1:3001"] --> FE
    P9090["127.0.0.1:9090"] --> PR
    P3000["127.0.0.1:3000"] --> GR
```

## 8. Kubernetes architecture

Shows the workloads and the node-level agent. Leaves out the init container's migration step.

```mermaid
flowchart TB
    subgraph Cluster["k3s cluster (two nodes)"]
        subgraph CP["control-plane node"]
            DS1["agent DaemonSet pod"]
        end
        subgraph WK["worker node"]
            DS2["agent DaemonSet pod"]
        end
        API3["api Deployment<br/>init: alembic upgrade head"]
        PG3[("postgres StatefulSet")]
        RD4[("redis")]
        FE2["frontend Deployment<br/>NodePort 30301"]
        PR2["prometheus"]
        GR2["grafana<br/>NodePort 30300"]
        DS1 --> API3
        DS2 --> API3
        API3 --> PG3
        API3 --> RD4
        FE2 --> API3
        PR2 --> API3
        GR2 --> PR2
    end
    OPS["operator kubectl"] --> Cluster
```
