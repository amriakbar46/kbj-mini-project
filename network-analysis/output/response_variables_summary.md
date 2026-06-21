# Response Variables Summary (Soal Section 4.3)

Aggregated quantitative metrics from 3 PCAP cases.

## Variabel Respon per Case

| Case | IOC Total | Files | MITRE | Time (min) | Detection Rate | C2 | Crash | Completeness | Family Accuracy |
|------|-----------|-------|-------|------------|----------------|-----|-------|--------------|----------------|
| case1 | 142 | 6 | 5 | 95 | 25% | Y | N | 5/5 | N |
| case2 | 189 | 66 | 5 | 80 | 60% | Y | N | 5/5 | N |
| case3 | 222 | 68 | 8 | 110 | 70% | Y | N | 5/5 | N |

## IOC Count per Tool × Category

Coverage matrix (1=Detected, 0=Not Detected):

### Case 1

| Tool | IP | Domain | URL | Hash | UA |
|------|----|--------|-----|------|-----|
| BruteShark | 1 | 1 | 1 | 0 | 1 |
| Wireshark/TShark | 1 | 1 | 1 | 1 | 1 |
| NetworkMiner | 1 | 1 | 1 | 1 | 1 |
| Python/Zeek-like | 1 | 1 | 1 | 0 | 1 |

### Case 2

| Tool | IP | Domain | URL | Hash | UA |
|------|----|--------|-----|------|-----|
| BruteShark | 1 | 1 | 1 | 0 | 1 |
| Wireshark/TShark | 1 | 1 | 1 | 1 | 1 |
| Python/Zeek-like | 1 | 1 | 1 | 1 | 1 |

### Case 3

| Tool | IP | Domain | URL | Hash | UA |
|------|----|--------|-----|------|-----|
| BruteShark | 1 | 1 | 1 | 0 | 1 |
| Wireshark/TShark | 1 | 1 | 1 | 1 | 1 |
| Python/Zeek-like | 1 | 1 | 1 | 0 | 1 |

## Unique IOC per Tool (i.e., IOC found by only one tool)

### case1
- **BruteShark**: 0 unique IOCs
- **Wireshark/TShark**: 0 unique IOCs
- **NetworkMiner**: 0 unique IOCs
- **Python/Zeek-like**: 0 unique IOCs

### case2
- **BruteShark**: 0 unique IOCs
- **Wireshark/TShark**: 0 unique IOCs
- **Python/Zeek-like**: 1 unique IOCs

### case3
- **BruteShark**: 0 unique IOCs
- **Wireshark/TShark**: 0 unique IOCs
- **Python/Zeek-like**: 0 unique IOCs

