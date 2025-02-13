200
[('JSESSIONID', 'D3BAF195C5EAF28CEF11F61DE39A08FB')]
{
    "machineCounterModel": {
        "offlineCleanCount": 4,
        "offlineInfectedCount": 1,
        "onlineCleanCount": 0,
        "onlineInfectedCount": 0,
        "totalMachines": 5
    },
    "malops": [
        {
            "@class": ".MalopInboxModel",
            "closed": false,
            "closerName": null,
            "containers": [],
            "creationTime": 1680501474700,
            "decisionStatuses": [],
            "detectionEngines": [
                "EDR"
            ],
            "detectionTypes": [
                "Malicious tool by hash"
            ],
            "displayName": "attacker.exe",
            "edr": true,
            "empty": true,
            "escalated": false,
            "group": "b1b14605-ab1d-463a-8524-13a0f84963ef",
            "guid": "AAAA06ZpLyo_ygxa",
            "iconBase64": "",
            "labels": [
                "Production\u74b0\u5883"
            ],
            "lastUpdateTime": 1680501474701,
            "machines": [
                {
                    "@class": ".MachineInboxModel",
                    "connected": false,
                    "displayName": "win10-x64-japanese",
                    "empty": true,
                    "guid": "zoSjPRCi55eyTiwX",
                    "isolated": false,
                    "lastConnected": 1681019177362,
                    "osType": "WINDOWS"
                }
            ],
            "malopCloseTime": null,
            "malopDetectionType": "KNOWN_MALWARE",
            "malopPriority": "HIGH",
            "malopSeverity": "High",
            "malopStatus": "Active",
            "malopType": "KNOWN_MALWARE",
            "primaryRootCauseName": "attacker.exe",
            "priority": "HIGH",
            "rootCauseElementHashes": "",
            "rootCauseElementNamesCount": 1,
            "rootCauseElementType": "File",
            "severity": "High",
            "status": "Active",
            "users": [
                {
                    "admin": false,
                    "displayName": "window manager\\dwm-2",
                    "domainUser": false,
                    "guid": "AAAAGHMoS-xyUCrp",
                    "localSystem": false
                }
            ]
        },
        {
            "@class": ".MalopInboxModel",
            "closed": false,
            "closerName": null,
            "containers": [],
            "creationTime": 1680450058428,
            "decisionStatuses": [],
            "detectionEngines": [
                "EDR"
            ],
            "detectionTypes": [
                "Operating system process masquerade"
            ],
            "displayName": "certutil.exe",
            "edr": true,
            "empty": true,
            "escalated": false,
            "group": "b1b14605-ab1d-463a-8524-13a0f84963ef",
            "guid": "AAAA0941gNqpw4ls",
            "iconBase64": "",
            "labels": [
                "Production\u74b0\u5883"
            ],
            "lastUpdateTime": 1680498833327,
            "machines": [
                {
                    "@class": ".MachineInboxModel",
                    "connected": false,
                    "displayName": "win10-x64-japanese",
                    "empty": true,
                    "guid": "zoSjPRCi55eyTiwX",
                    "isolated": false,
                    "lastConnected": 1681019177362,
                    "osType": "WINDOWS"
                }
            ],
            "malopCloseTime": null,
            "malopDetectionType": "MALICIOUS_PROCESS",
            "malopPriority": "HIGH",
            "malopSeverity": "High",
            "malopStatus": "Active",
            "malopType": "MALICIOUS_PROCESS",
            "primaryRootCauseName": "certutil.exe",
            "priority": "HIGH",
            "rootCauseElementHashes": "",
            "rootCauseElementNamesCount": 1,
            "rootCauseElementType": "Process",
            "severity": "High",
            "status": "Active",
            "users": [
                {
                    "admin": false,
                    "displayName": "win10-x64-japan\\admin",
                    "domainUser": false,
                    "guid": "AAAAGDJkF02hcMIf",
                    "localSystem": false
                }
            ]
        }
    ]
}

