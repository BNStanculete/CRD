# Copyright 2025 Bogdan Stanculete. All Rights Reserved.

HOSTS = [
    {
        "Mac": "08:00:00:00:01:01",
        "IPv4": "10.0.1.1",
        "SubnetMask": 32
    },
    {
        "Mac": "08:00:00:00:02:02",
        "IPv4": "10.0.2.2",
        "SubnetMask": 32   
    },
    {
        "Mac": "08:00:00:00:03:03",
        "IPv4": "10.0.3.3",
        "SubnetMask": 32   
    },
    {
        "Mac": "08:00:00:00:04:04",
        "IPv4": "10.0.4.4",
        "SubnetMask": 32   
    },
    {
        "Mac": "08:00:00:00:05:05",
        "IPv4": "10.0.5.5",
        "SubnetMask": 32   
    }
]

HOST_CONNECTIONS = [
    {
        "Host": 0,
        "Switch": "s1",
        "Port": 2
    },
    {
        "Host": 1,
        "Switch": "s1",
        "Port": 3
    },
    {
        "Host": 2,
        "Switch": "s1",
        "Port": 4
    },
    {
        "Host": 3,
        "Switch": "s2",
        "Port": 2
    },
    {
        "Host": 4,
        "Switch": "s2",
        "Port": 3
    }
]

SWITCH_CONNECTIONS = [
    {
        "Switches": ["s1", "s2"],
        "Port": 1
    }
]

SERVER_ADDRESS = HOSTS[0]
PROXY_SERVER_ADDRESS = HOSTS[-1]
ADVERSARY_ADDRESS = HOSTS[1]
