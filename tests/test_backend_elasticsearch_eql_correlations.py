import pytest
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError

from sigma.backends.elasticsearch.elasticsearch_eql import EqlBackend


@pytest.fixture(name="eql_backend")
def fixture_eql_backend():
    return EqlBackend()


def test_event_count_correlation_rule_stats_query(eql_backend: EqlBackend):
    correlation_rule = SigmaCollection.from_yaml(
        """
title: Base rule
name: base_rule
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value1
        fieldB: value2
    condition: selection
---
title: Multiple occurrences of base event
status: test
correlation:
    type: event_count
    rules:
        - base_rule
    group-by:
        - fieldC
        - fieldD
    timespan: 15m
    condition:
        gte: 10
            """
    )
    assert eql_backend.convert(correlation_rule) == [
        'sequence by fieldC, fieldD with maxspan=15m \n [any where fieldA:"value1" and fieldB:"value2"]  with runs=10'
    ]


def test_eql_correlation_event_count(eql_backend: EqlBackend):
    rule = SigmaCollection.from_yaml(
        r"""
title: Password Spraying via SChannelName
id: dcb9bf7c-216b-4a22-80a2-3232284cda18
name: password_spraying_schannel
status: experimental
description: Detecting Password Spraying via SChannelName
correlation:
    type: event_count
    rules:
        - ntlm_authentification
    group-by:
        - SChannelName
    timespan: 15m
    condition:
        gt: 35
---
title: NTLM Authentification
id: dcb9bf7c-216b-4a22-80a2-1232284cda18
name: ntlm_authentification
logsource:
    product: windows
    category: security
detection:
    selection:
        EventID: 8004
    condition: selection
        """
    )

    assert eql_backend.convert(rule) == [
        "sequence by SChannelName with maxspan=15m \n [any where EventID:8004]  with runs=35"
    ]


def test_eql_correlation_value_count(eql_backend: EqlBackend):
    rule = SigmaCollection.from_yaml(
        r"""
title: Password Spraying via SChannelName
id: dcb9bf7c-216b-4a22-80a2-3232284cda18
name: password_spraying_schannel
status: experimental
description: Detecting Password Spraying via SChannelName
correlation:
    type: value_count
    rules:
        - ntlm_authentification
    group-by:
        - SChannelName
    timespan: 15m
    condition:
        field: UserName
        gt: 35
---
title: NTLM Authentification
id: dcb9bf7c-216b-4a22-80a2-1232284cda18
name: ntlm_authentification
logsource:
    product: windows
    category: security
detection:
    selection:
        EventID: 8004
    condition: selection
        """
    )

    assert eql_backend.convert(rule) == [
        "sequence by SChannelName with maxspan=15m \n [any where EventID:8004] by UserName with runs=35"
    ]


def test_eql_correlation_temporal(eql_backend: EqlBackend):
    rule = SigmaCollection.from_yaml(
        r"""
title: Suspicious File Open Activity
status: experimental
description: Detects suspicious file open activity on Linux systems
correlation:
    type: temporal
    rules:
        - rule_one
        - rule_two
    group-by:
        - user.name
        - host.ip
    timespan: 15m
---
title: Linux Open File Activity
status: experimental
description: Detects open file activity on Linux systems
name: rule_one
logsource:
    category: audit
    product: linux
detection:
    selection:
        process.command_line|contains: git.exe
    condition: selection
---
title: Linux Open File Activity
name: rule_two
status: experimental
description: Detects open file activity on Linux systems
logsource:
    category: audit
    product: linux
detection:
    selection:
        process.command_line|contains: conhost.exe
    condition: selection

        """
    )

    assert eql_backend.convert(rule) == [
        'sample by user.name, host.ip \n [any where process.command_line:"*git.exe*"] \n [any where process.command_line:"*conhost.exe*"] '
    ]


def test_eql_correlation_temporal_ordered(eql_backend: EqlBackend):
    rule = SigmaCollection.from_yaml(
        r"""
title: Password Spraying via SChannelName
id: dcb9bf7c-216b-4a22-80a2-3232284cda18
name: password_spraying_schannel
status: experimental
description: Detecting Password Spraying via SChannelName
correlation:
    type: temporal_ordered
    rules:
        - ntlm_authentification
    group-by:
        - SChannelName
    timespan: 15m
    condition:
        field: UserName
        gt: 35
---
title: NTLM Authentification
id: dcb9bf7c-216b-4a22-80a2-1232284cda18
name: ntlm_authentification
logsource:
    product: windows
    category: security
detection:
    selection:
        EventID: 8004
    condition: selection
        """
    )

    assert eql_backend.convert(rule) == [
        "sequence by SChannelName with maxspan=15m \n [any where EventID:8004] by UserName with runs=35"
    ]


def test_eql_correlation_temporal_ordered_alias(eql_backend: EqlBackend):
    rule = SigmaCollection.from_yaml(
        r"""
title: Suspicious Parent Process Start
id: b72199a5-719a-4a59-bcf9-23f1337a0dcd
name: suspicious_parent_proc
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        process_image_path|endswith:
            - '\cmd.exe'
            - '\hwp.exe'
            - '\hword.exe'
            - '\gwp.exe'
    filter_messenger:
        parent_image_path|endswith:
            - '\AIWorks-Messenger.exe'
    condition: selection and not filter_messenger
---
title: PowerShell Child Process Start
id: 35e09a3a-51f0-4150-ba30-0276a272b02e
name: suspicious_child_proc
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        process_image_path|endswith:
            - '\powershell.exe'
    condition: selection
---
title: Suspicious Execution Chain (HWP/CMD -> PowerShell)
id: 96c3a0c0-aba0-4315-9a46-0e2e504707ee
status: experimental
author: Gemini
type: correlation
correlation:
    type: temporal_ordered
    rules:
        - suspicious_parent_proc
        - suspicious_child_proc
    aliases:
        link_id:
            suspicious_parent_proc: process_guid
            suspicious_child_proc: parent_guid
    group-by:
        - host_guid
        - link_id
    timespan: 20s
level: high
        """
    )

    assert eql_backend.convert(rule) == [
        'sequence by host_guid with maxspan=20s \n [any where (process_image_path like~ ("*\\\\cmd.exe", "*\\\\hwp.exe", "*\\\\hword.exe", "*\\\\gwp.exe")) and (not parent_image_path:"*\\\\AIWorks-Messenger.exe")] by process_guid \n [any where process_image_path:"*\\\\powershell.exe"] by parent_guid with runs=2'
    ]
