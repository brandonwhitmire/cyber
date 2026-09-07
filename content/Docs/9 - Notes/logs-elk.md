+++
title = "Logs - ELK"
+++

## **K**ibana Query Language (KQL)

- [Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/ecs-reference.html)
- [Elastic Common Schema (ECS) event fields](https://www.elastic.co/guide/en/ecs/current/ecs-event.html)
- [Winlogbeat fields](https://www.elastic.co/guide/en/beats/winlogbeat/current/exported-fields-winlog.html)
- [Winlogbeat ECS fields](https://www.elastic.co/guide/en/beats/winlogbeat/current/exported-fields-ecs.html)
- [Winlogbeat security module fields](https://www.elastic.co/guide/en/beats/winlogbeat/current/exported-fields-security.html)
- [Filebeat fields](https://www.elastic.co/guide/en/beats/filebeat/current/exported-fields.html)
- [Filebeat ECS fields](https://www.elastic.co/guide/en/beats/filebeat/current/exported-fields-ecs.html)

KQL queries are composed of `field:value` pairs

```shell
event.code:4625
```

### Free Text Search

```shell
"<KEYWORD>"
```

### Logical Operators

```shell
# Failure for account to login d/t being disabled
event.code:4625 AND winlog.event_data.SubStatus:0xC0000072
```

### Comparison Operators

```shell
event.code:4625 AND winlog.event_data.SubStatus:0xC0000072 AND @timestamp >= "2023-03-03T00:00:00.000Z" AND @timestamp <= "2023-03-06T23:59:59.999Z"
```

### Wildcards and Regular Expressions

```shell
event.code:4625 AND user.name: admin*
```

### Examples

**Identify failed login attempts against disabled accounts that took place between March 3rd 2023 and March 6th 2023**

- https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4625

```shell
event.code:4625 AND winlog.event_data.SubStatus:0xC0000072 AND @timestamp >= "2023-03-03T00:00:00.000Z" AND @timestamp <= "2023-03-06T23:59:59.999Z"
```