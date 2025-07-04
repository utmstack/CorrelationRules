# UTMStack Rules Documentation

## Introduction

Rules are YAML files that define how to analyze events to detect security threats. They're used by the analysis plugin to generate alerts when specific conditions are met.

## Rule Structure

A rule is defined as a YAML object with the following fields:

```yaml
- id: 1                           # Unique identifier for the rule
  dataTypes:                      # Types of data this rule applies to
    - google
  name: Hello                     # Name of the rule
  impact:                         # Impact information
    confidentiality: 0            # Impact on confidentiality (0-5)
    integrity: 0                  # Impact on integrity (0-5)
    availability: 3               # Impact on availability (0-5)
  category: Testing Category      # Category of the rule
  technique: Testing Technique    # Technique used by the threat
  adversary: origin               # Which side is considered the adversary (origin or target)
  references:                     # External references
    - https://quantfall.com
  description: This is a testing rule.  # Description of the rule
  where: safe(origin.geolocation.country, "") == "United States"  # Expression to evaluate
  afterEvents:                    # Additional events to search for
    - indexPattern: v11-log-*     # Index pattern to search in
      with:                       # Conditions for the search
        - field: origin.ip.keyword  # Field to match
          operator: filter_term     # Operator (filter_term, must_not_term, filter_match, must_not_match)
          value: '{{origin.ip}}'    # Value to match (can use variables from the event)
      within: now-12h             # Time window for the search
      count: 1                    # Number of events to match
  deduplicateBy:                  # Fields used for deduplication
    - adversary.ip
    - adversary.country
```



## Rule Fields

### id
A unique identifier for the rule.

### dataTypes
An array of data types that this rule applies to. The rule will only be evaluated for events with these data types.

### name
The name of the rule.

### impact
The impact of the threat detected by this rule, with scores for:
- **confidentiality**: Impact on confidentiality (0-5)
- **integrity**: Impact on integrity (0-5)
- **availability**: Impact on availability (0-5)

### category
The category of the rule.

### technique
The technique used by the threat.

### adversary
Which side is considered the adversary (origin or target).

### references
An array of external references for more information about the threat.

### description
A description of the rule.

### where
An expression to evaluate using the Common Expression Language (CEL).

### afterEvents
Additional events to search for, containing:
- **indexPattern**: The index pattern to search in
- **with**: Conditions for the search
  - **field**: The field to match
  - **operator**: The operator to use for matching. Possible values:
    - `filter_match`: Equality operator (using full-text search)
    - `filter_term`: Equality operator (using term search)
    - `must_not_match`: Not equal operator (using full-text search)
    - `must_not_term`: Not equal operator (using term search)
  - **value**: The value to match (can use variables from the event using the `{{field.path}}` syntax)
- **within**: The time window for the search
- **count**: The number of events to match (Max 50)

### deduplicateBy
Fields used for deduplication of alerts. COuld also be understood as grouping. This way multiple alerts that can be grouped together based on this field if they are similar.

## Rule Evaluation

When an event is received, the analysis plugin evaluates all rules that apply to the event's data type. For each rule:

1. The variables are extracted from the event
2. The expression is evaluated using the variables
3. If the expression evaluates to true, the afterEvents searches are performed
4. If all conditions are met, an alert is generated

## Advanced Rule Features

### Complex Expressions

The `where` field supports complex expressions using the Common Expression Language (CEL):

- **Logical Operators**: `&&` (AND), `||` (OR), `!` (NOT)
- **Comparison Operators**: `==`, `!=`, `<`, `<=`, `>`, `>=`
- **String Operations**: `startsWith()`, `endsWith()`, `contains()`
- **Array Operations**: `in`, `size()`
- **Mathematical Operations**: `+`, `-`, `*`, `/`, `%`

Example of a complex expression:
```yaml
where: has(origin.country) && !(origin.country in ["United States", "Canada", "United Kingdom"]) && (origin.user != "" && origin.user.startsWith("admin"))
```

### Nested AfterEvents

The `afterEvents` field supports nested searches using the `or` field:

```yaml
afterEvents:
  - indexPattern: v11-log-*
    with:
      - field: origin.ip.keyword
        operator: filter_term
        value: '{{origin.ip}}'
    within: now-12h
    count: 1
    or:
      - indexPattern: v11-alert-*
        with:
          - field: adversary.ip.keyword
            operator: filter_term
            value: '{{origin.ip}}'
        within: now-24h
        count: 2
```

The rule will match if either:
1. There is at least 1 event in the `v11-log-*` index with the same origin IP within the last 12 hours, OR
2. There are at least 2 alerts in the `v11-alert-*` index with the same adversary IP within the last 24 hours

### Dynamic Values

Rule fields can use dynamic values from the event using the `{{field.path}}` syntax:

```yaml
afterEvents:
  - indexPattern: v11-log-*
    with:
      - field: origin.user.keyword
        operator: filter_term
        value: '{{origin.user}}'
      - field: origin.ip.keyword
        operator: must_not_term
        value: '{{origin.ip}}'
    within: now-24h
    count: 3
```

This searches for events with the same user but a different IP address.

## Real-World Rule Examples

### Brute Force Attack Detection

```yaml
- id: 201
  dataTypes:
    - auth_logs
  name: Brute Force Attack Detection
  impact:
    confidentiality: 4
    integrity: 3
    availability: 2
  category: Authentication
  technique: Brute Force
  adversary: origin
  references:
    - https://attack.mitre.org/techniques/T1110/
  description: Detects multiple failed authentication attempts from the same IP address.
  where: has(origin.ip) && actionResult == "failure"
  afterEvents:
    - indexPattern: v11-log-auth_logs
      with:
        - field: origin.ip.keyword
          operator: filter_term
          value: '{{origin.ip}}'
        - field: actionResult.keyword
          operator: filter_term
          value: 'failure'
      within: now-1h
      count: 5
  deduplicateBy:
    - origin.ip
```

This rule generates an alert if there are at least 5 failed authentication attempts from the same IP address within the last hour.

### Data Exfiltration Detection

```yaml
- id: 202
  dataTypes:
    - network_logs
  name: Data Exfiltration Detection
  impact:
    confidentiality: 5
    integrity: 2
    availability: 1
  category: Exfiltration
  technique: Data Transfer
  adversary: origin
  references:
    - https://attack.mitre.org/techniques/T1048/
  description: Detects large data transfers to unusual destinations.
  where: has(origin.ip) && has(target.ip) && has(origin.bytesSent) && origin.bytesSent > 10000000 && !(target.ip in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])
  afterEvents:
    - indexPattern: v11-log-network_logs
      with:
        - field: origin.ip.keyword
          operator: filter_term
          value: '{{origin.ip}}'
        - field: target.ip.keyword
          operator: filter_term
          value: '{{target.ip}}'
      within: now-24h
      count: 1
  deduplicateBy:
    - origin.ip
    - target.ip
```

This rule generates an alert if there is a data transfer larger than 10MB to a destination outside the internal network.

### Unusual User Activity Detection

```yaml
- id: 203
  dataTypes:
    - user_activity
  name: Unusual User Activity
  impact:
    confidentiality: 3
    integrity: 4
    availability: 2
  category: Insider Threat
  technique: Unusual Activity
  adversary: origin
  references:
    - https://attack.mitre.org/techniques/T1078/
  description: Detects unusual user activity outside normal working hours.
  where: has(origin.user) && has(deviceTime) && has(action) && (time.hour < 8 || time.hour > 18) && action in ["file_access", "database_query", "admin_action"]
  afterEvents:
    - indexPattern: v11-log-user_activity
      with:
        - field: origin.user.keyword
          operator: filter_term
          value: '{{origin.user}}'
        - field: action.keyword
          operator: filter_term
          value: '{{action}}'
      within: now-7d
      count: 1
  deduplicateBy:
    - origin.user
    - action
```

This rule generates an alert if a user performs sensitive actions outside normal working hours (8 AM to 6 PM).

## Best Practices for Rule Development

1. **Start Simple**: Begin with simple rules that match specific patterns, then refine them as needed
2. **Test Thoroughly**: Test rules with a variety of events to ensure they work as expected
3. **Use Variables**: Use variables to make rules more readable and maintainable
4. **Document Rules**: Include a clear description and references in each rule
5. **Consider Performance**: Complex rules can impact performance, so optimize them as needed

## Rule Development Workflow

1. **Identify the Security Threat**: Determine what security threat you want to detect
2. **Understand the Data**: Examine the events that would indicate this threat
3. **Create a Rule File**: Create a new YAML file in the rules directory
4. **Define Basic Metadata**: Set the id, name, description, and other metadata
5. **Define Data Types**: Specify which data types this rule applies to
6. **Define Impact**: Set the confidentiality, integrity, and availability impact scores
7. **Define Where Conditions**: Create variables and an expression to identify events of interest
8. **Define After Events**: If needed, specify additional events to search for
9. **Define Deduplication**: Specify fields to use for deduplicating alerts
10. **Test the Rule**: Deploy the rule and test it with sample events
11. **Refine the Rule**: Adjust the rule based on testing results
12. **Document the Rule**: Add comments and references to explain the rule

## Rule Optimization

1. **Limit Data Types**: Specify only the data types that the rule applies to. This reduces the number of events that need to be evaluated
2. **Use Efficient Expressions**: Use efficient expressions in the `where` field. Avoid complex expressions that require a lot of processing
3. **Limit AfterEvents Searches**: Limit the number of `afterEvents` searches and the time window for each search. This reduces the load on the search engine
4. **Use Deduplication**: Use the `deduplicateBy` field to prevent alert fatigue

## Troubleshooting Rules

### Common Issues

1. **Rule Not Triggering**: Check that the event matches the dataTypes and where conditions
2. **Missing Fields**: Check that the fields referenced in rules exist in the events
3. **Performance Issues**: Check for complex rules that may be impacting performance

### Debugging

1. **Check Logs**: Look for error messages in the EventProcessor and plugin logs
2. **Test Rules Individually**: Test rules one at a time to isolate issues
3. **Validate YAML**: Ensure that rule YAML files are valid
4. **Check Field Names**: Verify that field names in rules match the actual field names in events
5. **Use Test Events**: Create test events that should trigger your rules and verify they work as expected

Important: The "safe" function should be used whenever the key evaluated is not from coming from a filer.
Important: When the field evaluated is not coming from a filter it should always start with "log."