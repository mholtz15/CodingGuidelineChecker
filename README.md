# CodingGuidelineChecker
Creating a guideline checker using Python
<br>
<br>
A coding guideline checker can be used so that developers are issued real-time feedback from a system. This can be helpful when dealing with security breaches and perhaps analyze and suggest new coding practices for the better. I used Python in order to create the checker inside of Visual Studio Code for those who are interested. 
<br>
<br> <i>make sure to have the Python extension installed onto VS code in order for you to use Python.</i>
<br> 
<br>
The code for the guideline checker is as follows:
<br>
```python
import re

RULES = {
    "Avoid_SQL_Injection": r"\b(select|insert|update|delete|drop|truncate)\b",
    "Avoid_XSS_Attacks": r"\b(document\.write|innerHTML|eval)\b",
    "Avoid_Hardcoded_Passwords": r"password\s*=\s*'[^']*'",
}

def check_secure_coding_guidelines(code):
    issues = []
    for rule_name, rule_pattern in RULES.items():
        matches = re.finditer(rule_pattern, code, re.IGNORECASE)
        for match in matches:
            start, end = match.span()
            issues.append((rule_name, start, end, match.group()))
    return issues
```
<br>
<br>
In order for me to test if the checker worked, I inserted the following: 
<br>
```python
def greet(name):
print("Hello, " + name + "!")
```
