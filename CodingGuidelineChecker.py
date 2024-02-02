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

if __name__ == "__main__":
     # Example Python script to check against secure coding guidelines
    python_script = """
    import psycopg2

    # Avoid SQL Injection
    user_input = input("Enter username: ")
    cursor.execute("SELECT * FROM users WHERE username = '%s'" % user_input)

    # Avoid XSS Attacks
    document.write("<script>alert('XSS attack')</script>")

    # Avoid Hardcoded Passwords
    password = 'Holtz141'
    """

    issues = check_secure_coding_guidelines(python_script)

    if issues:
        print("Security issues found:")
        for rule_name, start, end, snippet in issues:
            print(f"- Rule: {rule_name}, Location: {start}-{end}, Code Snippet: {snippet}")
    else:
        print("No security issues found.")
