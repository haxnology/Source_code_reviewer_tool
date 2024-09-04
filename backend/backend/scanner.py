# backend/scanner.py

class StaticCodeAnalyzer:
    def __init__(self):
        pass

    def analyze(self, code):
        results = []

        # OWASP Top 10 Example Rule: Check for hardcoded sensitive information
        if 'API_KEY' in code or 'password' in code:
            results.append({
                "rule": "Avoid hardcoding sensitive information",
                "category": "OWASP Top 10",
                "severity": "Critical"
            })

        # SANS Example Rule: Ensure input validation is present
        if 'input' in code and 'validate' not in code:
            results.append({
                "rule": "Ensure input validation is present",
                "category": "SANS",
                "severity": "High"
            })

        # CERT Example Rule: Check for buffer overflows
        if 'strcpy' in code:
            results.append({
                "rule": "Avoid unsafe string copy functions",
                "category": "CERT",
                "severity": "High"
            })

        # Add more rules as needed

        return results
