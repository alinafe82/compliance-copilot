class MockLLM:
    def complete(self, prompt: str) -> str:
        if "secrets" in prompt.lower():
            return "Potential secret exposure. Actions: rotate keys, add detect-secrets, update .gitignore."
        return "No critical risks detected. Actions: ensure codeowner review, run SAST, add tests."

def get_llm():
    return MockLLM()
