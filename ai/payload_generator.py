from transformers import pipeline

class PayloadGenerator:
    def __init__(self):
        self.generator = pipeline("text-generation", model="gpt-2")

    def generate_sqli_payloads(self, num=10):
        return self.generator("SQL Injection payload:", num_return_sequences=num)