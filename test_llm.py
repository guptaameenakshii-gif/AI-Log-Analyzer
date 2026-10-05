import os

from dotenv import load_dotenv
from openai import OpenAI


load_dotenv()

provider = os.getenv("LLM_PROVIDER")
model = os.getenv("LLM_MODEL")
api_key = os.getenv("GEMINI_API_KEY")


print("Provider:", provider)
print("Model:", model)
print("API key configured:", bool(api_key))


if not api_key:
    raise RuntimeError("GEMINI_API_KEY is missing from .env")

if not model:
    raise RuntimeError("LLM_MODEL is missing from .env")


client = OpenAI(
    api_key=api_key,
    base_url="https://generativelanguage.googleapis.com/v1beta/openai/",
)


response = client.chat.completions.create(
    model=model,
    messages=[
        {
            "role": "user",
            "content": "Reply with exactly: LLM TEST OK",
        }
    ],
)


print("\nResponse object:")
print(response)

print("\nMessage:")
print(response.choices[0].message)

print("\nContent:")
print(response.choices[0].message.content)