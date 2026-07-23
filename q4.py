from openai import OpenAI
# Initialize your AI client (ensure your API key is set in your environment variables)
client = OpenAI()

# Define the structure of the incoming request data
class SkillRequest(BaseModel):
    skill: str

SYSTEM_PROMPT = """[Insert the exact system prompt from Step 2 here]"""

@app.post("/")
async def scan_skill(request: SkillRequest):
    try:
        # Call the lightweight AI model
        response = client.chat.completions.create(
            model="gpt-4o-mini", # or another fast, reliable model
            response_format={"type": "json_object"}, # Forces the model to return valid JSON
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": request.skill}
            ],
            temperature=0.0 # Low temperature makes the output consistent and predictable
        )
        
        # Parse the AI response text back into a Python dictionary
        result = json.loads(response.choices[0].message.content)
        return result

    except Exception as e:
        # Fallback to an empty array so your server doesn't crash if something goes wrong
        return {"categories": []}
