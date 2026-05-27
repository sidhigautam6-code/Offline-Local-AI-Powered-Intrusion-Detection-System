import ollama
import streamlit as st

def query_ollama(prompt: str, model: str = "deepseek-coder"):
    """
    Query local Ollama model with error handling
    """
    try:
        with st.spinner(f"🤖 Thinking with {model}..."):
            response = ollama.chat(
                model=model,
                messages=[{
                    'role': 'user', 
                    'content': prompt
                }]
            )
            return response['message']['content']
            
    except Exception as e:
        error_msg = str(e)
        if "Connection refused" in error_msg or "ollama" in error_msg.lower():
            return "❌ Ollama is not running. Please start Ollama with command: `ollama serve` in terminal."
        elif "model" in error_msg.lower():
            return f"❌ Model '{model}' not found. Make sure you have pulled it using `ollama pull {model}`"
        else:
            return f"❌ Error connecting to Ollama: {error_msg}"