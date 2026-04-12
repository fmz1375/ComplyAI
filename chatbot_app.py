"""
Flask Web App for RAG Chatbot - Fixed Version
Answers questions about policy documents and NIST controls
"""

import os
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from werkzeug.utils import secure_filename
from rag_chatbot_fixed import RAGChatbot

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
ALLOWED_EXTENSIONS = {"pdf"}

app = Flask(__name__)
CORS(app)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Initialize chatbot
print("Initializing RAG Chatbot...")
chatbot = RAGChatbot(
    llm_model="saki007ster/CybersecurityRiskAnalyst",
    nist_vector_store_path="./faiss_index"
)

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/")
@app.route("/index.html")
def index():
    return send_from_directory(BASE_DIR, "chatbot_widget.html")


@app.route("/upload", methods=["POST"])
def upload_file():
    """Upload and index a policy document"""
    if "file" not in request.files:
        return jsonify({"error": "No file part"}), 400
    
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No selected file"}), 400
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
        save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(save_path)
        
        # Index the document
        success = chatbot.load_policy_document(save_path)
        
        if success:
            return jsonify({
                "filename": filename,
                "message": "Document uploaded and indexed successfully"
            })
        else:
            return jsonify({"error": "Failed to index document"}), 500
    
    return jsonify({"error": "Invalid file"}), 400


@app.route("/chat", methods=["POST"])
def chat():
    """Handle chat messages"""
    data = request.json
    message = data.get("message", "").strip()
    
    if not message:
        return jsonify({"error": "No message provided"}), 400
    
    try:
        response = chatbot.chat(message)
        return jsonify({
            "response": response,
            "history": chatbot.get_history()
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/clear", methods=["POST"])
def clear_history():
    """Clear conversation history"""
    chatbot.clear_history()
    return jsonify({"message": "History cleared"})


@app.route("/history", methods=["GET"])
def get_history():
    """Get conversation history"""
    return jsonify({"history": chatbot.get_history()})


if __name__ == "__main__":
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    print("\n" + "="*60)
    print("⚡ ULTRA-CONCISE RAG CHATBOT SERVER STARTING")
    print("="*60)
    print("Ultra-short responses (2-4 sentences max):")
    print("  - 120 token limit (forces brevity)")
    print("  - 0.1 temperature (no rambling)")
    print("  - 2-4 sentence limit enforced")
    print("  - Source citations: (Policy Page 3)")
    print("  - 5 relevant chunks with reranking")
    print("  - Smart relevance scoring")
    print("Server: http://localhost:5003")
    print("="*60 + "\n")
    app.run(host="0.0.0.0", port=5003, debug=False, threaded=True)
