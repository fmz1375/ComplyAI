"""
Fast RAG Chatbot - Fixed version
Answer questions about policy documents and NIST controls
No hardcoded responses - pure RAG
"""

import os
from typing import List, Dict, Any

import ollama
from langchain_community.document_loaders import PyPDFLoader
from langchain_community.vectorstores import FAISS
from langchain_ollama import OllamaEmbeddings
from rank_bm25 import BM25Okapi
import numpy as np

from security_utils import PromptInjectionDefense, InputValidation


class RAGChatbot:
    """Fast RAG Chatbot for policy documents and NIST compliance"""
    
    def __init__(
        self,
        llm_model: str = "saki007ster/CybersecurityRiskAnalyst",
        nist_vector_store_path: str = "./faiss_index"
    ):
        self.llm_model = llm_model
        self.nist_vector_store_path = nist_vector_store_path
        
        # Initialize embeddings
        print("Initializing RAG Chatbot...")
        self.embeddings = OllamaEmbeddings(model="qwen3-embedding")
        
        # Load NIST controls FAISS
        print(f"Loading NIST controls from {nist_vector_store_path}...")
        try:
            self.nist_store = FAISS.load_local(
                nist_vector_store_path,
                self.embeddings,
                allow_dangerous_deserialization=True
            )
            self.nist_corpus = [doc.page_content for doc in self.nist_store.docstore._dict.values()]
            print(f"✓ Loaded {len(self.nist_corpus)} NIST controls")
        except Exception as e:
            print(f"⚠ NIST controls not loaded: {e}")
            self.nist_store = None
            self.nist_corpus = []
        
        # Policy document store (created when user uploads)
        self.policy_store = None
        self.policy_docs = []
        self.policy_filename = None
        
        # Conversation history
        self.history = []
        
        print(f"✅ RAG Chatbot ready! Using {llm_model}")
    
    def load_policy_document(self, pdf_path: str) -> bool:
        """Load and index a policy document"""
        try:
            print(f"\nIndexing policy document: {pdf_path}")
            
            # Load PDF
            loader = PyPDFLoader(pdf_path)
            documents = loader.load()
            
            # Split into chunks with metadata
            chunks = []
            for doc in documents:
                content = doc.page_content.strip()
                if content:
                    # Split into smaller chunks
                    page = doc.metadata.get("page", 0) + 1
                    text_chunks = self._split_text(content, chunk_size=600, overlap=100)
                    for chunk in text_chunks:
                        chunks.append({
                            "content": chunk,
                            "page": page
                        })
            
            if not chunks:
                print("❌ No content found in document")
                return False
            
            # Store policy docs
            self.policy_docs = chunks
            
            # Create embeddings and FAISS store (in-memory)
            texts = [c["content"] for c in chunks]
            metadatas = [{"page": c["page"]} for c in chunks]
            
            self.policy_store = FAISS.from_texts(
                texts,
                self.embeddings,
                metadatas=metadatas
            )
            
            self.policy_filename = os.path.basename(pdf_path)
            
            print(f"✓ Indexed {len(chunks)} chunks from {len(documents)} pages")
            return True
            
        except Exception as e:
            print(f"❌ Failed to load policy: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def _split_text(self, text: str, chunk_size: int = 600, overlap: int = 100) -> List[str]:
        """Split text into overlapping chunks"""
        chunks = []
        start = 0
        
        while start < len(text):
            end = start + chunk_size
            chunk = text[start:end].strip()
            
            if chunk:
                chunks.append(chunk)
            
            start = end - overlap
            
            if start >= len(text):
                break
        
        return chunks
    
    def _rerank_results(self, results: List[Dict[str, Any]], query: str) -> List[Dict[str, Any]]:
        """Rerank results based on query relevance"""
        if not results:
            return results
        
        query_terms = set(query.lower().split())
        
        def relevance_score(doc):
            content = doc["content"].lower()
            score = 0
            
            # Exact phrase matches get highest score
            if query.lower() in content:
                score += 10
            
            # Individual term matches
            for term in query_terms:
                if term in content:
                    score += 2
            
            # Prefer policy over NIST for user questions
            if doc.get("type") == "policy":
                score += 1
            
            return score
        
        # Sort by relevance score
        ranked = sorted(results, key=relevance_score, reverse=True)
        return ranked
    
    def _search_docs(self, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """Search across both policy document and NIST controls"""
        results = []
        
        # Search policy document if loaded
        if self.policy_store:
            try:
                docs = self.policy_store.similarity_search(query, k=5)  # Get 5 chunks
                for doc in docs:
                    page = doc.metadata.get("page", "?")
                    results.append({
                        "content": doc.page_content[:150],
                        "source": f"Policy Page {page}",
                        "type": "policy"
                    })
            except Exception as e:
                print(f"Policy search error: {e}")
        
        # Search NIST controls if loaded
        if self.nist_store:
            try:
                docs = self.nist_store.similarity_search(query, k=5)  # Get 5 chunks
                for doc in docs:
                    results.append({
                        "content": doc.page_content[:150],
                        "source": "NIST Control",
                        "type": "nist"
                    })
            except Exception as e:
                print(f"NIST search error: {e}")
        
        # Rerank results by relevance
        reranked = self._rerank_results(results, query)
        return reranked[:5]  # Return top 5 reranked
    
    def chat(self, message: str) -> str:
        """Answer a question using RAG"""
        try:
            # Validate and sanitize user message input
            try:
                InputValidation.validate_message_size(message)
                sanitized_message = PromptInjectionDefense.sanitize_user_input(message)
            except ValueError as e:
                return f"Error: Invalid input - {str(e)}"
            
            # Add user message to history
            self.history.append({"role": "user", "message": message})
            
            # Retrieve relevant context
            print(f"\n🔍 Searching for: {sanitized_message[:60]}...")
            context_docs = self._search_docs(sanitized_message)
            
            print(f"✓ Found {len(context_docs)} relevant chunks (reranked)")
            
            # Build context string
            if context_docs:
                context = "\n\n".join([
                    f"[{doc['source']}]: {doc['content']}"
                    for doc in context_docs
                ])
            else:
                context = ""
            
            # Build conversation context (last 3 turns)
            conversation_context = ""
            if len(self.history) > 1:
                recent = self.history[-6:-1]  # Last 3 turns (excluding current)
                for msg in recent:
                    conversation_context += f"{msg['role'].upper()}: {msg['message']}\n"
            
            # Sanitize conversation context
            sanitized_context = PromptInjectionDefense.sanitize_user_input(conversation_context) if conversation_context else ""
            
            # Create prompt
            prompt = f"""You are a friendly assistant helping with security policy questions.

CONTEXT:
{context}

{f"CONVERSATION HISTORY:\n{sanitized_context}" if sanitized_context else ""}

USER QUESTION: {sanitized_message}

RESPONSE STYLE:
- Keep it simple and short: 1-3 sentences max.
- Answer directly and naturally, like talking to a colleague.
- Use plain language, avoid technical jargon.
- Always cite sources in parentheses when using context, e.g., (Policy Page 3) or (NIST Control). Page numbers are important for tracking.
- If unsure, just say so and ask what else you'd like to know.

ANSWER:"""

            # Generate response
            print("💭 Generating response...")
            response = ollama.generate(
                model=self.llm_model,
                prompt=prompt,
                stream=False,
                options={
                    "num_predict": 150,      # Keep responses short and punchy
                    "temperature": 0.3,      # Conversational but focused
                    "top_k": 30,
                    "top_p": 0.8
                }
            )
            
            assistant_message = response.get("response", "").strip()
            
            # Add to history
            self.history.append({"role": "assistant", "message": assistant_message})
            
            # Keep history manageable (last 20 messages)
            if len(self.history) > 20:
                self.history = self.history[-20:]
            
            return assistant_message
            
        except Exception as e:
            error_msg = f"Sorry, I encountered an error: {str(e)}"
            self.history.append({"role": "assistant", "message": error_msg})
            return error_msg
    
    def clear_history(self):
        """Clear conversation history"""
        self.history = []
        print("🗑️ Conversation history cleared")
    
    def get_history(self) -> List[dict]:
        """Get conversation history as JSON"""
        return self.history.copy()
