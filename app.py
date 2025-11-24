"""
AI Code Remediation Service - Core Application
Handles LLM inference, RAG, and code remediation logic
"""
import time
import re
import threading
from typing import Optional, Dict, List, Tuple
from pathlib import Path

from loguru import logger
import difflib
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig

# RAG imports (optional)
try:
    import faiss
    from sentence_transformers import SentenceTransformer
    FAISS_AVAILABLE = True
except ImportError:
    FAISS_AVAILABLE = False
    logger.warning("FAISS/SentenceTransformers not available - RAG disabled")


# ============================================================================
# CONFIGURATION
# ============================================================================

class Config:
    """Application configuration"""
    # Model Configuration
    MODEL_NAME: str = "Qwen/Qwen2.5-Coder-1.5B-Instruct"
    DEVICE: str = "auto"
    MAX_LENGTH: int = 2048
    TEMPERATURE: float = 0.3
    TOP_P: float = 0.95
    USE_4BIT: bool = True
    
    # RAG Configuration
    ENABLE_RAG: bool = True
    KNOWLEDGE_BASE_PATH: str = "./knowledge_base"
    RAG_TOP_K: int = 3
    
    # API Configuration
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    LOG_LEVEL: str = "INFO"
    
    # Security Limits
    MAX_CODE_LENGTH: int = 10000
    MAX_PROMPT_LENGTH: int = 8000
    ALLOWED_LANGUAGES: set = {"python", "javascript", "java", "go", "rust", "c", "cpp", "php", "ruby", "typescript"}
    ALLOWED_CWE_PATTERN: str = r"^CWE-\d+$"

config = Config()


# ============================================================================
# CWE DESCRIPTIONS & PROMPTS
# ============================================================================

CWE_DESCRIPTIONS = {
    "CWE-79": "Cross-Site Scripting (XSS)",
    "CWE-89": "SQL Injection",
    "CWE-22": "Path Traversal",
    "CWE-78": "OS Command Injection",
    "CWE-798": "Hard-coded Credentials",
    "CWE-676": "Use of Potentially Dangerous Function",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-434": "Unrestricted Upload of File with Dangerous Type",
    "CWE-306": "Missing Authentication",
    "CWE-287": "Improper Authentication",
    "CWE-20": "Improper Input Validation",
    "CWE-200": "Exposure of Sensitive Information",
}


def build_remediation_prompt(language: str, cwe: str, vulnerable_code: str, rag_context: Optional[str] = None) -> str:
    """Build prompt for code remediation"""
    cwe_description = CWE_DESCRIPTIONS.get(cwe, "Security Vulnerability")
    
    system_instruction = f"""You are an expert security engineer specializing in secure code remediation.
Your task is to fix security vulnerabilities in code while maintaining functionality.

CRITICAL RULES:
1. Only output the FIXED CODE - no explanations, no comments about changes
2. Preserve the original code structure and logic as much as possible
3. Apply minimal changes necessary to fix the security issue
4. Ensure the fixed code is production-ready and follows best practices
5. Do not add verbose comments explaining the fix
"""

    rag_section = ""
    if rag_context:
        rag_section = f"""
SECURITY BEST PRACTICES (Use these guidelines):
{rag_context}

"""

    prompt = f"""{system_instruction}

TASK:
Fix the following {language} code that contains a {cwe_description} ({cwe}) vulnerability.

{rag_section}VULNERABLE CODE:
```{language}
{vulnerable_code}
```

FIXED CODE:
```{language}"""

    return prompt


def build_explanation_prompt(language: str, cwe: str, vulnerable_code: str, fixed_code: str) -> str:
    """Build prompt for generating explanation"""
    cwe_description = CWE_DESCRIPTIONS.get(cwe, "Security Vulnerability")
    
    prompt = f"""Provide a clear, concise explanation following this structure:
1. What was the vulnerability?
2. How was it fixed?
3. Why is the fix secure?

Keep it under 100 words, technical but accessible.

VULNERABILITY: {cwe_description} ({cwe})
LANGUAGE: {language}

VULNERABLE CODE:
```{language}
{vulnerable_code}
```

FIXED CODE:
```{language}
{fixed_code}
```

EXPLANATION:"""

    return prompt


# ============================================================================
# SECURITY UTILITIES
# ============================================================================

def validate_input(language: str, cwe: str, code: str) -> Tuple[bool, Optional[str]]:
    """Validate user input to prevent injection and DoS attacks"""
    # Validate language
    if language.lower() not in config.ALLOWED_LANGUAGES:
        return False, f"Unsupported language: {language}. Allowed: {', '.join(config.ALLOWED_LANGUAGES)}"
    
    # Validate CWE format (prevent injection)
    if not re.match(config.ALLOWED_CWE_PATTERN, cwe):
        return False, f"Invalid CWE format: {cwe}. Expected format: CWE-XXX"
    
    # Validate code length (prevent DoS)
    if len(code) > config.MAX_CODE_LENGTH:
        return False, f"Code too large: {len(code)} chars. Max allowed: {config.MAX_CODE_LENGTH}"
    
    if len(code.strip()) == 0:
        return False, "Code cannot be empty"
    
    # Check for suspicious patterns (basic injection detection)
    dangerous_patterns = [
        r'__import__\s*\(',  # Python import injection
        r'eval\s*\(',         # Eval injection
        r'exec\s*\(',         # Exec injection
        r'os\.system\s*\(',   # System command
    ]
    
    for pattern in dangerous_patterns:
        if re.search(pattern, code, re.IGNORECASE):
            logger.warning(f"Suspicious pattern detected in input: {pattern}")
            # Don't reject, just log (code might legitimately contain these)
    
    return True, None

def sanitize_error_message(error: Exception) -> str:
    """Sanitize error messages to prevent information disclosure"""
    # Don't expose internal paths, model details, or stack traces to users
    error_str = str(error)
    
    # Remove file paths
    error_str = re.sub(r'[A-Za-z]:\\[^\s]+', '[PATH]', error_str)
    error_str = re.sub(r'/[^\s]+\.py', '[FILE]', error_str)
    
    # Generic error for production
    if "cuda" in error_str.lower() or "memory" in error_str.lower():
        return "Model inference error. Please try again or contact support."
    
    return "An error occurred during processing. Please check your input and try again."

# ============================================================================
# UTILITIES
# ============================================================================

def generate_diff(original_code: str, fixed_code: str) -> str:
    """Generate unified diff between original and fixed code"""
    original_lines = original_code.splitlines(keepends=True)
    fixed_lines = fixed_code.splitlines(keepends=True)
    
    diff = difflib.unified_diff(
        original_lines, fixed_lines,
        fromfile='vulnerable.code',
        tofile='fixed.code',
        lineterm='\n'
    )
    
    diff_text = ''.join(diff)
    # Clean: Remove empty diffs
    if not diff_text or diff_text.strip() == '':
        return "No changes detected"
    return diff_text.strip()


def extract_code_block(text: str) -> str:
    """Extract code from markdown code blocks or raw text, cleaning LLM artifacts"""
    # Clean common LLM artifacts
    text = text.strip()
    
    # Remove common prefixes
    artifacts = [
        'Here is the fixed code:',
        'Here\'s the fixed code:',
        'Fixed code:',
        'The fixed code is:',
        'FIXED CODE:',
        'Here is the secure version:',
    ]
    for artifact in artifacts:
        if text.lower().startswith(artifact.lower()):
            text = text[len(artifact):].strip()
    
    # Extract from code blocks
    if '```' in text:
        lines = text.split('\n')
        code_lines = []
        in_code_block = False
        
        for line in lines:
            stripped = line.strip()
            # Handle code fence with or without language
            if stripped.startswith('```'):
                if in_code_block:
                    break
                in_code_block = True
                continue
            
            if in_code_block:
                code_lines.append(line)
        
        if code_lines:
            code = '\n'.join(code_lines).strip()
            # Remove trailing explanatory text
            code = re.sub(r'\n\n(Note:|Explanation:|This code:).*$', '', code, flags=re.DOTALL)
            return code
    
    # Fallback: clean and return
    text = re.sub(r'\n\n(Note:|Explanation:|This code:).*$', '', text, flags=re.DOTALL)
    return text.strip()


# ============================================================================
# RAG SERVICE
# ============================================================================

class RAGService:
    """Retrieval-Augmented Generation service"""
    
    def __init__(self, knowledge_base_path: str = None):
        self.knowledge_base_path = knowledge_base_path or config.KNOWLEDGE_BASE_PATH
        self.enabled = FAISS_AVAILABLE and config.ENABLE_RAG
        
        if not self.enabled:
            self.index = None
            self.documents = []
            self.embedder = None
            return
        
        logger.info(f"Initializing RAG service: {self.knowledge_base_path}")
        self.embedder = SentenceTransformer('all-MiniLM-L6-v2')
        self.documents = self._load_documents()
        self.index = self._build_index()
        logger.info(f"RAG initialized with {len(self.documents)} documents")
    
    def _load_documents(self) -> List[dict]:
        """Load documents from knowledge base (with path traversal protection)"""
        documents = []
        kb_path = Path(self.knowledge_base_path).resolve()  # Resolve to absolute path
        
        # Security: Ensure knowledge base path is safe
        if not kb_path.exists():
            logger.warning(f"Knowledge base not found: {kb_path}")
            return documents
        
        if not kb_path.is_dir():
            logger.error(f"Knowledge base path is not a directory: {kb_path}")
            return documents
        
        for file_path in kb_path.rglob("*.txt"):
            try:
                # Security: Prevent path traversal
                resolved_path = file_path.resolve()
                if not str(resolved_path).startswith(str(kb_path)):
                    logger.warning(f"Skipping file outside knowledge base: {file_path}")
                    continue
                
                # Limit file size to prevent DoS
                if resolved_path.stat().st_size > 1_000_000:  # 1MB limit
                    logger.warning(f"Skipping large file: {file_path}")
                    continue
                
                content = resolved_path.read_text(encoding='utf-8')
                documents.append({
                    'content': content,
                    'source': file_path.name,
                    'cwe': self._extract_cwe(file_path.name)
                })
            except Exception as e:
                logger.error(f"Error loading {file_path}: {e}")
        
        for file_path in kb_path.rglob("*.md"):
            try:
                # Security: Prevent path traversal
                resolved_path = file_path.resolve()
                if not str(resolved_path).startswith(str(kb_path)):
                    logger.warning(f"Skipping file outside knowledge base: {file_path}")
                    continue
                
                # Limit file size
                if resolved_path.stat().st_size > 1_000_000:
                    logger.warning(f"Skipping large file: {file_path}")
                    continue
                
                content = resolved_path.read_text(encoding='utf-8')
                documents.append({
                    'content': content,
                    'source': file_path.name,
                    'cwe': self._extract_cwe(file_path.name)
                })
            except Exception as e:
                logger.error(f"Error loading {file_path}: {e}")
        
        return documents
    
    def _extract_cwe(self, filename: str) -> Optional[str]:
        """Extract CWE from filename"""
        import re
        match = re.search(r'CWE-\d+', filename, re.IGNORECASE)
        return match.group(0).upper() if match else None
    
    def _build_index(self) -> Optional[object]:
        """Build FAISS index"""
        if not self.documents:
            return None
        
        texts = [doc['content'] for doc in self.documents]
        embeddings = self.embedder.encode(texts, show_progress_bar=False)
        
        dimension = embeddings.shape[1]
        index = faiss.IndexFlatL2(dimension)
        index.add(embeddings.astype('float32'))
        
        return index
    
    def retrieve(self, query: str, cwe: str = None, top_k: int = None) -> str:
        """Retrieve relevant context with CWE scoring"""
        if not self.enabled or not self.index:
            logger.debug("RAG not enabled or no index available")
            return ""
        
        if not self.documents:
            logger.warning("No RAG documents available for retrieval")
            return ""
        
        top_k = top_k or config.RAG_TOP_K
        # Retrieve more candidates for re-ranking
        search_k = min(top_k * 3, len(self.documents))
        
        query_embedding = self.embedder.encode([query], show_progress_bar=False)
        distances, indices = self.index.search(query_embedding.astype('float32'), search_k)
        
        # Score and rank documents
        scored_docs = []
        for distance, idx in zip(distances[0], indices[0]):
            if idx < len(self.documents):
                doc = self.documents[idx]
                # CWE matching bonus: prioritize exact CWE matches
                cwe_bonus = 0.0
                if cwe and doc['cwe'] == cwe:
                    cwe_bonus = -0.5  # Lower distance = better match
                
                final_score = distance + cwe_bonus
                scored_docs.append((final_score, doc))
        
        # Sort by score and take top_k
        scored_docs.sort(key=lambda x: x[0])
        contexts = [doc['content'] for _, doc in scored_docs[:top_k]]
        
        if not contexts:
            logger.warning(f"No relevant context found for CWE: {cwe}")
            return ""
        
        logger.debug(f"Retrieved {len(contexts)} documents (CWE match bonus applied)")
        return "\n\n---\n\n".join(contexts)


# ============================================================================
# MODEL SERVICE
# ============================================================================

class ModelService:
    """LLM inference service with thread-safe generation"""
    
    def __init__(self):
        self.model = None
        self.tokenizer = None
        self.model_name = config.MODEL_NAME
        self._lock = threading.Lock()  # Thread safety for concurrent requests
        logger.info(f"Initializing model: {self.model_name}")
        self._load_model()
    
    def _load_model(self):
        """Load LLM and tokenizer"""
        try:
            logger.info("Loading tokenizer...")
            self.tokenizer = AutoTokenizer.from_pretrained(
                self.model_name,
                trust_remote_code=True
            )
            
            if self.tokenizer.pad_token is None:
                self.tokenizer.pad_token = self.tokenizer.eos_token
            
            logger.info("Loading model...")
            logger.info(f"Detecting hardware: CUDA available = {torch.cuda.is_available()}")
            
            quantization_config = None
            device_map = None
            model_dtype = torch.float32
            
            # Automatic GPU/CPU detection and optimization
            if torch.cuda.is_available():
                # GPU available - use optimal settings
                logger.info("✓ GPU detected - using CUDA acceleration")
                device_map = config.DEVICE  # "auto" or "cuda"
                model_dtype = torch.float16
                
                if config.USE_4BIT:
                    # 4-bit quantization for maximum efficiency
                    quantization_config = BitsAndBytesConfig(
                        load_in_4bit=True,
                        bnb_4bit_compute_dtype=torch.float16,
                        bnb_4bit_use_double_quant=True,
                        bnb_4bit_quant_type="nf4"
                    )
                    logger.info("✓ Using 4-bit quantization (~2GB VRAM, 1-3s latency)")
                else:
                    logger.info("✓ Using FP16 precision (~3GB VRAM, 1-3s latency)")
            else:
                # CPU only - fallback mode
                logger.warning("⚠ No GPU detected - falling back to CPU mode")
                device_map = "cpu"
                model_dtype = torch.float32
                
                if config.USE_4BIT:
                    logger.warning("⚠ 4-bit quantization disabled (requires CUDA)")
                
                logger.warning("⚠ CPU mode active: ~6GB RAM, 10-30s latency per request")
                logger.info("💡 For better performance: Use GPU or smaller model (0.5B)")
            
            # Load model with detected configuration
            self.model = AutoModelForCausalLM.from_pretrained(
                self.model_name,
                quantization_config=quantization_config,
                device_map=device_map,
                trust_remote_code=True,
                torch_dtype=model_dtype,
                low_cpu_mem_usage=True
            )
            
            # Report final configuration
            actual_device = next(self.model.parameters()).device
            logger.info(f"✓ Model loaded successfully")
            logger.info(f"  └─ Device: {actual_device}")
            logger.info(f"  └─ Dtype: {model_dtype}")
            logger.info(f"  └─ Quantization: {'4-bit' if quantization_config else 'None'}")
            
            logger.info(f"Model loaded successfully")
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            raise
    
    def generate(self, prompt: str, max_new_tokens: int = 1024, temperature: float = None, top_p: float = None) -> Tuple[str, Dict[str, int]]:
        """Generate text from prompt with thread safety and dynamic sizing"""
        temperature = temperature or config.TEMPERATURE
        top_p = top_p or config.TOP_P
        
        # Thread-safe generation
        with self._lock:
            try:
                inputs = self.tokenizer(
                    prompt,
                    return_tensors="pt",
                    truncation=True,
                    max_length=config.MAX_LENGTH - max_new_tokens
                )
                
                device = next(self.model.parameters()).device
                inputs = {k: v.to(device) for k, v in inputs.items()}
                input_length = inputs['input_ids'].shape[1]
                
                # Dynamic sizing: reduce tokens if prompt is large
                available_tokens = config.MAX_LENGTH - input_length
                adjusted_max_tokens = min(max_new_tokens, available_tokens - 50)  # Leave buffer
                
                if adjusted_max_tokens < max_new_tokens:
                    logger.warning(f"Reducing max_new_tokens from {max_new_tokens} to {adjusted_max_tokens} due to prompt size")
                
                with torch.no_grad():
                    outputs = self.model.generate(
                        **inputs,
                        max_new_tokens=adjusted_max_tokens,
                        temperature=temperature,
                        top_p=top_p,
                        do_sample=temperature > 0,
                        pad_token_id=self.tokenizer.pad_token_id,
                        eos_token_id=self.tokenizer.eos_token_id,
                    )
                
                generated_text = self.tokenizer.decode(
                    outputs[0][input_length:],
                    skip_special_tokens=True
                )
                
                output_length = outputs.shape[1] - input_length
                token_stats = {
                    'input_tokens': input_length,
                    'output_tokens': output_length,
                    'total_tokens': input_length + output_length
                }
                
                return generated_text, token_stats
            except Exception as e:
                logger.error(f"Error during generation: {e}")
                raise
    
    def get_model_info(self) -> Dict[str, str]:
        """Get model information with hardware detection"""
        device = next(self.model.parameters()).device
        dtype = next(self.model.parameters()).dtype
        
        # Determine hardware mode
        hardware_mode = "GPU (CUDA)" if device.type == "cuda" else "CPU"
        quantization = "4-bit" if (config.USE_4BIT and torch.cuda.is_available()) else "none"
        
        return {
            'model_name': self.model_name,
            'device': str(device),
            'dtype': str(dtype),
            'quantization': quantization,
            'hardware_mode': hardware_mode,
            'cuda_available': torch.cuda.is_available()
        }


# ============================================================================
# GLOBAL INSTANCES
# ============================================================================

model_service: Optional[ModelService] = None
rag_service: Optional[RAGService] = None


def get_model_service() -> ModelService:
    """Get or create model service"""
    global model_service
    if model_service is None:
        model_service = ModelService()
    return model_service


def get_rag_service() -> RAGService:
    """Get or create RAG service"""
    global rag_service
    if rag_service is None:
        rag_service = RAGService()
    return rag_service


# ============================================================================
# MAIN REMEDIATION FUNCTION
# ============================================================================

def remediate_code(language: str, cwe: str, vulnerable_code: str, use_rag: bool = True) -> dict:
    """
    Main function to remediate vulnerable code.
    
    Args:
        language: Programming language
        cwe: CWE identifier
        vulnerable_code: Vulnerable code to fix
        use_rag: Whether to use RAG
    
    Returns:
        Dictionary with fixed code, diff, explanation, and metrics
        
    Raises:
        ValueError: If input validation fails
    """
    start_time = time.time()
    
    # Security: Validate all inputs
    is_valid, error_msg = validate_input(language, cwe, vulnerable_code)
    if not is_valid:
        logger.warning(f"Input validation failed: {error_msg}")
        raise ValueError(error_msg)
    
    # Sanitize inputs (prevent injection in prompts)
    language = language.strip().lower()
    cwe = cwe.strip().upper()
    vulnerable_code = vulnerable_code.strip()
    
    # Get services
    model = get_model_service()
    rag = get_rag_service()
    
    # Retrieve RAG context with fallback handling
    rag_context = ""
    if use_rag and rag.enabled:
        try:
            query = f"{cwe} {language} {vulnerable_code[:500]}"
            rag_context = rag.retrieve(query, cwe=cwe)
            
            if rag_context:
                logger.debug(f"Retrieved RAG context: {len(rag_context)} chars")
            else:
                logger.info(f"No RAG context found for {cwe}, using base prompt")
        except Exception as e:
            logger.warning(f"RAG retrieval failed, proceeding without context: {e}")
            rag_context = ""
    
    # Build remediation prompt
    remediation_prompt = build_remediation_prompt(language, cwe, vulnerable_code, rag_context)
    
    # Dynamic token sizing based on code length
    code_length = len(vulnerable_code)
    if code_length < 200:
        max_tokens = 512  # Small snippets need fewer tokens
    elif code_length < 500:
        max_tokens = 768
    else:
        max_tokens = 1024  # Larger code gets full allocation
    
    logger.debug(f"Generating fixed code (max_tokens={max_tokens})...")
    generated_text, token_stats = model.generate(
        prompt=remediation_prompt,
        max_new_tokens=max_tokens,
        temperature=config.TEMPERATURE
    )
    
    # Extract code
    fixed_code = extract_code_block(generated_text)
    if not fixed_code or len(fixed_code.strip()) < 10:
        fixed_code = generated_text.strip()
    
    # Generate diff
    diff = generate_diff(vulnerable_code, fixed_code)
    
    # Generate explanation with optimized token usage
    explanation_prompt = build_explanation_prompt(language, cwe, vulnerable_code, fixed_code)
    explanation_text, explanation_stats = model.generate(
        prompt=explanation_prompt,
        max_new_tokens=150,  # Reduced from 256 for conciseness
        temperature=0.7
    )
    explanation = explanation_text.strip()
    # Clean any remaining artifacts from explanation
    explanation = re.sub(r'^(Explanation:|EXPLANATION:)\s*', '', explanation, flags=re.IGNORECASE)
    
    # Calculate metrics
    total_input_tokens = token_stats['input_tokens'] + explanation_stats['input_tokens']
    total_output_tokens = token_stats['output_tokens'] + explanation_stats['output_tokens']
    latency_ms = (time.time() - start_time) * 1000
    
    return {
        'fixed_code': fixed_code,
        'diff': diff,
        'explanation': explanation,
        'model_name': model.model_name,
        'input_tokens': total_input_tokens,
        'output_tokens': total_output_tokens,
        'total_tokens': total_input_tokens + total_output_tokens,
        'latency_ms': latency_ms
    }
