# AI Code Remediation Microservice

An advanced AI-powered Remediation-as-a-Service (RaaS) platform that automatically fixes insecure code using locally hosted Large Language Models (LLMs). This microservice analyzes vulnerable code snippets and generates secure alternatives with detailed explanations and diffs.

## 🎯 Features

- **Local LLM Inference**: Runs open-source coding models (Qwen2.5-Coder, DeepSeek-Coder, StarCoder2)
- **RESTful API**: FastAPI-based `/local_fix` endpoint for code remediation
- **RAG Enhancement**: Retrieval-Augmented Generation using FAISS for context-aware fixes
- **Comprehensive Logging**: Tracks token usage, latency, and model performance
- **Security Focus**: Supports major CWE categories (SQL Injection, XSS, Command Injection, etc.)
- **Docker Support**: Containerized deployment with GPU support
- **Production-Ready**: 4-bit quantization for efficient memory usage

## 📁 Project Structure

```
ai-code-remediation/
├── main.py                    # FastAPI application (REST API)
├── app.py                     # AI logic (LLM, RAG, remediation)
├── test_local.py              # Integration tests
├── requirements.txt           # Python dependencies
├── Dockerfile                 # Docker configuration
├── docker-compose.yml         # Docker Compose setup
├── knowledge_base/            # Security recipes for RAG
│   ├── CWE-89-sql-injection.txt
│   ├── CWE-79-xss.txt
│   ├── CWE-22-path-traversal.txt
│   ├── CWE-78-command-injection.txt
│   ├── CWE-798-hardcoded-credentials.txt
│   └── CWE-502-deserialization.txt
└── README.md                  # This file
```

## 🚀 Installation

### Prerequisites

- Python 3.10 or higher
- **Automatic GPU/CPU detection** - works on any hardware
- **GPU (CUDA)**: Automatically uses fast inference (~2-3 seconds)
- **CPU only**: Automatically falls back (~10-30 seconds per request)
- 8GB+ RAM (16GB recommended for larger models)

### Quick Start

```bash
# Check what hardware will be detected
python check_device.py

# Install dependencies
pip install -r requirements.txt

# Start the service (automatically detects GPU or CPU)
python main.py
```

The service **automatically detects** your hardware and uses optimal settings:
- **GPU available**: Uses CUDA + 4-bit quantization (fast)
- **CPU only**: Automatically falls back to CPU mode (works, but slower)

First run will download the model (~3GB, takes 5-10 minutes).

### 🔄 Automatic Hardware Detection

The service **automatically adapts** to your hardware:

| Your Hardware | Auto-Detected Config | Performance |
|---------------|---------------------|-------------|
| **NVIDIA GPU + CUDA** | Device: `cuda`, 4-bit quantization, FP16 | ⚡ Fast (1-3s) |
| **CPU only** | Device: `cpu`, No quantization, FP32 | ⏱️ Slower (10-30s) |

**No configuration needed!** The service detects and optimizes automatically.

## ⚙️ Configuration

**Most users don't need to change anything!** The service auto-detects your hardware.

Optional environment variables for customization:

```bash
# Model Configuration (auto-optimizes based on hardware)
export MODEL_NAME=Qwen/Qwen2.5-Coder-1.5B-Instruct  # Default model
export DEVICE=auto                                   # auto (recommended), cuda, or cpu
export USE_4BIT=true                                 # Auto-disabled on CPU
export TEMPERATURE=0.3                               # Sampling temperature

# RAG Configuration
export ENABLE_RAG=true                               # Enable RAG system
export KNOWLEDGE_BASE_PATH=./knowledge_base          # Path to security recipes
export RAG_TOP_K=3                                   # Number of documents to retrieve

# API Configuration
export HOST=0.0.0.0
export PORT=8000
export LOG_LEVEL=INFO
```

### Hardware-Specific Optimization (Optional)

**CPU users** can optionally use a smaller model for faster inference:
```bash
export MODEL_NAME=Qwen/Qwen2.5-Coder-0.5B-Instruct  # Smaller = faster on CPU
export MAX_LENGTH=1024  # Reduce context window
```

Supported models: Qwen/Qwen2.5-Coder-1.5B-Instruct, deepseek-ai/deepseek-coder-1.3b-instruct, bigcode/starcoder2-3b, codellama/CodeLlama-7b-Instruct-hf

## 📖 Usage

### Start the Server

```bash
python main.py
```

Server will start at `http://localhost:8000`. Check health:

```bash
curl http://localhost:8000/health
```

## 📡 API Documentation

### Endpoints

#### `GET /`
Root endpoint with service information.

#### `GET /health`
Health check endpoint returns model and RAG status.

#### `POST /local_fix`
Main code remediation endpoint.

**Request:**
```json
{
  "language": "python",
  "cwe": "CWE-89",
  "vulnerable_code": "query = 'SELECT * FROM users WHERE id=' + user_id",
  "use_rag": true
}
```

**Response:**
```json
{
  "fixed_code": "query = 'SELECT * FROM users WHERE id=?'\ncursor.execute(query, (user_id,))",
  "diff": "--- vulnerable.code\n+++ fixed.code\n...",
  "explanation": "The code was vulnerable to SQL injection...",
  "model_name": "Qwen/Qwen2.5-Coder-1.5B-Instruct",
  "input_tokens": 245,
  "output_tokens": 89,
  "total_tokens": 334,
  "latency_ms": 1847.3
}
```

### Supported CWEs

CWE-79 (XSS), CWE-89 (SQL Injection), CWE-22 (Path Traversal), CWE-78 (Command Injection), CWE-798 (Hard-coded Credentials), CWE-502 (Deserialization), CWE-434 (File Upload), CWE-306/287 (Authentication), CWE-20 (Input Validation), CWE-200 (Information Disclosure)

## 🧪 Testing

### Run Test Suite

```bash
python test_local.py
```

Tests 6+ vulnerability scenarios and displays fixes, diffs, explanations, and performance metrics. Results saved to `test_results.json`.

## 🔍 RAG System

The RAG system enhances fix quality using FAISS vector search over security best practices stored in `knowledge_base/`. Each CWE file contains vulnerability descriptions, remediation techniques, and code examples.

**Adding Custom Recipes**: Create `.txt` or `.md` files in `knowledge_base/` with CWE-XXX in the filename.

## 🐳 Docker Deployment

```bash
# Build and run
docker-compose up -d

# Check logs
docker-compose logs -f

# Stop
docker-compose down
```

## ⚡ Performance

**Benchmarks** (Qwen2.5-Coder-1.5B, 4-bit):
- Average Latency: 1.5-2.5s
- Memory Usage: ~4GB
- GPU Utilization: 30-50%

## 🎓 Architecture

- **main.py**: FastAPI REST API with request/response schemas
- **app.py**: Core AI logic including:
  - Configuration management
  - CWE-specific prompt templates
  - Utility functions (diff generation, code extraction)
  - RAG service (FAISS indexing, retrieval)
  - Model service (LLM loading, inference, 4-bit quantization)
  - Main remediation function orchestrating all components
- **test_local.py**: Integration tests for multiple vulnerabilities
- **knowledge_base/**: Security remediation recipes for RAG

## 🔧 Troubleshooting

**Out of Memory**: Use smaller model or enable 4-bit quantization (`export USE_4BIT=true`)

**Slow Inference on CPU**: 
- CPU inference takes 10-30 seconds (expected behavior)
- Use smaller model: `export MODEL_NAME=Qwen/Qwen2.5-Coder-0.5B-Instruct`
- Or use cloud GPU: Google Colab, AWS, Azure

**4-bit Quantization Error on CPU**: 
- 4-bit quantization requires CUDA
- Service will automatically fall back to FP32 on CPU
- Set `USE_4BIT=false` to suppress warnings

**Check GPU Availability**: 
```bash
python check_device.py  # Shows CUDA status and recommendations
python -c "import torch; print(torch.cuda.is_available())"
```

**RAG Not Working**: Install FAISS (`pip install faiss-cpu`) and check knowledge_base/ exists

**Thank You**
