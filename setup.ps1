$ErrorActionPreference = "Stop"

Write-Host "[ZERO SETUP] Initializing Zero Suite v1.0 on Windows..." -ForegroundColor Green

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "[ZERO SETUP] Python 3 not found. Installing via winget..." -ForegroundColor Yellow
    winget install -e --id Python.Python.3.12 --accept-package-agreements --accept-source-agreements
}

if (-not (Test-Path ".venv")) {
    Write-Host "[ZERO SETUP] Creating virtual environment (.venv)..." -ForegroundColor Green
    python -m venv .venv
}

$PyBin = ".\\.venv\\Scripts\\python.exe"
& $PyBin -m pip install --upgrade pip
& $PyBin -m pip install -r requirements.txt
& $PyBin -m pip install -e . --no-build-isolation --no-deps

$Mode = Read-Host "Select EmbeddingGemma 2 backend [1=Ollama embeddinggemma-2:270m, 2=HuggingFace sentence-transformers, 3=Lightweight 256d fallback] (default 3)"
if ([string]::IsNullOrWhiteSpace($Mode)) { $Mode = "3" }

switch ($Mode) {
    "1" {
        if (-not (Get-Command ollama -ErrorAction SilentlyContinue)) {
            winget install -e --id Ollama.Ollama --accept-package-agreements --accept-source-agreements
        }
        ollama pull embeddinggemma-2:270m
    }
    "2" {
        & $PyBin -m pip install -r requirements-eg2.txt
        & $PyBin -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('google/embeddinggemma-2', config_kwargs={'vision_config': None, 'audio_config': None})"
    }
    default {
        Write-Host "[ZERO SETUP] Configured zero-dependency 256d local semantic fallback." -ForegroundColor Green
    }
}

& $PyBin Zero-Suite.py --memory-status --accept-policy
Write-Host "[ZERO SETUP] Complete. Run: .\\.venv\\Scripts\\python.exe Zero-Suite.py" -ForegroundColor Green
