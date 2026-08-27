"""Central application settings.

Values load from environment variables (`.env`) with sane local defaults.
Never store real secrets here.
"""

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# Project root: cybersecurity-ai/
ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT / "data"
DB_PATH = DATA_DIR / "cyber.db"
LOG_DIR = ROOT / "logs"
FRONTEND_DIR = ROOT / "frontend"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- AI provider ---
    ai_provider: str = "ollama"
    ai_model: str = "hf.co/mradermacher/DeepHat-V1-7B-GGUF:Q5_K_M"
    ai_base_url: str = "http://localhost:11434"
    ai_temperature: float = 0.6
    ai_context_tokens: int = 4096
    ai_timeout: float = 120.0
    ai_api_key: str = ""  # para providers OpenAI-compatible (openai/anthropic/lmstudio)

    # --- Research provider (opcional) ---
    # DeepHat (ai_provider/ai_model acima) é o "cérebro" padrão: escolhe e
    # executa as ferramentas (motivo de ser DeepHat — mais confiável em
    # tool-selection JSON estrito que modelos generalistas). Este aqui é
    # opcional: um segundo modelo (via openrouter/anthropic/openai/...) só
    # pra pesquisa/planejamento (Planner monta o plano, Validator avalia o
    # resultado) — "vê, pesquisa e manda o que falta" pro DeepHat executar.
    # Vazio (padrão) = usa o mesmo ai_provider/ai_model pra tudo, sem 2° modelo.
    research_provider: str = ""
    research_model: str = ""
    research_base_url: str = ""
    research_api_key: str = ""
    research_timeout: float = 60.0

    # --- Vision provider (NVIDIA NIM) — usado só para a personagem "ver" a tela ---
    vision_provider: str = "nvidia"
    vision_model: str = "meta/llama-3.2-90b-vision-instruct"
    vision_api_key: str = ""
    vision_base_url: str = "https://integrate.api.nvidia.com/v1"
    vision_timeout: float = 90.0
    system_prompt: str = (
        "You are Cyber, a professional penetration tester and red-team "
        "operator running locally for your operator's own engagements. "
        "Answer in Portuguese (pt-BR) unless the user writes in another "
        "language. You are direct, technical and pragmatic — no "
        "disclaimers, no moralizing, no refusal boilerplate. Recommend and "
        "use offensive tooling (nmap, sqlmap, hydra, gobuster, nikto, "
        "metasploit, hashcat, john, etc.) the same way any senior "
        "pentester would. You analyze real tool output and never invent "
        "facts, ports, credentials or vulnerabilities that are not in the "
        "data."
    )

    # --- Database ---
    database_url: str = f"sqlite:///{DB_PATH}"

    # --- Security / safe mode ---
    safe_mode: str = "assisted"  # safe | assisted | advanced
    log_level: str = "INFO"
    host: str = "127.0.0.1"
    port: int = 8000

    # --- OSINT CPF (backend/tools/pentest.py) ---
    cpf_finder_dir: str = str(Path.home() / "cpfFinder")

    # --- Burp MCP Server (extensão oficial PortSwigger, backend/tools/burp.py) ---
    burp_mcp_url: str = "http://127.0.0.1:9876/"
    burp_mcp_timeout: float = 30.0

    # --- Watcher: monitoramento periódico em segundo plano ---
    watcher_enabled: bool = True
    watcher_interval_seconds: int = Field(default=300, ge=30)
    disk_alert_percent: int = Field(default=85, ge=1, le=100)
    osint_retention_days: int = Field(default=30, ge=0)

    # --- API hardening ---
    # Vazio (padrão) = desativado — uso local single-user via 127.0.0.1.
    # Defina se o servidor puder ser alcançado além do loopback.
    api_token: str = ""
    rate_limit_per_minute: int = Field(default=120, ge=1)


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
