"""
配置文件管理
"""
import os
from pathlib import Path
from typing import Optional
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    """应用配置"""
    
    # LLM配置
    llm_provider: str = Field("openai_compatible")
    llm_base_url: str = Field("https://api.openai.com/v1")
    llm_model: str = Field("gpt-4o-mini")
    llm_api_key: str = Field("")
    
    # 本地配置
    tshark_path: str = Field("/usr/local/bin/tshark")
    default_window: int = Field(20)
    case_db_path: str = Field("data/cases.sqlite")
    
    # 项目路径
    project_root: Path = Path(__file__).parent.parent
    knowledge_dir: Path = project_root / "knowledge"
    rules_dir: Path = knowledge_dir / "rules"
    protocol_fields_dir: Path = knowledge_dir / "protocol_fields"
    data_dir: Path = project_root / "data"
    
    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8"
    }


# 全局配置实例
settings = Settings()


def get_llm_config() -> dict:
    """获取LLM配置"""
    return {
        "provider": settings.llm_provider,
        "base_url": settings.llm_base_url,
        "model": settings.llm_model,
        "api_key": settings.llm_api_key,
    }


def ensure_directories() -> None:
    """确保必要的目录存在"""
    directories = [
        settings.data_dir,
        settings.rules_dir,
        settings.protocol_fields_dir,
    ]
    
    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)