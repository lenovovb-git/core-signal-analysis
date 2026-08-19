"""
历史案例库模块 - 基于SQLite的案例存储和检索
"""
import sqlite3
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
import logging

from .config import settings


logger = logging.getLogger(__name__)


class CaseStore:
    """历史案例库"""
    
    def __init__(self, db_path: Optional[str] = None):
        """
        初始化案例库
        
        Args:
            db_path: SQLite数据库路径
        """
        self.db_path = str(Path(db_path)) if db_path else settings.case_db_path
        self._ensure_db()
    
    def _ensure_db(self) -> None:
        """确保数据库和表存在"""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cases (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    domain TEXT,
                    protocol TEXT,
                    procedure_name TEXT,
                    message_type TEXT,
                    cause_category TEXT,
                    cause_value TEXT,
                    symptoms TEXT,
                    root_cause TEXT,
                    solution TEXT,
                    evidence TEXT,
                    tags TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)
            conn.commit()
    
    def save_case(self, case_data: Dict[str, Any]) -> int:
        """
        保存案例
        
        Args:
            case_data: 案例数据
            
        Returns:
            案例ID
        """
        now = datetime.now().isoformat()
        
        # 处理tags字段（列表转JSON字符串）
        tags = case_data.get("tags", [])
        if isinstance(tags, list):
            tags = json.dumps(tags, ensure_ascii=False)
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                """INSERT INTO cases 
                (title, domain, protocol, procedure_name, message_type,
                 cause_category, cause_value, symptoms, root_cause, solution,
                 evidence, tags, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    case_data.get("title", ""),
                    case_data.get("domain", ""),
                    case_data.get("protocol", ""),
                    case_data.get("procedure_name", ""),
                    case_data.get("message_type", ""),
                    case_data.get("cause_category", ""),
                    case_data.get("cause_value", ""),
                    case_data.get("symptoms", ""),
                    case_data.get("root_cause", ""),
                    case_data.get("solution", ""),
                    case_data.get("evidence", ""),
                    tags,
                    now,
                    now,
                )
            )
            conn.commit()
            case_id = cursor.lastrowid
            logger.info(f"案例已保存，ID: {case_id}")
            return case_id
    
    def search_cases(
        self,
        protocol: Optional[str] = None,
        procedure_name: Optional[str] = None,
        cause_category: Optional[str] = None,
        cause_value: Optional[str] = None,
        keyword: Optional[str] = None,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """
        检索相似案例
        
        Args:
            protocol: 协议
            procedure_name: 流程名
            cause_category: Cause类别
            cause_value: Cause值
            keyword: 关键词
            limit: 返回数量限制
            
        Returns:
            案例列表
        """
        conditions = []
        params = []
        
        if protocol:
            conditions.append("protocol = ?")
            params.append(protocol)
        
        if procedure_name:
            conditions.append("procedure_name = ?")
            params.append(procedure_name)
        
        if cause_category:
            conditions.append("cause_category = ?")
            params.append(cause_category)
        
        if cause_value:
            conditions.append("cause_value = ?")
            params.append(cause_value)
        
        if keyword:
            conditions.append(
                "(title LIKE ? OR symptoms LIKE ? OR root_cause LIKE ? OR solution LIKE ?)"
            )
            kw = f"%{keyword}%"
            params.extend([kw, kw, kw, kw])
        
        where_clause = " AND ".join(conditions) if conditions else "1=1"
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                f"SELECT * FROM cases WHERE {where_clause} ORDER BY updated_at DESC LIMIT ?",
                params + [limit]
            )
            rows = cursor.fetchall()
        
        cases = []
        for row in rows:
            case = dict(row)
            # 反向转换tags
            try:
                case["tags"] = json.loads(case.get("tags", "[]")) if case.get("tags") else []
            except (json.JSONDecodeError, TypeError):
                case["tags"] = []
            cases.append(case)
        
        return cases
    
    def search_similar(
        self,
        normalized_packet: Dict[str, Any],
        limit: int = 5
    ) -> List[Dict[str, Any]]:
        """
        根据标准化报文搜索相似案例
        
        Args:
            normalized_packet: 标准化后的报文
            limit: 返回数量限制
            
        Returns:
            匹配的案例列表
        """
        protocol = normalized_packet.get("protocol")
        procedure = normalized_packet.get("procedure")
        cause_category = normalized_packet.get("cause_category")
        cause_value = normalized_packet.get("cause_value")
        
        # 先精确匹配
        cases = self.search_cases(
            protocol=protocol,
            procedure_name=procedure,
            cause_category=cause_category,
            cause_value=cause_value,
            limit=limit
        )
        
        # 如果匹配太少，放宽条件
        if len(cases) < 2 and cause_category:
            cases = self.search_cases(
                protocol=protocol,
                procedure_name=procedure,
                cause_category=cause_category,
                limit=limit
            )
        
        # 还是太少，只匹配协议
        if len(cases) < 2 and protocol:
            cases = self.search_cases(
                protocol=protocol,
                limit=limit
            )
        
        return cases
    
    def get_case(self, case_id: int) -> Optional[Dict[str, Any]]:
        """获取单个案例"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,))
            row = cursor.fetchone()
        
        if row:
            case = dict(row)
            try:
                case["tags"] = json.loads(case.get("tags", "[]"))
            except (json.JSONDecodeError, TypeError):
                case["tags"] = []
            return case
        return None
    
    def list_cases(self, offset: int = 0, limit: int = 20) -> List[Dict[str, Any]]:
        """列出所有案例"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                "SELECT id, title, protocol, procedure_name, cause_category, cause_value, created_at FROM cases ORDER BY updated_at DESC LIMIT ? OFFSET ?",
                (limit, offset)
            )
            rows = cursor.fetchall()
        
        return [dict(row) for row in rows]
    
    def count_cases(self) -> int:
        """统计案例总数"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT COUNT(*) FROM cases")
            return cursor.fetchone()[0]
    
    def delete_case(self, case_id: int) -> bool:
        """删除案例"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("DELETE FROM cases WHERE id = ?", (case_id,))
            conn.commit()
            return cursor.rowcount > 0
    
    def update_case(self, case_id: int, case_data: Dict[str, Any]) -> bool:
        """更新案例"""
        case_data["updated_at"] = datetime.now().isoformat()
        
        update_fields = []
        params = []
        
        for field in ["title", "domain", "protocol", "procedure_name", "message_type",
                       "cause_category", "cause_value", "symptoms", "root_cause",
                       "solution", "evidence", "tags", "updated_at"]:
            if field in case_data:
                value = case_data[field]
                if field == "tags" and isinstance(value, list):
                    value = json.dumps(value, ensure_ascii=False)
                update_fields.append(f"{field} = ?")
                params.append(value)
        
        if not update_fields:
            return False
        
        params.append(case_id)
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                f"UPDATE cases SET {', '.join(update_fields)} WHERE id = ?",
                params
            )
            conn.commit()
            return cursor.rowcount > 0