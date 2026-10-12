from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Dict, Any, Optional
import sqlite3
import os
import re


def validate_sql_identifier(name: str, identifier_type: str = "identifier") -> bool:
    """
    Validate that a SQL identifier (table name, column name) is safe.
    
    Prevents SQL injection by ensuring identifiers only contain alphanumeric
    characters and underscores, and don't start with a digit.
    
    Args:
        name: The identifier to validate
        identifier_type: Description for error messages (e.g., "table name", "column name")
    
    Returns:
        True if valid, False otherwise
    """
    if not name or not isinstance(name, str):
        return False
    
    # SQL identifiers must:
    # - Start with a letter or underscore
    # - Contain only letters, digits, and underscores
    # - Not be a SQL keyword (basic check)
    if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', name):
        return False
    
    # Basic SQL keyword check (not exhaustive but catches common ones)
    sql_keywords = {
        'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE', 'ALTER',
        'TABLE', 'INDEX', 'FROM', 'WHERE', 'AND', 'OR', 'NOT', 'NULL',
        'TRUE', 'FALSE', 'IN', 'LIKE', 'BETWEEN', 'EXISTS', 'UNION',
        'JOIN', 'INNER', 'LEFT', 'RIGHT', 'OUTER', 'ON', 'AS', 'ORDER',
        'BY', 'GROUP', 'HAVING', 'LIMIT', 'OFFSET', 'VALUES', 'SET',
        'INTO', 'PRIMARY', 'KEY', 'FOREIGN', 'REFERENCES', 'CONSTRAINT'
    }
    
    if name.upper() in sql_keywords:
        return False
    
    return True


@dataclass
class TableSchema:
    name: str
    columns: List[Dict[str, str]]  # List of {name: str, type: str} dicts
    indexes: Optional[List[str]] = None


class StorageProvider(ABC):
    @abstractmethod
    def init_tables(self, schemas: List[TableSchema]) -> bool:
        pass

    @abstractmethod
    def reset_table(self, table_name: str) -> bool:
        pass

    @abstractmethod
    def execute(self, query: str, params: tuple = None) -> Any:
        pass

    @abstractmethod
    def execute_insert(self, query: str, params: tuple = None) -> Optional[int]:
        """
        Execute an INSERT and return the database-assigned row id if available.
        Returns None on failure.
        """
        pass


class SQLiteProvider(StorageProvider):
    def __init__(self, db_path: str, output_handler: Optional[Any] = None):
        self.db_path = os.path.expanduser(db_path)
        self.output = output_handler
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

    def init_tables(self, schemas: List[TableSchema]) -> bool:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                for schema in schemas:
                    # Validate table name
                    if not validate_sql_identifier(schema.name, "table name"):
                        if self.output:
                            self.output.error(f"Invalid table name: {schema.name}")
                        return False
                    
                    # Validate and build column definitions
                    col_defs = []
                    for col in schema.columns:
                        if not validate_sql_identifier(col['name'], "column name"):
                            if self.output:
                                self.output.error(f"Invalid column name: {col['name']}")
                            return False
                        col_defs.append(f"{col['name']} {col['type']}")
                    
                    query = f"CREATE TABLE IF NOT EXISTS {schema.name} ({', '.join(col_defs)})"
                    cursor.execute(query)

                    if schema.indexes:
                        for idx in schema.indexes:
                            if not validate_sql_identifier(idx, "index column"):
                                if self.output:
                                    self.output.error(f"Invalid index column: {idx}")
                                return False
                            cursor.execute(f"CREATE INDEX IF NOT EXISTS idx_{schema.name}_{idx} ON {schema.name}({idx})")
                return True
        except sqlite3.Error as e:
            if self.output:
                self.output.error(f"Database error creating tables: {str(e)}")
            return False

    def reset_table(self, table_name: str) -> bool:
        # Validate table name to prevent SQL injection
        if not validate_sql_identifier(table_name, "table name"):
            if self.output:
                self.output.error(f"Invalid table name: {table_name}")
            return False
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(f"DELETE FROM {table_name}")
                return True
        except sqlite3.Error as e:
            if self.output:
                self.output.error(f"Database error resetting table: {str(e)}")
            return False

    def execute(self, query: str, params: tuple = None) -> Any:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                if params:
                    cursor.execute(query, params)
                else:
                    cursor.execute(query)
                conn.commit()
                return cursor.fetchall()
        except sqlite3.Error as e:
            if self.output:
                self.output.error(f"Database error executing query: {str(e)}")
            return None

    def execute_insert(self, query: str, params: tuple = None) -> Optional[int]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                if params:
                    cursor.execute(query, params)
                else:
                    cursor.execute(query)
                conn.commit()
                return cursor.lastrowid
        except sqlite3.Error as e:
            if self.output:
                self.output.error(f"Database error executing insert: {str(e)}")
            return None


class StorageHandler:
    """
    Handles data storage operations like key-value persistence and table management.
    """

    def __init__(self, config: Any, output_handler: Optional[Any] = None) -> None:
        """
        Initialize storage handler with user configuration.
        """
        self.config = config
        self.output = output_handler
        self.provider = SQLiteProvider(
            config.get_option('DEFAULT', 'user_db'),
            output_handler
        )
        self._init_core_schema()

    def _init_core_schema(self):
        core_schemas = [
            TableSchema(
                name="keyvalue",
                columns=[
                    {"name": "key", "type": "TEXT PRIMARY KEY"},
                    {"name": "value", "type": "TEXT"},
                    {"name": "updated_at", "type": "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"}
                ]
            )
        ]
        self.provider.init_tables(core_schemas)

    def register_schema(self, schema: TableSchema) -> bool:
        """
        Register a new table schema.

        Args:
            schema: TableSchema defining the table structure

        Returns:
            True if successful, False on failure
        """
        return self.provider.init_tables([schema])

    def reset_table(self, table_name: str) -> bool:
        """
        Clear all data from a table.

        Args:
            table_name: Name of table to reset

        Returns:
            True if successful, False on failure
        """
        return self.provider.reset_table(table_name)

    def set(self, key: str, value: str) -> bool:
        """
        Store or update a key-value pair.

        Args:
            key: Storage key
            value: Value to store

        Returns:
            True if successful, False on failure
        """
        query = """
            INSERT OR REPLACE INTO keyvalue (key, value, updated_at)
            VALUES (?, ?, CURRENT_TIMESTAMP)
        """
        # execute() returns [] on success for DML, which is falsy; treat non-None as success
        return self.provider.execute(query, (key, value)) is not None

    def get(self, key: str) -> Optional[str]:
        """
        Retrieve a value by key.

        Args:
            key: Storage key

        Returns:
            Stored value or None if not found
        """
        result = self.provider.execute(
            "SELECT value FROM keyvalue WHERE key = ?",
            (key,)
        )
        return result[0][0] if result else None

    def delete(self, key: str) -> bool:
        """
        Delete a key-value pair.

        Args:
            key: Storage key to delete

        Returns:
            True if successful, False on failure
        """
        # execute() returns [] on success for DML, which is falsy; treat non-None as success
        return self.provider.execute(
            "DELETE FROM keyvalue WHERE key = ?",
            (key,)
        ) is not None

    def list_keys(self) -> List[str]:
        """
        List all stored keys.

        Returns:
            List of stored keys
        """
        result = self.provider.execute(
            "SELECT key FROM keyvalue ORDER BY key"
        )
        return [row[0] for row in result] if result else []
