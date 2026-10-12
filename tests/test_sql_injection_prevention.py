"""
Tests for SQL injection prevention in storage_utils and debug_storage_action
"""
import pytest
import tempfile
import os
from utils.storage_utils import (
    validate_sql_identifier,
    SQLiteProvider,
    StorageHandler,
    TableSchema
)


class TestValidateSqlIdentifier:
    """Test the SQL identifier validation function"""
    
    def test_valid_identifiers(self):
        """Valid identifiers should pass"""
        assert validate_sql_identifier("table1") is True
        assert validate_sql_identifier("my_table") is True
        assert validate_sql_identifier("_private") is True
        assert validate_sql_identifier("Table123") is True
        assert validate_sql_identifier("user_data") is True
        assert validate_sql_identifier("a") is True
    
    def test_invalid_identifiers_special_chars(self):
        """Identifiers with special characters should fail"""
        assert validate_sql_identifier("table; DROP TABLE users") is False
        assert validate_sql_identifier("table-name") is False
        assert validate_sql_identifier("table name") is False
        assert validate_sql_identifier("table'name") is False
        assert validate_sql_identifier("table\"name") is False
        assert validate_sql_identifier("table`name") is False
        assert validate_sql_identifier("table$name") is False
        assert validate_sql_identifier("1table") is False  # Can't start with digit
    
    def test_empty_and_none(self):
        """Empty and None values should fail"""
        assert validate_sql_identifier("") is False
        assert validate_sql_identifier(None) is False
    
    def test_sql_keywords(self):
        """SQL keywords should be rejected"""
        assert validate_sql_identifier("SELECT") is False
        assert validate_sql_identifier("select") is False
        assert validate_sql_identifier("DROP") is False
        assert validate_sql_identifier("TABLE") is False
        assert validate_sql_identifier("DELETE") is False
        assert validate_sql_identifier("INSERT") is False
        assert validate_sql_identifier("UPDATE") is False
        assert validate_sql_identifier("FROM") is False
        assert validate_sql_identifier("WHERE") is False


class TestSQLiteProviderSQLInjection:
    """Test that SQLiteProvider prevents SQL injection"""
    
    @pytest.fixture
    def temp_db(self):
        """Create a temporary database for testing"""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as f:
            db_path = f.name
        yield db_path
        if os.path.exists(db_path):
            os.unlink(db_path)
    
    @pytest.fixture
    def provider(self, temp_db):
        """Create a SQLiteProvider instance"""
        return SQLiteProvider(temp_db)
    
    def test_reset_table_rejects_injection(self, provider, temp_db):
        """reset_table should reject malicious table names"""
        # Try to inject SQL via table name
        malicious_names = [
            "users; DROP TABLE users",
            "users' OR '1'='1",
            "users\" OR \"1\"=\"1",
            "users` OR `1`=`1",
            "users -- comment",
        ]
        
        for malicious_name in malicious_names:
            result = provider.reset_table(malicious_name)
            assert result is False, f"Should reject malicious table name: {malicious_name}"
    
    def test_reset_table_accepts_valid_name(self, provider, temp_db):
        """reset_table should accept valid table names"""
        # Create a table first
        schema = TableSchema(
            name="test_table",
            columns=[{"name": "id", "type": "INTEGER PRIMARY KEY"}]
        )
        assert provider.init_tables([schema]) is True
        
        # Should successfully reset valid table
        result = provider.reset_table("test_table")
        assert result is True
    
    def test_init_tables_rejects_malicious_table_name(self, provider, temp_db):
        """init_tables should reject malicious table names"""
        malicious_schema = TableSchema(
            name="users; DROP TABLE users",
            columns=[{"name": "id", "type": "INTEGER PRIMARY KEY"}]
        )
        
        result = provider.init_tables([malicious_schema])
        assert result is False
    
    def test_init_tables_rejects_malicious_column_name(self, provider, temp_db):
        """init_tables should reject malicious column names"""
        malicious_schema = TableSchema(
            name="test_table",
            columns=[{"name": "id; DROP TABLE test_table", "type": "INTEGER PRIMARY KEY"}]
        )
        
        result = provider.init_tables([malicious_schema])
        assert result is False
    
    def test_init_tables_rejects_malicious_index_column(self, provider, temp_db):
        """init_tables should reject malicious index column names"""
        malicious_schema = TableSchema(
            name="test_table",
            columns=[{"name": "id", "type": "INTEGER PRIMARY KEY"}],
            indexes=["id; DROP TABLE test_table"]
        )
        
        result = provider.init_tables([malicious_schema])
        assert result is False


class TestStorageHandlerSQLInjection:
    """Test that StorageHandler prevents SQL injection"""
    
    @pytest.fixture
    def temp_db(self):
        """Create a temporary database for testing"""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as f:
            db_path = f.name
        yield db_path
        if os.path.exists(db_path):
            os.unlink(db_path)
    
    @pytest.fixture
    def mock_config(self, temp_db):
        """Create a mock config object"""
        class MockConfig:
            def get_option(self, section, key):
                if section == 'DEFAULT' and key == 'user_db':
                    return temp_db
                return None
        return MockConfig()
    
    @pytest.fixture
    def handler(self, mock_config):
        """Create a StorageHandler instance"""
        return StorageHandler(mock_config)
    
    def test_reset_table_rejects_injection(self, handler):
        """reset_table should reject malicious table names"""
        malicious_names = [
            "keyvalue; DROP TABLE keyvalue",
            "keyvalue' OR '1'='1",
            "keyvalue\" OR \"1\"=\"1",
        ]
        
        for malicious_name in malicious_names:
            result = handler.reset_table(malicious_name)
            assert result is False, f"Should reject malicious table name: {malicious_name}"


class TestDebugStorageActionSQLInjection:
    """Test that DebugStorageAction prevents SQL injection"""
    
    @pytest.fixture
    def temp_db(self):
        """Create a temporary database for testing"""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as f:
            db_path = f.name
        yield db_path
        if os.path.exists(db_path):
            os.unlink(db_path)
    
    @pytest.fixture
    def mock_config(self, temp_db):
        """Create a mock config object"""
        class MockConfig:
            def get_option(self, section, key):
                if section == 'DEFAULT' and key == 'user_db':
                    return temp_db
                return None
        return MockConfig()
    
    @pytest.fixture
    def mock_session(self, mock_config):
        """Create a mock session object"""
        class MockStorage:
            def __init__(self, config):
                self.provider = SQLiteProvider(config.get_option('DEFAULT', 'user_db'))
                # Initialize keyvalue table
                self.provider.init_tables([
                    TableSchema(
                        name="keyvalue",
                        columns=[
                            {"name": "key", "type": "TEXT PRIMARY KEY"},
                            {"name": "value", "type": "TEXT"},
                            {"name": "updated_at", "type": "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"}
                        ]
                    )
                ])
            
            def reset_table(self, table_name):
                return self.provider.reset_table(table_name)
            
            def set(self, key, value):
                return self.provider.set(key, value)
            
            def get(self, key):
                return self.provider.get(key)
            
            def list_keys(self):
                return self.provider.list_keys()
        
        class MockUtils:
            def __init__(self, config):
                self.storage = MockStorage(config)
                self.tab_completion = MockTabCompletion()
        
        class MockTabCompletion:
            def set_session(self, session):
                pass
            def run(self, mode):
                pass
        
        class MockSession:
            def __init__(self, config):
                self.utils = MockUtils(config)
        
        return MockSession(mock_config)
    
    def test_validate_before_use_command(self, mock_session):
        """The 'use' command should validate table names"""
        from examples.user_actions.debug_storage_action import DebugStorageAction
        
        action = DebugStorageAction(mock_session)
        
        # Try malicious table name
        malicious_names = [
            "keyvalue; DROP TABLE keyvalue",
            "keyvalue' OR '1'='1",
        ]
        
        for malicious_name in malicious_names:
            # Should reject the malicious name
            action.handle_table_selection(["use", malicious_name])
            # current_table should not be changed
            assert action.current_table == "keyvalue"
    
    def test_validate_before_show_command(self, mock_session):
        """The 'show' command should validate table names"""
        from examples.user_actions.debug_storage_action import DebugStorageAction
        
        action = DebugStorageAction(mock_session)
        
        # Try malicious table name
        malicious_name = "keyvalue; DROP TABLE keyvalue"
        
        # Should not raise an exception
        action.handle_table_command(["show", malicious_name])
    
    def test_validate_before_clear_command(self, mock_session):
        """The 'clear' command should validate table names"""
        from examples.user_actions.debug_storage_action import DebugStorageAction
        
        action = DebugStorageAction(mock_session)
        
        # Try malicious table name
        malicious_name = "keyvalue; DROP TABLE keyvalue"
        
        # Should not raise an exception
        action.handle_table_command(["clear", malicious_name])
    
    def test_validate_before_count_command(self, mock_session):
        """The 'count' command should validate table names"""
        from examples.user_actions.debug_storage_action import DebugStorageAction
        
        action = DebugStorageAction(mock_session)
        
        # Try malicious table name
        malicious_name = "keyvalue; DROP TABLE keyvalue"
        
        # Should not raise an exception
        action.handle_table_command(["count", malicious_name])
    
    def test_validate_column_in_find_command(self, mock_session):
        """The 'find' command should validate column names"""
        from examples.user_actions.debug_storage_action import DebugStorageAction
        
        action = DebugStorageAction(mock_session)
        
        # Try malicious column name
        malicious_column = "key; DROP TABLE keyvalue"
        
        # Should not raise an exception
        action.handle_row_command(["find", malicious_column, "value"])


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
