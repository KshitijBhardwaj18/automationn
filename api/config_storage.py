import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

from api.models import CustomerConfigResolved
from api.settings import settings


class ConfigStorageBackend(ABC):
    @abstractmethod
    def save(self, customer_id: str, config: CustomerConfigResolved) -> None:
        """Save a customer configuration."""
        pass

    @abstractmethod
    def get(self, customer_id: str) -> Optional[CustomerConfigResolved]:
        """Retrieve a customer configuration."""
        pass

    @abstractmethod
    def delete(self, customer_id: str) -> bool:
        """Delete a customer configuration."""
        pass

    @abstractmethod
    def list_all(self) -> list[CustomerConfigResolved]:
        """List all customer configurations."""
        pass

    @abstractmethod
    def exists(self, customer_id: str) -> bool:
        """Check if a customer configuration exists."""
        pass


class FileConfigStorage(ConfigStorageBackend):
    """File-based configuration storage using JSON files."""

    def __init__(self, base_path: str = "config") -> None:
        """Initialize file-based storage."""
        self.base_path = Path(base_path)
        self.base_path.mkdir(parents=True, exist_ok=True)

    def _get_config_path(self, customer_id: str) -> Path:
        """Get the file path for a customer's configuration."""
        return self.base_path / f"{customer_id}.json"

    def save(self, customer_id: str, config: CustomerConfigResolved) -> None:
        """Save a customer configuration to a JSON file."""
        config_path = self._get_config_path(customer_id)
        config_data = config.model_dump(mode="json")
        config_path.write_text(json.dumps(config_data, indent=2, default=str))

    def get(self, customer_id: str) -> Optional[CustomerConfigResolved]:
        """Retrieve a customer configuration from file."""
        config_path = self._get_config_path(customer_id)
        if not config_path.exists():
            return None

        config_data = json.loads(config_path.read_text())
        return CustomerConfigResolved.model_validate(config_data)

    def delete(self, customer_id: str) -> bool:
        """Delete a customer configuration file."""
        config_path = self._get_config_path(customer_id)
        if not config_path.exists():
            return False

        config_path.unlink()
        return True

    def list_all(self) -> list[CustomerConfigResolved]:
        """List all customer configurations from files."""
        configs: list[CustomerConfigResolved] = []
        for config_file in self.base_path.glob("*.json"):
            try:
                config_data = json.loads(config_file.read_text())
                configs.append(CustomerConfigResolved.model_validate(config_data))
            except (json.JSONDecodeError, ValueError):
                continue
        return configs

    def exists(self, customer_id: str) -> bool:
        """Check if a customer configuration file exists."""
        return self._get_config_path(customer_id).exists()


config_storage = FileConfigStorage(base_path=settings.config_storage_path)
