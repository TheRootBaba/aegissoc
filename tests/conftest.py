from types import SimpleNamespace
from uuid import uuid4
import pytest
from app.core.security import get_current_user
from app.main import app

@pytest.fixture(autouse=True)
def authenticated_test_identity():
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(
        id=uuid4(), username="test-admin", role="admin", is_active=True
    )
    yield
    app.dependency_overrides.pop(get_current_user, None)
