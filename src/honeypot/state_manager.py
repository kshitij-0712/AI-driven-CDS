import logging
from typing import Dict, Any
from interceptor.session_store import SessionStore

logger = logging.getLogger(__name__)

class SessionStateManager:
    def __init__(self, store: SessionStore):
        self.store = store

    def load_state(self, session_id: str) -> Dict[str, Any]:
        """Load persistent session memory for a given session ID."""
        try:
            return self.store.get_session_memory(session_id)
        except Exception as e:
            logger.error(f"Failed to load session memory for {session_id}: {e}")
            return {}

    def save_state(self, session_id: str, new_state: Dict[str, Any]):
        """Save persistent session memory for a given session ID."""
        try:
            self.store.save_session_memory(session_id, new_state)
        except Exception as e:
            logger.error(f"Failed to save session memory for {session_id}: {e}")

    def update_state(self, session_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Merge LLM session updates into the existing session memory and save."""
        current_state = self.load_state(session_id)
        if updates and isinstance(updates, dict):
            for key, val in updates.items():
                if isinstance(val, list) and key in current_state and isinstance(current_state[key], list):
                    # Append unique values for lists (like files/users)
                    current_state[key] = list(set(current_state[key] + val))
                elif isinstance(val, dict) and key in current_state and isinstance(current_state[key], dict):
                    # Merge sub-dictionaries
                    current_state[key].update(val)
                else:
                    current_state[key] = val
            
            self.save_state(session_id, current_state)
            logger.info(f"Updated session state for {session_id}: {updates}")
        return current_state
