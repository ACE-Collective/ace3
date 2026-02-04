import logging
from typing import Dict, Any

from saq.analysis.observable_registry import ObservableRegistry


class ObservableRegistrySerializer:
    """Handles serialization and deserialization of ObservableRegistry to/from JSON."""
    
    @staticmethod
    def serialize(registry: ObservableRegistry) -> dict:
        """
        Serialize an ObservableRegistry to JSON-compatible format.
        
        Args:
            registry: The ObservableRegistry to serialize
            
        Returns:
            Dict containing serialized observable store (uuid -> observable json)
        """
        serialized_store = {}
        for uuid, observable in registry.store.items():
            serialized_store[uuid] = observable.json

        return serialized_store
    
    @staticmethod
    def deserialize(registry: ObservableRegistry, json_data: dict):
        """
        Deserialize dict loaded from JSON into an existing ObservableRegistry.
        
        Args:
            registry: The existing ObservableRegistry to deserialize into.  This is modified in place.
            json_data: Dict containing serialized observable store (uuid -> observable json)
            
        Returns:
            ObservableRegistry instance with loaded observables
        """
        from saq.observables.generator import create_observable_from_dict

        registry.clear()
        
        invalid_uuids = []
        for uuid, observable_json in json_data.items():
            # Create observable from JSON dict
            observable = create_observable_from_dict(observable_json)
            if observable:
                # Set the JSON to restore all properties
                observable.json = observable_json
                # Store in registry
                registry._store[uuid] = observable
            else:
                logging.warning("invalid observable type {} value {}".format(
                    observable_json.get('type'), observable_json.get('value')))
                invalid_uuids.append(uuid)
        
        # Remove any invalid observables that couldn't be loaded
        for uuid in invalid_uuids:
            if uuid in registry._store:
                del registry._store[uuid]

        # Resolve relationship targets from UUID strings to Observable objects
        # This must happen after all observables are loaded into the registry
        for observable in registry.store.values():
            for relationship in observable.relationships:
                # If the target is a string UUID, resolve it to an Observable object
                if isinstance(relationship.target, str):
                    target_observable = registry.get_by_id(relationship.target)
                    if target_observable:
                        relationship.target = target_observable
                    else:
                        logging.warning(f"Could not resolve relationship target UUID {relationship.target} for observable {observable.uuid}")
