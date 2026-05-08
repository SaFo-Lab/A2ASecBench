from __future__ import annotations

import importlib

from sut.base import A2ASecuritySUT, ComparatorSUT, SelectorSUT


def _parse_path(path: str) -> tuple[str, str]:
    if ":" not in path:
        raise ValueError(f"Invalid class path '{path}'. Expected format 'module.submodule:ClassName'.")
    module_name, class_name = path.split(":", 1)
    if not module_name or not class_name:
        raise ValueError(f"Invalid class path '{path}'. Expected format 'module.submodule:ClassName'.")
    return module_name, class_name


def _load_class(path: str):
    module_name, class_name = _parse_path(path)
    try:
        module = importlib.import_module(module_name)
    except Exception as exc:
        raise ImportError(f"Failed to import module for '{path}': {exc}") from exc

    if not hasattr(module, class_name):
        available = sorted(name for name in dir(module) if not name.startswith("__"))
        raise AttributeError(
            f"Class '{class_name}' not found in module '{module_name}' for '{path}'. "
            f"Available attributes: {available}"
        )
    return getattr(module, class_name)


def load_selector(path: str, **kwargs) -> SelectorSUT:
    cls = _load_class(path)
    try:
        instance = cls(**kwargs)
    except Exception as exc:
        raise TypeError(f"Failed to instantiate selector '{path}' with kwargs={kwargs}: {exc}") from exc
    if not isinstance(instance, SelectorSUT):
        raise TypeError(
            f"Loaded object from '{path}' is not a SelectorSUT. "
            f"Expected {SelectorSUT.__name__}, got {type(instance).__name__}."
        )
    return instance


def load_comparator(path: str, **kwargs) -> ComparatorSUT:
    cls = _load_class(path)
    try:
        instance = cls(**kwargs)
    except Exception as exc:
        raise TypeError(f"Failed to instantiate comparator '{path}' with kwargs={kwargs}: {exc}") from exc
    if not isinstance(instance, ComparatorSUT):
        raise TypeError(
            f"Loaded object from '{path}' is not a ComparatorSUT. "
            f"Expected {ComparatorSUT.__name__}, got {type(instance).__name__}."
        )
    return instance


def load_a2a_security(path: str, **kwargs) -> A2ASecuritySUT:
    cls = _load_class(path)
    try:
        instance = cls(**kwargs)
    except Exception as exc:
        raise TypeError(f"Failed to instantiate A2A security SUT '{path}' with kwargs={kwargs}: {exc}") from exc
    if not isinstance(instance, A2ASecuritySUT):
        raise TypeError(
            f"Loaded object from '{path}' is not an A2ASecuritySUT. "
            f"Expected {A2ASecuritySUT.__name__}, got {type(instance).__name__}."
        )
    return instance
