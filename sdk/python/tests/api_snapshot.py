"""Record public handwritten signatures and TypedDict shapes from an installation."""

import inspect
import json
import typing

import cigar_sdk


def signature(value):
    try:
        return str(inspect.signature(value))
    except (ValueError, TypeError):
        return None


def snapshot():
    result = {}
    for name in cigar_sdk.__all__:
        value = getattr(cigar_sdk, name)
        row = {"signature": signature(value)}
        if typing.is_typeddict(value):
            row["required"] = sorted(value.__required_keys__)
            row["optional"] = sorted(value.__optional_keys__)
            row["annotations"] = {key: str(item) for key, item in typing.get_type_hints(value).items()}
        elif inspect.isclass(value):
            row["methods"] = {
                method: signature(member)
                for method, member in inspect.getmembers(value, inspect.isfunction)
                if not method.startswith("_")
            }
        result[name] = row
    return {"abi": cigar_sdk.CONTEXT_ABI, "exports": result}


if __name__ == "__main__":
    print(json.dumps(snapshot(), sort_keys=True, indent=2))
