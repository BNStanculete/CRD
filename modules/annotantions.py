# Copyright 2025 Bogdan Stanculete. All Rights Reserved.

def singleton(cls):
    """
    Ensure that the annotated class is a Singleton.
    """
    instances = {}

    def get_instance(*args, **kwargs):
        if cls not in instances:
            instances[cls] = cls(*args, **kwargs)
        return instances[cls]

    return get_instance