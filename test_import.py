# test_import.py
print("Testing imports...")

try:
    from src.defense_system import DefenseSystem
    print("✓ Successfully imported DefenseSystem")
except ImportError as e:
    print(f"✗ Failed to import DefenseSystem: {e}")

try:
    import yaml
    print("✓ Successfully imported yaml")
except ImportError as e:
    print(f"✗ Failed to import yaml: {e}")

print("\nAll imports test completed!")