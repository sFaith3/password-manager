def test_import():
    try:
        import PasswordManager
    except ImportError:
        assert False, "Failed to import PasswordManager"
