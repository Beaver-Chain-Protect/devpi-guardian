from importlib import metadata


def test_package_exposes_devpi_server_entry_point() -> None:
    matches = [
        entry_point
        for entry_point in metadata.entry_points(group="devpi_server")
        if entry_point.name == "guardian"
    ]

    assert len(matches) == 1
    assert matches[0].value == "devpi_guardian.plugin"
