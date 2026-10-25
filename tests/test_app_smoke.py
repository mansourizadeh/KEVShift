"""Dashboard smoke tests: every page renders without errors using the synthetic demo data."""

import pytest
from streamlit.testing.v1 import AppTest

from src import database, demo

APP = str(__import__("pathlib").Path(__file__).resolve().parent.parent / "app.py")
PAGES = ["Overview", "Import scan CSV", "KEV catalog", "Findings", "History", "Help and limitations"]


@pytest.fixture
def seeded_app(tmp_path, monkeypatch, sample_dir):
    monkeypatch.setenv("KEVSHIFT_DATA_DIR", str(tmp_path))
    conn = database.connect(tmp_path / "kevshift.db")
    database.init_schema(conn)
    demo.apply_step(conn, tmp_path, sample_dir, 3)
    conn.close()
    return tmp_path


@pytest.mark.parametrize("page", PAGES)
def test_every_page_renders_with_data(seeded_app, page):
    app = AppTest.from_file(APP, default_timeout=60).run()
    app.sidebar.radio(key="page").set_value(page).run()
    assert not app.exception, [e.value for e in app.exception]


def test_findings_page_shows_the_explained_table(seeded_app):
    app = AppTest.from_file(APP, default_timeout=60).run()
    app.sidebar.radio(key="page").set_value("Findings").run()
    assert not app.exception
    frame = app.dataframe[0].value
    assert len(frame) == 5 and "Why it was flagged" in frame.columns
    assert "Newly added to KEV" in set(frame["Change category"])


def test_empty_database_shows_helpful_empty_states(tmp_path, monkeypatch):
    monkeypatch.setenv("KEVSHIFT_DATA_DIR", str(tmp_path))
    for page in PAGES:
        app = AppTest.from_file(APP, default_timeout=60).run()
        app.sidebar.radio(key="page").set_value(page).run()
        assert not app.exception, (page, [e.value for e in app.exception])


def test_failed_refresh_never_shows_a_success_message(tmp_path, monkeypatch):
    from src import kev_client

    monkeypatch.setenv("KEVSHIFT_DATA_DIR", str(tmp_path))

    def offline(*args, **kwargs):
        raise kev_client.KevDownloadError("no internet")

    monkeypatch.setattr(kev_client, "download_kev_json", offline)
    app = AppTest.from_file(APP, default_timeout=60).run()
    app.sidebar.radio(key="page").set_value("KEV catalog").run()
    app.button[0].click().run()
    assert not app.exception
    assert not app.success and app.error  # error shown, no green success banner
