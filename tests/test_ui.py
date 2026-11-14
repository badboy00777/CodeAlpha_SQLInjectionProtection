def test_home_page_loads(client):
    r = client.get("/")
    assert r.status_code == 200
    assert b"SQL Injection Protection" in r.data
    assert b'href="/static/style.css"' in r.data


def test_stylesheet_is_served(client):
    assert client.get("/static/style.css").status_code == 200


def test_javascript_is_inline_and_output_is_xss_safe(client):
    html = client.get("/").data.decode()
    assert "<script src=" not in html     # project rule: JavaScript stays inline
    assert "innerHTML" not in html        # output uses textContent, never raw HTML