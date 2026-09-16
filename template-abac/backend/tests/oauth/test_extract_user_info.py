from kalekit.oauth.endpoints import _extract_user_info


def test_github_prefers_name_over_login() -> None:
    account_id, email, display_name = _extract_user_info(
        "github",
        {"id": 1, "email": "a@example.com", "name": "Alice Adams", "login": "aadams"},
    )
    assert account_id == "1"
    assert email == "a@example.com"
    assert display_name == "Alice Adams"


def test_github_falls_back_to_login_when_name_missing() -> None:
    _, _, display_name = _extract_user_info(
        "github", {"id": 1, "email": None, "login": "aadams"}
    )
    assert display_name == "aadams"


def test_google_extracts_name() -> None:
    account_id, email, display_name = _extract_user_info(
        "google", {"id": "abc", "email": "b@example.com", "name": "Bob Brown"}
    )
    assert account_id == "abc"
    assert email == "b@example.com"
    assert display_name == "Bob Brown"


def test_twitter_has_no_email_and_prefers_name_over_username() -> None:
    account_id, email, display_name = _extract_user_info(
        "twitter",
        {"data": {"id": "123", "username": "carol_x", "name": "Carol X"}},
    )
    assert account_id == "123"
    assert email is None
    assert display_name == "Carol X"


def test_twitter_falls_back_to_username_when_name_missing() -> None:
    _, email, display_name = _extract_user_info(
        "twitter", {"data": {"id": "123", "username": "carol_x"}}
    )
    assert email is None
    assert display_name == "carol_x"
