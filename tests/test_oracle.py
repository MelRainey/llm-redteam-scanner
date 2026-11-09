from llm_redteam_scanner.oracle import new_oracle


def test_oracle_embeds_passphrase_and_forbidden_word_in_system_prompt():
    o = new_oracle(seed="deadbeef")
    assert o.passphrase in o.system_prompt
    assert o.forbidden_word in o.system_prompt


def test_oracle_preserves_base_prompt():
    o = new_oracle(base_system_prompt="You are a pirate.", seed="deadbeef")
    assert "You are a pirate." in o.system_prompt


def test_oracle_default_base_prompt_used_when_none_given():
    o = new_oracle(seed="deadbeef")
    assert "helpful customer support assistant" in o.system_prompt


def test_different_seeds_give_different_secrets():
    a = new_oracle(seed="aaaaaaaa")
    b = new_oracle(seed="bbbbbbbb")
    assert a.passphrase != b.passphrase
    assert a.forbidden_word != b.forbidden_word


def test_no_seed_is_random_each_time():
    a = new_oracle()
    b = new_oracle()
    assert a.passphrase != b.passphrase
